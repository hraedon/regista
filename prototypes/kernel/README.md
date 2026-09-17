# Regista kernel prototype

This is the F0a instrument for [Plan 032](../../plans/032-final-public-release.md):
a complete, running `create → claim → transition → query → replay` path with **no
keys, no trust log, no genesis ceremony and no suite configuration**, built to
settle the extract-versus-sever question in Plan 032 §5 with code rather than
argument.

It is not yet the shipped package. See [the verdict](#what-this-settles).

## Try it in two minutes

You need PostgreSQL and `psycopg`. A disposable instance:

```bash
docker compose -f ../../docker-compose.test.yml up -d
export DSN="postgresql://regista_test:regista_test@localhost:5432/regista_test"
```

Run the scenarios:

```bash
python example_handoff.py   "$DSN"   # agents: contention, takeover, fencing
python example_documents.py "$DSN"   # people: document review, driven via the CLI
```

It files remediation work, races **two real OS processes** for the lease, walks a
worker/reviewer handoff with a change request, kills the worker, expires its
lease, lets another worker take over, and then tries to commit the dead worker's
write — which is refused. Finally it replays the item from events alone and
prints the history.

Prove the checks can actually fail:

```bash
python test_mutations.py "$DSN"
```

30 checks, each with a control. They let real leases expire and write with them,
heartbeat a dead lease, present a live holder's fencing token as someone else,
hold a row lock until a lease dies underneath a waiting writer, edit event
payloads, delete middle *and* final events, rewrite a projection's fields, pass
a `datetime` as a custom field, overwrite a reducer-owned payload key, reuse
idempotency keys for different requests, present the wrong role, and point
`initialize()` at a 0.7-era schema. Every one asserts something was refused
**and** that the legitimate version of the same call still succeeds.

Expiry is exercised with genuinely short leases and real waits, never by
backdating `expires_at` in SQL — a backdated row cannot tell a correct expiry
predicate from one evaluated against the wrong clock.

And the CLI a person participates through:

```bash
export REGISTA_DSN="$DSN"
python cli.py health
python cli.py list --state needs_review
python cli.py transition <id> --transition correct --actor erin \
    --actor-kind human --role editor --field invoice_total=1420.55
```

The [F0a product-fit report](F0a-report.md) records what both scenarios measured
— including the three places the API had to be **changed** because a scenario
could not be written without reaching past it.

## The model

Register a workflow, create work, claim it, make validated transitions, query,
replay. Regista owns coordination state; you own execution and your interfaces.

```python
from kernel import Kernel, Workflow

k = Kernel.connect(DSN)
k.initialize("schema.sql")

k.register_workflow(Workflow(
    name="remediation", version=0,
    states=("open", "in_progress", "in_review", "done"),
    initial="open",
    transitions={
        "start":  (("open",), "in_progress"),
        "submit": (("in_progress",), "in_review"),
        "accept": (("in_review",), "done"),
    },
    roles={"accept": ("reviewer",)},
    required_fields={"submit": ("remediation_note",)},
    terminal=("done",),
))

item = k.create_work_item(workflow="remediation", type="finding",
                          actor_id="scanner", fields={"host": "web-01"})

claim = k.claim(item.id, actor_id="worker-1", ttl_seconds=300)
k.transition(item.id, transition="start", actor_id="worker-1", attempt=claim.attempt)
```

`claim.attempt` is a **fencing token**. An item is always in exactly one of
three lease conditions, and every refusal says which one it found:

| Condition | A write is… |
| --- | --- |
| **unclaimed** (no lease row) | allowed with **no** `attempt`. Passing one is refused — you believe you are fenced and you are not. |
| **expired** (lease row, past its TTL) | refused, with or without an `attempt` (`LeaseExpiredError`). Expiry is terminal: it cannot be renewed or written through. Resolve it with `expire_leases()` or take it over with `claim()`. |
| **live** | allowed only with the **current** `attempt` *and* the holder's `actor_id`. A wrong or absent attempt is `StaleAttemptError`; a correct attempt presented by anyone else is `LeaseNotHeldError`. |

That is what makes a worker that hung, got paused, or lost its network harmless
to this store when it wakes up and tries to finish — including before anyone has
noticed and taken over. Handing work to a reviewer means *releasing* the lease:
a lease is exclusive, so the holder writes and nobody else does.

Checking the holder is **ownership, not authentication**. `actor_id` is still
caller-supplied attribution; the kernel refuses a write *attributed* to someone
who does not hold the lease, because recording one would make the history say
something the coordination state contradicts.

Lease expiry is decided by the **database** clock, using `clock_timestamp()`
rather than `now()`, and evaluated after the row lock is taken — at the point
the write serializes, not when its transaction began. Every stored timestamp
comes from the same clock. A coordination store has many clients and one
serialization point; if a client's clock decided liveness, `available()` and
`transition()` could disagree about whether the same lease is held.

### What a custom field may hold

A custom field value — and a caller-supplied event `payload` value — may be a
string, number (finite), boolean, `null`, list, or object with string keys,
nested. **Anything else is refused** with `InvalidFieldError` naming the path
and the type; convert at the call site (`datetime.isoformat()`, `str(uuid)`).
The kernel does not coerce, because a silent `str()` means replay hands back a
different type from the one you wrote and nothing records that it happened.

`payload` may not contain the keys the event reducer owns — `from`, `to`,
`fields`, `created` — and says so (`ReservedPayloadKeyError`) rather than
letting a caller displace the record replay reads back.

## What it does not do, stated plainly

- **It does not authenticate anyone.** `actor_id` is caller-supplied attribution.
  Workflow role checks enforce *your* application's policy; the kernel does not
  verify that a caller holds the role it presents.
- **`prev_event_hash` is a consistency chain, not authenticity evidence.** It
  catches accidental gaps, reordering and edited payloads. It does **not** on
  its own catch a truncated tail: deleting the last event leaves a chain that
  still verifies. `replay()` catches that separately, by reconciling the history
  against the projection row. Anyone who can write the table can rewrite the
  chain. The trusted host and database administrator are part of the contract.
- **`replay()` reconciles the *reconstructible* projection, and nothing else.**
  It checks current state, custom fields, the last event sequence, every payload
  hash and every chain link, against one repeatable-read snapshot. It cannot see
  **leases, the attempt/fencing counter, typed links or idempotency keys** —
  nothing appends an event for those, so there is no history to reconcile them
  against. An empty `drift` list means "the reconstructible projection matches
  its history", not "the store matches its history". The exact boundary is
  published as `REPLAY_COVERS` / `REPLAY_DOES_NOT_COVER`. Nor can it catch a
  rewrite that changes the events *and* the projection consistently — the chain
  is unkeyed.
- **A lease does not make an external effect exactly-once.** It stops a stale
  worker committing *here*. It cannot stop that process issuing an HTTP request.
  If the effect must be fenced, pass `attempt` to the target system as well and
  let the target enforce it.
- **There is no in-place upgrade from 0.7.2 or earlier.** `initialize()` refuses
  an old or unknown schema without mutating it. Point it at a fresh database.
- **It is not a job executor, scheduler, or durable-execution engine.** If you
  need those, [Temporal](https://docs.temporal.io/),
  [DBOS](https://docs.dbos.dev/architecture) and
  [Procrastinate](https://procrastinate.readthedocs.io/en/stable/) address them
  directly and better.

## What this settles

Plan 032 §5 asks for dependency evidence before choosing between severing the
trust stack out of the current kernel and extracting a corrected kernel into a
fresh tree. The [dependency map](../../plans/032-f0-dependency-map.md) supplies
the static half; this supplies the running half.

| | Lines |
| --- | ---: |
| This prototype (implementation) | 1,188 (769 code, 237 docstring) |
| This prototype (schema) | 121 |
| …its scenario + mutation checks | 1,375 |
| Kernel-classified code to sever and re-cut | 22,610 |
| …of which six modules couple hardest to the trust stack | 6,046 |

The prototype is **not** a complete MVP. Missing against Plan 032's keep table:
the CLI, bounded/ordered pagination, connection-pool behaviour and health,
workflow definitions loaded from YAML/JSON Schema, bounded custom-field
filtering, archive, observability, the async surface, and cross-project links.
Completing those plausibly lands in the low thousands of lines — an estimate, not
a measurement.

The prototype is `ruff` clean under the repository's own configuration and passes
`mypy --strict`, which `[tool.mypy]` requires of every new module. Following the
D14 ruling, `prototypes/` is now **inside** both gates (`[tool.ruff]` lints it,
`[tool.mypy]` `files` includes it) and `test_scenarios.py` runs the two scenarios
and the mutation checks against a real PostgreSQL service in CI.

Even allowing generously for that, the comparison is an order of magnitude, and
the decisive factor is not size. §5 of the dependency map shows the retained
event record itself has to change: `events.key_id` and `events.signature` have
been `NOT NULL` since `001_initial.sql`, and `project_identity` could not be
populated without a trust domain and a genesis event. Severing in place means
re-cutting the six hot modules against a changed row anyway, while carrying the
history of every design that row used to serve.

**Recommendation: extract.** Promote this to the retained implementation rather
than severing the existing kernel, per Plan 032 F0a's requirement that the
minimal implementation "must become the retained implementation, not a throwaway
second engine."

The maintainer decides. If the decision goes the other way, the scenario and the
mutation checks still apply unchanged to a severed kernel — they test the
contract, not this implementation.
