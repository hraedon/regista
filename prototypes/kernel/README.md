# Regista kernel prototype

This is the F0a instrument for [Plan 032](../../plans/032-final-public-release.md):
a complete, running `create → claim → transition → query → replay` path with **no
keys, no trust log, no genesis ceremony and no suite configuration**, built to
settle the extract-versus-sever question in Plan 032 §5 with code rather than
argument.

It is not yet the shipped package. See [the verdict](#what-this-settles).

## Getting it running

Everything below runs from **this directory** — the scripts find each other and
`schema.sql` by relative path. There is nothing to install: the kernel is a
single module.

You need **Python 3.11 or newer** (tested on 3.11–3.14), **`psycopg` v3**
(`pip install "psycopg[binary]"`), and a **PostgreSQL you can point at**. The
commands below say `python3`; use whatever name your Python 3 has.

**A database.** Any reachable, *empty* PostgreSQL database works —
`initialize()` refuses a database that already holds an older regista schema,
without touching it. Set `DSN` to yours:

```bash
export DSN="postgresql://USER:PASSWORD@HOST:5432/YOUR_EMPTY_DATABASE"
```

If you have Docker and you are inside a clone of this repository, there is a
disposable one two levels up (this path only works from the repo; it is not
shipped with the package):

```bash
docker compose -f ../../docker-compose.test.yml up -d
export DSN="postgresql://regista_test:regista_test@localhost:5432/regista_test"
```

### 1. Watch it work

```bash
python3 example_handoff.py   "$DSN"   # agents: contention, takeover, fencing
python3 example_documents.py "$DSN"   # people: document review, driven via the CLI
```

The first files remediation work, races **two real OS processes** for the lease,
walks a worker/reviewer handoff with a change request, kills the worker, expires
its lease, lets another worker take over, and then tries to commit the dead
worker's write — which is refused. Finally it replays the item from events alone
and prints the history.

The second drives the same kernel through a document-review workflow, with a
person acting through the CLI. It adds **no** document-specific code: a
different workflow document and different field names, nothing else.

Its output shows commands as `regista-kernel …`. That is what the command would
be called if this were installed; here you run it as `python3 cli.py …`.

### 2. Check the checks can fail

```bash
python3 test_mutations.py "$DSN"
```

53 checks, each with a control. They let real leases expire and write with them,
heartbeat a dead lease, present a live holder's fencing token as someone else,
hold a row lock until a lease dies underneath a waiting writer, edit event
payloads, delete middle *and* final events, rewrite a projection's fields, pass
a `datetime` as a custom field, overwrite a reducer-owned payload key, reuse
idempotency keys for different requests, present the wrong role, point
`initialize()` at a 0.7-era schema, create an undeclared work-item type, make a
v2-only transition on a v1-pinned item, and load a workflow document carrying a
duplicated YAML key or any 0.7 key this format dropped. Every one asserts
something was refused **and** that the legitimate version of the same call still
succeeds.

Expiry is exercised with genuinely short leases and real waits, never by
backdating `expires_at` in SQL — a backdated row cannot tell a correct expiry
predicate from one evaluated against the wrong clock.

### 3. Drive it yourself, from the CLI

The CLI reads its connection from `REGISTA_DSN`:

```bash
export REGISTA_DSN="$DSN"
python3 cli.py health
python3 cli.py list
```

`list` with no filter lists **everything**, leased items included: a leased row
is marked `[leased by NAME]`, or `[lease EXPIRED, held by NAME]` for one that is
dead but not yet swept. Nothing is ever silently withheld — `--available`
applies the lease filter when you want it, and a page that fills says so and
tells you how to resume rather than truncating quietly.

`--state needs_review` narrows further. Note that after the two scenarios above
have run, **nothing is left in `needs_review`**: they finish their items. To get
something you can act on:

```bash
python3 cli.py list --state received      # the documents scenario leaves one here
```

Take an id from the first column of `list` and use it. The id is a UUID, so
substitute the real value — a literal `<id>` is read by your shell as an input
redirection, not a placeholder:

```bash
ID=$(python3 cli.py list --state received | head -1 | awk '{print $1}')
python3 cli.py show "$ID"
```

`show` prints a `lease` line covering all three conditions — unclaimed, held, or
expired-and-unswept.

The rest of the CLI, for reference:

| | |
| --- | --- |
| `health` | counts, including `expired_leases` |
| `list` | `--state --workflow --type --field k=v --available --owned ACTOR --limit --after` |
| `list --blocked-by TYPE` | with `--direction {incoming,outgoing}` and `--satisfied STATE…` |
| `show` / `lease` | one item; who holds its lease |
| `history` | `--limit --after` |
| `create` / `link` | file work; relate two items |
| `claim` / `heartbeat` / `release` | hold a lease across steps |
| `transition` | `--field` to set, `--unset-field` to clear |
| `expire-leases [<id>]` | sweep dead leases, all or one |
| `workflow validate --file` | check a document; **needs no database** |
| `workflow register --file` | register one from YAML or JSON |
| `workflow list` / `workflow show` | what states and transitions exist |
| `replay` | rebuild from events; exits 1 on drift |

`--satisfied` is required on the CLI even though the library allows an empty
set: at a terminal, an omission is far likelier than the intent.

### 4. Or from Python

```bash
python3 my_first_item.py
```

...where `my_first_item.py` is the snippet in [The model](#the-model) below. Two
things that snippet assumes and does not say: `DSN` must be defined **in
Python** (the shell `export` above does not reach it — use
`DSN = os.environ["DSN"]`), and it prints nothing, so add a `print()` if you
want to see that it worked.

### Where things are

| | |
| --- | --- |
| The library | `kernel.py` — one module, no install step |
| The schema | `schema.sql`, applied by `Kernel.initialize()` |
| The CLI | `cli.py`, reads `REGISTA_DSN` |
| The workflow format | `workflow.schema.json`, with `remediation.workflow.yaml` and `ingest.workflow.yaml` as worked examples |
| Worked examples | `example_handoff.py`, `example_documents.py` |
| Proof the checks bite | `test_mutations.py` |

The [F0a product-fit report](F0a-report.md) records what both scenarios measured
— including the places the API had to be **changed** because a scenario could
not be written without reaching past it.

## The model

Register a workflow, create work, claim it, make validated transitions, query,
replay. Regista owns coordination state; you own execution and your interfaces.

```python
from kernel import Kernel, Workflow

k = Kernel.connect(DSN)
k.initialize("schema.sql")

k.register_workflow(Workflow(
    name="remediation",
    states=("open", "in_progress", "in_review", "done"),
    initial="open",
    transitions={
        "start":  (("open",), "in_progress"),
        "submit": (("in_progress",), "in_review"),
        "accept": (("in_review",), "done"),
    },
    roles={"accept": ("reviewer",)},
    role_names=("reviewer",),
    required_fields={"submit": ("remediation_note",)},
    terminal=("done",),
    types=("finding",),
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

### Writing a workflow as a document

The Python literal above is one way in. The other is a document — YAML or JSON,
validated against `workflow.schema.json`:

```yaml
kernel_workflow: 1
name: remediation

states:
  - name: open
    initial: true
  - name: in_progress
  - name: in_review
  - name: done
    terminal: true

roles: [reviewer]
work_item_types: [finding]

transitions:
  - name: start
    from: [open]          # one source, or several, under ONE entry
    to: in_progress
  - name: submit
    from: in_progress
    to: in_review
    required_fields: [remediation_note]
  - name: accept
    from: in_review
    to: done
    roles: [reviewer]
```

```bash
python3 cli.py workflow validate --file remediation.workflow.yaml   # no database
python3 cli.py workflow register --file remediation.workflow.yaml
```

`validate` runs before anything is provisioned — no DSN, no connection, no
schema — and reports **every** problem in one pass, because a person fixing a
file wants the list and not the first line of it. `register` stops at the first,
because a program loading a file has nothing to do with the rest.

`kernel_workflow: 1` is the version of the *document format*. It is not the
library version and not the workflow's version: the registry assigns workflow
versions, and a file on disk cannot know what the registry already holds.

Four rules exist because their absence is silent rather than loud:

- **Exactly one state carries `initial: true`.** Zero or two is a document that
  would otherwise start items somewhere arbitrary.
- **Every state is reachable.** A state no transition enters can never hold an
  item, so every report that mentions it is answering about nothing.
- **`roles:` is a closed set, cross-checked both ways.** Misspell a role on a
  transition and nothing can ever present it — the workflow looks fine until
  someone tries the transition and is told they need a role nobody has. The
  catalogue catches that, and the "declared but unused" half catches the same
  typo from the other side.
- **`work_item_types:` is a closed set.** `create_work_item(type=…)` is checked
  against it. An unchecked type string is how `finding` and `findings` become
  two populations that no type filter reunites.

`workflow.schema.json` is read from disk at validation time, so on promotion it
has to be packaged as package data — a wheel that ships `kernel.py` without it
would fail on the first `validate`, and not until then.

A duplicated YAML key is refused rather than resolved: `yaml.safe_load` keeps
the last and discards the first in silence, which in a workflow means a whole
block disappearing from a file that still validates.

**Keys from the 0.7 format are refused by name, with what happened to the
feature** — `allowed_roles` (renamed to `roles`), `validator`, `validator_params`,
`privileged`, `hooks`, `hook_defaults`, `extends`, `link_types`,
`attempt_threshold`, `version`, `regista_version`. Several of those *restricted*
something, so accepting-and-ignoring one would silently open a transition that
used to be closed. `work_item_types` and `roles` are lists of names here, not of
objects; the 0.7 object form is refused with the same explanation.

### What a custom field may hold

A custom field value — and a caller-supplied event `payload` value — may be a
string, number (finite), boolean, `null`, list, or object with string keys,
nested. **Anything else is refused** with `InvalidFieldError` naming the path
and the type; convert at the call site (`datetime.isoformat()`, `str(uuid)`).
The kernel does not coerce, because a silent `str()` means replay hands back a
different type from the one you wrote and nothing records that it happened.

`payload` may not contain the keys the event reducer owns — `from`, `to`,
`fields`, `unset`, `created` — and says so (`ReservedPayloadKeyError`) rather than
letting a caller displace the record replay reads back.

### How fields change across a transition

Fields **merge**: keys you do not mention survive. A rejected proposal's
`invoice_date` is still there after a rework, which is usually what a caller
wants and is occasionally a surprise, so it is stated here rather than
discovered.

The merge is **shallow**. A supplied object replaces the previous one wholesale;
there is no deep merge and no way to ask for one.

To remove a field, pass `unset_fields=("invoice_date",)`. That is the only way —
setting it to `null` does not remove it, because **`null` is a value**: stored,
replayed, and findable with `where_fields={"k": None}`, distinct from absence. A
**required** field must be present *and* non-null, so a workflow's own gate
cannot be satisfied by nothing; the refusal distinguishes "not set" from
"present but null" because the two need different fixes.

Clears are recorded on the event and reproduced by replay, so a cleared field
stays cleared through a rebuild. Setting and clearing the same key in one call
refuses rather than applying an ordering rule you would have to memorise.
Clearing a key that is not there is a **no-op, not a refusal**, so a retry is
safe and two callers clearing the same stale value do not race — the cost being
that a misspelled name in `unset_fields` does nothing quietly.

### Asking what is blocked

`blocked()` is the one link-aware query, and the line it stays on is deliberate.

You supply the link type, the direction, and — the part that matters — **which
states count as satisfied**. The kernel does not assume a terminal state means
success, because a *rejected* blocker is terminal and has not satisfied
anything. Getting that wrong silently inverts the answer, so an unrecognised
state name is refused rather than quietly matching nothing.

It is **single-hop**. Given `a → b → c`, finishing `b` frees `c` even while `a`
is still open. There is no transitive closure and there will not be one: links
describe relationships, and a dependency scheduler is explicitly not what this
is. A check in the suite fails if anyone turns the query into a recursive walk.

The result is a **snapshot**. Nothing stops a blocker being reopened a moment
after you read it, and `blocked()` gates nothing — it will not refuse a claim or
a transition on your behalf. A caller who treats it as a guarantee has a race.

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
| This prototype (implementation) | 1,746 |
| This prototype (schema) | 128 |
| …its CLI | 474 |
| …its scenario + mutation checks | 1,897 |
| Kernel-classified code to sever and re-cut | 22,610 |
| …of which six modules couple hardest to the trust stack | 6,046 |

The prototype is **not yet** a complete MVP, but the gap has narrowed. Against
Plan 032's keep table, still missing: **connection-pool behaviour**. Done since
the first draft: the CLI, bounded and ordered pagination across every collection
query, bounded custom-field filtering, work-discovery queries including the
link-aware one, health, and workflow documents loaded from YAML/JSON against a
JSON Schema.

The keep table's custom-field row can be read two ways, and the maintainer
should rule rather than inherit the reading below. "Basic validated domain
data" is satisfied today by the JSON type and depth checks every field value
passes, plus per-transition required fields. It is **not** satisfied in the 0.7
sense of per-type field declarations — `type: enum`, `enum_values`, `required` —
which this document format deliberately does not carry, because the kernel
enforces no such declaration and a declaration nothing enforces is worse than
none. Adding them is a real feature with its own validation surface, not a
loader change.

Archive, observability, the async surface and cross-project links are **out of
scope for 0.8.0** rather than missing — none of them appears in the keep table,
and the review was explicit that they should not be priced back in silently.

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
