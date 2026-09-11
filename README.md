# regista

Durable ownership, validated handoffs, and replayable history across independent
workers and people.

Regista is an embeddable work-coordination ledger over PostgreSQL. It gives a
Python application one shared, durable answer to four questions about a piece of
work: who owns it, what state is it in, what may happen next, and how did it get
here. Callers own execution and their own interfaces; regista owns coordination
state.

It is a library, not a service. No HTTP server, no keys, no configuration
ceremony: point it at a database, register a workflow, and start coordinating.

[![CI](https://github.com/hraedon/regista/actions/workflows/ci.yml/badge.svg)](https://github.com/hraedon/regista/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)]()

## Install

```bash
pip install regista-hraedon
```

The distribution is `regista-hraedon`; the import name and the console script are
both `regista`. Requires Python 3.11+ and PostgreSQL.

## Quickstart

Start a disposable PostgreSQL (or use your own) and point `REGISTA_DSN` at it:

```bash
docker compose -f docker-compose.test.yml up -d
export REGISTA_DSN="postgresql://regista_test:regista_test@localhost:5432/regista_test"
```

Define a workflow. States, transitions, roles, custom fields, and link types are
declared in YAML (validated against a JSON Schema):

```yaml
name: remediation
version: 1
regista_version: "0.8.0"
states:
  - name: ready
    initial: true
  - name: in_progress
  - name: in_review
  - name: done
    terminal: true
roles:
  - name: worker
  - name: reviewer
transitions:
  - name: start
    from: ready
    to: in_progress
    allowed_roles: [worker]
  - name: submit_for_review
    from: in_progress
    to: in_review
    allowed_roles: [worker]
  - name: approve
    from: in_review
    to: done
    allowed_roles: [reviewer]
work_item_types:
  - name: remediation
    custom_fields:
      - name: title
        type: string
        required: true
      - name: severity
        type: enum
        enum_values: [low, medium, high]
```

Connect, register, create, claim, transition, query:

```python
from regista import Regista

with Regista.create_project("postgresql://user:pass@host:5432/db", "my_project") as sub:
    sub.register_workflow(open("remediation.yaml").read())

    item, _ = sub.create_work_item(
        "remediation",
        "remediation",
        "discovery",
        custom_fields={"title": "Fix null dereference", "severity": "high"},
    )

    claim = sub.acquire_claim(item.work_item_id, "worker-a", ttl_seconds=120)
    sub.transition(
        item.work_item_id,
        "start",
        "worker-a",
        actor_metadata={"role": "worker"},
        expected_attempt_number=claim.attempt_number,
    )

    claimable = sub.query_work_items(
        workflow_name="remediation",
        current_states=["ready"],
        claimable_now=True,
    )
    print(f"{len(claimable.items)} item(s) ready to claim")

    report = sub.replay()  # rebuild the projection from the event log
    assert report.replayed_drift == 0
```

Reconnect to an existing project with `Regista(dsn, project)`; `create_project`
bootstraps the schema and refuses to run against an old or unknown one.

## Runnable examples

Two complete, runnable scenarios against disposable PostgreSQL:

- [`examples/worker_reviewer.py`](examples/worker_reviewer.py) — a discovery step
  files remediation work; two workers race for it; a reviewer sends it back; a
  stale attempt is refused; a fresh review reaches `done`. Demonstrates claim
  contention, lease fencing, and the external-effect caveat.
- [`examples/document_processing.py`](examples/document_processing.py) — a
  non-agent document pipeline: machine extraction, a human correction through a
  transition, `not_before` scheduling, and claimable/owned/review-ready queries
  over a second workflow and field set.

Both need only a disposable database. See [`examples/README.md`](examples/README.md).

## The trusted-host boundary

Regista trusts the host application and the database administrators; it does not
try to defend against them.

- **Actor IDs are caller-supplied attribution.** `actor_id` records who the
  caller says acted. Regista does not authenticate people or agents, and does not
  cryptographically bind an actor to an identity.
- **Workflow role checks enforce application policy.** `allowed_roles` and
  `strict_roles` gate transitions to the roles your workflow declares, but the
  role is asserted by the caller. They express your application's rules, not an
  independent proof of who is acting.
- **Replay detects inconsistency; it does not prove tamper-evidence.** Replay
  folds the event log into expected state and diffs it against the projection.
  Drift and halts are reported honestly. Regista makes no non-repudiation,
  hostile-administrator, authenticity, or external-freshness claim.

The database administrator can read and write the schema directly. If your threat
model includes a hostile operator, regista is not the control that addresses it.

## Leases, fencing, and external effects

A claim is a durable lease. Under concurrency exactly one actor owns an attempt,
and claim theft increments `attempt_number`. Pass `expected_attempt_number` on
lease-protected mutations (`transition`, `release_claim`, `heartbeat_claim`) and a
stale worker is refused with `CLAIM_LOST` rather than committing over the
replacement's work.

A lease does **not** make a downstream side effect exactly once. If a worker calls
an external system and crashes before recording the result, a retry can repeat the
call. The application owns duplicate protection for external systems: generate a
stable operation key before the effect and have the downstream system de-dupe on
it. The event append itself is idempotent when retried with the same `event_id`.

## When a task queue or durable-execution engine fits better

Regista coordinates *ownership and handoffs*. It is not a job executor, a durable
code-execution engine, a scheduler, or a hosted tracker. Reach for a different
tool when you need:

- automatic retries and exactly-once execution of code (DBOS, Temporal);
- a PostgreSQL task queue with worker scheduling and priorities (Procrastinate);
- recurring scheduling, cron, or a human UI.

Regista complements these. It is the shared ledger an existing worker, agent, or
application consults; it does not run your work. Demand for this niche is not
claimed here — the two examples are a product-fit check, not evidence of
adoption.

## What changed in 0.8.0

Regista 0.8.0 is a deliberate, breaking scope reset: the general
work-coordination kernel was kept and everything else was removed. There is **no
supported in-place upgrade** from 0.7.2 or earlier — a fresh schema is required.

Removed relative to 0.7.2:

- signing, keys, HMAC/Ed25519 schemes, and all cryptographic verification;
- trust domains, genesis/root governance, principals, custody, delegation
  credentials, and estate catalogs;
- audit bundles and their verifiers, witnesses, and transparency anchoring;
- async hooks/webhooks, witness/hook leases, and the hook dead-letter queue;
- recurrence scheduling;
- model lineage, assurance classification, and canonical review policy;
- suite configuration, secret backends, and provisioning;
- payload encryption-at-rest;
- workflow composition (`extends:`) and the archive subsystem;
- the HTTP sidecar and its authentication/deployment surface;
- the in-memory backend (tests now use disposable PostgreSQL fixtures).

See [`CHANGELOG.md`](CHANGELOG.md) for the full 0.8.0 entry and the historical
record of earlier releases.

### Preserving old data

There is no converter. To keep an old database readable:

1. Keep the old dump, the matching `regista-hraedon` package and its exact
   dependency environment, and any old key/trust material your workflows used.
2. Restore the dump into a scratch PostgreSQL instance and confirm the old
   package can open it, query it, and replay it there.
3. Only after the scratch restore verifies should you touch the original. Old
   readers retain their own known limitations; do not expect them to work against
   a 0.8.0 schema or the reverse.

## Administration CLI

```bash
regista workflow validate workflow.yaml   # no database required
regista work-item list --workflow remediation --claimable-now
regista work-item show <uuid>
regista work-item transition <uuid> --transition start --actor-id worker-a
regista events show --work-item-id <uuid>
regista replay
regista schema init --project my_project
regista schema status --project my_project
regista actor-roles list
regista version --json
regista doctor --json
```

Connection parameters come from `--dsn`/`--project` or `REGISTA_DSN`/`REGISTA_PROJECT`.

## Documentation

- [`spec.md`](spec.md) — authoritative specification of the reduced kernel
- [`spec.yaml`](spec.yaml) — machine-readable sidecar
- [`AGENTS.md`](AGENTS.md) — developer guide, source layout, and conventions
- [`CHANGELOG.md`](CHANGELOG.md) — version history
- [`docs/history/`](docs/history/) — historical pre-0.8.0 specifications and design records

## Maintenance

This is a complete, bounded MVP. Maintenance covers release regressions and
serious security or data-loss defects only. There is no feature roadmap and no
SLA. Concrete usage feedback is welcome; it does not create an obligation to
expand the product.

## License

MIT. See [LICENSE](LICENSE).