# Regista

Regista gives independently running workers and people durable ownership of work
and validated handoffs. Your application runs the workers; Regista records who
owns an attempt, what state the work is in, and how it got there in PostgreSQL.

```bash
pip install regista-hraedon
```

0.8.0 requires Python 3.11 or newer and PostgreSQL (qualified on PostgreSQL 15).
Provision a database and a role with permission to create and use its project
schema. Set `REGISTA_DSN` to its connection string; this example uses a fresh
`tasks` schema. Creating service roles is the operator's job.

```python
import os

from regista import Kernel, Workflow

store = Kernel.connect(os.environ["REGISTA_DSN"], schema=os.getenv("REGISTA_SCHEMA", "tasks"))
try:
    store.initialize()  # empty destination, or the 0.8.0 baseline
    store.register_workflow(Workflow(
        name="tasks", types=("task",), states=("new", "review", "done"), initial="new",
        transitions={"submit": (("new",), "review"), "approve": (("review",), "done")},
        roles={"approve": ("reviewer",)}, role_names=("reviewer",), terminal=("done",),
    ))
    item = store.create_work_item(workflow="tasks", type="task", actor_id="worker")
    lease = store.claim(item.id, actor_id="worker")
    store.transition(item.id, transition="submit", actor_id="worker", attempt=lease.attempt)
    store.release(item.id, actor_id="worker", attempt=lease.attempt)  # explicit handoff
    store.transition(item.id, transition="approve", actor_id="alice", role="reviewer",
                     actor_kind="human")
    print(store.get(item.id).state)  # done
finally:
    store.close()
```

This exact example is exercised by `tests/test_documentation.py` and is available
as [quickstart.py](https://github.com/hraedon/regista/blob/main/examples/quickstart.py).
Roles here are supplied by the trusted application; `role="reviewer"` does not
authenticate Alice.

The two full scenarios run through the public API and installed CLI:
[worker/reviewer repair and takeover](https://github.com/hraedon/regista/blob/main/examples/example_handoff.py)
and [document extraction with human correction](https://github.com/hraedon/regista/blob/main/examples/example_documents.py).
Their workflows and scripts ship as `regista/examples` package resources. See the
[example commands](https://github.com/hraedon/regista/blob/main/examples/README.md).

## The bounded coordination contract

Immutable workflow versions define states, allowed transitions, caller-presented
roles, required fields, and optional field/link vocabularies. Items pin their
workflow version. Claims provide durable leases and increasing attempt tokens;
protected transitions require the current holder and attempt. Leases survive
transitions until explicit release, including terminal transitions. An expired
lease refuses writes until takeover or an operator sweep (`regista expire-leases`).
The operator schedules sweeps; Regista has no background scheduler.

Custom fields merge shallowly. `unset_fields` (CLI `--unset-field`) clears keys
atomically; JSON null remains a value. Typed links connect items within a project.
Available, owned, state-based review-ready, and single-hop blocked queries are
bounded snapshots. Links neither gate claims nor schedule dependent work.

Each create/transition appends history and updates current state atomically.
Idempotency keys deduplicate identical requests to Regista; conflicting reuse
refuses. A lease cannot stop a process making external requests. Downstream
systems must provide their own idempotency and enforce fencing when needed.

Use a task queue when you need to enqueue and execute jobs with worker management.
Use a durable-execution engine when application code needs persisted execution,
resumption, timers, or orchestration. Regista is useful when execution already
exists and the shared problem is ownership and handoff. Demand for this narrower
product has not been demonstrated, and no claim of uniqueness is made.

## Trust and recovery

The host application and database administrators are trusted. Actor names and
kinds are attribution; role checks enforce caller-presented application policy.
There is no identity authentication, signing, or hostile-administrator protection.
Unkeyed hashes check consistency and provide no authenticity evidence: a database
writer can alter records and recompute them.

`regista check-history` checks history read-only (the old `replay` command is
removed). Replay covers state, fields and clears, sequence density, payload hashes,
chain links, final sequence, and transition names against the pinned workflow.
`REPLAY_DOES_NOT_COVER` explicitly excludes leases, attempt counters, typed links,
and idempotency keys. A clean report proves neither those tables nor external
effects, identity, freshness, or an independently authenticated history.

Back up the whole database with PostgreSQL tools. Restore into a separate database,
check the whole namespace while quiescent, and test another valid write before
using it. See [operations and preservation](https://github.com/hraedon/regista/blob/main/docs/operations.md).

## Breaking 0.8.0 scope reduction

**A fresh database is required. There is no in-place upgrade from 0.7.2 or earlier,
no converter, and no automatic reset.** Keep the old dump, matching package and
dependency environment, and all old keys/trust material. Verify a scratch restore
with that environment before changing anything. Old readers keep their known
limitations; preservation does not certify their historical evidence claims.

0.8.0 removes the old `Regista`/in-memory/async facades, signing and trust governance,
bundles and witness/anchoring formats, principal custody, field encryption, suite
configuration, canonical agent review policy, HTTP sidecar and its extras,
recurrence, hooks/webhooks, synchronous validators, and workflow composition.
Callers validate before transitions; kernel role, field and required-field checks
remain. Project deletion is a manual operator `DROP SCHEMA`; role provisioning
is also manual. See the [complete breaking-change list](https://github.com/hraedon/regista/blob/main/docs/breaking-0.8.md).

Inputs are bounded: fields and transition payloads are each at most 64 KiB of
UTF-8 JSON, workflows 256 KiB, nested JSON depth 32, names 255 UTF-8 bytes, and
schema names 63 bytes. Queries default to 50 rows and cap at 500; field filters
allow eight scalar equality predicates. See the
[API](https://github.com/hraedon/regista/blob/main/docs/api.md),
[CLI](https://github.com/hraedon/regista/blob/main/docs/cli.md), and
[current specification](https://github.com/hraedon/regista/blob/main/spec.md).

## Maintenance and reporting

The maintainer provides a **90-day stabilization window from publication** for
release regressions and serious security or data-loss reports. The publication
date and resulting end date will be recorded in the release notes when 0.8.0 is
published; the window has not started for this candidate. There are no promised
new features and no SLA.

Report regressions and usage feedback through
[GitHub issues](https://github.com/hraedon/regista/issues).
Report sensitive security or data-loss details privately to **plm@hraedon.com**.
Historical designs under `docs/0.6.0`, `docs/0.7.*`, and `docs/pre-0.8` do not
define this release's contract.
