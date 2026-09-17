# Plan 032 F0a — product-fit report

**Scope.** Both F0a scenarios, run against real PostgreSQL through the proposed
public API, with the measurements Plan 032 F0a asks for. Date 2026-09-17,
prototype at `prototypes/kernel/`.

**Result: both scenarios fit, and the API was revised twice because they did
not.** Details in §4 — that is the part of this report worth reading.

## 1. Setup and prerequisites

```bash
docker compose -f docker-compose.test.yml up -d
export DSN="postgresql://regista_test:regista_test@localhost:5432/regista_test"
python prototypes/kernel/example_handoff.py   "$DSN"
python prototypes/kernel/example_documents.py "$DSN"
python prototypes/kernel/test_mutations.py    "$DSN"
```

Prerequisites are PostgreSQL and `psycopg`. **No keys, no trust log, no genesis
ceremony, no suite configuration, no `~/.config` anything, no environment beyond
a DSN.** Plan 032's release-checklist line "ordinary operation requires no suite
or cryptographic ceremony" holds for both scenarios.

## 2. Time to first completed item, and glue

Recorded clean run, empty database to one item in a terminal state:

| Measure | Value |
| --- | ---: |
| Empty database → first completed item | **0.07 s** |
| Caller lines to get there (workflow definition included) | **12** |
| Scenario 2 end to end, including CLI subprocesses | 1.5 s |

The twelve lines are: connect, initialize, a five-line workflow definition,
create, claim, and two transitions. No application-specific tables, no migration
step of the caller's own, no bootstrap module.

## 3. Application glue required

Neither scenario needed Regista to learn anything about its domain. Scenario 2
adds **zero** document-specific code: it differs from scenario 1 only by a JSON
workflow document and the caller's own field names. `invoice_total`,
`confidence`, `source_uri` and `reject_reason` are custom fields; `follows` and
`blocks` are caller-chosen link types. Plan 032's requirement to "add no
document-specific code to Regista" is met.

No scheduler, execution engine, or suite-specific policy was needed to make
either scenario work — the F0a exit condition that would otherwise force the
product to narrow.

## 4. Surprising refusals and private-API temptations

This is what F0a exists to find, and it found three. All three were real, and the
API was changed rather than worked around.

**(a) The CLI could not be built from the public API.** Plan 032 requires that
"the library and CLI must expose the same useful coordination operations."
Writing `cli.py` immediately required `kernel._conn` for two commands — `health`
and `workflow list` had no public equivalent at all. Fixed by adding
`Kernel.health()` and `Kernel.list_workflows()`.

**(b) `release()` took the wrong primitive.** It accepted a `Claim`, but a CLI
holds only `(id, actor, attempt)` from an earlier invocation in a different
process. The only way to call it was to fabricate a `Claim` with a `None`
expiry — a lie the type system had to be silenced about. Reshaped to
`release(work_item_id, *, actor_id, attempt)`. A library caller with a `Claim`
now unpacks it; the CLI just calls it.

**(c) Scenario 1 was reaching into the claims table to expire a lease.** It
backdated `expires_at` by SQL to avoid waiting. That made the scenario faster and
also made it stop being a test of the public API. Replaced with a genuinely short
lease and a real 2.2-second wait. The scenario now runs entirely through public
calls, and demonstrates actual expiry rather than database surgery.

After these, **both scenarios and the CLI use zero private attributes.** The
mutation checks still reach into the database deliberately — that is their job.

A fourth finding was **not** fixed, because it is a design question rather than a
defect: **"blocked" is not expressible as a link-aware query.** The scenarios
report blocked work by naming a state (`rejected`), which Plan 032 permits —
"'blocked' and 'review-ready' are queries over a caller's workflow." But the link
graph is stored and cannot be asked "is anything blocking this item still
unfinished." Plan 032 also says links "do not introduce a dependency scheduler,"
so a link-aware blocked query sits close to a line the plan draws deliberately.
**This needs a ruling, not a patch.**

One behaviour worth documenting rather than changing: **custom fields carry
forward across transitions.** In scenario 2, `invoice_date` from the first
extraction survived a reject and a rework and was still present at approval. That
is correct — fields are merged, not replaced — but a caller could reasonably
expect a rejected proposal's fields to be cleared, and nothing says otherwise.

## 5. The benefit over bespoke state and claim tables

Plan 032 requires this report to make that case, so here it is with its limits.

**When a bespoke table is the better answer:** one worker pool, one state
machine, one process topology, no need for the history to be authoritative. A
`status` column and a `locked_until` timestamp genuinely are enough, and they are
less to understand than a dependency.

**What this provides that such a table usually does not, until it is rewritten
two or three times:**

- **Takeover that cannot be fooled by the worker it replaced.** `locked_until`
  alone does not give you this: the classic bug is a worker that stalls past its
  lock, wakes, and writes as though it still held it. The fencing token makes
  that write refusable, and the mutation checks prove the refusal fires and that
  the legitimate write still succeeds.
- **A history that is the source of truth, not a log written beside it.** The
  projection and the event are written in one transaction, and `replay()`
  rebuilds state from events alone and reports disagreement rather than
  asserting. Hand-rolled audit tables usually drift from the row they describe,
  and nothing notices.
- **Refusals as a contract.** Invalid transitions, unmet role policy, missing
  required fields and terminal states refuse with typed errors and no partial
  effect. In a bespoke table these are conditionals scattered across the callers
  that update it, and each new caller re-implements them slightly differently.
- **One vocabulary across independently running participants.** Scenario 2's
  reviewer is a person at a terminal; its worker is a cron job. They did not
  share a codebase, a language runtime, or a process — only the store.

**What it is not:** none of this is novel, and it is not a claim that the
alternatives cannot model the same problems.
[Temporal](https://docs.temporal.io/) (durable execution),
[DBOS](https://docs.dbos.dev/architecture) (PostgreSQL-backed durable workflows)
and [Procrastinate](https://procrastinate.readthedocs.io/en/stable/) (PostgreSQL
task queues) are better answers when you want work *executed*. The niche here is
narrower: explicit ownership and validated handoffs among participants that are
already running somewhere else. "Python plus PostgreSQL" is not a differentiator.

**Demand remains unproven.** Two scenarios written by the author of the API are a
fit check, not evidence of adoption, and Plan 032 says so.

## 6. Measurement this report does NOT contain

Plan 032 F0a asks that "a reviewer unfamiliar with the implementation must be
able to follow the quickstart unaided; record where they needed clarification."

**That was not done, and cannot be self-reported.** Whoever wrote the API is the
worst available judge of whether its quickstart is followable. This measurement
is outstanding and needs a person who has not seen the code. It is the one F0a
exit criterion this report leaves open.

## 7. Exit assessment

| F0a exit condition | Status |
| --- | --- |
| Both scenarios fit naturally through the proposed public surface | Met, after the three revisions in §4 |
| Ownership and handoff failures are understandable | Met — refusals name the holder, the current attempt, and what was expected |
| Report explains the benefit over bespoke state/claim tables | Met, with limits stated (§5) |
| Neither scenario required a scheduler, execution engine, or suite policy | Met |
| Quickstart followable by an unfamiliar reviewer | **Outstanding** (§6) |
| Both scenarios become release acceptance cases in F3 | Ready — both are runnable and assert their own outcomes |
