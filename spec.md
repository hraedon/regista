# Regista 0.8.0 coordination specification

This document is normative for the reduced 0.8.0 package. It supersedes the
[historical specification](docs/pre-0.8/spec.md). Plan 032 and its
[dated rulings and adopted defaults](plans/032-open-decisions.md) record design
choices; older designs do not define current behavior. `spec.yaml` is retired.

## Scope and boundary

Regista persists coordination state for independently running participants in
one PostgreSQL project schema. Callers own execution and interfaces. The public
surface is exactly `regista.__all__` and [the CLI reference](docs/cli.md).
Transition/reduction rules have one implementation in `src/regista/kernel.py`.
There is no in-memory/async engine, task executor, durable-execution runtime,
HTTP server, scheduler, callback registry, or suite dependency.

The host application and database administrators are trusted. Actor IDs/kinds
are attribution. Workflow roles are caller-presented assertions checked against
policy, not identity authentication or proof of role membership. Unkeyed hashes
check internal consistency; they provide no authenticity evidence and can be
recomputed by a database writer. Regista provides no non-repudiation, hostile-admin
tamper evidence, external freshness, or model identity guarantee. Encryption,
credentials and database privileges belong to the operator.

## Storage and initialization

Python >=3.11 is advertised; CI qualifies 3.11–3.14 without a speculative upper
bound. PostgreSQL 15 is qualified. `Kernel.connect` opens a bounded pool (default
min 1, max 4, timeout 5 seconds) for an explicit schema. It creates nothing.
Each operation borrows an exclusive connection and scopes one transaction; rollback
and connection reset isolate borrowers. Pool exhaustion/unavailability and database
failures surface as typed `KernelError` subclasses.

`initialize` accepts an empty destination or the supported schema baseline
(`KERNEL_SCHEMA_VERSION = 1`). Old/unknown occupied schemas refuse before writes.
Existing unsupported kernel versions remain diagnostic-readable but reject writes
and initialization. There is **no in-place upgrade from 0.7.2 or earlier**, reset,
or converter. Package resources supply `schema.sql` and `workflow.schema.json`.
The operator provisions service roles and grants privileges; dropping a project is
manual `DROP SCHEMA`. Schema names cannot redirect queries to another namespace. Special `$user`, `pg_*`
and `information_schema` names refuse; every checkout/operation verifies literal
namespace resolution. `initialize()` creates an absent schema transactionally and
always loads pinned package SQL, with no SQL-path parameter. Existing baseline 1
must match the complete committed catalog manifest; every write rechecks it.

## Workflows and work items

Registered workflow definitions are immutable and versioned by the registry.
Equal re-registration returns the existing version; a changed definition creates
a new version. Nonzero caller versions assert the assigned version. Each item
pins its workflow version and a declared work-item type. Workflow validation
checks initial/terminal states, transitions, closed role/type vocabularies,
required fields, basic per-type field schemas and optional link vocabularies.
YAML/JSON authoring uses `kernel_workflow: 1`; duplicate keys and retired keys
(including validators, recurrence, hooks and composition) refuse explicitly.

Create appends a creation event and the projection atomically. Transition locks
the item, validates the pinned workflow, live lease/attempt and holder attribution,
optional expected sequence, presented role and merged/cleared fields, then commits
the event and projection together. Required fields must exist and be non-null.
Terminal states refuse further transitions. Failures leave no partial effects.
Callers perform domain validation before transition; synchronous validators are
retired by the 2026-10-05 ruling.

Fields accept JSON-compatible finite values. Merge is shallow: supplied keys
replace values wholesale, omitted keys survive. `unset_fields` atomically removes
keys; clearing an absent key is a no-op, setting and clearing the same key refuses.
JSON null is a value rather than a clear. Reference fields validate same-namespace
UUID targets/types. A free-form transition payload may annotate events but cannot
set the reserved reducer keys `from`, `to`, `fields`, `unset`, or `created`.

Optional idempotency keys share one namespace for create and transition. Identical
retries return the original result; conflicting reuse refuses without effects.
For transitions a matching retry returns before current fencing/expected-sequence
validation; it creates no new event. Attempt tokens are excluded from request
identity so a retry can recover its result after ownership changes. Actor/kind,
role, fields, payload, ordered clears, and expected sequence bind transition
identity. This contract protects only Regista writes, never external effects.

## Claims, handoff and discovery

Claim acquires a durable lease with an increasing attempt token. Contention gives
one winner; takeover invalidates earlier attempts. Lease decisions use the database
clock after locking. Heartbeat/release require holder attribution and current
attempt. Protected transitions require both too. An expired lease refuses writes
until takeover or explicit expiry sweep; a truly unclaimed item accepts a
transition with no attempt, while a supplied attempt without a lease refuses.
**Leases persist through all transitions until explicit release**, a behavior
change from 0.7 ruled 2026-10-05. The operator schedules `expire-leases`; sweeps
remove expired leases only and retain attempt counters. No worker is terminated
by a lease. Downstream effects need downstream idempotency/fencing.

Typed links connect existing items in one namespace. Source workflow vocabulary
is enforced if declared; `None` is free-form and an empty tuple permits none.
Link add/remove is idempotent. Links have no scheduling/claim-gating effect.

`list_items` includes leased items. `available` excludes live leases; `owned`
requires a live lease for the named actor. `in_states` defines state-based blocked
or review-ready discovery. `blocked` is a single-hop, read-only link query whose
caller specifies relationship, direction and satisfied counterpart states.
Terminal states are not automatically satisfaction. These are snapshots; no
query promises claim success or future dependency satisfaction.

Item pages order by creation timestamp and UUID with exclusive item cursors.
Workflow pages order by name/version; link pages by type/target UUID; history
pages by ascending event sequence. History supports exclusive `after`/`before`
and newest suffix selection, still returned ascending. Full pages may have more.
Field filters AND at most eight top-level scalar-equality predicates.

## History, replay and recovery

Per-item ordered events contain attribution, transition, payload and a native
PostgreSQL timestamp. `replay` reduces events read-only and reports drift against
the current projection. `REPLAY_COVERS` comprises state, fields/clears, final
sequence, payload hashes, chain links, sequence density and transition names
against the pinned workflow. It neither rebuilds tables nor certifies identity.

`REPLAY_DOES_NOT_COVER` comprises **leases, attempt/fencing counters, typed links,
and idempotency keys**: they have no event history. A clean report says nothing
about them or external effects. Whole-namespace `replay_all` includes event-only
and projection-only IDs, streams UUID pages and reduces each item in a separate
repeatable-read snapshot. Run recovery checks while quiescent. Drift is bounded
at 100 messages plus an omission summary; retained summaries expose projection
mismatches even on badly damaged histories.

Back up all tables and restore to a separate database. Reconnect, check the whole
namespace and perform another valid write before considering recovery usable.
The old CLI `replay` is removed; `check-history` implements read-only checks.
[Operations](docs/operations.md) defines preservation of old dumps, matching
package/dependency environments and keys/trust material; verify a scratch old
restore before changing anything. Historical reader limitations remain.

## Limits and maintenance

Fields/payloads each cap at 64 KiB of UTF-8 JSON; workflows at 256 KiB, JSON depth
at 32, names at 255 bytes, schema names at 63 bytes. Query limits are 1–500
(default 50), queried name/state sets at most 500, field filters at most eight.
The [API reference](docs/api.md) exports these constants and typed errors.

The stabilization window is 90 days from publication for release regressions and
serious security/data-loss reports, with no new-feature promise or SLA. Publication
notes must record the publication date and the end date (publication + 90 days).
The candidate has not started that window. Public reports use GitHub issues;
sensitive reports use plm@hraedon.com. [Breaking changes](docs/breaking-0.8.md)
defines removals; historical documents are retained and explicitly historical.
