# Specification: regista (0.8.0 reduced kernel)

**Spec Level:** 3
**Desired Level:** 3
**Date:** 2026-09-11

> **Historical note:** the pre-0.8.0 specification (v9, the full trust/evidence
> product) is preserved at [`docs/history/spec-0.7.2.md`](docs/history/spec-0.7.2.md)
> and is historical, not normative. This document is authoritative for the 0.8.0
> reduced kernel.

**Extensions active:** None

---

## 1. Purpose and scope

**Problem.** Independently running workers, agent processes, scripts, and people
coordinate over ad-hoc conventions, flat files, or bespoke state tables. They lack
one durable, shared answer to: who owns this work, what state is it in, what may
happen next, and how did it get here?

**Product.** Regista is an embeddable work-coordination ledger over PostgreSQL. It
provides durable ownership, validated handoffs, and replayable history across
independent participants. Register a workflow, create and claim work, make
validated transitions, query state, and recover after restart or restore. Events
and the current projection commit atomically.

**In scope.**

- Schema-per-project isolation over one shared PostgreSQL database.
- Immutable registered workflow versions, with work-item version pinning.
- Work-item creation, structured discovery queries, and transitions.
- Durable claims/leases with attempt-number fencing.
- Atomic event append plus denormalized projection update.
- Ordered event history and replay that reports drift honestly.
- Idempotent retries by `event_id`.
- Basic validated custom fields with bounded equality filtering.
- Typed directed links.
- A small administration CLI.

**Out of scope.** Regista is not a job executor, durable code-execution engine,
scheduler, hosted tracker, or human UI. It runs no caller code. It does not
provide automatic retries or exactly-once execution of external effects; tools
such as DBOS, Temporal, or Procrastinate address those needs. Regista complements
them as the shared ledger they consult.

## 2. Trust boundary and non-goals

Regista trusts the host application and the database administrators.

- **Attribution, not authentication.** `actor_id` records who the caller says
  acted. Regista does not authenticate people or agents and does not bind an actor
  to a cryptographic identity.
- **Application policy, not proof of identity.** Workflow `allowed_roles` and
  `strict_roles` gate transitions to roles the caller asserts. They enforce the
  application's rules; they are not an independent authentication mechanism.
- **Consistency, not tamper-evidence.** Replay folds the event log into expected
  state and diffs it against the projection. It reports drift, halts, and
  warnings. Regista makes no non-repudiation, hostile-administrator, authenticity,
  or external-freshness claim.
- **Leases, not exactly-once effects.** A claim guarantees one owner per attempt
  and refuses stale attempts. It does not make a downstream external effect happen
  exactly once; the application owns downstream duplicate protection.

A database administrator can read and write the schema directly. Regista is not
the control that addresses a hostile operator.

## 3. Glossary

| Term | Definition |
|---|---|
| **Project** | A logical namespace corresponding 1:1 to one PostgreSQL schema within a shared database. Hosts one or more workflow definitions. |
| **Workflow** | A named, versioned declarative state machine describing how a kind of work proceeds. |
| **Workflow definition** | YAML validated against regista's JSON Schema, declaring states, transitions, roles, work-item types, custom fields, and link types. |
| **Work-item** | A discrete unit of trackable work: workflow + version, type, current state, custom fields, `needs_review`, `not_before`, and claim facts. |
| **Work-item type** | A category within a workflow, declaring its own custom fields and allowed link types. |
| **Event** | An immutable record appended to the project event log. The authoritative history. |
| **Actor** | The attributed entity performing an operation: `actor_id`, `actor_kind` (`agent`/`human`/`system`), and optional `actor_metadata`. |
| **Claim** | A durable lease held by an actor on a work item: TTL, attempt number, explicit release. |
| **Link** | A typed directed reference from one work item to another (or a cross-project value reference). |
| **Transition** | A workflow-defined state change from a `from` state to a `to` state, optionally role-gated. |
| **Projection** | `work_items_current`, a denormalized view transactionally consistent with the event log. |

## 4. Architecture overview

Regista is a library, not a service. A `Regista` instance owns one project schema.
It uses a shared `psycopg_pool.ConnectionPool`; each transaction issues
`SET LOCAL search_path` to scope operations to the project schema. Every
connection sets `synchronous_commit = on`.

Persistence is hybrid, not pure event-sourcing: events are authoritative, and
`work_items_current` is updated in the same transaction as each event. Reads use
the projection; replay derives it from the log.

```
Regista.create_project(dsn, project)   # schema + baseline migrations + catalog row
Regista(dsn, project)                  # connect to an existing project
```

`create_project` runs the single baseline migration on an empty destination and
refuses an old, untracked, or unknown schema before writing.

## 5. Data model

### 5.1 `events` (immutable log)

| Column | Notes |
|---|---|
| `event_id` UUID, primary key | Global identity; caller-supplied on retry, otherwise generated (UUIDv4). |
| `work_item_id` UUID | Logical owner of the event. |
| `entity_kind` TEXT | `work_item` (default) or another allowed entity kind. |
| `entity_id` UUID | Entity the `event_seq` is allocated against. |
| `event_seq` INTEGER | Gap-free per `(entity_kind, entity_id)`. |
| `actor_id` TEXT, `actor_kind` TEXT | Attribution; kind ∈ `agent`/`human`/`system`. |
| `actor_metadata` JSONB | Free-form structured metadata. |
| `workflow_name` TEXT, `workflow_version` INTEGER | Pinned workflow, when applicable. |
| `timestamp` TIMESTAMPTZ | Library-stamped at append. |
| `transition` TEXT | Workflow transition name or an intrinsic transition. |
| `payload` JSONB | Transition/event data. |
| `on_behalf_of` JSONB | Self-attested delegation metadata. |

Indexes cover actor, timestamp, transition, workflow, and `(work_item_id,
event_seq)`. There is no signing, envelope, hash chain, or global sequence.

### 5.2 `work_items_current` (projection)

Holds `work_item_id`, `workflow_name`/`workflow_version`, `work_item_type`,
`current_state`, `custom_fields` JSONB, `needs_review`, `not_before`,
`last_event_seq`, `last_event_at`, `next_event_seq`, `claimed_by`,
`claim_expires_at`, and `attempt_number`. A GIN index
(`jsonb_path_ops`) supports custom-field containment queries.

### 5.3 `claims`

Holds `work_item_id` (primary key), `actor_id`, `acquired_at`, `expires_at`,
`attempt_number`, and `last_heartbeat_emitted_at`. A work item has at most one
live claim.

### 5.4 `workflow_registry`

`(workflow_name, version)` primary key, `regista_version`, `definition` JSONB,
`content_hash`, `registered_at`. Registrations are immutable and append-only.

### 5.5 `actor_roles`

`(actor_id, role)` primary key, `created_at`. Used by `strict_roles` enforcement.

### 5.6 `public.projects` (catalog)

Cross-project registry: `schema_name` primary key, `display_name`,
`owner_actor_id`, `created_by`, `created_at`. It lives in `public` so it is
reachable regardless of `search_path`.

### 5.7 `_regista_migrations`

The migration-tracking table (version + checksum). It is internal.

## 6. Workflow definitions

A workflow is YAML validated against a JSON Schema and then checked semantically.
It declares:

- **`name`**, **`version`** (integer ≥ 1), **`regista_version`** (semver).
- **`states`**: each with `name`, optional `initial`/`terminal`. Exactly one
  initial state; every state must be reachable; every non-terminal state must
  have an outgoing transition.
- **`transitions`**: `name`, `from`, `to`, optional `allowed_roles`,
  `validator`, `hooks`, `privileged`, `validator_params`. A transition name may
  not be a reserved intrinsic transition.
- **`roles`**: declared role names referenced by transitions.
- **`work_item_types`**: each with `name` and `custom_fields`.
- **`link_types`**: each with `name`, `source_type`, `target_type`.

Semantic validation rejects duplicate names, unknown states/roles/types,
unreachable states, undeclared terminal states, and malformed `work_item_ref`
targets.

**Custom field types:** `string`, `integer`, `boolean`, `timestamp` (ISO 8601
string), `json`, `enum` (with `enum_values`), and `work_item_ref` (a UUID
string). A `work_item_ref` may constrain its referent with
`target_work_item_type` (singular) or `target_work_item_types` (plural); both at
once is refused. Referenced work items must exist and, when constrained, match the
declared type.

Registration is idempotent for identical content; different content under the same
`name`+`version` raises `WORKFLOW_VERSION_CONFLICT`. A work item pins the version
it was created against.

> **0.8.0 note.** The workflow schema still accepts `validator`, `hooks`, and
> `validator_params`, but no validator or hook subsystem ships: those fields are
> inert. `privileged` is enforced (it requires `actor_kind="system"`). Workflow
> composition (`extends:`) is not resolved.

## 7. Work items and custom fields

`create_work_item(workflow, work_item_type, actor_id, ...)` validates
`custom_fields` against the pinned work-item type: required fields present,
known fields only, and each value coerced to its declared type. Unknown or
invalid fields raise `CUSTOM_FIELD_VIOLATION`; an undeclared type raises
`WORK_ITEM_TYPE_NOT_DECLARED`. The work item starts in the workflow's initial
state. `not_before` is an optional scheduling gate; it may not be more than 365
days in the future (`INVALID_ARGUMENT`).

Custom fields are caller-owned domain data. They are not a schema language:
regista validates declared types and supports equality filtering but does not
interpret their meaning.

## 8. Claims and leases

A claim is a durable lease with an attempt number.

- **Acquire.** Same-actor re-acquire silently extends the TTL. A cross-actor
  acquire on an active claim raises `CLAIM_CONTESTED`. A cross-actor acquire on an
  expired claim auto-steals and increments `attempt_number`, emitting a
  `claim_stolen` event. An unclaimed work item acquires as attempt 1 (emitting
  `claim_acquired`). A future `not_before` raises `NOT_BEFORE_FUTURE`.
- **Heartbeat.** Renews the TTL; only the current holder may heartbeat. A
  mismatched `expected_attempt_number` raises `CLAIM_LOST`. Heartbeats coalesce
  event emission within `max(60s, ttl/2)` (or the caller's `coalesce_threshold`).
- **Release.** Only the holder may release; otherwise `CLAIM_LOST` or
  `CLAIM_NOT_FOUND`.
- **Sweep.** `sweep_expired_claims()` expires lapsed claims, clears the
  projection, and emits a `claim_expired` event attributed to `system`. Each
  claim is processed in its own savepoint: a refusal for one claim leaves it
  intact and does not abort the rest. Only `RegistaError` is isolated; unexpected
  errors abort the sweep.
- **Escalation.** When `attempt_number >= attempt_threshold`, acquire sets
  `needs_review` and emits an `escalated` event once (idempotent).

**Fencing.** A transition may pass `expected_attempt_number`; if the work item's
current attempt has advanced, the transition is refused with `CLAIM_LOST`. This
stops a stale worker from committing protected changes to regista. It does not
stop that process from touching external systems.

## 9. Transitions and events

`transition(work_item_id, name, actor_id, ...)`:

1. Locks the work-item row (`SELECT FOR UPDATE`).
2. Checks `expected_attempt_number` (if supplied).
3. Returns the existing event on an idempotent `event_id` retry.
4. Resolves the transition against the pinned workflow version and current state
   (`INVALID_TRANSITION` if not valid), and a missing workflow raises
   `WORKFLOW_NOT_REGISTERED`.
5. Enforces `privileged` (system only) and role gating (`ROLE_NOT_PERMITTED`,
   `ACTOR_ROLE_NOT_AUTHORIZED`).
6. Validates and applies `custom_fields` updates.
7. Appends the transition event and updates the projection in one transaction,
   releasing any active claim.

`append_event(...)` appends free-form events. It refuses a transition that is
defined in the workflow (`TRANSITION_VIA_APPEND_BLOCKED`) and any reserved
intrinsic transition (`created`, `claim_acquired`, `claim_stolen`,
`claim_released`, `claim_expired`, `claim_heartbeat`, `link_created`,
`link_removed`, `escalated`, `not_before_set`, `hook_dead_lettered`,
`checkpoint`). Use `transition()` for state changes.

**Sequence and concurrency.** `event_seq` is gap-free per entity. Work-item
appends derive it from the locked projection row (`next_event_seq`); other
entities use an advisory transaction lock. Callers may pass `expected_event_seq`
for optimistic concurrency; a mismatch raises `CONCURRENT_MODIFICATION`. A
unique-violation on `(entity_kind, entity_id, event_seq)` is translated to
`CONCURRENT_MODIFICATION`.

**Ordered history.** `read_events` returns events ordered by `event_seq` with
filters on work item, actor, time range, transition, and `before_seq`.
`read_events_since` pages forward by sequence.

## 10. Event log and projection

The event log is authoritative and append-only. Every mutation writes an event
and updates `work_items_current` in the same transaction, so a committed state is
always derivable from committed events. The projection is never edited directly;
replay rebuilds it.

## 11. Replay

`replay()` folds each work item's events in `event_seq` order into the state the
projection should hold and diffs it against the live row. It reports:

- `replayed_ok` — matching work items;
- `replayed_drift` — work items where fields differ (or the projection row is
  missing);
- `halted` — work items whose log cannot be reduced (a missing workflow, an event
  before `created`, or a transition invalid from its state);
- `warnings` — non-fatal anomalies such as an unknown transition name.

Drift is reported, never silently corrected. `replay(work_item_id=...)` scopes
the check; `Regista(..., read_only=True)` runs replay without DDL. No
cryptographic verification is performed: replay is a consistency and
rebuildability check.

## 12. Typed links

`create_link(from_id, to_id, link_type, actor_id, ...)` requires the link type to
be declared for the source work-item type (`LINK_TYPE_NOT_ALLOWED`), and both
endpoints to exist and match the declared source/target types
(`LINK_TARGET_NOT_FOUND`, `LINK_CROSS_PROJECT`). A `target_project` creates a
cross-project value reference without a local lookup. An opaque `content_hash`
may be recorded. `remove_link` matches on target and type. `list_links` returns
live links derived from the event log: a `link_created` event is live unless a
matching `link_removed` event exists. Links describe relationships; they do not
introduce a dependency scheduler.

## 13. Queries and pagination

`query_work_items` returns a `QueryPage` (`items`, `cursor`, `has_more`).
Filters (AND semantics):

- `workflow_name`, `workflow_version`, `work_item_types`, `current_states`;
- `claimed_by`;
- `claimable_now=True` — unclaimed and past `not_before`;
- `needs_review=True`;
- `has_link_type`;
- `custom_field_filters` — equality on custom fields, JSONB containment.

Results are ordered by `work_item_id`. `page_size` is clamped to `[1, 1000]`;
the implementation fetches one extra row to set `has_more` and returns the last
item's id as `cursor`. Invalid filter input raises `INVALID_FILTER`.

## 14. Idempotency

Every append accepts an optional `event_id`. Repeating an operation with the same
`event_id` returns the original event without duplicating effects. Reusing an
`event_id` with different facts raises
`IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD`; cross-entity reuse raises
`EVENT_ID_GLOBAL_COLLISION`. `event_id` values must be UUIDv4
(`INVALID_ARGUMENT`). Creation compares the complete creation request before
allocating a projection row.

## 15. Isolation, connections, and deployment

- **Schema-per-project.** The project name is validated and used as the schema;
  `SET LOCAL search_path` scopes each transaction. Isolation is
  engine-enforced by schema privileges.
- **Pooling.** Pool size is bounded (`pool_min`, `pool_max`, optional
  `pool_max_lifetime`). Session-scoped `search_path` is incompatible with
  transaction-mode poolers; use session mode or connect directly.
- **SSL.** `require_ssl=True` rejects connections where SSL is not active.
- **Atomicity.** Event append and projection update are one transaction with
  `synchronous_commit = on`.
- **Storage encryption.** Storage/database encryption is an explicit operator
  responsibility; regista performs no payload encryption.

## 16. Administration CLI

`regista` (no database required for `workflow validate` and `version`):

- `workflow validate <path|->`
- `work-item show <id>`, `work-item list [--workflow --state --claimed-by
  --claimable-now --needs-review --limit --page-size]`
- `work-item create --workflow --type --actor-id [--custom-fields --not-before]`
- `work-item transition <id> --transition --actor-id [--payload --custom-fields
  --expected-attempt-number]`
- `events show --work-item-id <id> [...]`, `events tail [...]`
- `replay [--work-item-id <id>]`
- `schema init`, `schema status`
- `actor-roles list [--actor-id]`
- `version --json`, `doctor --json`

Connection comes from `--dsn`/`--project` or `REGISTA_DSN`/`REGISTA_PROJECT`.
Errors are emitted as `[CODE] message`; JSON mode emits an envelope with
`code`, `message`, `detail`, and `retryable`.

## 17. Public API surface

`Regista` is the sole entry point.

```python
Regista.create_project(dsn, project, *, pool_min=1, pool_max=10,
                       pool_max_lifetime=None, require_ssl=False,
                       prometheus_registry=None, strict_roles=False,
                       owner=None, display_name=None, created_by=None)
Regista(dsn, project, *, pool_min=1, pool_max=10, pool_max_lifetime=None,
        require_ssl=False, prometheus_registry=None, strict_roles=False,
        read_only=False)

register_workflow(yaml) / register_workflow_file(path) / get_workflow(name, version)
create_work_item(workflow, type, actor_id, actor_kind="agent", actor_metadata=None, *,
                 custom_fields=None, not_before=None, event_id=None)
create_work_items_batch(items, actor_id, actor_kind="agent")
query_work_items(*, workflow_name=None, workflow_version=None, work_item_types=None,
                 current_states=None, claimed_by=None, claimable_now=None,
                 needs_review=None, has_link_type=None, custom_field_filters=None,
                 cursor=None, page_size=100)
get_work_item(work_item_id) / update_not_before(work_item_id, not_before, actor_id, ...)
transition(work_item_id, transition, actor_id, actor_kind="agent", actor_metadata=None, *,
           payload=None, custom_fields=None, event_id=None, expected_event_seq=None,
           expected_attempt_number=None)
append_event(work_item_id, actor_id, actor_kind="agent", actor_metadata=None, *,
             transition=None, payload=None, event_id=None, expected_event_seq=None)
read_events(*, work_item_id=None, actor_id=None, start=None, end=None,
            transition=None, limit=100, before_seq=None)
read_events_since(work_item_id, after_seq, *, limit=100)
acquire_claim(work_item_id, actor_id, ttl_seconds=300, *, event_id=None)
heartbeat_claim(work_item_id, actor_id, ttl_seconds=300, *,
                expected_attempt_number=None, coalesce_threshold=None)
release_claim(work_item_id, actor_id, *, event_id=None)
sweep_expired_claims()
create_link(from_id, to_id, link_type, actor_id, ...) / remove_link(...) / list_links(id)
replay(*, work_item_id=None) -> ReplayReport
versions() -> VersionInfo
close()
```

Facades: `sub.workflows`, `sub.work_items`, `sub.events`, `sub.claims`,
`sub.links`. Standalone: `validate_yaml`, `parse_and_validate`, `parse_file`,
`canonical_workflow_yaml`, `versions`.

## 18. Invariants

1. Events are the authoritative record; `work_items_current` is a projection.
2. Every mutation holds `SELECT FOR UPDATE` on the work-item row.
3. Event append and projection update commit atomically.
4. `event_seq` is gap-free per entity and strictly ordered within a work item.
5. At most one live claim exists per work item; it has exactly one holder.
6. A refused stale attempt (`expected_attempt_number` mismatch) writes nothing.
7. Identical `event_id` retries are no-ops; conflicting reuse refuses.
8. Replay reconstructs the same supported state as live, or reports drift/halt.
9. Operations stay inside the project schema; supplied names cannot redirect
   them elsewhere.
10. Old or unknown schemas are refused before any write.

## 19. Error codes

The kernel emits a subset of `ErrorCode`:

`WORK_ITEM_NOT_FOUND`, `WORKFLOW_NOT_REGISTERED`, `WORKFLOW_VERSION_CONFLICT`,
`WORKFLOW_VALIDATION_FAILED`, `WORKFLOW_SEMANTIC_ERROR`,
`WORK_ITEM_TYPE_NOT_DECLARED`, `CUSTOM_FIELD_VIOLATION`, `INVALID_TRANSITION`,
`RESERVED_TRANSITION_NAME`, `TRANSITION_VIA_APPEND_BLOCKED`,
`PRIVILEGED_TRANSITION_REQUIRED`, `ROLE_NOT_PERMITTED`,
`ACTOR_ROLE_NOT_AUTHORIZED`, `ACTOR_ROLE_NOT_REGISTERED`, `CLAIM_CONTESTED`,
`CLAIM_LOST`, `CLAIM_NOT_FOUND`, `NOT_BEFORE_FUTURE`, `CONCURRENT_MODIFICATION`,
`IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD`, `EVENT_ID_GLOBAL_COLLISION`,
`LINK_TYPE_NOT_ALLOWED`, `LINK_TARGET_NOT_FOUND`, `LINK_CROSS_PROJECT`,
`LINK_NOT_FOUND`, `INVALID_FILTER`, `INVALID_ACTOR_KIND`, `INVALID_ARGUMENT`,
`DB_NOT_FOUND`, `MIGRATION_REQUIRED`, `MIGRATION_DRIFT`,
`UNSUPPORTED_SCHEMA_VERSION`, `WORKFLOW_VERSION_INCOMPATIBLE`.

Removed-feature codes remain in the enum for source compatibility but are not
reachable from the kernel.

## 20. Removed in 0.8.0 and compatibility

This release is a deliberate, breaking scope reset from 0.7.2. Removed: signing
and keys, trust domains/genesis/governance, principals/custody/secrets,
audit bundles and verifiers, witnesses, hooks/webhooks, transparency anchoring,
recurrence, lineage/assurance/review policy, suite configuration, provisioning,
payload encryption, workflow composition, archive, the HTTP sidecar, and the
in-memory backend.

**There is no supported in-place upgrade from 0.7.2 or earlier.** A fresh schema
is required. Initialization refuses an old, untracked, or unknown schema before
writing and never auto-drops or resets it. To preserve old data, keep the old
dump with its matching package/dependency environment and any old keys, verify a
scratch restore, and only then touch the original. No converter is provided.

## 21. Maintenance posture

Regista 0.8.0 is a complete, bounded MVP. Maintenance covers release regressions
and serious security or data-loss defects only. There is no feature roadmap, no
SLA, and no obligation to expand the product. Future changes must serve the
coordination niche and be justified by concrete usage.