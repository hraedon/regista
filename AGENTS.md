# Substrate — Agent Guide

## Project Overview

Substrate is a Python library providing coordination and durable state for agent pipelines over Postgres. It implements an event-sourced model with a transactionally-consistent denormalized projection.

**Spec:** `spec.md` is authoritative. `spec.yaml` is a machine-readable sidecar. The spec is amendable when implementation reveals it cannot deliver a stated guarantee — see BC-008/FR-15 for precedent. Amendments are made deliberately, with a breadcrumb resolution note explaining the change; do not silently diverge from the spec.

## Architecture

### Isolation: Schema-per-project

One Postgres database, one schema per project. The `Substrate` handle owns one logical project namespace. Connection pool is shared; `SET LOCAL search_path` scopes each transaction.

### Core data model

- **Events** (`events` table): immutable append-only log. Gap-free `event_seq` per work-item, allocated under canonical row lock.
- **Projection** (`work_items_current`): denormalized, transactionally-consistent with events. Fully derivable from event log via replay.
- **Claims** (`claims` table): durable leases with TTL, attempt tracking, auto-steal on expiry.
- **Workflow registry** (`workflow_registry`): append-only, versioned workflow definitions. Work-items pin their version at creation.

### Key invariants

- Events are the authoritative source. `work_items_current` is a projection, never edited directly.
- Every mutation acquires `SELECT FOR UPDATE` on the work-item's row in `work_items_current`.
- Library is the sole signer (HMAC-SHA256 over RFC 8785 canonical JSON). API rejects pre-signed events.
- `synchronous_commit = on` on all connections.

## Source Layout

```
src/substrate/
  __init__.py       # Public API: Substrate class
  _connection.py    # Connection pool, schema-per-project
  _contract.py      # Single-source-of-truth business logic (RFC-062) + Jsonb wrapper type
  _migrations.py    # Migration runner
  _events.py        # Event append, idempotency, seq allocation
  _work_items.py    # Create, query (FR-05b)
  _claims.py        # Claim lifecycle
  _links.py         # Typed directed links
  _event_store.py   # EventStore protocol + shared append + InMemory/Postgres stores (BC-128)
  _replay.py        # Rebuild projection from event log
  _integrity.py     # Startup version compatibility checks
  _workflow.py      # YAML parse, JSON Schema validate, semantic checks
  _hooks.py         # Sync validators + async hook consumer (FR-13)
  _actor_roles.py   # Actor → role registration and enforcement (FR-24)
  _lint.py          # Actor metadata lint helper (FR-18)
  _signing.py       # HMAC-SHA256 signing/verification
  _jcs.py           # RFC 8785 JSON Canonicalization Scheme (rfc8785 lib)
  _keys.py          # Key set management, hot-reload
  _observability.py # Structured logging + Prometheus metrics
  _errors.py        # ErrorCode enum + SubstrateError
  _types.py         # Frozen dataclasses for domain types
  _testing.py       # Test-only helpers (centralizes _mgr coupling)
  _workflow_schema.json  # JSON Schema for workflow YAML files
  _workflow_compose.py  # Workflow YAML composition via `extends:` (FR-29)
  _cli.py               # Admin CLI entry point (Plan 002)
  _recurrence.py        # Recurring work-item schedule engine (FR-28)
  _recurrence_api.py    # Thin facade for recurrence on Substrate class
  _transition.py        # Extracted transition logic (delegated from Substrate)
  _datetime_utils.py   # Shared datetime comparison for replay modules
  _ops.py              # Facade classes: WorkflowOps, WorkItemOps, etc. (Plan 007)
  _maintenance.py      # MaintenanceThread — timer-driven sweep/recurrence (Plan 009)
  _signing_scheme.py   # SigningScheme protocol + HMACSHA256Scheme + Ed25519Scheme (Plan 011)
  _timestamping.py     # RFC 3161 TSA Merkle tree batching (Plan 012)
  _hooks_api.py        # Postgres-only hooks helpers for _ops facades
  _in_memory_replay.py # InMemory replay engine (FR-16)
  _vendor/             # Vendored dependencies
    __init__.py
    rfc8785.py         # Vendored rfc8785 0.1.4 (Plan 008 WS-3)
  sidecar/              # HTTP sidecar (Plan 005, optional)
    __init__.py
    __main__.py         # Entry point: python -m substrate.sidecar
    app.py              # FastAPI app factory + error/middleware setup
    auth.py             # Bearer-token registry (SHA-256 hashed tokens)
    routes.py           # 1:1 pass-through of Substrate public API
    routes_hooks.py     # Hook claim/complete/fail endpoints
    models.py           # Pydantic request/response models (extra="forbid")
    errors.py           # ErrorCode → HTTP status mapping
```

## Testing

```bash
# Start Postgres
docker compose -f docker-compose.test.yml up -d

# Run tests
.venv/bin/python -m pytest tests/ -v

# Run including property-based tests (slow)
.venv/bin/python -m pytest tests/ -v -m slow

# Lint
.venv/bin/ruff check src/ tests/
```

Test DSN: `postgresql://substrate_test:substrate_test@localhost:5432/substrate_test`
Test keys: `tests/test_keys.json`
Sample workflow: `tests/test_workflow.yaml`

## Public API (§19)

The `Substrate` class is the sole entry point. No Postgres internals leak across the boundary.

```python
from substrate import Substrate

# Create a new project
sub = Substrate.create_project(dsn, "my_project", hmac_key_path="/path/to/keys.json")

# Connect to existing
sub = Substrate(dsn, "my_project", hmac_key_path="/path/to/keys.json")

# Operations
sub.register_workflow(yaml_content)
sub.create_work_item(workflow_name, work_item_type, actor_id, ...)
sub.transition(work_item_id, transition_name, actor_id, ...)
sub.append_event(work_item_id, actor_id, *, transition=..., payload=...)
sub.acquire_claim(work_item_id, actor_id, ttl_seconds=300)
sub.heartbeat_claim(work_item_id, actor_id, ttl_seconds, *, expected_attempt_number=...)
sub.release_claim(work_item_id, actor_id)
sub.sweep_expired_claims()
sub.ensure_event_partitions(months_ahead=3)  # no-op (partitioning removed); returns []
sub.query_work_items(workflow_name=..., current_states=[...], claimable_now=True, custom_field_filters={...})
sub.read_events(work_item_id=...)
sub.create_link(from_id, to_id, link_type, actor_id, payload=...)
sub.remove_link(from_id, to_id, link_type, actor_id)
sub.replay()  # -> ReplayReport with drift detection
sub.replay(continue_on_revoked=True)  # skip revoked-key events with warnings
sub.close()

# Phase 2 — hooks, validators, escalation, lint
sub.register_validator(transition_name, fn)        # sync, 5s timeout, blocks transition on failure
sub.register_hook_handler(event_type, fn)          # async dispatch via hook_queue
sub.start_hook_consumer()                          # background thread: LISTEN + 30s poll
sub.stop_hook_consumer()
sub.poll_hooks()                                   # manual drain (in lieu of consumer thread)
sub.claim_hooks(max_batch, lease_seconds)          # lease a batch for out-of-process processing
sub.complete_hook(hook_queue_id)                   # ack success on a leased hook
sub.fail_hook(hook_queue_id, error)                # ack failure; requeues or dead-letters per max_retries
sub.sweep_expired_hook_leases()                    # requeue rows past their lease deadline
sub.list_dead_lettered_hooks()
sub.requeue_dead_lettered_hook(hook_id)
sub.validate_actor_metadata(metadata, schema=None)  # lint helper (FR-18)

# Phase 3 — actor role enforcement, replay resilience
sub.update_not_before(work_item_id, not_before, actor_id)  # reschedule work item
sub.register_actor_role(actor_id, role)              # register actor → role mapping
sub.unregister_actor_role(actor_id, role)            # remove actor → role mapping
sub.list_actor_roles(actor_id=None)                  # list registered roles

# Facade API (Plan 007) — domain-scoped sub-objects
sub.workflows.register(yaml_content)
sub.work_items.create(workflow_name, work_item_type, actor_id, ...)
sub.events.append(work_item_id, actor_id, *, transition=..., payload=...)
sub.claims.acquire(work_item_id, actor_id, ttl_seconds=300)
sub.claims.heartbeat(work_item_id, actor_id, ttl_seconds)
sub.claims.release(work_item_id, actor_id)
sub.links.create(from_id, to_id, link_type, actor_id)
sub.hooks.register_validator(name, fn)
sub.hooks.register_handler(name, fn)
sub.hooks.claim(max_batch, lease_seconds)
sub.hooks.complete(hook_queue_id)
sub.hooks.fail(hook_queue_id, error)
sub.recurrence.register_rule(...)
sub.recurrence.fire(rule_id)

# Legacy top-level methods still work — they delegate to facades

# Maintenance (Plan 009)
sub.start_maintenance(sweep_interval=30, recurrence_interval=10)  # background thread
sub.stop_maintenance()
sub.maintenance_healthy  # True when thread is running and healthy (or not started)

# Trust hardening (Plan 008)
sub = Substrate(dsn, project, hmac_key_path, strict_roles=True)  # reject unregistered actors
# Env-var key injection: SUBSTRATE_HMAC_KEY_<KEY_ID> overrides file secrets
# Key rotation safety: unknown status raises KEY_LOAD_ERROR at startup

# Standalone utilities (no database required)
validate_yaml(yaml_string_or_path)                     # -> ValidationResult
compose_workflow(file_or_path)                         # -> composed dict + SourceMap (FR-29)
```

**API constraints:**
- `append_event` rejects transitions that match a workflow-defined transition name — use `transition()` for state changes
- `heartbeat_claim` accepts optional `expected_attempt_number` to detect stale sessions after claim theft
- Claim mutations (acquire, release, sweep) emit events for audit trail; heartbeats do not
- Escalation (FR-10) fires automatically inside `acquire_claim` when `attempt_number >= attempt_threshold`; sets `needs_review`, emits `escalated`, idempotent
- Hooks dead-letter after max retries and emit `hook_dead_lettered`; replay handles both `escalated` and `hook_dead_lettered`
- `strict_roles=True` requires all actors to have registered roles before transitioning; `prompt`-source roles are rejected (Plan 008 WS-1)
- `start_maintenance()` subsumes `start_hook_consumer()` — calling both is unnecessary but harmless

## Key Design Decisions

1. **Schema-per-project** not DB-per-project. One pool, one backup target, engine-enforced isolation via `GRANT ON SCHEMA`. Migration path to `tenant_id`-in-shared-DB documented but not needed at homelab scale.
2. **Library with optional maintenance thread.** Runs in-process. No HTTP server required. Exposes `prometheus_client.CollectorRegistry` for host app to mount. Optional `start_maintenance()` runs sweep/recurrence in a background thread.
3. **Hybrid persistence.** Events authoritative; projection updated in same transaction. Not pure event-sourcing (no per-read replay cost).
4. **Signing is internal.** RFC 8785 canonicalization (vendored in `_vendor/rfc8785.py`) + HMAC-SHA256 computed inside the library. Callers submit unsigned field tuples.

## Known constraints

- **Schema-per-project requires session-scoped `search_path`.** Substrate uses `SET LOCAL search_path` per transaction. This is incompatible with connection-pooling middleware that dispatches transactions across different backends (e.g., PgBouncer in transaction mode). Use PgBouncer in session mode, or connect directly to Postgres. Medium-term migration path: fully-qualified table names (BC-033).
- **`events` table is flat (partitioning removed in RFC-001).** A global `UNIQUE(event_id)` index ensures event identity. `hook_queue.event_id → events.event_id` FK is maintained. `ensure_event_partitions` is a no-op returning `[]`. Partition gauges (`events_default_rows`, `events_partition_horizon_days`) have been removed. `heartbeat_claim` coalesces `claim_heartbeat` events within a `max(60s, ttl/2)` threshold (BC-194).

## Status

MVP + Phase 2 + Phase 3 + Plans 002-012 implemented. All FRs FR-01 through FR-29 are in tree. 888 tests passing (including sidecar, property-based, and plan-specific tests).

Production readiness additions: migration packaging for pip installs (importlib.resources + force-include), claims_stolen metric wired, actor_kind validation at API boundary, docstrings on all public methods, spec.yaml synced to v5, structured replay error handling, CHANGELOG.md.

Phase 3 additions: FR-24 (actor → allowed_roles enforcement, closes BR-09), FR-25 (continue-on-revoked replay flag), FR-26 (update_not_before API), FR-27 (custom field validation at transition time). Migration `005_actor_roles.sql` adds the actor_roles table. ReplayReport gains `warnings` field.

Plans 002-004 additions:
- **Plan 002 (Admin CLI):** `substrate` console entry point (`src/substrate/_cli.py`). Commands: `workflow validate`, `work-item show/list`, `events show/tail`, `replay`, `schema init/status`, `hooks dead-letter list/requeue`, `actor-roles list`, `recurrence list/due/fire/cancel/update`. No DB required for `workflow validate`. Structlog routes to stderr in CLI mode.
- **Plan 003 (Recurring work-items, FR-28):** New `recurrence_rules` table (migration 011). Schedule kinds: `interval` and `rrule`. Public API on `Substrate` and `InMemorySubstrate`: `register_recurrence_rule`, `list_recurrence_rules`, `due_recurrences`, `fire_recurrence`, `cancel_recurrence_rule`, `update_recurrence_rule`. New error codes: `RECURRENCE_RULE_NOT_FOUND`, `RECURRENCE_RULE_EXHAUSTED`, `RECURRENCE_SCHEDULE_INVALID`, `RECURRENCE_TEMPLATE_INVALID`. Dependency: `python-dateutil`.
- **Plan 004 (Workflow composition, FR-29):** `_workflow_compose.py` with `resolve_includes`, `_deep_merge`, and `compose_workflow`. `extends:` field added to JSON Schema. `parse_file()` now resolves composition. Keyed list merge by `(name, from)` for transitions, `__append`/`__remove` list modifiers. New error code `WORKFLOW_COMPOSE_ERROR`.

Plan 005 additions:
- **Plan 005 (HTTP sidecar):** `src/substrate/sidecar/` package with FastAPI. 1:1 pass-through of the Substrate public API. Bearer-token auth via SHA-256 hashed token registry. Sole-signer middleware rejects `signature`/`payload_canonical_hash` fields. Hook claim/complete/fail lifecycle for non-Python consumers. ErrorCode → HTTP status mapping. Optional install extra `[sidecar]`. Dockerfile in `deploy/sidecar/`. 17 integration tests.

Code structure: `transition()` extracted to `_transition.py`, `recurrence` API extracted to `_recurrence_api.py`, reducing `__init__.py` from ~1580 to ~1200 lines. Facade decomposition (Plan 007) adds `_ops.py` with 7 domain-scoped facade classes; top-level methods delegate to facades.

Plans 007-009 additions:
- **Plan 007 (Facade decomposition):** `_ops.py` with `WorkflowOps`, `WorkItemOps`, `EventOps`, `ClaimOps`, `LinkOps`, `HookOps`, `RecurrenceOps`, `TimestampOps`. Cached properties on `Substrate`. Old top-level methods remain as thin delegates (no deprecation warnings). 30 tests.
- **Plan 008 (Trust model hardening):** WS-1 (`strict_roles` flag — rejects unregistered actors and `prompt`-source roles). WS-2 (env-var key injection via `SUBSTRATE_HMAC_KEY_<KEY_ID>`). WS-3 (vendored `rfc8785` in `_vendor/` with 73 cross-validation tests). WS-5 (raise on unknown key status, `expected_key_count`, `keys_loaded` log). WS-4 (sidecar rate limiting) deferred.
- **Plan 009 (Operational runtime):** `_maintenance.py` with `MaintenanceThread`. `start_maintenance()`/`stop_maintenance()` on `Substrate`. Subsumes hook consumer. `maintenance_healthy` property reflects thread state. 5 integration tests.

Plans 011-012 additions:
- **Plan 011 (Pluggable signing, Ed25519):** `SigningScheme` protocol with `sign()`/`verify()` methods. `HMACSHA256Scheme` (default) and `Ed25519Scheme` (optional, via `pip install substrate[ed25519]`). Module-level registry in `_signing_scheme.py`. `KeyEntry.scheme` field selects scheme per key. `scheme_id` column on `events` (migration 015). Replay resolves scheme per event. 10 unit + 10 integration tests.
- **Plan 012 (RFC 3161 timestamping):** `_timestamping.py` with Merkle tree batching, TSA HTTP submission, token verification. `tsp_batches` table (migration 016). `TimestampOps` facade (`sub.timestamping.trigger/list_batches/verify_batch`). `MaintenanceThread._maybe_timestamp_events` for background timestamping. `replay(verify_timestamps=True)` cross-references events against confirmed batches. Sidecar routes and CLI commands. `timestamping_errors` metric. 17 tests.

RFC-062: Single-source-of-truth backend contract via `_contract.py` — 20 pure validation/decision functions shared by both Postgres and InMemory backends. Property-based conformance tests via hypothesis in `tests/test_property_conformance.py`.

BC-139: `query_work_items` accepts `custom_field_filters: dict[str, object] | None` for equality filtering on custom field values (AND semantics). Postgres uses JSONB containment (`@>`) with a GIN index. InMemory uses equivalent dict matching. Migration `009_custom_fields_gin.sql` adds the index. Unknown filter keys produce empty results, not errors.

BC-171: `work_item_ref` custom fields now accept `target_work_item_types: [typeA, typeB]` (plural list) in addition to the existing singular `target_work_item_type`. The plural form constrains the referent to one of an enumerated set; each listed type must exist in the workflow. Specifying both singular and plural is rejected at registration (by JSON Schema first, then `_validate_semantics` as defense-in-depth). Omitting both retains the existing behavior: UUID format + existence validation only, no type enforcement.

## Conventions

- Python 3.11+, `from __future__ import annotations` in all files
- No comments in code (style rule). Rationale: `spec.md` and `AGENTS.md` are the canonical reference for behavior and intent. Code is expected to be self-explanatory through naming and structure. Comments drift as the spec evolves. Instead of comments, extract well-named helper functions, add test cases, or update the spec. Inline spec cross-references (e.g., `# AC-28`) are acceptable on non-obvious invariants.
- Frozen dataclasses for all domain types
- `dict_row` factory on all psycopg connections
- All mutations go through `mgr.transaction()` which sets `SET LOCAL search_path`
- Error codes are part of the API contract (§19.5)
- Tests reach internal state via `substrate._testing` only — never import `_mgr` directly
- **`InMemorySubstrate` without `hmac_key_path` silently skips event emission.** Operations that emit events (claim acquire, release, heartbeat) check `key_set is not None` before appending. Tests asserting on event counts must provide `hmac_key_path`. The `test_in_memory_conformance.py` fixture deliberately omits it; new test files that need event observability should pass `KEY_PATH`.

## Agent Workflow

This project tracks work outside the code. New agents should orient to these conventions before making changes.

### Breadcrumbs (`breadcrumbs/`)

Defects, design questions, and improvements live one-file-per-item under `breadcrumbs/`, with resolved items moved to `breadcrumbs/resolved/`. Schema and severity definitions are in `breadcrumbs/README.md`. Open the index before starting work — it's the canonical "what's known to be wrong" list.

When you notice an issue you're not fixing in this session, file a breadcrumb. When you fix one, move it to `resolved/` and update the README index. The `/end` skill automates both.

### Worklog (`.substrate/worklog.md`)

Reverse-chronological session log. Each entry: focus, context, what was delivered (with file references), breadcrumbs resolved, test/lint results. Read the most recent entry on session start; prepend a new entry on session end.

### Reflections (`.substrate/reflections/`)

Per-session subjective notes from the agent. Useful signal for the next agent — read the latest before starting. Written via the `/reflect` skill.

### Session commands

Substrate-specific wrappers in `.substrate/commands/`:
- `/start` — orient to current state (worklog tail, open breadcrumbs, git status)
- `/end` — run tests, reconcile breadcrumbs, update worklog, write reflection, commit
- `/reflection` — write a reflection only

System-wide skills (`/reflect`, `/end`) provide portable equivalents; the substrate-specific versions add test runs and worklog updates.

## Patterns

### Telemetry via hooks

Substrate's `actor_metadata` is JSONB — free-form structured metadata for downstream consumers. To produce indexed aggregates (e.g., per-role pass rates), register a hook handler on the relevant event types that writes denormalized rows to a consumer-maintained reporting table. The reporting table lives outside substrate's schema; substrate's contract is the authoritative event log, and the reporting table is a derived view that can be rebuilt by replaying events through the same handler.

A complete, runnable minimal example is in `examples/telemetry_via_hooks.py`.

Recommended shape:

1. **Reporting table** in a separate schema (or external store) with indexed columns for the dimensions you query by.
2. **Hook handler** that reads `actor_metadata`, extracts dimensions, and upserts the reporting row.
3. **Rebuild path**: drain the events table through the same handler in `event_seq` order to reconstruct from scratch.

Do not add denormalized columns to substrate's `events` table for consumer-specific dimensions. Substrate stays general; the consumer maintains its own reporting layer.

### Diagnostic payload shape

Transition events carrying failure information should use this canonical shape for `payload`:

```python
payload = {
    "diagnostics": {
        "kind": str,           # consumer-defined enum value (e.g. "gate_fail", "channel_fail")
        "summary": str,        # one-line human-readable
        "messages": list[str], # detailed lines
        "context": dict,       # consumer-specific structured data
    }
}
```

Each consumer extends `kind` and `context` for its domain. This shape is not code-enforced, but using it prevents fragmentation across consumers and ensures telemetry tooling can aggregate failures uniformly.
