# Regista — Agent Guide

> **Renamed 2026-05-27:** project was previously `substrate`. PyPI/GitHub/module/console-script all moved to `regista` (Plan 018 / v0.4.0). Pre-rename history pinned at tag `v0.4.0-pre-rename`. Older breadcrumbs, reflections, and design docs that still say "substrate" are intentional historical record.

## Project Overview

Regista is a Python library providing coordination and durable state for agent pipelines over Postgres. It implements an event-sourced model with a transactionally-consistent denormalized projection.

**Spec:** `spec.md` is authoritative. `spec.yaml` is a machine-readable sidecar. The spec is amendable when implementation reveals it cannot deliver a stated guarantee — see BC-008/FR-15 for precedent. Amendments are made deliberately, with a breadcrumb resolution note explaining the change; do not silently diverge from the spec.

## Architecture

### Isolation: Schema-per-project

One Postgres database, one schema per project. The `Regista` handle owns one logical project namespace. Connection pool is shared; `SET LOCAL search_path` scopes each transaction.

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
src/regista/
  __init__.py       # Public API: Regista class
  _connection.py    # Connection pool, schema-per-project
  _contract.py      # Single-source-of-truth business logic (RFC-062) + Jsonb wrapper type
  _migrations.py    # Migration runner
  _events.py        # Event append, idempotency, seq allocation
  _work_items.py    # Create, query (FR-05b)
  _claims.py        # Claim lifecycle
  _links.py         # Typed directed links
  _event_store.py   # EventStore protocol + shared append + InMemory/Postgres stores (BC-128)
  _archive.py        # Archive complete dormant work-items (BC-258)
  _archive_segments.py  # Plan 028: segment sealing for chain-preserving retention
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
  _errors.py        # ErrorCode enum + RegistaError
  _types.py         # Frozen dataclasses for domain types
  _testing.py       # Test-only helpers (centralizes _mgr coupling)
  _workflow_schema.json  # JSON Schema for workflow YAML files
  _workflow_compose.py  # Workflow YAML composition via `extends:` (FR-29)
  _cli.py               # Admin CLI entry point (Plan 002)
  _recurrence.py        # Recurring work-item schedule engine (FR-28)
  _recurrence_api.py    # Thin facade for recurrence on Regista class
  _transition.py        # Extracted transition logic (delegated from Regista)
  _datetime_utils.py   # Shared datetime comparison for replay modules
  _ops.py              # Facade classes: WorkflowOps, WorkItemOps, etc. (Plan 007)
  _maintenance.py      # MaintenanceThread — timer-driven sweep/recurrence/witness
  _signing_scheme.py   # SigningScheme protocol + HMACSHA256Scheme + Ed25519Scheme (Plan 011)
  _timestamping.py     # RFC 3161 TSA Merkle tree batching (Plan 012)
  _hooks_api.py        # Postgres-only hooks helpers for _ops facades
  _in_memory_replay.py # InMemory replay engine (FR-16)
  _witness.py          # Witness registration, receipt creation, event filtering, delivery (Plan 013)
  _config.py           # Suite config resolver: layered env → user suite.env → system (Plan 025)
  _secrets.py          # Secret backend resolver: file/env/literal/vault/azure (Plan 025)
  _version_info.py     # Version surface: library/schema/workflow/envelope versions (Plan 025)
  _doctor.py           # Health check JSON contract: `regista doctor --json` (Plan 025)
  _principal_keys.py   # Principal→public-key registry: register/rotate/revoke (Plan 026)
  _custody.py          # Backend-aware private-key custody helper (Plan 029)
  _provision.py        # Schema + service-role + principal-key provisioning (Plan 025 WI-2.1)
  _vendor/             # Vendored dependencies
    __init__.py
    rfc8785.py         # Vendored rfc8785 0.1.4 (Plan 008 WS-3)
  sidecar/              # HTTP sidecar (Plan 005, optional)
    __init__.py
    __main__.py         # Entry point: python -m regista.sidecar
    app.py              # FastAPI app factory + error/middleware setup
    auth.py             # Bearer-token registry (SHA-256 hashed tokens)
    routes.py           # 1:1 pass-through of Regista public API
    routes_hooks.py     # Hook claim/complete/fail endpoints
    models.py           # Pydantic request/response models (extra="forbid")
    errors.py           # ErrorCode → HTTP status mapping
  docs/
    suite-config.md     # Suite config contract: vars, precedence, doctor shape, version surface (Plan 025)
    review-assurance.md # Review assurance levels and gate profiles (Plan 027)
    retention.md        # Event-log retention + segment sealing model (Plan 028)
  suite.env.example     # Template for ~/.config/agent-suite/suite.env (Plan 025)
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

# Type-check (strict; burndown list in pyproject.toml [tool.mypy])
.venv/bin/mypy
```

Test DSN: `postgresql://regista_test:regista_test@localhost:5432/regista_test`
Test keys: `tests/test_keys.json`
Sample workflow: `tests/test_workflow.yaml`

## Public API (§19)

The `Regista` class is the sole entry point. No Postgres internals leak across the boundary.

```python
from regista import Regista

# Create a new project
sub = Regista.create_project(dsn, "my_project", hmac_key_path="/path/to/keys.json")

# Connect to existing
sub = Regista(dsn, "my_project", hmac_key_path="/path/to/keys.json")

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
sub.replay(verify_principal_binding=True)  # verify event signatures against principal_keys registry (Plan 026 WI-2.2)
sub.sign_spec(spec_yaml, spec_md_hash, spec_schema_version, actor_id, ...)  # sign spec.yaml as founding artifact (Plan 025 WI-4.3)
sub.read_spec_events(spec_id=None, limit=100)  # read spec-entity events (Plan 025 WI-4.3)
sub.enroll_principal(principal_id, *, actor_id="system", private_key_dir=None, secret_backend=None)  # issue+register Ed25519 keypair, emit signed enrollment event (Plan 026 WI-3.3); backend-aware custody (Plan 029)
sub.read_principal_enrollment_events(principal_id=None, limit=100)  # read principal enrollment events (Plan 026 WI-3.3)
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

sub.witnesses.register(url, headers, event_filter, ...)
sub.witnesses.unregister(witness_id)
sub.witnesses.pause(witness_id)
sub.witnesses.reactivate(witness_id)
sub.witnesses.list(status=None)
sub.witnesses.receipts(event_id=None, witness_id=None, status=None, limit=100)
sub.witnesses.deliver()

# Legacy top-level methods also available:
sub.register_witness(url, headers=None, event_filter=None, max_failures=10, max_retries=3)
sub.unregister_witness(witness_id)
sub.pause_witness(witness_id)
sub.reactivate_witness(witness_id)
sub.list_witnesses(status=None)
sub.list_witness_receipts(event_id=None, witness_id=None, status=None, limit=100)
sub.deliver_pending_witness_receipts()

# Maintenance (Plan 009/013)
sub.start_maintenance(sweep_interval=30, recurrence_interval=10)  # background thread
sub.stop_maintenance()
sub.maintenance_healthy  # True when thread is running and healthy (or not started)

# Suite cohesion (Plan 025)
regista.config.resolve()  # -> SuiteConfig (dsn, key_path, require_ssl, project, source)
regista.secrets.resolve(ref)  # -> bytes (file:/env:/literal:/vault:/azure:)
regista.versions()  # -> VersionInfo (library/schema/workflow/envelope versions)
regista version --json  # CLI: version surface
regista doctor --json   # CLI: health check
regista config           # CLI: show resolved config
regista secrets --list-providers  # CLI: list secret backends

# Principal key registry (Plan 026)
sub.principals.register(principal_id, public_key, scheme="ed25519", *, key_id=None, registered_by="system")
sub.principals.list(principal_id=None, *, status=None)
sub.principals.get_active(principal_id)
sub.principals.rotate(principal_id, new_public_key, scheme="ed25519", *, registered_by="system")
sub.principals.revoke(principal_id, key_id, *, reason="unspecified")
sub.principals.verify_binding(principal_id, actor_id)  # actor_id must match principal_id

# Provisioning (Plan 025 WI-2.1)
from regista._provision import provision, provision_principal
provision(dsn, ["project1", "project2"], dry_run=False)  # create schemas + service roles
provision_principal(dsn, project, "alice", hmac_key_path=key_path)  # issue+register Ed25519 keypair, emit signed enrollment event (Plan 026 WI-3.3); backend-aware custody via secret_backend (Plan 029)

# Signer binding verification (Plan 026 WI-1.2)
sub.verify_event_principal_binding(event)  # -> dict: verified, principal_id, key_id, error

# Trust hardening (Plan 008)
sub = Regista(dsn, project, hmac_key_path, strict_roles=True)  # reject unregistered actors
# Env-var key injection: REGISTA_HMAC_KEY_<KEY_ID> overrides file secrets
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
- Principal key registry (Plan 026): `SELECT FOR UPDATE` prevents concurrent-registration race; a `UNIQUE` partial index on `(principal_id) WHERE status = 'active'` enforces one-active-key at the DB level; rotation is atomic (supersede + insert in one transaction); `verify_binding` raises `ACTOR_SIGNER_MISMATCH` if `actor_id != principal_id`, `UNREGISTERED_SIGNER` if no active key exists
- Signer binding (Plan 026 WI-1.2): `verify_event_principal_binding` looks up the active key for the event's `actor_id` in the registry, verifies the signature under that public key, and confirms actor↔signer equality. Returns `unregistered-signer` if no active key, `scheme-mismatch` if event scheme differs from registered key scheme, `signature-verification-failed` if the signature is invalid
- Per-principal signing (Plan 026 WI-2.1): key file entries support `secret_ref` field (e.g. `"secret_ref": "file:/path/to/key"`) resolved via `regista._secrets.resolve()`; the private key is loaded from the secret backend, not embedded in the key file. `provision-principal` issues an Ed25519 keypair, stores the private key via the secret backend, registers the public key in the principal_keys registry, and adds a key file entry with `secret_ref`
- Replay principal binding (Plan 026 WI-2.2): `replay(verify_principal_binding=True)` closes the non-repudiation loop end-to-end. During replay, each event's signature is verified against the principal_keys registry (not just the key set). A forged actor with a valid key-set key but no matching principal key is caught. Events whose `actor_id` has no registered principal keys are skipped (backward compatible with HMAC-only deployments). Emits warnings, not halts. CLI: `regista replay --verify-principal-binding`. Sidecar: `ReplayRequest.verify_principal_binding`
- Provisioning (Plan 025 WI-2.1): `regista provision` creates per-project schemas, runs migrations, and creates scoped service roles (`regista_<slug>`) with privileges only on their own schema. `regista provision-principal` issues and registers Ed25519 keypairs. Both are idempotent; `--dry-run` writes nothing
- Spec entity (Plan 025 WI-4.3): `sign_spec` stores a `spec.yaml` as a signed `entity_kind="spec"` event — the project's founding artifact. Regista does not parse the spec; it stores and signs it. An unrecognized `spec_schema_version` is a named, non-fatal state (stored, flagged via `SPEC_SCHEMA_VERSION_UNKNOWN` warning). CLI: `regista spec sign/events`. Sidecar: `POST /spec/sign`, `GET /spec/events`

## Key Design Decisions

1. **Schema-per-project** not DB-per-project. One pool, one backup target, engine-enforced isolation via `GRANT ON SCHEMA`. Migration path to `tenant_id`-in-shared-DB documented but not needed at homelab scale.
2. **Library with optional maintenance thread.** Runs in-process. No HTTP server required. Exposes `prometheus_client.CollectorRegistry` for host app to mount. Optional `start_maintenance()` runs sweep/recurrence in a background thread.
3. **Hybrid persistence.** Events authoritative; projection updated in same transaction. Not pure event-sourcing (no per-read replay cost).
4. **Signing is internal.** RFC 8785 canonicalization (vendored in `_vendor/rfc8785.py`) + HMAC-SHA256 computed inside the library. Callers submit unsigned field tuples.

## Known constraints

- **Schema-per-project requires session-scoped `search_path`.** Regista uses `SET LOCAL search_path` per transaction. This is incompatible with connection-pooling middleware that dispatches transactions across different backends (e.g., PgBouncer in transaction mode). Use PgBouncer in session mode, or connect directly to Postgres. Medium-term migration path: fully-qualified table names (BC-033).
- **`events` table is flat (partitioning removed in RFC-001).** A global `UNIQUE(event_id)` index ensures event identity. `hook_queue.event_id → events.event_id` FK is maintained. `ensure_event_partitions` is a no-op returning `[]`. Partition gauges (`events_default_rows`, `events_partition_horizon_days`) have been removed. `heartbeat_claim` coalesces `claim_heartbeat` events within a `max(60s, ttl/2)` threshold (BC-194).

## Status

MVP + Phase 2 + Phase 3 + Plans 002-022 implemented. All FRs FR-01 through FR-29 are in tree. Full test suite (core, sidecar, property-based, witness, timestamping, and plan-specific) — run `pytest tests/ -v` for current count.

Production readiness additions: migration packaging for pip installs (importlib.resources + force-include), claims_stolen metric wired, actor_kind validation at API boundary, docstrings on all public methods, spec.yaml synced to v5, structured replay error handling, CHANGELOG.md, mypy --strict type-checking (burndown ratchet — see `[tool.mypy]` in `pyproject.toml`).

Phase 3 additions: FR-24 (actor → allowed_roles enforcement, closes BR-09), FR-25 (continue-on-revoked replay flag), FR-26 (update_not_before API), FR-27 (custom field validation at transition time). Migration `005_actor_roles.sql` adds the actor_roles table. ReplayReport gains `warnings` field.

Plans 002-004 additions:
- **Plan 002 (Admin CLI):** `regista` console entry point (`src/regista/_cli.py`). Commands: `workflow validate`, `work-item show/list`, `events show/tail`, `replay`, `schema init/status`, `hooks dead-letter list/requeue`, `actor-roles list`, `recurrence list/due/fire/cancel/update`. Plan 025 adds: `version --json`, `doctor --json`, `config show`, `secrets --list-providers`. Plan 026 adds: `principal list/register/revoke`. No DB required for `workflow validate` or `version`. Structlog routes to stderr in CLI mode.
- **Plan 003 (Recurring work-items, FR-28):** New `recurrence_rules` table (migration 011). Schedule kinds: `interval` and `rrule`. Public API on `Regista` and `InMemoryRegista`: `register_recurrence_rule`, `list_recurrence_rules`, `due_recurrences`, `fire_recurrence`, `cancel_recurrence_rule`, `update_recurrence_rule`. New error codes: `RECURRENCE_RULE_NOT_FOUND`, `RECURRENCE_RULE_EXHAUSTED`, `RECURRENCE_SCHEDULE_INVALID`, `RECURRENCE_TEMPLATE_INVALID`. Dependency: `python-dateutil`.
- **Plan 004 (Workflow composition, FR-29):** `_workflow_compose.py` with `resolve_includes`, `_deep_merge`, and `compose_workflow`. `extends:` field added to JSON Schema. `parse_file()` now resolves composition. Keyed list merge by `(name, from)` for transitions, `__append`/`__remove` list modifiers. New error code `WORKFLOW_COMPOSE_ERROR`.

Plan 005 additions:
- **Plan 005 (HTTP sidecar):** `src/regista/sidecar/` package with FastAPI. 1:1 pass-through of the Regista public API. Bearer-token auth via SHA-256 hashed token registry. Sole-signer middleware rejects `signature`/`payload_canonical_hash` fields. Hook claim/complete/fail lifecycle for non-Python consumers. ErrorCode → HTTP status mapping. Optional install extra `[sidecar]`. Dockerfile in `deploy/sidecar/`. 17 integration tests.

Code structure: `transition()` extracted to `_transition.py`, `recurrence` API extracted to `_recurrence_api.py`, reducing `__init__.py` from ~1580 to ~1200 lines. Facade decomposition (Plan 007) adds `_ops.py` with 7 domain-scoped facade classes; top-level methods delegate to facades.

Plans 007-009 additions:
- **Plan 007 (Facade decomposition):** `_ops.py` with `WorkflowOps`, `WorkItemOps`, `EventOps`, `ClaimOps`, `LinkOps`, `HookOps`, `RecurrenceOps`, `TimestampOps`. Cached properties on `Regista`. Old top-level methods remain as thin delegates (no deprecation warnings). 30 tests.
- **Plan 008 (Trust model hardening):** WS-1 (`strict_roles` flag — rejects unregistered actors and `prompt`-source roles). WS-2 (env-var key injection via `REGISTA_HMAC_KEY_<KEY_ID>`). WS-3 (vendored `rfc8785` in `_vendor/` with 73 cross-validation tests). WS-5 (raise on unknown key status, `expected_key_count`, `keys_loaded` log). WS-4 (sidecar rate limiting) deferred.
- **Plan 009 (Operational runtime):** `_maintenance.py` with `MaintenanceThread`. `start_maintenance()`/`stop_maintenance()` on `Regista`. Subsumes hook consumer. `maintenance_healthy` property reflects thread state. 5 integration tests.

Plans 011-012 additions:
- **Plan 011 (Pluggable signing, Ed25519):** `SigningScheme` protocol with `sign()`/`verify()` methods. `HMACSHA256Scheme` (default) and `Ed25519Scheme` (optional, via `pip install regista[ed25519]`). Module-level registry in `_signing_scheme.py`. `KeyEntry.scheme` field selects scheme per key. `scheme_id` column on `events` (migration 015). Replay resolves scheme per event. 10 unit + 10 integration tests.
- **Plan 012 (RFC 3161 timestamping):** `_timestamping.py` with Merkle tree batching, TSA HTTP submission, token verification. `tsp_batches` table (migration 016). `TimestampOps` facade (`sub.timestamping.trigger/list_batches/verify_batch`). `MaintenanceThread._maybe_timestamp_events` for background timestamping. `replay(verify_timestamps=True)` cross-references events against confirmed batches. Sidecar routes and CLI commands. `timestamping_errors` metric. 17 tests.

Plan 013 additions:
- **Plan 013 (Witness/co-signature post-append hooks):** `_witness.py` with registration, event filtering, receipt creation, and HTTP delivery. `witness_registrations` and `witness_receipts` tables (migration 020). `WitnessOps` facade (`sub.witnesses.register/unregister/pause/reactivate/list/receipts/deliver`). Legacy top-level methods: `register_witness`, `unregister_witness`, `pause_witness`, `reactivate_witness`, `list_witnesses`, `list_witness_receipts`, `deliver_pending_witness_receipts`. InMemory witness support with receipt creation. `MaintenanceThread._maybe_deliver_witness_receipts` for background delivery. Sidecar witness routes (7 endpoints). CLI `regista witness list/deliver/receipts` subcommands. New error codes: `WITNESS_NOT_FOUND`, `WITNESS_DELIVERY_FAILED`, `WITNESS_PAUSED`. 28 unit tests + 17 integration tests.

RFC-062: Single-source-of-truth backend contract via `_contract.py` — 20 pure validation/decision functions shared by both Postgres and InMemory backends. Property-based conformance tests via hypothesis in `tests/test_property_conformance.py`.

BC-139: `query_work_items` accepts `custom_field_filters: dict[str, object] | None` for equality filtering on custom field values (AND semantics). Postgres uses JSONB containment (`@>`) with a GIN index. InMemory uses equivalent dict matching. Migration `009_custom_fields_gin.sql` adds the index. Unknown filter keys produce empty results, not errors.

BC-171: `work_item_ref` custom fields now accept `target_work_item_types: [typeA, typeB]` (plural list) in addition to the existing singular `target_work_item_type`. The plural form constrains the referent to one of an enumerated set; each listed type must exist in the workflow. Specifying both singular and plural is rejected at registration (by JSON Schema first, then `_validate_semantics` as defense-in-depth). Omitting both retains the existing behavior: UUID format + existence validation only, no type enforcement.

Plan 025 additions (Suite cohesion spine):
- **Plan 025 WI-1.1 (Config resolver):** `_config.py` with `resolve()` implementing layered resolution: process env → per-user `~/.config/agent-suite/suite.env` → system `/etc/agent-suite/suite.env` → default. Canonical vars: `REGISTA_DSN`, `REGISTA_KEY_PATH`, `REGISTA_REQUIRE_SSL`, `REGISTA_PROJECT`. Deprecated alias: `REGISTA_HMAC_KEY_PATH` → `REGISTA_KEY_PATH` (one-release). `suite.env.example` ships with placeholders. `docs/suite-config.md` documents the vocabulary + precedence + alias policy.
- **Plan 025 WI-1.2 (Secret backend resolver):** `_secrets.py` with `resolve(ref)` supporting `file:`, `env:`, `literal:`, `vault:` (HashiCorp KV v2), `azure:` (AKV) providers. Pluggable via `register_provider()`. Vault requires `[vault]` extra (`hvac`); Azure requires `[azure]` extra (`azure-identity`, `azure-keyvault-secrets`). Auto-detection of prefix; bare paths default to `file:`.
- **Plan 025 WI-3.1 (Doctor JSON contract):** `_doctor.py` with `run_doctor()` emitting `{component, version, reachable, schema_version, projects, checks}` shape. CLI: `regista doctor --json`. Check statuses: `ok`/`warn`/`fail`/`skip`. Unreachable DSN is a clean fail, not a traceback. Error details are sanitized (no credentials leaked). DSN passwords masked in `config show`.
- **Plan 025 WI-4.1 (Version surface):** `_version_info.py` with `versions()` returning `VersionInfo` (frozen dataclass): `library_version`, `schema_version` (38), `canonical_workflow_version`, `envelope_version` (4), `canonical_workflow_hash`, `available_signing_schemes`. CLI: `regista version --json`. API: `regista.versions()`. Schema version is the highest migration number; envelope version is the signed-envelope format version. `docs/suite-config.md` documents the shape a `SUITE.lock` records.

Plan 026 additions (Per-actor Ed25519 non-repudiation):
- **Plan 026 WI-1.1 (Principal→public-key registry):** `_principal_keys.py` with register/rotate/revoke/list/get_active/verify_binding. Migration `038_principal_keys.sql` creates `principal_keys` table with `UNIQUE` partial index enforcing one active key per principal. `PrincipalKeyOps` facade (`sub.principals.register/list/get_active/rotate/revoke/verify_binding`). CLI: `regista principal list/register/revoke`. Row-level locking (`SELECT FOR UPDATE`) prevents concurrent-registration race. Rotation is atomic (single transaction). Error codes: `PRINCIPAL_KEY_NOT_FOUND`, `PRINCIPAL_KEY_ALREADY_EXISTS`, `ACTOR_SIGNER_MISMATCH`, `UNREGISTERED_SIGNER`.

Plan 029 additions (Backend-aware principal key custody):
- **Plan 029 WI-1.1/1.2 (Secret write protocol):** `SecretProvider` protocol gains `store(ref, data) -> str` (the write companion to `resolve`). `file` writes `0o600` atomic (temp+rename); `windows` DPAPI-protects (no plaintext on disk); `vault` KV v2 `create_or_update` (base64-encodes raw key); `azure` `set_secret` (base64-encodes). `env`/`literal` raise `SECRET_WRITE_UNSUPPORTED` (read-only by nature). New error codes: `SECRET_WRITE_UNSUPPORTED`, `SECRET_WRITE_EXTERNAL`. WI-1.2 decision (documented in `docs/suite-config.md` §3): self-custody backends write via `store()`; the `operator` backend is the operator-writes seam — `enroll_principal` does **not** generate a keypair, it raises `SECRET_WRITE_EXTERNAL` carrying the ref the operator must populate + guidance to use `principal register`. No silent fallback to `file:` ever.
- **Plan 029 WI-2.1/2.2 (Custody helper + backend selection):** `_custody.py` with `store_private_key()` — extracts the keypair-generate → backend-write → ref-record sequence; `provision_principal`/`enroll_principal` delegate to it (no hardcoded `file:` path). Backend selected via `REGISTA_SECRET_BACKEND` (added to `SuiteConfig`) or `--secret-backend`; `private_key_dir` is meaningful only for `file`. Key-file entries record `encoding: base64` for vault/azure; `_keys.py` applies `encoding` to `secret_ref` results (backward compatible: absent = raw).
- **Plan 029 WI-3.1/3.2 (Tests + doctor):** 29 new tests in `test_custody.py` incl. the gap-catching test (non-file backend writes **no** `.key` file to disk). `regista doctor` gains `custody:consistency` check that warns when a principal's recorded `secret_ref` scheme ≠ configured backend (e.g. a `file:` ref on a Vault deployment). CLI `provision-principal`/`principal enroll` accept `--secret-backend`. Sidecar error map: `SECRET_WRITE_UNSUPPORTED`→400, `SECRET_WRITE_EXTERNAL`→409.

## Conventions

- Python 3.11+, `from __future__ import annotations` in all files
- No comments in code (style rule). Rationale: `spec.md` and `AGENTS.md` are the canonical reference for behavior and intent. Code is expected to be self-explanatory through naming and structure. Comments drift as the spec evolves. Instead of comments, extract well-named helper functions, add test cases, or update the spec. Inline spec cross-references (e.g., `# AC-28`) are acceptable on non-obvious invariants.
- Frozen dataclasses for all domain types
- `dict_row` factory on all psycopg connections
- All mutations go through `mgr.transaction()` which sets `SET LOCAL search_path`
- Error codes are part of the API contract (§19.5)
- Tests reach internal state via `regista._testing` only — never import `_mgr` directly
- **`InMemoryRegista` without `hmac_key_path` silently skips event emission.** Operations that emit events (claim acquire, release, heartbeat) check `key_set is not None` before appending. Tests asserting on event counts must provide `hmac_key_path`. The `test_in_memory_conformance.py` fixture deliberately omits it; new test files that need event observability should pass `KEY_PATH`.

## Agent Workflow

This project tracks work outside the code. New agents should orient to these conventions before making changes.

### Work tracking (issues)

Work-items for this project live in **regista** — the single source of truth.
regista is the authoritative, signed, hash-chained event log; the local
agent-notes store is a read projection of it. **Do not create physical breadcrumb
files** (`breadcrumbs/`, `OPEN_BREADCRUMBS.txt`, `*.breadcrumb.md`) — the
file-based store is retired; its history was migrated into regista's own project
schema. (regista dogfoods its own convergence: it tracks its work in regista.)

**Agent face — the `agent-notes` CLI (and the `/file-breadcrumb` etc. skills).**
Run from the repo root so `--path .` resolves this project; the CLI routes to this
project's regista schema automatically (you never set the schema).

```
# File an issue
agent-notes breadcrumb file --path . --title "<short title>" \
    --type <kind> [--severity low|medium|high|critical] [--body "<details>"]

# Find / show / update
agent-notes breadcrumb find  --path . [--status open] [--type bug] [--text "<q>"]
agent-notes breadcrumb get   --path . <WI-id>
agent-notes breadcrumb update --path . <WI-id> [--status <state>] [--title ...] [--body ...]
```

**Lifecycle (canonical workflow):**
`open → in_progress → (blocked | deferred) → in_review → in_human_review → done`.
`done` is reachable only through the two-stage review gate (a cross-lineage
adversarial-review pass, then accept), except a pre-work `close_from_open`
dismissal (won't-fix / duplicate). "Who's working this" is a regista **claim**
(a separate liveness axis), not a lifecycle state.

Open the backlog before starting work — `agent-notes breadcrumb find --path .
--status open` is the canonical "what's known to be wrong" list. When you notice
an issue you're not fixing, file it; when you fix one, transition it. The `/end`
command does both via the CLI.

### Worklog (`.regista/worklog.md`)

Reverse-chronological session log. Each entry: focus, context, what was delivered (with file references), breadcrumbs resolved, test/lint results. Read the most recent entry on session start; prepend a new entry on session end.

### Reflections (`.regista/reflections/`)

Per-session subjective notes from the agent. Useful signal for the next agent — read the latest before starting. Written via the `/reflect` skill.

### Session commands

Regista-specific wrappers in `.regista/commands/`:
- `/start` — orient to current state (worklog tail, open breadcrumbs, git status)
- `/end` — run tests, reconcile breadcrumbs, update worklog, write reflection, commit
- `/reflection` — write a reflection only

System-wide skills (`/reflect`, `/end`) provide portable equivalents; the regista-specific versions add test runs and worklog updates.

## Patterns

### Telemetry via hooks

Regista's `actor_metadata` is JSONB — free-form structured metadata for downstream consumers. To produce indexed aggregates (e.g., per-role pass rates), register a hook handler on the relevant event types that writes denormalized rows to a consumer-maintained reporting table. The reporting table lives outside regista's schema; regista's contract is the authoritative event log, and the reporting table is a derived view that can be rebuilt by replaying events through the same handler.

A complete, runnable minimal example is in `examples/telemetry_via_hooks.py`.

Recommended shape:

1. **Reporting table** in a separate schema (or external store) with indexed columns for the dimensions you query by.
2. **Hook handler** that reads `actor_metadata`, extracts dimensions, and upserts the reporting row.
3. **Rebuild path**: drain the events table through the same handler in `event_seq` order to reconstruct from scratch.

Do not add denormalized columns to regista's `events` table for consumer-specific dimensions. Regista stays general; the consumer maintains its own reporting layer.

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
