# Changelog

All notable changes to regista are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Plan 028 (Event-log retention & segment sealing):** `event_segments` table (migration 039) records sealed contiguous ranges of the global event chain. `sub.archive.seal(before_timestamp)` verifies global and per-work-item hash chains, signs a `segment_sealed` event, and stores the segment seal. Replay bridges across sealed ranges via `first_event_prev_hash` / `head_hash`, so older events can be moved out of the hot store without orphan warnings. CLI: `regista archive seal/verify/list`. Added `docs/retention.md`.

### Fixed

- **BC-310:** Replay now runs at REPEATABLE READ isolation to prevent spurious drift/halt under concurrent writes. Spec §17.1 amended: mutating transactions remain READ COMMITTED; replay (read-only) is the sole exception. `ConnectionManager.transaction_repeatable_read()` uses `conn.isolation_level` for SSL-safe isolation setting.
- **Plan 027 follow-up:** Added `AssuranceOps` facade (`sub.assurance.compute_assurance()` / `sub.assurance.gate_rationale()`) so review-assurance computations live in the ops layer alongside other Plan 007 facades. Top-level `compute_assurance()`/`gate_rationale()` delegate to the facade.
- **BC-308:** `verify_event()` now filters backward-compat envelope candidates by the stored envelope's classified version — v4 events try only v4 candidates, v3 try v3/v4, v2 try v2/v3/v4. `classify_envelope_version()` v3 detection fixed to check any chain field (not just `prev_event_hash`). Dead code removed from non-chained branch.
- **BC-306:** `entity_kind` validated at sidecar (`Literal["work_item"]` → 422 on unknown), core API, and InMemory boundaries. Allowed set centralized in `_contract.py`. Public API docstring corrected.
- **BC-294:** Migration runner gains `repair_checksums()` (with advisory lock) and CLI `schema repair-checksums` command. `-- regista: autocommit` directive enables non-transactional migrations for `CREATE INDEX CONCURRENTLY`.

## [0.5.0] — 2026-06-26

### Added

- **Plan 020 (Validator context enrichment):** `ValidatorContext` (the object passed to sync transition validators) gains two additive fields: `actor_kind` (the acting actor's kind, identical to the `transition()` argument) and `prior_events` (the work-item's complete pre-transition event history as a tuple of `Event` objects, ascending `event_seq`). Both are populated only inside the registered-validator branch (zero-cost when no validator is registered), on the transition's own connection/store handle for transactional consistency. `to_dict()`/`from_dict()` round-trip both fields; `from_dict` tolerates their absence for forward-compatibility with pre-Plan-020 payloads (missing `actor_kind` decodes to `"agent"`, missing `prior_events` to `()`).
- **Plan 021 (Validator delegation chain on context):** `ValidatorContext` now also exposes the acting actor's `on_behalf_of` delegation chain (the same value passed to `transition()`). This enables separation-of-duties validators to detect self-review-via-delegation by comparing the transition's principal against prior-event authors. The field is zero-cost when no validator is registered and round-trips through `to_dict()`/`from_dict()`; `from_dict` tolerates its absence for forward-compatibility (missing `on_behalf_of` decodes to `None`).
- **Plan 022 (Entity generalization and crypto agility):** events carry `entity_kind`/`entity_id` (generalizing beyond `work_item_id`), a global event hash chain (`global_seq` + `prev_global_event_hash`), signing envelope v4, and per-event `hash_alg`. Spec updated to v9 (§17.11–17.14). Additive and backward-compatible via envelope-version retry in `verify_event`.
- **Witness Ed25519 co-signing (BC-297/303/305):** witnesses may register Ed25519 public keys; witness signatures verified against the public key at delivery time. Missing/invalid signatures treated as delivery failures.
- **WI-003 (Per-work-item scoped replay):** `replay()` now accepts an optional `work_item_id` keyword argument to replay and verify a single work item in isolation. Scoped replay runs per-item hash chain, signature, and projection checks, compares the derived state to the live projection row, and reports one warning that global-chain verification was skipped. Global chain, chain-head, and TSP timestamp coverage checks remain full-`replay()` concerns. A scoped id whose projection row is missing but whose events exist is reported as `halted` (corruption) rather than `WORK_ITEM_NOT_FOUND`.

### Fixed

- **BC-298/300:** `PostgresEventStore.append()` persists `prev_global_event_hash`; replay now verifies the global hash chain and detects tail-deletion via the `event_chain_head`.
- **BC-301:** `MAX_JSONB_BYTES` (1MB) enforced on all JSONB-bearing fields (payloads, `actor_metadata`, `custom_fields`) via the `Jsonb` wrapper.
- **BC-304:** `KeySet.verify_key_status` parses timestamps to `datetime` before comparison (was plain-string compare).
- **Adversarial review batch (Session 66–71):** numerous input-validation, parity, signature-verification, and replay-coverage fixes tracked under BC-276–BC-308.


## [0.4.0] — 2026-05-27

### Changed

- **Project renamed: `substrate` → `regista`.** The Python module, console script, PyPI name, and all env vars now use `regista`. Repo is at `hraedon/regista`; the old URL redirects. See Plan 018.
- **Schema:** `workflow_registry.substrate_version` column renamed to `regista_version`; `_substrate_migrations` table renamed to `_regista_migrations` (migration 028).
- **Env vars:** `SUBSTRATE_DSN`, `SUBSTRATE_HMAC_KEY_*`, `SUBSTRATE_BIND`, `SUBSTRATE_DISABLE_DOCS`, `SUBSTRATE_DISABLE_RATE_LIMIT`, `SUBSTRATE_POOL_MAX`, `SUBSTRATE_POOL_MIN`, `SUBSTRATE_PROJECT`, `SUBSTRATE_TOKENS_PATH`, `SUBSTRATE_VERSION` → all renamed `REGISTA_*`. No backwards-compat aliasing.
- **Console script:** `substrate` → `regista` in `[project.scripts]`.
- **Classes:** `Substrate` → `Regista`, `InMemorySubstrate` → `InMemoryRegista`, `SubstrateError` → `RegistaError`.

### Migration notes for consumers

Consumers pin to `v0.4.0-pre-rename` during their migration window. Migration steps:

1. Update `pyproject.toml` / requirements: `substrate` → `regista`.
2. Update imports: `from substrate import …` → `from regista import …`.
3. Update env var references in code, scripts, and deployment configs.
4. Re-run tests.

## [0.3.0] — 2026-05-26

### Added

- **Plan 010 (Delegation chain):** `on_behalf_of` field on every event for agent-to-principal binding. `validate_delegation_chain` with temporal validation (`expires_at`, `authenticated_at`). Integrity-protected by HMAC signature. Migration 019.
- **Plan 011 (Pluggable signing):** `SigningScheme` protocol with `HMACSHA256Scheme` (default) and `Ed25519Scheme` (optional, via `pip install regista[ed25519]`). `scheme_id` column on events (migration 015). Replay resolves scheme per event.
- **Plan 012 (RFC 3161 timestamping):** `_timestamping.py` with Merkle tree batching, TSA HTTP submission, token verification. `tsp_batches` table (migration 016). `TimestampOps` facade. `replay(verify_timestamps=True)` cross-references events against confirmed batches.
- **Plan 013 (Witness co-signing):** `_witness.py` with registration, event filtering, receipt creation, and HTTP delivery. `witness_registrations` and `witness_receipts` tables (migration 020). `WitnessOps` facade. Maintenance thread integration. Sidecar witness routes (7 endpoints).
- **Plan 014 (Global event sequence):** `global_seq BIGSERIAL` on events (migration 017). Rewrote timestamping batching and replay verification to use global sequence for coherent multi-work-item batching.
- **Plan 015 (Trust envelope v3):** Signing envelope v3 includes `prev_event_hash` and `global_seq`. `prev_event_hash BYTEA` column on events (migration 018). Hash chain verification in replay.
- **Plan 016 (Privileged transitions):** `privileged: true` flag on workflow transitions. Only `actor_kind='system'` can execute. New `PRIVILEGED_TRANSITION_REQUIRED` error code. Enforced in Postgres and InMemory backends.
- **Plan 017 (Webhook/witness unification):** Webhooks rewritten as thin wrapper over witness machinery. Migration 026 adds `mode` column to `witness_registrations`, unifies status to `paused` (dropped `failed`), drops `webhook_registrations` table. `X-Regista-Signature` header. Optional `sign_secret` on all endpoints.
- **Webhooks:** Push-model event delivery with `register_webhook`, auto-pause on failure. Now delegates to witness receipt+delivery model (async, not synchronous).
- **Event archival:** `archive_events(before_timestamp, dry_run)` with `ArchiveOps` facade. Only archives complete work-items to preserve hash chain integrity. Migration 024.
- **Batch operations:** `create_work_items_batch` for multi-create in a single transaction.
- **CLI additions:** `work-item create/transition`, `events archive`, `witness list/deliver/receipts`, `webhook register/list/remove`, `timestamp status/trigger/verify`, `workflow compose`.
- **`work_item_ref` multi-target:** Custom fields accept `target_work_item_types` (plural list) in addition to singular `target_work_item_type`.
- **CI:** All optional extras (`[sidecar,ed25519,timestamping]`) now installed in CI so full test suite runs.

### Fixed

- **Adversarial review (BC-238–BC-256):** 19 breadcrumbs covering witness receipt TOCTOU, sidecar error mapping gaps, InMemory parity issues, missing CHECK constraints, input validation across CLI/sidecar/core.
- **Adversarial review (BC-244–BC-256):** Input validation, error handling, and robustness improvements across 15 files.
- **BC-233:** Event hash chain — `prev_event_hash` computation in Postgres and InMemory backends.
- **BC-236:** `PostgresEventStore.append()` now includes `prev_event_hash` in INSERT.
- **BC-222:** Replay `_EVENT_FIELDS` now includes `scheme_id` for Ed25519 verification.

## [0.2.0] — 2026-05-22

### Added

- **Plan 007 (Facade decomposition):** Domain-scoped sub-objects (`sub.workflows`, `sub.work_items`, `sub.events`, `sub.claims`, `sub.links`, `sub.hooks`, `sub.recurrence`) via `_ops.py`. Legacy top-level methods remain as thin delegates.
- **Plan 008 (Trust model hardening):**
  - WS-1: `strict_roles=True` flag rejects unregistered actors and `prompt`-source roles at transition time
  - WS-2: Environment-variable key injection via `REGISTA_HMAC_KEY_<KEY_ID>` overrides file secrets
  - WS-3: Vendored `rfc8785` 0.1.4 into `_vendor/` with 73 cross-validation tests against system library
  - WS-5: Raise on unknown key status at startup; `expected_key_count` parameter; `keys_loaded` structured log
- **Plan 009 (Operational runtime):** `MaintenanceThread` in `_maintenance.py` with configurable sweep, recurrence, hook-poll, and partition intervals. `start_maintenance()` / `stop_maintenance()` on `Regista`. `maintenance_healthy` property. Subsumes hook consumer lifecycle.
- Shared datetime utilities (`_datetime_utils.py`): `ts_equal`, `to_utc`, `ts_equal_within` — eliminated 88 lines of duplication between replay modules.
- CI now installs `[vendor-check]` extra so rfc8785 cross-validation tests run in CI.

### Changed

- Constructor positional-signature contract test (BC-195) pins `Regista(dsn, project, hmac_key_path)` shape used by sf2.
- BC-196/197/198 (trust model design gaps) accepted and documented; implementation deferred.

### Deprecated

- WS-4 (sidecar rate limiting) explicitly deferred per reviewer consensus.

## [0.1.1] — 2026-05-21

### Changed

- **RFC-001:** Reverted events table partitioning. Events table is now flat with a global `UNIQUE(event_id)` index. `ensure_event_partitions()` is a no-op returning `[]`. Partition gauges (`events_default_rows`, `events_partition_horizon_days`) removed from Prometheus metrics. Migrations renumbered 010–013 (gaps 010/014 closed; no production data affected).
- **BC-194:** Heartbeat coalescing — `heartbeat_claim` suppresses `claim_heartbeat` events within `max(60s, ttl/2)` threshold. New optional `coalesce_threshold` parameter for custom override. Replay drift detection tolerates `claim_expires_at` deltas within the coalesce threshold.

### Deprecated

- `ensure_event_partitions()` — no-op, will be removed in a future version
- `auto_partition` parameter on `Regista.create_project()` — no-op, will be removed in a future version
- Prometheus gauges `regista_events_default_rows` and `regista_events_partition_horizon_days` — no longer emitted

### Fixed

- `_ts_equal_within` in replay modules incorrectly called `.astimezone(UTC)` on naive datetimes (assumed local time instead of UTC)
- `_ts_equal` mixed naive/aware comparison logic simplified to normalize both to UTC

## [0.1.0] — 2026-05-15

### Added

- Event-sourced coordination library for agent pipelines over Postgres (FR-01 through FR-29)
- Schema-per-project isolation with `SET LOCAL search_path` scoping
- Immutable append-only event log with gap-free `event_seq` per work-item
- Transactionally-consistent denormalized projection (`work_items_current`)
- HMAC-SHA256 signing with RFC 8785 canonicalization; library is sole signer (FR-15)
- Monthly partitioned events table (migration 010) — **removed in RFC-001**; events table is now flat with global `UNIQUE(event_id)`
- Durable claims with TTL, attempt tracking, and auto-steal on expiry
- Workflow registry with content-hash idempotency
- Sync transition validators with 5s timeout and I/O safety AST check (FR-13)
- Async hook queue with dead-letter, retry, and out-of-process claim/complete/fail lifecycle
- Actor role enforcement (FR-24) with `register_actor_role` / `check_actor_role_authorized`
- Custom field validation at workflow registration and transition time (FR-27)
- Typed directed links between work items
- Cursor-based pagination on `query_work_items`
- JSONB containment (`@>`) filtering on custom fields with GIN index (BC-139)
- Replay with drift detection and continue-on-revoked flag (FR-25)
- `update_not_before` API for rescheduling work items (FR-26)
- Recurring work items with interval and RRULE schedules, catch-up policies (FR-28)
- Workflow composition via `extends:` with keyed list merge and `__append`/`__remove` modifiers (FR-29)
- Admin CLI: `workflow validate`, `work-item show/list`, `events show/tail`, `replay`, `schema init/status`, `hooks dead-letter list/requeue`, `actor-roles list`, `recurrence list/due/fire/cancel/update`
- HTTP sidecar (Plan 005): thin 1:1 pass-through of the Python API over FastAPI with bearer-token auth, sole-signer enforcement, hook claim/complete/fail lifecycle, and OpenAPI docs
- Dockerfile and README for sidecar deployment (`deploy/sidecar/`)
- Prometheus metrics via `prometheus_client.CollectorRegistry`
- Structured logging via structlog
- CI configuration (`.github/workflows/ci.yml`)
- In-memory backend for testing (`InMemoryRegista`)
- Single-source-of-truth backend contract via `_contract.py` (RFC-062)
- Property-based conformance tests via hypothesis

### Fixed

- 188 breadcrumbs resolved across security, correctness, and conformance dimensions
- Key fixes: claim zombie revival prevention (BC-071), cross-partition event_id uniqueness (BC-148), projection-before-event ordering (BC-147), validator ThreadPoolExecutor lock leak (BC-146), structlog stderr routing in CLI
