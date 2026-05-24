# Substrate Worklog

Structured log of development sessions and milestones.

---

## 2026-05-24 — Session 56: Plan 015 (Wake/Provenance v1 Trust-Envelope) — BC-219 + BC-221

**Focus:** Implement the remaining Plan 015 items: upgrade `validate_delegation_chain` (BC-219), reserve `checkpoint` transition at workflow registration (BC-221), add missing error codes, update all call sites.

**Delivered:**

1. **BC-219 — `validate_delegation_chain` upgraded**
   - `src/substrate/_contract.py`: `validate_delegation_chain()` now accepts optional `event_timestamp: str | None` parameter.
   - UUID validation: `session_id` and `session_grant_event_id` must be valid UUID strings when present.
   - RFC 3339 timestamp parsing: `expires_at` and `authenticated_at` parsed via `datetime.fromisoformat()` (with `Z` → `+00:00` normalization).
   - Temporal comparison: when `event_timestamp` is provided, raises `DELEGATION_CHAIN_EXPIRED` if `event_timestamp >= expires_at`, and `INVALID_ARGUMENT` if `authenticated_at > event_timestamp`.
   - All 9 call sites across `__init__.py`, `_ops.py`, `_transition.py`, `_events_api.py`, `_in_memory.py`, `_in_memory_transition.py` updated to pass `event_timestamp=datetime.now(UTC).isoformat()`.

2. **BC-221 — `checkpoint` transition name reserved at workflow registration**
   - `src/substrate/_workflow.py`: `_validate_semantics()` now checks each transition name and rejects `"checkpoint"` with `RESERVED_TRANSITION_NAME`.
   - This is a second line of defense in addition to the existing `check_reserved_transition()` runtime guard.

3. **Error codes**
   - Added `DELEGATION_CHAIN_EXPIRED` and `RESERVED_TRANSITION_NAME` to `ErrorCode` enum in `_errors.py`.

4. **Migration 019**
   - `migrations/019_explicit_event_timestamp.sql`: comment-only migration documenting the BC-220 design decision (explicit timestamp parameter in INSERT).

5. **Test expansion**
   - `tests/test_bc215_219_220_221.py`: +12 new tests covering UUID validation, RFC 3339 parsing, `DELEGATION_CHAIN_EXPIRED` boundary conditions, `authenticated_at` ordering, and `checkpoint` workflow registration rejection.
   - `tests/test_plan010.py`: fixed `test_valid_with_session_id` to use a valid UUID string.

6. **Lint fix**
   - Fixed `_transition.py` import ordering (stdlib `datetime` before third-party `structlog`).

**Files modified:**
- `src/substrate/_contract.py` — upgraded `validate_delegation_chain()`
- `src/substrate/_errors.py` — added `DELEGATION_CHAIN_EXPIRED`, `RESERVED_TRANSITION_NAME`
- `src/substrate/_workflow.py` — `checkpoint` reservation in `_validate_semantics()`
- `src/substrate/__init__.py`, `_ops.py`, `_transition.py`, `_events_api.py`, `_in_memory.py`, `_in_memory_transition.py` — call sites pass `event_timestamp`
- `tests/test_bc215_219_220_221.py` — 12 new tests
- `tests/test_plan010.py` — fixed session_id to use valid UUID

**Test results:** 927 passed, 10 deselected, lint clean.
**Breadcrumbs:** Plan 015 BCs 219 and 221 resolved.
**Reflection:** pending

---

## 2026-05-24 — Session 55: BC-233 InMemory hash chain parity, spec v8, test coverage

**Focus:** Wire `prev_event_hash` computation into the InMemory backend (shared `_store_append` path), add InMemory + multi-event chain tests, update spec.md to v8.

**Delivered:**

1. **InMemory hash chain parity (BC-233 gap)**
   - `src/substrate/_event_store.py`: `append_event` (shared by InMemory) now computes `prev_event_hash` by looking up the previous event via `store.read(work_item_id=..., limit=1, before_seq=event_seq)` and hashing `SHA-256(prev.canonical_envelope + prev.signature)`. First events (`event_seq == 1`) correctly get `prev_event_hash=None`.
   - When `key_set is None` (no HMAC), dummy envelope+signature still produce deterministic chain hashes.
   - Both `sign_event()` calls (with and without key) now pass `prev_event_hash` through, ensuring v3 envelope is used when the chain is present.

2. **Test coverage expansion**
   - Added `TestBC233HashChainInMemory` class (4 tests): `test_first_event_has_no_prev_hash`, `test_second_event_includes_prev_hash`, `test_multi_event_chain`, `test_chain_without_keys`.
   - Added `test_multi_event_chain` to `TestBC233HashChain` (Postgres): creates 3+ transitions, verifies each event's `prev_event_hash` matches `SHA-256(prev.canonical_envelope + prev.signature)`.
   - Total: 9 tests in `test_hash_chain.py`, all passing.

3. **Spec v8**
   - Updated `spec.md`:
     - Added `prev_event_hash` and `global_seq` to FR-03 event field list.
     - Signing envelope section updated from v2 to v3, documenting `prev_event_hash` (hex) and `global_seq` inclusion.
     - Storage description updated (v3 envelope).
     - Signing envelope decision row updated.
     - Core data model row updated.
     - Revision history: v8 entry documenting BC-233, migration 018, InMemory parity.
    - Updated `breadcrumbs/README.md` BC-233 resolution to note InMemory parity and 9 tests.

4. **BC-236 — PostgresEventStore.append() missing prev_event_hash**
   - `PostgresEventStore.append()` was not including `prev_event_hash` in its INSERT statement. Events created via `Substrate.append_event()` (public API path using `PostgresEventStore`) would have `prev_event_hash` computed correctly in memory but never persisted to DB — the column would remain NULL.
   - Direct Postgres paths (`_events.py:append_event`, `_events.py:append_transition_event`) were unaffected (they have their own INSERT with `prev_event_hash`).
   - Fixed by adding `prev_event_hash` to the INSERT column list and parameter list in `PostgresEventStore.append()`.
   - Fixed by adding `prev_event_hash` to the INSERT column list and parameter list in `PostgresEventStore.append()`.
   - Added `test_append_event_api_persists_prev_hash` to verify the public API path persists `prev_event_hash` correctly.

5. **InMemory replay hash chain verification**
   - Added `_verify_hash_chain_in_memory()` to `_in_memory_replay.py`, mirroring the Postgres replay's `_verify_hash_chain()`.
   - Tracks `prev_evt` across events and verifies `SHA-256(prev.canonical_envelope + prev.signature)` matches `event.prev_event_hash`.
   - Chain breaks emit warnings (not halt), consistent with Postgres replay behavior.
   - **BC-237**: Fixed variable naming collision: `ok` was both the replay counter and the hash chain check result. Renamed to `chain_ok`/`chain_err`.

**Files modified:**
- `src/substrate/_event_store.py` — added `import hashlib`, `prev_event_hash` computation in `append_event()`, pass-through to `sign_event()`, set on `Event` dataclass, fixed `PostgresEventStore.append()` INSERT to include `prev_event_hash`
- `src/substrate/_in_memory_replay.py` — added `_verify_hash_chain_in_memory()`, tracks `prev_evt` in replay loop, verifies hash chain per-event, fixed `ok` variable collision (BC-237)
- `tests/test_hash_chain.py` — added `TestBC233HashChainInMemory` (4 tests), `test_multi_event_chain` to Postgres class, `test_append_event_api_persists_prev_hash`
- `spec.md` — v8 revision
- `breadcrumbs/236-postgreseventstore-append-missing-prev-event-hash.md` — new
- `breadcrumbs/237-variable-name-collision-in-memory-replay.md` — new
- `breadcrumbs/README.md` — BC-233, BC-236, BC-237 updated

**Breadcrumbs:** Resolved BC-236 (PostgresEventStore INSERT), BC-237 (variable name collision). Open: 213 (accepted), 234 (low), 235 (medium).
**Reflection:** pending

## 2026-05-24 — Session 54: Breadcrumb cleanup + BC-233 event hash chain

**Focus:** Close resolved breadcrumbs 223–232, defer BC-229, implement BC-233 (event hash chain) with signing envelope v3.

**Delivered:**

1. **Breadcrumb cleanup**
   - Moved resolved breadcrumbs 223, 224, 225, 226, 227, 228, 229, 230, 232 to `breadcrumbs/resolved/`.
   - Updated `breadcrumbs/README.md` Open/Resolved tables with resolution descriptions.
   - Accepted BC-229 (`TSAConfig.tsa_cert_path`) as deferred — field already documented as reserved for future use in `_timestamping.py`.

2. **BC-233 — Event hash chain (`prev_event_hash`)**
   - Migration `018_prev_event_hash.sql`: added `prev_event_hash BYTEA` to `events`.
   - `Event` dataclass (`_types.py`): added `prev_event_hash: bytes | None` and `global_seq: int | None`.
   - `_events.py`: both `append_event` and `append_transition_event` now query the previous event's `canonical_envelope` and `signature`, compute `SHA-256(prev_env + prev_sig)`, and store it. The INSERT statements include `prev_event_hash`.
   - `_event_store.py`: updated `PostgresEventStore._EVENT_FIELDS` and `InMemory` `Event` constructor to include the new fields.
   - `_signing.py`: added `build_signing_envelope_v3()` with `prev_event_hash` and `global_seq`. `sign_event` selects v3 vs v2 based on presence of `prev_event_hash`. `verify_event` tries v3 first, then v2, then v1 backward compat. Added `classify_envelope_version()` for auto-detection.
   - `_replay.py`: added `_verify_hash_chain()` (AC-28) called per-event during `_replay_work_item`. Chain breaks emit warnings rather than halting replay.
   - Tests (`tests/test_hash_chain.py`, 4 tests):
     - `test_first_event_has_no_prev_hash`
     - `test_second_event_includes_prev_hash`
     - `test_replay_hash_chain_check`
     - `test_broken_chain_detected`

3. **Lint & test**
   - 274 targeted tests passing across signing, replay, coverage, hash chain, e2e, timestamping, idempotency, CLI, contract.
   - Lint clean on all modified files.
   - E501 fix in `_replay.py`.

**Files modified:**
- `migrations/018_prev_event_hash.sql` (new)
- `src/substrate/_types.py`, `_signing.py`, `_events.py`, `_event_store.py`, `_replay.py`
- `tests/test_hash_chain.py` (new)
- `breadcrumbs/README.md`, `breadcrumbs/resolved/*`

**Breadcrumbs:** Resolved BC-233. Open: 213 (accepted), 234 (low), 235 (medium).
**Reflection:** `.substrate/reflections/2026-05-24-kimi-k2.6-2.md`

---

## 2026-05-24 — Session 53: Plan 014 — Global event sequence for coherent batch timestamping

**Focus:** Implement Plan 014: add `global_seq BIGSERIAL` to `events`, rewrite timestamping batching and replay verification to use it, resolve BC-231.

**Delivered:**

1. **Migration `017_events_global_seq.sql`**
   - Added `global_seq BIGSERIAL UNIQUE NOT NULL` to `events` with `CACHE 100`.
   - Backfilled existing rows by `(timestamp, event_id)` order.
   - Switched `tsp_batches` columns from `first_event_seq/last_event_seq` to `first_global_seq/last_global_seq`.
   - Marked pre-existing `tsp_batches` rows as `superseded`.

2. **Rewrote `trigger_timestamping` (`_timestamping.py`)**
   - Replaced the broken per-WI `event_seq` arithmetic with `global_seq` range queries.
   - `SELECT MAX(last_global_seq) FROM tsp_batches WHERE status = 'confirmed'` for high-water mark.
   - `SELECT ... WHERE global_seq > last_confirmed ORDER BY global_seq LIMIT batch_size` for event selection.
   - Updated `_rehydrate_event_ids` and `list_batches` to use `first_global_seq/last_global_seq`.

3. **Rewrote replay `verify_timestamps` block (`_replay.py`)**
   - Added `global_seq` to `_EVENT_FIELDS`.
   - Changed coverage tracking from `event_seq` (per-WI, ambiguous) to `global_seq` (global, one-to-one).
   - Replaced `event_ids_by_seq: dict[int, list[UUID]]` with `event_ids_by_global_seq: dict[int, UUID]`.
   - Re-derived Merkle roots from `global_seq` ranges instead of `event_seq` ranges.

4. **InMemory parity (`_event_store.py`)**
   - Added `_next_global_seq` counter and `_global_seq_by_event_id` mapping to `InMemoryEventStore`.

5. **Tests (`tests/test_timestamping.py`)**
   - Updated existing tests to use new column names and query shapes.
   - Fixed `TestBC228UTCTimestamps` mock call signatures after query count reduction.
   - Added `TestPlan014GlobalSeq` (4 tests):
     - `test_global_seq_monotonic_across_work_items`
     - `test_trigger_timestamping_selects_by_global_seq`
     - `test_replay_verify_timestamps_multi_wi`
     - `test_replay_merkle_root_mismatch_multi_wi`

6. **Breadcrumb reconciliation**
   - Moved BC-231 to `breadcrumbs/resolved/` and updated README index.

**Files modified:**
- `migrations/017_events_global_seq.sql` (new)
- `src/substrate/_timestamping.py`, `_replay.py`, `_event_store.py`
- `tests/test_timestamping.py`
- `breadcrumbs/README.md`, `breadcrumbs/resolved/231-trigger-timestamping-event-seq-not-global.md`

**Test results:** 905 passed, lint clean.
**Breadcrumbs:** Resolved BC-231. 1 remains accepted (BC-213).

---

## 2026-05-24 — Session 52: Plan 011/012 verification, Ed25519 integration, TSA protocol, spec v7

**Focus:** Verify Plans 011 and 012 against plan documents, fix bugs found, complete remaining items.

**Delivered:**

1. **BC-222 — Replay _EVENT_FIELDS missing scheme_id (high)**
   - `_replay.py` `_EVENT_FIELDS` was missing `scheme_id`, causing Ed25519 events to always verify with HMAC during Postgres replay.
   - Fixed by adding `scheme_id` to the tuple.
   - Added `verify_key` resolution in both replay paths: uses `key_entry.public_key` for Ed25519.

2. **Ed25519 integration tests** (`tests/test_signing_ed25519.py`, 10 tests)
   - Postgres: create/read, transition, replay with Ed25519 keys.
   - Key rotation: mixed HMAC+Ed25519 with combined key file.
   - InMemory: full lifecycle.
   - Error paths: missing PyNaCl, unknown scheme.
   - Fixed Ed25519 test key files (added `encoding: "base64"` and `public_key`).

3. **TSA wire protocol** (`_timestamping.py`)
   - Implemented `submit_to_tsa()` with RFC 3161 TimeStampReq DER construction + HTTP POST.
   - Implemented `verify_tsa_token()` with digest-matching verification.
   - 8 new tests: submission, HTTP errors, token verification, batch serialization.

4. **Replay verify_timestamps** (`_replay.py`, `__init__.py`)
   - Added `verify_timestamps: bool = False` to `replay()` (Plan 012 §5.4).
   - When `True`, cross-references events against confirmed `tsp_batches`; uncovered events increment warnings.
   - 2 integration tests.

5. **Spec v7 reconciliation** (`spec.md`)
   - Updated: FR-03 (scheme_id), FR-15 (pluggable scheme), FR-16 (verify_timestamps), §16 (signing decision), §17.9 (trust tiers), §19.2 (signing), §19.5 (error codes), revision history.

6. **Minor fixes**
   - `_testing.py`: re-exported `get_scheme` and `available_schemes`.
   - `_signing_scheme.py`: `Ed25519Scheme.verify()` uses `VerifyKey` directly (expects public key).
   - AGENTS.md: updated test count to 888, added Plans 011-012 section.

**Files modified:**
- `src/substrate/_replay.py`, `_in_memory_replay.py`, `_signing_scheme.py`, `_testing.py`, `_timestamping.py`, `__init__.py`
- `spec.md`, `AGENTS.md`
- `tests/test_signing_ed25519.py` (new), `tests/test_timestamping.py` (expanded)
- `tests/test_keys_ed25519.json` (fixed), `tests/test_keys_combined.json` (new)
- `breadcrumbs/resolved/222-replay-missing-scheme-id-ed25519.md` (new)

**Test results:** 888 passed, 10 deselected, lint clean.

---

## 2026-05-24 — Session 51: Plan 012 completion (timestamping API + sidecar + CLI)

**Focus:** Complete the remaining Plan 012 wiring flagged in Session 50 reflection: expose `timestamping` on `Substrate`, sidecar routes, CLI commands, and `start_maintenance` TSA config passthrough.

**Delivered:**

1. **TimestampOps on Substrate**
   - Added `Substrate.timestamping` cached property returning `TimestampOps` (facade pattern matching `workflows`, `claims`, etc.).
   - `start_maintenance` gains `timestamp_interval: float = 3600.0` and `tsa_config=None` parameters.
   - When `tsa_config` is passed, it is forwarded to both `TimestampOps.set_config()` and `MaintenanceThread` so the maintenance cycle can auto-trigger timestamping.

2. **Sidecar timestamp routes**
   - `POST /v1/timestamp/trigger` — triggers a batch (admin-only).
   - `GET /v1/timestamp/batches` — lists batches with optional `status` query param (admin-only).
   - `POST /v1/timestamp/batches/{id}/verify` — verifies a batch by ID (admin-only).
   - Added `TriggerTimestampRequest` and `VerifyTimestampBatchRequest` Pydantic models to `sidecar/models.py`.
   - Restored accidentally-deleted `ClaimHooksRequest` base model (fixes `ImportError` in `routes_hooks.py`).

3. **CLI timestamp commands**
   - `substrate timestamp status` — lists batches.
   - `substrate timestamp trigger` — triggers a new batch.
   - `substrate timestamp verify <id>` — verifies a batch.

4. **Lint / test**
   - Fixed duplicate `verify` subparser registration causing `ArgumentError` in CLI.
   - Full suite: 861 passed, 3 skipped, 10 deselected; lint clean on `src/` and `tests/`.

**Files modified:** `src/substrate/__init__.py`, `src/substrate/_cli.py`, `src/substrate/_ops.py`, `src/substrate/_maintenance.py`, `src/substrate/sidecar/routes.py`, `src/substrate/sidecar/models.py`.

**Test results:** 861 passed, 3 skipped, 10 deselected, lint clean on `src/` and `tests/`.

**Reflection:** `.substrate/reflections/2026-05-24-session-51.md`

---

## 2026-05-24 — Session 50: Plan 011 (pluggable signing) + Plan 012 (RFC 3161 timestamping)

**Focus:** Implement Plans 011 and 012 per their draft RFCs, plus prerequisite recovery of missing `_hooks_api.py`.

**Delivered:**

1. **Plan 011 — Pluggable Signing (Ed25519 + HMAC-SHA256)**
   - New `src/substrate/_signing_scheme.py`: `SigningScheme` protocol, `HMACSHA256Scheme`, `Ed25519Scheme`, registry.
   - `Event` dataclass gains `scheme_id: str = "hmac-sha256"` with round-trip `to_dict`/`from_dict`.
   - `KeyEntry` gains `scheme` field; `KeySet._load()` validates scheme and checks for PyNaCl when `scheme == "ed25519"`.
   - Sign path (`_events.py`, `_event_store.py`) resolves scheme from key entry and passes to `sign_event()`.
   - Replay (`_replay.py`, `_in_memory_replay.py`) resolves scheme per-event before verification.
   - Migration `015_event_scheme_id.sql` adds `scheme_id` column to `events`.
   - New error code: `SIGNING_SCHEME_NOT_FOUND`.
   - `pyproject.toml` gains `[ed25519]` optional dependency.
   - New tests: `tests/test_signing_scheme.py` (10 tests).

2. **Plan 012 — RFC 3161 Timestamping on Event Batches**
   - New `src/substrate/_timestamping.py`: `TSAConfig`, `TimestampBatch`, SHA-256 Merkle tree (`compute_merkle_root`, `merkle_proof`, `verify_merkle_proof`), `trigger_timestamping()`, `list_batches()`.
   - `submit_to_tsa` / `verify_tsa_token` raise `NotImplementedError` (DER encoding deferred until cryptography dependency decision).
   - Migration `016_tsp_batches.sql` creates `tsp_batches` table with indexes.
   - `TimestampOps` facade added to `_ops.py` with `trigger()`, `list_batches()`, `verify_batch()`.
   - `MaintenanceThread` gains `_maybe_timestamp_events()` gated by `TSAConfig`.
   - New error codes: `TSA_NOT_CONFIGURED`, `TSA_SUBMISSION_FAILED`, `TSA_VERIFICATION_FAILED`.
   - New tests: `tests/test_timestamping.py` (9 tests).

3. **Prerequisite fix: re-created `_hooks_api.py` and facade wiring**
   - `_hooks_api.py` was missing from the tree, causing `ModuleNotFoundError` in `HookOps` methods.
   - Re-created the module with `refresh_hook_queue_metrics`, `list_dead_lettered_hooks`, `requeue_dead_lettered_hook`.
   - Fixed `HookOps.sweep_expired_leases` to increment `maintenance_hook_leases_swept` metric.
   - Added `_hook_channel` alias to `HookOps`.
   - Fixed `Substrate.list_dead_lettered_hooks` / `requeue_dead_lettered_hook` method names to match facade.

4. **Documentation**
   - `spec.md` revision history updated to v7.
   - `AGENTS.md` source layout updated with new modules.

**Files modified:** `src/substrate/_errors.py`, `_types.py`, `_keys.py`, `_signing.py`, `_events.py`, `_event_store.py`, `_replay.py`, `_in_memory_replay.py`, `_ops.py`, `_maintenance.py`, `__init__.py`; new `src/substrate/_signing_scheme.py`, `_timestamping.py`, `_hooks_api.py`; migrations `015_event_scheme_id.sql`, `016_tsp_batches.sql`; new tests `tests/test_signing_scheme.py`, `test_timestamping.py`; `pyproject.toml`, `spec.md`, `AGENTS.md`.

**Test results:** 836 passed, 3 skipped (Ed25519 without PyNaCl), lint clean on `src/` and `tests/`.

**Reflection:** `.substrate/reflections/2026-05-24-kimi-k26.md`

---

## 2026-05-24 — Session 49: BC-215/219/220/221 batch + spec v6 reconciliation

**Focus:** Implement the remaining identity/signing cluster breadcrumbs and reconcile `spec.md` with the v2 envelope already present in code.

**Delivered:**

1. **BC-215 — Key revocation temporal dimension boundary tests**
   - Added `test_revoked_at_*` (6 tests) covering exact equality rejection, predates acceptance, absent-field fallback.
   - No code change needed — `KeyEntry.revoked_at` and `verify_key_status` already existed from Session 48.

2. **BC-219 — Delegation chain fields**
   - Added `expires_at: str | None` and `session_grant_event_id: str | None` to `DelegationChain` dataclass (`_types.py`).
   - Extended `validate_delegation_chain` (`_contract.py`) to validate the two new fields as non-empty strings when present.
   - Added 9 new tests: valid/rejects-empty/rejects-non-string/null-allowed for each field, plus full round-trip.

3. **BC-220 — Unify event timestamp source**
   - Removed `RETURNING timestamp` from Postgres INSERT in `_events.py` (`append_event`, `append_transition_event`) and `_event_store.py` (`PostgresEventStore.append`).
   - Client-side `now = datetime.now(UTC)` is now passed explicitly and returned unchanged in the `Event` constructor.
   - Added `test_postgres_appends_client_timestamp` verifying the returned timestamp is the client-side value.

4. **BC-221 — Checkpoint transition reservation**
   - Added `"checkpoint"` to `_RESERVED_TRANSITIONS` in `_contract.py`.
   - `check_reserved_transition` and `check_append_blocked` now reject manual use.
   - Added 4 checkpoint tests.

5. **Spec reconciliation: v5 → v6**
   - Updated revision history, date header, §FR-15 canonical signing envelope paragraph, and decision table row to describe the v2 envelope honestly (11 fields, not 6).
   - Documented backward-compat fallback (v2 → v1 retry at replay time).
   - Removed stale "server-stamped fields excluded" claim.

6. **Breadcrumb bookkeeping**
   - Moved BC-214/215/216/217/218/219/220/221 to `breadcrumbs/resolved/`.
   - Updated `breadcrumbs/README.md`: Open list now only BC-213 (accepted).

**Files modified:**
- `src/substrate/_contract.py`, `_types.py`, `_event_store.py`, `_events.py`
- `spec.md`
- `tests/test_bc215_219_220_221.py` (new, 24 tests)

**Test results:** 845 passed, 10 deselected, lint clean on `src/` and `tests/`.

---

## 2026-05-23 — Session 33: Spec-drift fixes, breadcrumb reconciliation, signing cleanup

**Focus:** Resolve open spec-drift and bookkeeping breadcrumbs; address reflection-flagged code-quality items.

### Addendum (Session 33½)

Fixed full lint across `src/` and `tests/`. Removed unused imports and prefixed underscores on unused unpacked variables in `test_plan010.py`, `test_replay_coverage.py`, `test_plan010_integration.py`, `test_recurrence_postgres.py`. Updated breadcrumb README Open list to reflect BC-213. Filed BC-214 (resolved in same session) to document and prevent future agent sessions from only linting `src/`.

**Original delivered:**

1. **BC-211 — Spec drift: "own database" is stale**
   - Fixed `spec.md` line 22: changed "own database" to "own Postgres schema within a shared database".
   - Moved breadcrumb to `resolved/`.

2. **BC-212 — Spec drift: FR-10 references non-existent `event_type` column**
   - Fixed `spec.md` line 124: changed `event_type = 'escalated'` to `transition = 'escalated'`.
   - Moved breadcrumb to `resolved/`.

3. **BC-209 — Move to `resolved/`** (implementation was already in tree from Session 32).

4. **Moved BC-184, 185, 188, 189, 190, 191, 192 to `resolved/`** (all had `status: implemented` in root).

5. **Updated `spec.md` for `on_behalf_of` (reflection from Session 32):**
   - Added `on_behalf_of` to FR-03 event field list.
   - Updated canonical signing envelope to include `on_behalf_of` with backward-compat note.
   - Added Plan 010 mention to v5 revision history.
   - Updated core data model decision table.

6. **Updated `AGENTS.md` test count:** 721 → 802.

7. **BC-213 — Accepted as design tension**
   - Heartbeat claim return type intentionally models durable claim state, not event-log delta.
   - Updated breadcrumb with resolution rationale while leaving it as the single open item.

8. **Extracted `_verify_once` helper in `_signing.py` (reflection gap)**
   - Eliminates duplicated HMAC-verify + hash-check logic in backward-compat branch.
   - No behavioral change; verified by 48 targeted tests (signing + replay + coverage + Plan 010).

9. **Fixed pre-existing E501 lint in `test_replay_coverage.py`** (two SQL string line-too-long lines from Session 32).

**Test results:** 802 passed, lint clean on modified files.
**Breadcrumbs:** Resolved 12 open items; 1 remains accepted (BC-213).
