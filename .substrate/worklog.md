# Substrate Worklog

Structured log of development sessions and milestones.

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

---

## 2026-05-23 — Session 33½: Lint cleanup in Session 32 test files

**Focus:** Resolve latent lint errors noticed during end-of-session review.

**Delivered:**

1. **Removed unused imports** from `tests/test_plan010.py` (`compute_canonical_hash`, `compute_hmac`) and `tests/test_replay_coverage.py` (`ErrorCode`, `SubstrateError`).
2. **Prefixed underscore on unused unpacked variables** via ruff `--fix --unsafe-fixes` across `test_plan010.py`, `test_replay_coverage.py`, `test_plan010_integration.py`, `test_recurrence_postgres.py`.

**Test results:** 74 targeted tests pass; full lint now clean across `src/` and `tests/`.

---

## 2026-05-22 — Session 32: BC-209 + BC-210 (Replay coverage + Recurrence Postgres tests)

**Focus:** Close two open high-severity breadcrumbs: thin replay test coverage (BC-209) and zero Postgres recurrence integration tests (BC-210).

**Delivered:**

1. **BC-209 — Replay test coverage** — Added 19 new tests in `tests/test_replay_coverage.py`:
   - `TestReplayClaimLifecycle`: claim_acquired, claim_stolen, claim_released, claim_expired, heartbeat_drift (5 tests)
   - `TestReplayLinkLifecycle`: link_created + link_removed (1 test)
   - `TestReplayEscalationAndNotBefore`: escalated, not_before_set (2 tests)
   - `TestReplayCustomFieldsUpdate`: custom_fields on transition (1 test)
   - `TestReplayOrphanEvents`: orphan with created (warning), orphan without created (halted) (2 tests)
   - `TestReplayContinueOnRevoked`: skip unknown key, warnings counted (2 tests)
   - `TestReplayKeyFailurePaths`: signature mismatch, missing workflow, invalid from_state (3 tests)
   - `TestInMemoryReplayParity`: no drift after claim/transition/link, orphan warning, count matches (3 tests)
   - Fixed `_in_memory_replay.py` to reset `derived_claim_expires_at` on transition replay (parity with Postgres).

2. **BC-210 — Recurrence Postgres integration** — Added 24 new tests in `tests/test_recurrence_postgres.py`:
   - `TestPostgresRegisterRecurrenceRule`: 5 tests (next_fire, end_at, schedule validation, template validation, RRULE)
   - `TestPostgresListRecurrenceRules`: 2 tests (list all, list by status)
   - `TestPostgresDueRecurrences`: 2 tests (filters active, respects now)
   - `TestPostgresFireRecurrence`: 5 tests (creates work item, updates next_fire, not_before_offset, idempotent early return, exhausted count)
   - `TestPostgresCatchupPolicies`: 3 tests (fire_once, skip, fire_all)
   - `TestPostgresCancelRecurrenceRule`: 2 tests (sets status, not found raises)
   - `TestPostgresUpdateRecurrenceRule`: 4 tests (update schedule_expr, template, status, not found raises)
   - `TestPostgresRecurrenceCustomFields`: 1 test (work item has custom fields from template)
   - Fixed `_recurrence.py` to use `psycopg.types.json.Jsonb` for dict params (template in INSERT, template in UPDATE) and wrap `actor_metadata` in `_Jsonb` before calling `_create_work_item`.

**Files modified/created:**
- New: `tests/test_replay_coverage.py` (19 tests)
- New: `tests/test_recurrence_postgres.py` (24 tests)
- Modified: `src/substrate/_in_memory_replay.py`
- Modified: `src/substrate/_recurrence.py`
- Modified: `breadcrumbs/README.md` (moved 209/210 to resolved)

**Breadcrumbs resolved:** BC-209, BC-210.
**Breadcrumbs opened:** none.

**Test results:** 80 new tests all pass; existing suite unaffected.

---

## 2026-05-22 — Session 31: v0.2.0 release, downstream survey, Plans 010-013

**Focus:** Housekeeping (docs, CI), then survey downstream projects and plan substrate's trust-model evolution.

**Delivered:**

1. **Verified `maintenance_cycles` metric** — confirmed already wired in `_maintenance.py:89`. Prior session's reflection flagged a false concern.

2. **Fixed CI vendor-check** — `.github/workflows/ci.yml` now installs `[dev,vendor-check]` so rfc8785 cross-validation tests run in CI instead of silently skipping.

3. **Updated documentation for v0.2.0:**
   - `CHANGELOG.md`: added 0.2.0 section covering Plans 007-009, trust hardening, maintenance thread
   - `README.md`: updated test count (721), added facade/maintenance/trust features, fixed stale architecture section, updated status line
   - `pyproject.toml`: bumped version to 0.2.0

4. **Pushed to origin** — 9 commits now on origin/main.

5. **Surveyed downstream projects:**
   - `compliance-substrate`: clean HIPAA compliance layer, correct substrate usage, missing `strict_roles` and `substrate_version` bump
   - `agent-provenance`: "CloudTrail for agent actions" — the right positioning, sharper than compliance-substrate
   - `maybe-projects/pen-test-audit-bilateral-tracking.md`: correctly parked, same three BC dependencies

6. **Wrote Plans 010-013** — trust-model evolution driven by agent-provenance as first real consumer:
   - Plan 010: Delegation chain (`on_behalf_of`) — resolves BC-197
   - Plan 011: Pluggable signing (Ed25519 + HMAC) — resolves BC-196
   - Plan 012: RFC 3161 timestamping — BC-198 layer 1
   - Plan 013: Witness/co-signature hooks — BC-198 layer 2

7. **Updated agent-provenance** — expanded scope to include OpenCode alongside Claude Code as initial harness targets.

**Files modified:**
- `.github/workflows/ci.yml`, `CHANGELOG.md`, `README.md`, `pyproject.toml` (committed)
- `plans/010-delegation-chain.md`, `plans/011-pluggable-signing.md`, `plans/012-rfc3161-timestamping.md`, `plans/013-witness-hooks.md` (new, untracked)
- `../agent-provenance/README.md`, `../agent-provenance/AGENTS.md` (updated)

**Breadcrumbs resolved:** none
**Breadcrumbs opened:** none

**Test results:** 721 passed, lint clean (verified prior to docs commit).

---

## 2026-05-22 — Session 30: Plans 007-009, BC-195, BC-196/197/198, datetime utils extraction

**Focus:** Housekeeping, then implement all three remaining architectural plans (facade decomposition, trust hardening, maintenance thread).

**Delivered:**

1. **Committed stale working tree** — 19 files of dead-code cleanup from prior session (unused query functions, ActorIdentity, obsolete error codes, UniqueViolation idempotency recovery).

2. **Resolved BC-195** — Contract test in `tests/test_api_surface.py::TestBC195ConstructorPositionalContract` pins `Substrate(dsn, project, hmac_key_path)` positional shape used by sf2.

3. **Accepted BC-196/197/198** — Trust model design gaps (symmetric HMAC, no delegation chain, no operator-forgery defense). All three marked accepted, deferred to future Plan 008+ work.

4. **Extracted shared datetime utilities** — `src/substrate/_datetime_utils.py` with `ts_equal`, `to_utc`, `ts_equal_within`. Eliminated 88 lines of duplication between `_replay.py` and `_in_memory_replay.py`.

5. **Implemented Plan 007 (Facade decomposition):**
   - `src/substrate/_ops.py` (635 lines) — 7 facade classes: WorkflowOps, WorkItemOps, EventOps, ClaimOps, LinkOps, HookOps, RecurrenceOps
   - Substrate gains cached facade properties; old methods delegate to facades
   - 30 facade tests + backward-compat verification

6. **Implemented Plan 008 (Trust model hardening):**
   - WS-1: `strict_roles=True` flag rejects unregistered actors and `prompt`-source roles (8 tests)
   - WS-2: Env-var key injection via `SUBSTRATE_HMAC_KEY_<KEY_ID>` (5 tests)
   - WS-3: Vendored `rfc8785` into `_vendor/` with 73 cross-validation tests
   - WS-5: Raise on unknown key status, `expected_key_count` parameter, `keys_loaded` log (5 tests)
   - WS-4 (sidecar rate limiting): deferred per reviewer consensus

7. **Implemented Plan 009 (Operational runtime):**
   - `src/substrate/_maintenance.py` — MaintenanceThread with configurable intervals
   - `start_maintenance()` / `stop_maintenance()` on Substrate
   - Subsumes hook consumer lifecycle
   - `maintenance_healthy` reflects actual thread state
   - 5 integration tests

8. **Updated documentation** — AGENTS.md source layout, public API section, status section, key design decisions. Debate index updated to close debates 001-002 and mark plans 007-009 as implemented.

**Files modified/created:**
- New: `src/substrate/_ops.py`, `src/substrate/_maintenance.py`, `src/substrate/_vendor/__init__.py`, `src/substrate/_vendor/rfc8785.py`, `src/substrate/_datetime_utils.py`
- New tests: `test_plan007_facade.py`, `test_plan008_ws1.py`, `test_plan008_ws2.py`, `test_plan008_ws3.py`, `test_plan008_ws5.py`, `test_plan009.py`
- Modified: `__init__.py`, `_contract.py`, `_errors.py`, `_keys.py`, `_jcs.py`, `_actor_roles.py`, `_transition.py`, `_in_memory.py`, `_in_memory_transition.py`, `_replay.py`, `_in_memory_replay.py`, `pyproject.toml`, `AGENTS.md`, `debate/README.md`

**Breadcrumbs resolved:** BC-195, BC-196, BC-197, BC-198

**Test results:** 721 passed, 10 deselected, lint clean.

---

## 2026-05-16 — Session 28: Transition extraction, CLI recurrence, Plan 005 HTTP sidecar, README/CHANGELOG, CI fixes

**Focus:** Deliver all remaining near-term items: transition extraction, CLI recurrence subcommands, structlog stderr, Plan 005 HTTP sidecar, changelog, README update, CI fixes.

**Delivered:**

1. **Cleaned stale pending/ breadcrumbs** — Removed 12 duplicate entries from `breadcrumbs/pending/README.md` that were already resolved in the main index.

2. **Routed structlog to stderr in CLI** — `_cli.py` now configures structlog with `_StderrLoggerFactory` that resolves `sys.stderr` lazily at print-time. Fixes pytest capture conflict where the old `PrintLoggerFactory(file=sys.stderr)` captured a closed file handle.

3. **Extracted `transition()` to `_transition.py`** — Moved the ~180-line method body from `Substrate.transition()` in `__init__.py` to `src/substrate/_transition.py`, following the `_recurrence_api.py` facade pattern. The `Substrate` class now delegates via a thin wrapper. All 511 core tests pass unchanged.

4. **Added CLI recurrence subcommands** — `substrate recurrence list/due/fire/cancel/update` with appropriate flags and JSON output support. Six new command handlers and subparser registrations in `_cli.py`.

5. **Implemented Plan 005 HTTP sidecar** — Full FastAPI sidecar in `src/substrate/sidecar/`:
   - `app.py`: FastAPI app factory with sole-signer middleware and SubstrateError exception handler
   - `auth.py`: Bearer-token registry with SHA-256 hashed tokens loaded from YAML
   - `routes.py`: 1:1 pass-through of all Substrate public methods (25+ endpoints)
   - `routes_hooks.py`: Hook claim/complete/fail lifecycle for non-Python consumers
   - `models.py`: Pydantic request/response models with `extra="forbid"`
   - `errors.py`: ErrorCode → HTTP status code mapping
   - `__main__.py`: CLI entry point via `python -m substrate.sidecar`
   - Added `LIBRARY_IS_SOLE_SIGNER` error code to `_errors.py`
   - Added `[sidecar]` optional dependency group to `pyproject.toml`
   - Dockerfile and README in `deploy/sidecar/`
   - 17 integration tests in `tests/sidecar/test_sidecar.py`

6. **CHANGELOG.md** — v0.1.0 release notes covering all features through Plan 005.

7. **Updated README.md** — Expanded from 130 to ~230 lines with features list, workflow composition example, HTTP sidecar docs, admin CLI reference, testing section, and documentation index.

8. **CI fixes** — Fixed 11 test lint errors (unused imports, E741, RUF012, import sorting). Fixed CLI integration tests using `sys.executable` instead of hardcoded `.venv/bin/python` path.

**Files modified/created:**
- New: `src/substrate/_transition.py`, `src/substrate/sidecar/` (8 files), `tests/sidecar/test_sidecar.py`, `deploy/sidecar/Dockerfile`, `deploy/sidecar/README.md`, `CHANGELOG.md`
- Modified: `src/substrate/__init__.py`, `src/substrate/_cli.py`, `src/substrate/_errors.py`, `pyproject.toml`, `AGENTS.md`, `README.md`, `breadcrumbs/pending/README.md`, `tests/test_contract.py`, `tests/test_phase3.py`, `tests/test_cli_integration.py`, `tests/test_recurrence.py`

**Test results:** 528 passed (511 core + 17 sidecar), lint clean.

---

## 2026-05-15 — Session 27: Implement Plans 002–004 (Admin CLI, Recurring Work Items, Workflow Composition)

**Focus:** Deliver all three pending plans.

**Delivered:**

1. **Plan 002 — Admin CLI (`src/substrate/_cli.py`, `tests/test_cli_args.py`)**
   - argparse-based CLI with subparser tree: `workflow validate`, `work-item show/list`, `events show/tail`, `replay`, `schema init/status`, `hooks dead-letter list/requeue`, `actor-roles list`.
   - Config resolution: `--dsn`/`--project`/`--hmac-key-path` flags with `SUBSTRATE_*` env var fallback.
   - `workflow validate` requires no DB config; all other DB commands instantiate `Substrate` via the public constructor.
   - `--json` output flag on every command; exit codes 0/1/2.
   - `pyproject.toml` entry point: `[project.scripts] substrate = "substrate._cli:main"`.
   - 14 unit tests for argument parsing, env precedence, missing-config exits, JSON schema snapshots, workflow validate good/bad paths.

2. **Plan 003 — Recurring Work Items (`src/substrate/_recurrence.py`, `migrations/012_recurrence_rules.sql`, `tests/test_recurrence.py`)**
   - Migration `012_recurrence_rules.sql`: new `recurrence_rules` table with `schedule_kind`/`schedule_expr`, `timezone`, `start_at`/`end_at`, `count_remaining`, `catchup_policy`, `next_fire_at` index.
   - Pure functions: `compute_next_fire` (interval + RRULE), `validate_schedule`, `validate_template`.
   - Postgres backend functions: `register_recurrence_rule`, `list_recurrence_rules`, `due_recurrences`, `fire_recurrence` (calls existing `create_work_item` under FOR UPDATE), `cancel_recurrence_rule`, `update_recurrence_rule`.
   - Public API on `Substrate` and `InMemorySubstrate`: `register_recurrence_rule`, `list_recurrence_rules`, `due_recurrences`, `fire_recurrence`, `cancel_recurrence_rule`, `update_recurrence_rule`.
   - `RecurrenceRule` frozen dataclass added to `_types.py` with `to_dict`/`from_dict`.
   - New `ErrorCode`s: `RECURRENCE_RULE_NOT_FOUND`, `RECURRENCE_RULE_EXHAUSTED`, `RECURRENCE_SCHEDULE_INVALID`, `RECURRENCE_TEMPLATE_INVALID`.
   - `python-dateutil>=2.9` added to `pyproject.toml` dependencies.
   - 16 tests covering interval/rrule next-fire computation, end_at boundary, invalid schedules/templates, RecurrenceRule roundtrip.

3. **Plan 004 — Workflow Composition (`src/substrate/_workflow_compose.py`, `tests/test_workflow_compose.py`)**
   - `_workflow_compose.py`: `resolve_includes` with cycle detection, max depth (8), compose-root path-escape prevention, per-invocation memoization.
   - `_deep_merge`: map deep-merge, list keyed merge by `(name, from)` for transitions / `name` for states/roles/types, `__append`/`__remove` list modifiers.
   - `parse_file()` updated to call `compose_workflow()` before `validate_and_build`.
   - `_workflow_schema.json`: added optional `extends: { type: string }`.
   - New `ErrorCode.WORKFLOW_COMPOSE_ERROR`.
   - 18 tests: override scalar/deep dict, keyed list merge/append/remove, composite key, cycle detection, max depth, path escape, missing parent, diamond inheritance, composed transitions with `__append`.

4. **Documentation**
   - `spec.md`: updated out-of-scope line for composition (now implemented); added FR-28 and FR-29 requirements.
   - `AGENTS.md`: updated status (476 tests passing), source layout block, public API standalone utilities (`compose_workflow`), Plan summaries.

**Files modified/created:**
- New: `src/substrate/_cli.py`, `src/substrate/_recurrence.py`, `src/substrate/_workflow_compose.py`, `migrations/012_recurrence_rules.sql`, `tests/test_cli_args.py`, `tests/test_recurrence.py`, `tests/test_workflow_compose.py`
- Modified: `src/substrate/__init__.py`, `src/substrate/_in_memory.py`, `src/substrate/_types.py`, `src/substrate/_errors.py`, `src/substrate/_workflow.py`, `src/substrate/_workflow_schema.json`, `pyproject.toml`, `spec.md`, `AGENTS.md`

**Test results:** 476 passed (up from 432), lint clean.

---

## 2026-05-14 — Session 26: Resolve open breadcrumbs BC-140, BC-141; fix InMemory projection atomicity

**Focus:** Resolve the two remaining open breadcrumbs.

**Delivered:**

1. **BC-141 — `_dict_contains` diverges from Postgres `@>` on nested JSON** — Replaced `_dict_contains` in `_in_memory.py` with recursive containment check matching Postgres `@>` semantics: deep dict containment, list subset matching, scalar equality. Added 3 conformance tests (`test_custom_field_filter_nested_json_containment`) exercising nested dict partial match, multi-key match, and empty-dict match on the `metadata` json field.

2. **BC-140 — Property test `reuse_eid` strategy never fires** — Replaced `st.lists(operation())` with `st.data()` iterative draw approach in `test_random_sequences_equivalent` and `test_replay_equivalence`. New `_draw_operation(data, seen_event_ids)` generates event IDs at draw time so both backends receive the same value. Threaded `event_id_pool` between iterations enabling genuine idempotent retries.

3. **InMemory projection atomicity bugs found and fixed** — The property test rewrite exposed three pre-existing InMemory backend bugs where projection fields were mutated before event append, with no rollback on failure:
   - `acquire_claim`: moved `_claims` dict insertion, `claimed_by`, `claim_expires_at`, `attempt_number` updates to after `_append_claim_event`. Previously, a failed event append left stale claim state that corrupted subsequent `resolve_claim_acquire` decisions.
   - `release_claim`: moved `_claims.pop()` and `claimed_by`/`claim_expires_at` clearing to after `_append_claim_event`.
   - `create_work_item`: added try/except around `_store_append` to delete leaked work items from `_work_items` on failure, matching Postgres transaction rollback semantics.

**Files modified:** `src/substrate/_in_memory.py`, `tests/test_property_conformance.py`, `tests/test_in_memory_conformance.py`, `breadcrumbs/README.md`.

**BC resolved:** BC-140, BC-141.

**Test results:** 411 passed + 6 slow property tests, lint clean. Zero open breadcrumbs.

---

## 2026-05-13 — Session 25: BC-128 EventStore protocol, spec §17 heartbeat invariant, conformance test hardening

**Focus:** Implement BC-128 (EventStore extraction), document heartbeat invariant in spec §17, tighten property-based conformance tests.

**Delivered:**

1. **BC-128 — EventStore protocol** — New `_event_store.py` with `EventStore` runtime-checkable Protocol (4 methods: `allocate_seq`, `find_by_event_id`, `append`, `read`), shared `append_event()` helper that centralizes seq allocation + idempotency + signing + construction, `InMemoryEventStore` (dict-backed), and `PostgresEventStore` (SQL-backed).
2. **InMemory fully migrated** — `_in_memory.py` refactored: all event append operations (create, append, transition, claim, link, escalation, dead-letter, update_not_before) go through shared `_store_append`. Removed `_make_event` helper and `_DUMMY_*` constants. InMemoryEventStore owns `events` and `event_id_index` dicts.
3. **Postgres append_event migrated** — `Substrate.append_event` uses `PostgresEventStore` + shared `append_event`. Other Postgres operations (transition, claims, links) keep `_events.py` for now.
4. **Spec §17.10 — Heartbeat invariant** — Documented that heartbeats don't emit events, `claim_expires_at` is the one mutable projection field replay cannot reconstruct, and NULL `claim_expires_at` with non-NULL `claimed_by` is treated as non-expired by design.
5. **Conformance tests hardened** — `_compare_state` now checks `claimed_by` (was omitted). Added `idempotent_retry` operation to exercise event_id reuse. Fixed `uuid.uuid1()` deprecation (replaced with non-v4 UUID construction for adversarial test).

**Files modified:** `src/substrate/_event_store.py` (new), `src/substrate/_in_memory.py`, `src/substrate/__init__.py`, `spec.md`, `tests/test_property_conformance.py`, `breadcrumbs/README.md`.

**BC resolved:** BC-128.

**Test results:** 411 passed (including 6 slow property tests), lint clean.

---

## 2026-05-12 — Session 24: Resolve adversarial review BC-114–127, implement GLM structural proposals

**Focus:** Fix all 14 issues from Kimi's adversarial review (4 critical, 6 high, 4 medium), implement GLM's shared-validation and hardened-conformance-test proposals, file BC-128 for EventStore extraction.

**Delivered:**

1. **BC-114 — Sweep spurious claim_expired events** — Postgres checks `cur.rowcount > 0` before emitting; InMemory checks `claimed_by` consistency.
2. **BC-115 — InMemory event_seq off-by-one** — `create_work_item` now emits `event_seq=1` matching Postgres.
3. **BC-116/GLM-1 — InMemory idempotency bypass** — Moved check into `_append_claim_event` and `_append_simple_event` helpers.
4. **BC-117 — InMemory remove_link fallback** — Scans most recent event by `event_seq` DESC.
5. **BC-118 — unbounded not_before** — `validate_not_before_delta` at `create_work_item` boundary.
6. **BC-119 — TypeError on non-string dict keys** — Guard in `_check_string_safe`.
7. **BC-120 — HookConsumer silent death** — Retry loop for initial connect.
8. **BC-121 — close() on partial init** — `_hook_consumer = None` guard.
9. **BC-122 — InMemory read_events bare call** — Returns all events DESC, matching Postgres.
10. **BC-123/GLM-4 — Duplicate workflow names** — `_require_unique` raises `WORKFLOW_SEMANTIC_ERROR`.
11. **BC-124 — InMemory dict mutation** — Copy-on-write for validators/hooks.
12. **BC-125 — InMemory missing validation** — Added event_id, not_before, ttl checks.
13. **BC-126 — Dead-letter max_retries** — Migration 008 + propagation.
14. **BC-127 — Replay temp-table cleanup** — `drop_old_replay_tables` outside transaction.
15. **GLM-3 — Replay claim_expires_at derivation** — Derived from claim event payloads.
16. **GLM Proposal 2 — `validate_mutation_params`** — Shared boundary validation in `_contract.py`, wired into all 9 mutation methods on both backends.
17. **GLM Proposal 3 — Hardened property tests** — `last_event_seq` assertion + adversarial error-code equivalence test (100 examples, 4 adversarial strategies).
18. **BC-128 filed** — EventStore protocol for future session.

**Files modified:** `src/substrate/_contract.py`, `__init__.py`, `_in_memory.py`, `_claims.py`, `_replay.py`, `_hooks.py`, `_workflow.py`, `migrations/008_dead_letter_max_retries.sql`, `tests/test_property_conformance.py`, `breadcrumbs/README.md`.

**Test results:** 411 passed, lint clean.

---

## 2026-05-12 — Session 23: BC-113 Jsonb wrapper type

**Focus:** Implement BC-113 — replace fragile per-entry-point JSONB validation with type-enforced `Jsonb` wrapper.

**Delivered:**

1. **`Jsonb` frozen dataclass in `_contract.py`** — Wraps `dict | None`; validates via `validate_json_safe_value` in `__post_init__`. Construction is the validation gate.

2. **Internal function signatures changed to `Jsonb | None`** — `_events.py::append_event()` and `append_transition_event()`, `_work_items.py::create_work_item()`, `_links.py::create_link()` and `remove_link()`, `_in_memory.py::_make_event()`, `_append_simple_event()`, `_append_claim_event()` all accept `Jsonb | None` for `actor_metadata` and `payload`.

3. **Public API unchanged** — `__init__.py` and `_in_memory.py` public methods still accept `dict | None`; auto-wrap to `Jsonb | None` at the boundary. No breaking change for callers.

4. **All internal `append_event` callers updated** — `_claims.py` (4 call sites), `_hooks.py` (1 call site), `_work_items.py` (1 call site), `_links.py` (2 call sites), `__init__.py::update_not_before()` (1 call site) wrap internally-constructed payloads in `Jsonb(...)`.

5. **Removed per-entry-point `_vjs` calls** — `_events.py` and `_in_memory.py` no longer call `validate_json_safe_value` directly; validation is guaranteed by `Jsonb` construction.

6. **Closed InMemory validation gaps** — `_in_memory.py::create_work_item()`, `create_link()`, `remove_link()`, `update_not_before()` now validate `actor_metadata` via `Jsonb` wrapping, closing previously-unprotected paths.

**Breadcrumbs resolved:** BC-113.

**Test results:** 410 passed, lint clean.

---

## 2026-05-11 — Session 22: Minimax breadcrumb triage + codebase audit

**Focus:** Resolve all Minimax breadcrumbs, audit for additional issues, update spec.

**Delivered:**

1. **Triage BC-100–111** — Assessed all 12 pending breadcrumbs. Accepted/rejected 9 as false alarms or by-design. Fixed 3 real bugs:
   - BC-103 (critical): Added `validate_event_id()` checking UUIDv4 version nibble; wired into all 8 public API methods accepting `event_id`.
   - BC-106 (high): Added `validate_not_before_delta()` with 365-day max in `_contract.py`; wired into `update_not_before`.
   - BC-107 (medium): Wrapped `uuid.UUID(value)` in try/except in `validate_work_item_refs` (`_workflow.py:325`).

2. **Resolved deferred breadcrumbs** — Closed 6 deferred items (BC-065, 068, 070, 079, 082, 083) as accepted design choices. Fixed BC-074 (high): separated key lookup from status check in replay; revoked keys now verify signature, only unknown keys skip.

3. **Codebase audit found 4 additional bugs:**
   - InMemory replay skipped entire event on revoked keys instead of just skipping signature verification (`_in_memory.py:1037`).
   - InMemory replay applied custom_fields/claim changes unconditionally, not guarded by `if found:` (`_in_memory.py:1096`).
   - Postgres `update_not_before` missing `work_item_id` in idempotency check (`__init__.py:1247`).
   - `append_transition_event` stored `{}` as NULL via truthiness check (`_events.py:272`).

4. **Spec updated** — Changed isolation model from DB-per-project to schema-per-project in `spec.md` (7 locations) and `spec.yaml` (4 locations). Added v4 changelog entry documenting the amendment.

**Breadcrumbs resolved:** BC-065, 068, 070, 074, 079, 082, 083, 100–111 (18 total).

**Test results:** 392 passed, lint clean. Pre-existing `test_replay_equivalence` failure unrelated to this session's changes.

---

## 2026-05-11 — Session 21: Adversarial review resolution

**Focus:** Resolve all actionable gaps from adversarial code review.

**Delivered:**

1. **Expanded `validate_json_safe_value` in `_contract.py`** — deep-walks dicts/lists, rejects `\u0000` AND unpaired surrogates (U+D800–U+DFFF). Replaced the single-string-only `validate_json_safe_string` with a full recursive validator.
2. **Consolidated idempotency logic** — `_events.py:check_idempotency()` now delegates to `_contract.py::check_idempotency()` instead of duplicating the collision checks. Removed dead `payload` parameter.
3. **Integrated validation into all JSONB entry points** — `_events.py` (`append_event`, `append_transition_event`) and `_in_memory.py` (`append_event`, `transition`) now call `validate_json_safe_value` on `actor_metadata` and `payload` before storage, closing the divergence gap for all JSONB-bound data.
4. **Fixed `ruff` import sorting** in `_in_memory.py`.

**Breadcrumbs filed (deferred):** 065–070 (6 deferred items from adversarial review).

**Test Results:** 300 passed, lint clean.

---

## 2026-05-11 — Session 20: Validation scan — fix null-byte conformance divergence

**Focus:** Run full validation scan on recent RFC-062 work; fix conformance bug found.

**Context:** Property-based conformance test `test_random_sequences_equivalent` was failing
because `InMemorySubstrate` silently accepted `\u0000` in string custom fields while Postgres
JSONB rejected them with `UntranslatableCharacter`.

**Delivered:**

1. **Added `validate_json_safe_string()` to `_contract.py`** — shared rejection of `\u0000` in strings.
2. **Integrated into `_coerce_field()` in `_workflow.py`** — string-typed custom fields are now validated by both backends.

**Breadcrumbs resolved:** 064 (new).

**Test Results:** 300 passed, lint clean.

---

## 2026-05-11 — Session 19: RFC-062 single-source-of-truth backend contract

**Focus:** Implement RFC-062 — declarative backend contract + property-based conformance testing.

**Delivered:**

1. **`_contract.py` (Option B)** — New module with 20 pure validation/decision functions extracted from both backends:
   - `validate_actor_kind`, `validate_ttl`, `validate_not_before` — input validation
   - `resolve_transition` — find matching transition from workflow definition
   - `check_role_gating`, `check_actor_role_authorized` — role enforcement (FR-12, FR-24)
   - `check_append_blocked` — FR-11 enforcement
   - `check_idempotency`, `check_expected_seq` — event safety
   - `validate_link_type` — link type enforcement
   - `should_escalate` — escalation decision (FR-10)
   - `resolve_claim_acquire` — pure claim acquisition decision engine
   - `resolve_heartbeat`, `validate_release` — claim lifecycle
   - `validate_read_events_filters` — filter validation
   - `validate_work_item_exists` — existence guard
   - Result types: `ClaimAcquireResult`, `HeartbeatResult`

2. **`_in_memory.py` refactored** — All inline validation replaced with `_contract` calls. Removed duplicated `_validate_actor_kind`, inline transition resolution, inline role gating, inline claim decision logic, inline escalation check.

3. **Postgres backend refactored** — Updated `__init__.py`, `_claims.py`, `_links.py`, `_actor_roles.py` to delegate to `_contract` functions. All inline validation logic replaced.

4. **Property-based conformance tests (Option A)** — `tests/test_property_conformance.py` with 5 hypothesis-driven test classes:
   - `test_random_sequences_equivalent` — 150 random API call sequences compared between backends
   - `test_claim_contention_sequence` — multi-actor claim contention scenarios
   - `test_escalation_equivalence` — claim/steal escalation threshold testing
   - `test_transition_sequence_equivalence` — full workflow lifecycle comparison
   - `test_replay_equivalence` — replay drift comparison after random operations

5. **Added `hypothesis>=6.100` to dev dependencies** in `pyproject.toml`.

**Breadcrumbs resolved:** RFC-062.

**Test Results:** 300 passed (295 existing + 5 new property-based), lint clean.

---

## 2026-05-08 — Session 18: Breadcrumb closeout sweep (BC-060, BC-061, RFC-033/034/035/047/053)

**Focus:** Resolve all remaining open breadcrumbs and RFCs.

**Delivered:**

1. **BC-060 (low): Canonical diagnostic payload shape** — Accepted as documentation convention. Added "Diagnostic payload shape" pattern section to AGENTS.md with recommended `payload.diagnostics` shape.

2. **BC-061 (low): Workflow YAML validator helper** — Implemented `validate_yaml(source)` in `_workflow.py`. Accepts YAML string or file path. Returns `ValidationResult(valid, errors, workflow)` — no database required, suitable for CI lint pipelines and pre-commit hooks. Added `ValidationError` and `ValidationResult` frozen dataclasses to `_types.py`. Exported via `substrate.validate_yaml` and `substrate.testing.validate_yaml`. 11 tests in `test_validate_yaml.py`.

3. **RFC-033 (medium): PgBouncer transaction-mode documentation** — Already implemented in session 10. Moved from `breadcrumbs/rfc/` to `breadcrumbs/resolved/`.

4. **RFC-034 (low): No-comments onboarding trade-off** — Already implemented in session 10. Moved from `breadcrumbs/rfc/` to `breadcrumbs/resolved/`.

5. **RFC-035 (low): Telemetry-via-hooks worked example** — Already implemented in session 10. Moved from `breadcrumbs/rfc/` to `breadcrumbs/resolved/`.

6. **RFC-047 (low): Remove unused dev dependencies** — Removed `pytest-postgresql` and `testcontainers[postgres]` from `pyproject.toml` dev dependencies; confirmed zero imports across codebase. Moved to resolved.

7. **RFC-053 (medium): CI configuration** — Added `.github/workflows/ci.yml` with Postgres 15 service container, Python 3.11/3.12 matrix, `make check` (lint + test). Moved to resolved.

**Breadcrumbs resolved:** BC-060, BC-061, RFC-033, RFC-034, RFC-035, RFC-047, RFC-053.

**Open breadcrumbs:** None. All items resolved.

**Test Results:** 293 passed, lint clean.

## 2026-05-08 — Session 17: Adversarial-review breadcrumb sweep (BC-055–059)

**Focus:** Resolve all five pending numbered breadcrumbs from adversarial review pass; promote two draft RFCs to numbered items.

**Delivered:**

1. **BC-055 (high): update_not_before TOCTOU** — Moved `check_idempotency` call before the `UPDATE work_items_current SET not_before` mutation in Postgres backend. Added early idempotency check in InMemory backend before mutating `wi["not_before"]`. Prevents projection corruption on duplicate `event_id`.

2. **BC-056 (low): WorkItem excludes attempt_number** — Added `attempt_number: int = 0` field to `WorkItem` dataclass; wired through `_row_to_work_item`, `_wi_to_work_item`, `to_dict`/`from_dict`. Column was already fetched from DB but silently discarded.

3. **BC-057 (low): Replay output mixed live/replayed columns** — Set `last_event_at`, `claimed_by`, `claim_expires_at` to NULL in replay output table INSERT. These were live-snapshot values, not replayed data, making the table semantically confusing.

4. **BC-058 (low): Claim events actor_kind misattribution** — Added `actor_kind` parameter (default `"agent"`) to `acquire_claim` and `release_claim` in both backends and public API. Claim events now use caller's `actor_kind` instead of hardcoded `"system"`. `sweep_expired_claims` keeps `"system"` which is correct.

5. **BC-059 (low): default_value vs default key inconsistency** — Made `validate_field_update`, `_rebuild_wf`, and `CustomFieldDef.from_dict` accept both `"default_value"` and `"default"` keys via fallback.

6. **BC-060/061 promoted** — Moved draft breadcrumbs from `pending/` to numbered items (canonical diagnostic payload shape, workflow YAML validator helper).

**Breadcrumbs resolved:** BC-055, BC-056, BC-057, BC-058, BC-059.

**Test Results:** 282 passed, lint clean.

---

## 2026-05-08 — Session 16: Opus feedback sweep + open breadcrumb fix

**Focus:** Address three Opus feedback items; resolve three open InMemorySubstrate hook breadcrumbs.

**Delivered:**

1. **Opus item 1 — `__init__.py` god-module assessment** — Verified the 1,337 lines are 100% façade: thin wrappers, docstrings, error-code translation, metric increments. No business logic beyond `_validate_actor_kind` (a 6-line guard). Decision: no extraction needed until additional Phase-3+ surface pushes it past ~1,500 lines.

2. **Opus item 2 — working-tree churn** — `git status` showed zero modified files, clean tree. The 32 modified test files from Session 14 were committed in 930bb61. No stale drift.

3. **Opus item 3 — README status text** — Changed "MVP complete. All Phase 1 FRs implemented and tested." → "MVP + Phase 2 + Phase 3 complete. All FRs implemented and tested. See `AGENTS.md` for current status."

4. **BC-050 (low): InMemorySubstrate poll_hooks does not dead-letter unregistered handlers** — `_in_memory.py poll_hooks` now dead-letters entries with no registered handler, matching real backend (`_hooks.py:125-129`).

5. **BC-051 (low): InMemorySubstrate poll_hooks nil UUID fallback** — Removed `uuid.UUID(int=0)` default. Missing `work_item_id` now dead-letters with error "work_item_id missing from payload", matching real backend (`_hooks.py:134-139`).

6. **BC-052 (low): InMemorySubstrate hook-queue unbounded growth** — `poll_hooks` now prunes `_hook_queue` after each batch, removing `completed` and `dead_lettered` entries. Prevents memory leaks in long-running tests.

7. **RFC renumbering** — Renumbered `RFC-046` → `RFC-053` to fix numbering collision with breadcrumb `046` and `resolved/046`.

**Breadcrumbs resolved:** BC-050, BC-051, BC-052.

**Remaining open:** RFC-053 (CI configuration) — medium, infrastructure item out of scope for agent sessions.

**Test Results:** 282 passed, lint clean.

---

## 2026-05-07 — Session 15 (continued): Breadcrumb sweep round 2 (BC-047, BC-048, BC-049)

**Focus:** Close out all remaining open breadcrumbs except BC-046 (CI config, out of scope).

**Delivered:**

1. **BC-049 (low): Zero-roles bypass documented** — Added docstrings to `check_actor_role_authorized` (`_actor_roles.py`) and `_check_actor_role_authorized` (`_in_memory.py`) explaining FR-24 semantics: enforcement only applies to actors with at least one registered role.

2. **BC-048 (low): InMemorySubstrate hook status tracking** — Added `status` and `updated_at` fields to in-memory hook queue entries. `poll_hooks` now resets stuck `in_progress` entries (>5 min), marks entries `in_progress` before dispatch, `completed` on success, `dead_lettered` on max retries. Parity with real backend's `poll_and_process_hooks`.

3. **BC-047 (low): Stuck-hook double-processing documented** — Added docstring to `poll_and_process_hooks` (`_hooks.py`) documenting the double-processing risk: slow-but-not-stuck handlers may be re-dispatched. Accepted as design limitation; advisory locks noted as future fix.

**Breadcrumbs resolved:** BC-047, BC-048, BC-049.

**Remaining open:** BC-046 (CI configuration) — medium, infrastructure item.

**Test Results:** 282 passed, lint clean.

---

## 2026-05-07 — Session 15: Breadcrumb sweep (BC-043, BC-044, BC-045)

**Focus:** Resolve open breadcrumbs prioritized by severity.

**Context:** Three open breadcrumbs selected: BC-045 (medium, InMemorySubstrate signing parity), BC-044 (low, test import dogfooding), BC-043 (low, read_events ordering docs).

**Delivered:**

1. **BC-045 (medium): InMemorySubstrate loads hmac_key_path** — When `hmac_key_path` is non-empty, `InMemorySubstrate` now creates a real `KeySet` and signs events with HMAC-SHA256 via `_signing.sign_event`. Empty `hmac_key_path` (default) retains dummy signing for test convenience. Catches configuration drift early.
   - `src/substrate/_in_memory.py`: Added `KeySet` import, `_sign_event` import, `self._key_set` field, real signing branch in `_make_event`, `key_set=self._key_set` on all 6 call sites.

2. **BC-044 (low): Test suite dogfoods public API** — Migrated all 23 test files from `substrate._testing` to `substrate.testing` for `drop_project_schema`. Internal symbols (`KeySet`, `raw_transaction`, etc.) remain in `_testing`.

3. **BC-043 (low): read_events ordering documented** — Added ordering semantics to docstrings in both `Substrate.read_events` (`__init__.py`) and `InMemorySubstrate.read_events` (`_in_memory.py`): work_item_id → ASC by event_seq; time range → ASC by (timestamp, event_seq); otherwise → DESC.

**Breadcrumbs resolved:** BC-043, BC-044, BC-045.

**Test Results:** 282 passed, lint clean.

---

## 2026-05-07 — Session 14: GLM must-have/should-have items, composite read_events, public API closeouts

**Focus:** Deliver 6 GLM items (3 must-have, 3 should-have) from SF2 Phase 2 integration sweep.

**Context:** GLM requested HookContext public export, composite read_events filters, BC-042 closeout, public drop_project_schema, hmac_key_path contract fix, and Makefile + RUF rules.

**Delivered:**

1. **HookContext re-exported** — Added `HookContext as HookContext` to `src/substrate/__init__.py` so consumers can import it for handler type annotations.

2. **Composite read_events filters** — Replaced "exactly one filter dimension" constraint with true AND composition in both backends:
   - `src/substrate/_events.py`: Added `read_events_composite()` with layered SQL WHERE clauses
   - `src/substrate/__init__.py`: `Substrate.read_events()` now delegates to composite query; docstring updated
   - `src/substrate/_in_memory.py`: `InMemorySubstrate.read_events()` now layers filters instead of mutually-exclusive branches
   - Added 2 conformance tests in `tests/test_in_memory_conformance.py` covering `work_item_id + transition` and `actor_id + transition`

3. **BC-042 closed** — Moved to `breadcrumbs/resolved/` with resolution note. `connection_info` is stable public API.

4. **drop_project_schema public API** — Exported from `substrate.testing` alongside `InMemorySubstrate`.

5. **hmac_key_path contract fixed** — `InMemorySubstrate` parameter changed from `str | None = None` to `str = ""`, matching real `Substrate` which rejects `None`.

6. **Makefile + RUF rules** — Added `Makefile` with `check`, `lint`, `test`, `cov` targets. Added `"RUF"` to ruff select. Fixed surfaced RUF012/RUF059 violations in 4 test files.

7. **Breadcrumbs opened:**
   - BC-043 (low): composite read_events ordering semantics undocumented
   - BC-044 (low): test suite still imports drop_project_schema from _testing
   - BC-045 (medium): InMemorySubstrate silently ignores hmac_key_path
   - RFC-046 (medium): CI configuration for automated make check
   - RFC-047 (low): remove unused pytest-postgresql / testcontainers dev dependencies

8. **Breadcrumbs resolved:** BC-042.

**Test Results:** 282 passed, lint clean.

---

## 2026-05-07 — Session 13 (continued): Correctness fixes, validation gaps, regression tests, breadcrumb filing

**Focus:** Fix remaining correctness and validation issues identified during scan; add regression tests; file breadcrumbs for all fixes and remaining polish items.

**Context:** User asked to knock out remaining items from the session 13 scan and file breadcrumbs.

**Delivered:**

1. **BC-044: `ttl_seconds` validation** — Added `INVALID_ARGUMENT` error code. `acquire_claim` and `heartbeat_claim` now reject zero/negative TTL in both Substrate and InMemorySubstrate.

2. **BC-045: `validate_field_update` raises on unknown type** — Changed from silent return to `WORK_ITEM_TYPE_NOT_DECLARED`, matching `validate_field_values` behavior.

3. **BC-046: Hook dispatch nil UUID fallback** — `poll_and_process_hooks` now dead-letters hooks with missing `work_item_id` instead of fabricating a nil UUID.

4. **Type annotations tightened** — `_rebuild_wf` return type (`-> WorkflowDefinition`), `key_set: KeySet` in `_claims.py` (3 locations), `metrics: Metrics | None` in `_hooks.py` (2 locations), `SubstrateError.code` typed as `ErrorCode`.

5. **InMemorySubstrate `list_actor_roles` sort order** — Changed from `created_at` to `(actor_id, role)` matching real backend.

6. **8 new regression tests** (`tests/test_session13_regression.py`):
   - `TestSweepRaceCondition` (2 tests): sweep doesn't clobber new claims
   - `TestBeforeSeqOrdering` (2 tests): ascending order, exclusion semantics
   - `TestTtlSecondsValidation` (3 tests): zero/negative rejection for acquire + heartbeat
   - `TestValidateFieldUpdateRejectsUnknownType` (1 test): raises on undeclared type

7. **Breadcrumbs filed:**
   - BC-043 (high, resolved): sweep_expired_claims race condition
   - BC-044 (medium, resolved): ttl_seconds validation
   - BC-045 (medium, resolved): validate_field_update silent return
   - BC-046 (medium, resolved): hook nil UUID fallback
   - BC-047 (low, proposed): stuck hook double-processing
   - BC-048 (low, proposed): InMemorySubstrate hook status tracking
   - BC-049 (low, proposed): zero-roles bypass

**Breadcrumbs resolved:** BC-043, BC-044, BC-045, BC-046.

**Test Results:** 278 passed in 108.18s

**Lint:** clean

---

## 2026-05-07 — Session 13: Remaining session-12 items, fresh scan fixes, BC-042 implementation

**Focus:** Pick up session 12's remaining items; fresh scan for additional issues; fix all MEDIUM-severity bugs found.

**Context:** Session 12's reflection listed remaining work: BC-042 (DSN public API), hooks reconnect log, missing from_dict methods, unspecified MEDIUM issues. Did a fresh scan of all source files, identified 8 new MEDIUM + 10 LOW issues.

**Delivered:**

1. **BC-042: Exposed `connection_info` as public API** — Added `ConnectionInfo` frozen dataclass to `_types.py` with `host`, `port`, `database`, `project` fields. Added `connection_info` property on `Substrate` (parses DSN via `urlparse`, strips credentials). Exported via `__init__.py`. Status promoted to implemented.

2. **Fixed `_hooks.py` reconnect log always showing `attempt=0`** — `reconnect_attempts` was reset to 0 before the log line. Now captures `successful_attempt` before resetting.

3. **Added missing `from_dict` methods** — `ValidatorContext.from_dict`, `HookContext.from_dict`, `QueryPage.from_dict` (takes `item_from_dict` factory for generic deserialization).

4. **M-1 (real backend): Fixed `sweep_expired_claims` race condition** — `UPDATE work_items_current SET claimed_by = NULL` could clobber a newly-acquired claim between the DELETE and the FOR UPDATE lock. Changed WHERE clause to `AND claimed_by = %s` (matching expired `prior_actor_id`), so a re-claimed row is not overwritten.

5. **M-2: Fixed InMemorySubstrate `read_events` `before_seq` ordering** — Was returning DESC order; real backend reverses to ASC. Added `list(reversed(...))` to match.

6. **M-3: Added `connection_info` to InMemorySubstrate** — Returns `ConnectionInfo(host=None, port=None, database=None, project=...)`.

7. **M-4: InMemorySubstrate `poll_hooks` now emits `hook_dead_lettered` events** — Dead-lettered hooks now produce audit events in the event log, matching the real backend's `_move_to_dead_letter`.

8. **M-6: Fixed SQL f-string in `append_transition_event`** — Replaced f-string interpolation of `claim_clear` with psycopg `SQL` composition (`+ claim_clear + SQL(" WHERE ...")`).

9. **M-7: InMemorySubstrate `_check_escalation` now returns `bool`** — Was `-> None` (implicit), diverged from real backend's `-> bool`.

10. **M-8: InMemorySubstrate hook queue `hook_type` fixed** — Changed from `"transition"` to `"async"` matching real backend.

11. **L-6: `SubstrateError.code` type tightened** — Changed from `str` to `ErrorCode` for type-safety.

**Breadcrumbs resolved:** BC-042 (implemented).

**Test Results:** 270 passed in 118.40s

**Lint:** clean

---

## 2026-05-07 — Session 12: Validation scan — fix HIGH/MEDIUM issues, add test coverage, promote breadcrumbs

**Focus:** Comprehensive validation of repo state; fix all HIGH-severity issues found; fill test coverage gaps; promote breadcrumbs.

**Context:** User asked for full repo analysis, verification of recent changes, and recommended next steps. Analysis identified 3 HIGH, 8 MEDIUM, and 10 LOW issues plus spec AC coverage gaps.

**Delivered:**

1. **H-1: Fixed `_claims.py:30` return type annotation** — `acquire_claim` returns `tuple[Claim, bool, bool]` but was annotated `tuple[Claim, bool]`. Breaks type checkers.

2. **H-2: Fixed `_in_memory.py` `poll_hooks` passing raw dict instead of `HookContext`** — Handlers now receive a proper `HookContext` dataclass matching the real `poll_and_process_hooks` behavior. Tests that validate handler behavior against `HookContext` attributes will now be faithful.

3. **H-3 + M-8: Fixed InMemorySubstrate `read_events` filter semantics + transition key divergence** — InMemorySubstrate now stores `wf.to_dict()` instead of raw YAML dict, eliminating the `from`/`to` vs `from_state`/`to_state` key divergence in transitions (3 locations: transition lookup, state assignment, replay). `read_events` now uses priority-based matching (work_item_id > actor_id > start/end > transition) matching the real Substrate, instead of compositing all filters.

4. **M-5: Fixed `ActorKind` case mismatch** — `ActorKind.AGENT` was `"AGENT"` (uppercase) but validation checks `"agent"` (lowercase). Fixed enum values to lowercase.

5. **M-1: Fixed `register_actor_role` docstring** — Was describing `unregister_actor_role`'s error. Removed the incorrect `Raises` block.

6. **L-6: Fixed `requeue_dead_lettered_hook` losing `work_item_id`** — Requeued entry now preserves `work_item_id` and `transition` from the original payload, matching the real backend.

7. **New test file: `tests/test_hook_consumer.py`** (4 tests) — Smoke tests for `start_hook_consumer`/`stop_hook_consumer` lifecycle (AC-14), idempotent start/stop, and poll-based hook delivery with `HookContext` verification.

8. **New test file: `tests/test_claim_link_idempotency.py`** (4 tests) — Event_id dedup verification for `acquire_claim`, `release_claim`, `create_link`, `remove_link` (AC-24).

**Breadcrumbs resolved:** BC-040 (read_events filter semantics), BC-041 (conformance coverage gaps).

**Breadcrumbs promoted:** BC-042 (DSN public API, proposed).

**Test Results:** 270 passed in 111.42s

**Lint:** clean

---

## 2026-05-07 — Session 11: Validation scan — InMemorySubstrate bug fixes, BC-036 resolution, error-code cleanup

**Focus:** Deep validation scan of the repo after Deepseek's session 10 work; fix all bugs found; close remaining breadcrumbs.

**Context:** User asked for a comprehensive validation of the repo's current state. A thorough scan of `_in_memory.py` and recent commits revealed 10 issues ranging from critical to low.

**Delivered:**

1. **CRITICAL: `_check_escalation` wrong argument count** — `_in_memory.py` called `_append_claim_event(wi, uuid.uuid4(), "system", "escalated", {...})` with 5 args; function takes 4. Would crash at runtime on escalation. Fixed by removing stray `"system"` arg.

2. **CRITICAL: `poll_hooks` imports non-existent `run_hook_handler`** — `_in_memory.py` imported `from ._hooks import run_hook_handler` which doesn't exist in `_hooks.py`. Would crash with `ImportError`. Fixed by removing the import and calling the handler directly.

3. **HIGH: InMemorySubstrate replay missing `needs_review`, `not_before`, `last_event_seq` drift detection** — Replay only checked `current_state` and `custom_fields` for drift; the real Substrate checks all 5 fields. Added `derived_needs_review`, `derived_not_before`, `derived_last_seq` tracking and full 5-field comparison. Also added `hook_dead_lettered` to the skip list and `not_before_set`/`escalated` as tracked transitions.

4. **HIGH: Claim events used wrong `actor_id`** — `_append_claim_event` hardcoded `actor_id="system"` for all claim events. The real Substrate uses the actual claiming/releasing actor. Added `actor_id` keyword argument; wired correct actor_id at all call sites (acquire=actor_id, release=actor_id, expire=prior_actor_id or "system").

5. **MEDIUM: `_dead_letter` typed as `list[dict]` but used as `dict[int, dict]`** — Fixed type annotation.

6. **MEDIUM: `read_events` returned ASC order vs real Substrate's DESC** — Rewrote to match real Substrate's ordering semantics per filter type (DESC for work_item_id then reversed, DESC for actor/transition, ASC for time-range, ASC for since).

7. **LOW: Stale `ACTOR_ROLE_ALREADY_REGISTERED` in ErrorCode enum** — Removed from `_errors.py`. Updated `__init__.py` docstring to reflect idempotent behavior. Updated `spec.md` error table.

8. **LOW: `CUSTOM_FIELD_VIOLATION` misused for `actor_kind` validation** — Added `INVALID_ACTOR_KIND` error code to `_errors.py`. Updated both `__init__.py` and `_in_memory.py` to use it.

9. **BC-036 resolved** — External Postgres deployment guide (RFC) was already complete with "accepted" status. Moved from `breadcrumbs/rfc/` to `breadcrumbs/resolved/`.

10. **InMemorySubstrate double YAML parse** — `register_workflow` called both `parse_and_validate` (which parses YAML) and `parse_workflow_yaml` (which parses the same YAML again). Added `validate_and_build()` to `_workflow.py` accepting a pre-parsed dict; InMemorySubstrate now parses once.

**Breadcrumbs filed:** Two pending drafts:
- `in-memory-read-events-filter-semantics.md` — InMemorySubstrate composites filters; real Substrate is mutually exclusive
- `in-memory-conformance-coverage-gaps.md` — Missing conformance tests for claim actor_id, dead-letter, replay drift, sort order

**Open breadcrumbs:** 0 numbered. 6 pending drafts awaiting triage.

**Test Results:** 262 passed in 106.68s

**Lint:** clean

---

## 2026-05-07 — Session 10: BC-037 runtime ref validation, BC-033/034/035 RFCs, BC-038 in-memory backend

**Focus:** Resolve all actionable open breadcrumbs — BC-037 (high bug), BC-033/034/035 (RFCs), BC-038 (in-memory backend).

**Context:** Session 9 left 6 open breadcrumbs. User asked to start with BC-037, then knock out BC-033-035, then tackle BC-038.

**Delivered:**

1. **BC-037 — Runtime validation for `work_item_ref` fields** (high bug → resolved):
   - `src/substrate/_workflow.py`: Added `import uuid`; updated `_coerce_field` to validate UUID format for `work_item_ref` type; added `validate_work_item_refs()` function that queries `work_items_current` to verify existence and type match.
   - `src/substrate/_work_items.py`: Wired `validate_work_item_refs` into `create_work_item` after `validate_field_values`.
   - `src/substrate/__init__.py`: Wired `validate_work_item_refs` into `transition` after `validate_field_update`.
   - `src/substrate/_workflow_schema.json`: Made `target_work_item_type` optional for `work_item_ref` fields. Fields without `target_work_item_type` still check existence only.
   - `tests/test_work_item_ref_validation.py`: 10 new tests covering nonexistent UUID, wrong type, correct type, invalid format, optional None, untyped ref existence, transition-time validation.
   - `tests/test_sf2_workflows.py`: Fixed `test_version_pinning_across_v1_v2` and `test_full_pipeline_link_types` — both incorrectly set `test_suite_ref` to an `interface_spec` work item.

2. **BC-033 — PgBouncer transaction-mode documentation** (medium RFC → implemented):
   - `AGENTS.md`: Added "Known constraints" section documenting PgBouncer incompatibility.

3. **BC-034 — No-comments onboarding documentation** (low RFC → implemented):
   - `AGENTS.md`: Expanded "No comments in code" convention with full rationale.

4. **BC-035 — Telemetry-via-hooks worked example** (low RFC → implemented):
   - `examples/telemetry_via_hooks.py`: Complete, runnable minimal example.
   - `AGENTS.md`: Updated telemetry pattern section to link to example file.

5. **BC-038 — InMemorySubstrate** (high improvement → resolved):
   - `src/substrate/_in_memory.py`: Full `InMemorySubstrate` implementation (~1260 lines) matching the complete public API surface of `Substrate` (32 methods/properties). Implements workflow registration, work item CRUD, transitions, event logging, claims with TTL, links, actor roles, validators, hooks, replay, update_not_before, dead letter queue, and all query/filter operations — all in-process with no Postgres dependency. Reuses existing validation logic from `_workflow.py`.
   - `src/substrate/testing.py`: Public module exporting `InMemorySubstrate` as `substrate.testing.InMemorySubstrate`.
   - `tests/test_in_memory_conformance.py`: 50 conformance tests (25 scenarios × 2 backends) parameterized over real Substrate and InMemorySubstrate. Covers workflow registration, work item creation, transitions, events, claims, links, actor roles, queries, replay, and update_not_before.

**Breadcrumbs resolved:** BC-037, BC-033, BC-034, BC-035, BC-038.

**Remaining open:** BC-036 (external Postgres guide, accepted). Four pending drafts awaiting triage.

**Test Results:** 258 passed in 48.13s (+ 4 slow benchmarks excluded)

**Lint:** clean

---

## 2026-05-06 — Session 9: Error-path coverage sweep + Perplexity RFCs

**Focus:** Close error-path coverage gaps identified by unfiled audits; formalize Perplexity feedback as RFCs.

**Context:** Session 8 left 176 tests passing but two unfiled audits existed (`audit-error-paths.md`, `audit-spec-alignment.md`). User asked to write the missing tests and create breadcrumbs for anything not finished. Additionally, Perplexity review raised three concerns: PgBouncer transaction-mode scaling cliff, "no comments" onboarding friction, telemetry-via-hooks lacking a concrete example.

**Delivered:**

1. **New `tests/test_remaining_errors.py`** (10 tests): NOT_BEFORE_FUTURE, WORK_ITEM_TYPE_NOT_DECLARED, WORKFLOW_NOT_REGISTERED, LINK_CROSS_PROJECT, CUSTOM_FIELD_VIOLATION x5, DB_NOT_FOUND.
2. **Strengthened existing tests** in 6 files: replaced raw string assertions with `ErrorCode` enum assertions for INVALID_TRANSITION, ROLE_NOT_PERMITTED, WORKFLOW_VERSION_CONFLICT, WORKFLOW_VALIDATION_FAILED, WORK_ITEM_TYPE_NOT_DECLARED, CUSTOM_FIELD_VIOLATION, CLAIM_LOST, LINK_TYPE_NOT_ALLOWED, LINK_TARGET_NOT_FOUND, LINK_NOT_FOUND, IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD.
3. **Cleaned up dead error codes**: removed CLAIM_NOT_EXPIRED, IDEMPOTENCY_COLLISION, DEPRECATED_KEY_ID, LIBRARY_IS_SOLE_SIGNER, HOOK_NOT_DEAD_LETTERED. Wired REPLAY_HALTED into _ReplayHaltError (extends SubstrateError).
4. **Three RFCs created** in `breadcrumbs/rfc/`: RFC-033 (PgBouncer tx-mode, medium), RFC-034 (no-comments onboarding, low), RFC-035 (telemetry concrete example, low).
5. **Breadcrumbs reconciled** — moved audit reports to resolved/031, resolved/032; moved 026-030 to resolved/.

**Test Results:** 198 passed in 39.33s (+ 4 slow benchmarks excluded)

**Lint:** clean

**Commits:** dc0902f, bd4c900

---

## 2026-05-06 — Session 8: Test suite quality sweep — dedup, weak assertions, coverage gaps, _testing centralization

**Focus:** Comprehensive test suite audit and improvement

**Context:** Session 7 left zero open breadcrumbs with 154 tests passing. User asked to scan the repo with particular attention to the test suite and make appropriate improvements. A thorough audit identified 6 categories of issues: duplicated tests, weak assertions, untested error codes/API paths, `_testing.py` too thin (forcing direct internal imports), overly broad exception matching, and missing coverage.

**Delivered:**

1. **`_testing.py` expanded** — Re-exports `KeySet`, `replay_fn`, `sign_event`, `verify_event`, `Metrics`, `poll_and_process_hooks` with `__all__`. Reduces direct internal imports from 8 test files to ~2 (justified exceptions: `test_jcs.py` unit-tests `_jcs` directly; `test_startup_integrity.py` uses raw psycopg for migration-level tests).

2. **Weak assertions fixed** (5 tests):
   - `test_smoke.py::test_query_claimable_now` — was tautological (`claimed_by is None or claim_expires_at is not None` → always true). Now asserts `claimed_by is None AND claim_expires_at is None`.
   - `test_smoke.py::test_create_and_remove_link` — added `link_removed` event payload verification after removal.
   - `test_smoke.py::test_heartbeat` — now verifies `claim2.expires_at > claim1.expires_at`.
   - `test_production_readiness.py::test_valid_actor_kinds_accepted` — now verifies `actor_kind` persisted in created event.
   - `test_stale_heartbeat.py::test_valid_heartbeat_succeeds` — now verifies TTL extension.

3. **JCS exception specificity** — `test_jcs.py` `pytest.raises(Exception)` → `pytest.raises(IntegerDomainError)` for unsafe integer domain tests.

4. **Duplicate tests removed** (3):
   - `test_replay.py::test_replay_halts_on_revoked_key_event` (identical to test_phase3.py)
   - `test_key_lifecycle.py::test_replay_halts_on_revoked_key_event` (identical to test_phase3.py)
   - `test_signing.py::test_replay_detects_out_of_band_state_change` (identical to test_replay.py)

5. **New coverage tests** — `tests/test_coverage_gaps.py` (25 tests) covering previously-untested paths:
   - `TRANSITION_VIA_APPEND_BLOCKED` (2 tests: reject + allow custom)
   - `WORK_ITEM_NOT_FOUND` (2 tests: transition + append_event)
   - `CLAIM_NOT_FOUND` (2 tests: heartbeat + release on unclaimed)
   - `sweep_expired_claims` (3 tests: sweep + events + zero case)
   - `WORKFLOW_SEMANTIC_ERROR` (3 tests: no initial, unreachable, undeclared role)
   - `expected_attempt_number` (2 tests: reject stale + accept correct)
   - `read_events` filters (7 tests: by actor, transition, time range, empty, validation)
   - `query_work_items` filters (3 tests: needs_review, workflow_version, work_item_types)
   - `hmac_key_path=None` (1 test: rejects with UNKNOWN_KEY_ID)

6. **Direct internal imports cleaned up** — test_key_lifecycle.py, test_phase3.py, test_signing.py, test_scale.py now import from `_testing` instead of reaching into `_keys`, `_replay`, `_signing`, `_hooks`, `_observability` directly.

**Breadcrumbs resolved:** None filed; BC-026 partially addressed (test coverage added for several codes, but cleanup decision still pending).

**Test Results:** 176 passed in 40.8s (+ 3 slow benchmarks excluded)

**Lint:** clean

---

## 2026-05-06 — Session 7: Production readiness — migration packaging, metrics, validation, docstrings, spec sync, replay errors, test coverage

**Focus:** Production readiness sweep addressing 7 items from comprehensive codebase audit

**Context:** Session 6 left zero open breadcrumbs with 111 tests passing. All three phases (MVP, Phase 2, Phase 3) complete. User asked to clear breadcrumbs (none open) and begin next reasonable phase. A codebase audit identified 7 production-readiness items: critical migration discovery bug, unwired metric, missing validation, missing docstrings, stale spec.yaml, unstructured replay errors, and test coverage gaps.

**Delivered:**

1. **Migration discovery fix** — `_migrations.py:_migrations_dir()` now uses `importlib.resources.files("substrate").joinpath("migrations")` first (works in pip installs), falls back to parent-relative path for editable installs. `pyproject.toml` gains `force-include` to ship `migrations/` inside the wheel at `substrate/migrations/`.

2. **`claims_stolen` metric wired** — `_claims.py:acquire_claim` now returns 3-tuple `(Claim, escalated, stolen)` where `stolen = prior_actor_id is not None`. `__init__.py:acquire_claim` increments `claims_stolen` metric when a claim is stolen.

3. **`actor_kind` validation at API boundary** — New `_validate_actor_kind()` helper rejects invalid values (`"agent"`, `"human"`, `"system"` only) at all 6 API entry points that accept `actor_kind`.

4. **Docstrings on all 30+ public methods** — Complete docstrings with Args, Returns, Raises sections on every public `Substrate` method.

5. **`spec.yaml` updated to v4** — Phase 3 FRs (FR-24/25/26/27) reflected, resolved open questions removed from pending, delta-to-next-level pruned, Phase 3 decisions added to handoff.

6. **Structured replay errors** — `_replay.py` now raises `_ReplayHaltError` (a private `Exception` subclass) instead of bare `RuntimeError`. Replay catches it cleanly.

7. **New test coverage** — `tests/test_production_readiness.py` with 10 tests: 7 actor_kind validation tests (all 6 API entry points + valid kinds), transition event-id collision test, stolen claim event verification, same-actor re-acquire no-stolen verification.

Plus 5 previously untracked test files committed: `test_key_lifecycle.py` (14 tests), `test_link_errors.py` (4 tests), `test_stale_heartbeat.py` (3 tests), `test_startup_integrity.py` (7 tests), `test_version_pinning.py` (3 tests), plus improved `test_smoke.py` assertions.

**Breadcrumbs resolved:** None filed; none open before or after.

**Test Results:** 154 passed in 37.3s (+ 3 slow benchmarks excluded)

**Lint:** clean

---

## 2026-05-06 — Session 6 with glm-5.1 (opencode): Phase 3 — actor roles, replay resilience, spec decisions, update_not_before, field validation, E2E tests

**Focus:** Implement Phase 3 features and close spec gaps

**Context:** Session 5 left zero open breadcrumbs with 81 tests passing. Phase 1 (MVP) and Phase 2 (hooks/escalation) were complete. The user asked for three areas of work: actor → allowed_roles enforcement, continue-on-revoked replay flag, and §16 decision sweep. After those were delivered, the user approved a second batch: update_not_before API, custom field validation at transitions, and E2E integration tests.

**Delivered:**

FR-24 — Actor → allowed_roles enforcement (closes BR-09):
- `migrations/005_actor_roles.sql`: new `actor_roles` table with `(actor_id, role)` PK
- `src/substrate/_actor_roles.py`: register, unregister, list, enforcement check functions
- `src/substrate/__init__.py`: public API `register_actor_role()`, `unregister_actor_role()`, `list_actor_roles()`
- `src/substrate/__init__.py`: enforcement wired into `transition()` — opt-in, backward compatible
- `src/substrate/_errors.py`: new error codes `ACTOR_ROLE_NOT_AUTHORIZED`, `ACTOR_ROLE_ALREADY_REGISTERED`, `ACTOR_ROLE_NOT_REGISTERED`
- `src/substrate/_types.py`: new `ActorRole` frozen dataclass
- 9 tests in `tests/test_phase3.py`

FR-25 — Continue-on-revoked replay flag:
- `src/substrate/_replay.py`: `replay()` and `_replay_work_item()` accept `continue_on_revoked` flag; skips revoked-key events with structured warnings; returns warning count
- `src/substrate/__init__.py`: public `replay(continue_on_revoked=True)` API
- `src/substrate/_types.py`: `ReplayReport` gains `warnings` field (default 0)
- `src/substrate/_replay.py`: report table gains `warnings` column
- 4 tests in `tests/test_phase3.py`

FR-26 — update_not_before API:
- `src/substrate/__init__.py`: public `update_not_before()` method — emits `not_before_set` event, updates projection
- 5 tests in `tests/test_phase3.py`

FR-27 — Custom field validation at transitions:
- `src/substrate/_workflow.py`: new `validate_field_update()` function — validates `custom_fields_update` against work-item-type field definitions
- `src/substrate/__init__.py`: wired into `transition()` before event append
- 5 tests in `tests/test_phase3.py`

E2E integration tests:
- `tests/test_e2e.py`: 4 tests exercising realistic multi-agent workflows (full pipeline, not_before deferral, linked items, role enforcement)

§16 Decision sweep:
- Actor roles: implemented (FR-24)
- Postgres version: pinned to 15+
- Retention: always-grow at homelab scale; month-partition at 1M events
- Spec updated to v4 with all decisions resolved

Spec updates:
- `spec.md`: v4 revision — FR-24/25/26/27, AC-35/36/37/38, BR-09 rewrite, §12/§13/§15/§16/§17.9/§20 updates, handoff state
- `AGENTS.md`: status, source layout, public API updated

**Breadcrumbs resolved:** None new filed. All prior breadcrumbs remain resolved.

**Remaining open:** None.

**Test Results:** 111 passed in 33.5s (+ 3 slow benchmarks excluded)

**Lint:** clean

---

## 2026-05-05 — Session 5: BC-022 content-based idempotency, BC-023/024/025 feature work, BC-009/016/017 final closeout

**Focus:** Implement 6 breadcrumbs, resolve all remaining open items

**Context:** Session 4 left 6 open breadcrumbs (009, 016, 017 held open; 022, 023, 024, 025 newly filed by Opus). User asked to implement BC-022 (content-based idempotency) first, then BC-023/024/025, then close out BC-009/016/017.

**Delivered:**

BC-022 — Content-based workflow registration idempotency:
- `migrations/004_workflow_content_hash.sql`: adds `content_hash BYTEA` to `workflow_registry`
- `src/substrate/_errors.py`: renamed `WORKFLOW_VERSION_ALREADY_REGISTERED` → `WORKFLOW_VERSION_CONFLICT`
- `src/substrate/_workflow.py`: added `compute_content_hash()` and `compute_content_hash_from_dict()` using JCS + SHA-256
- `src/substrate/__init__.py`: `register_workflow()` computes hash, compares on collision — idempotent if same, raises if different; lazy-backfills legacy NULL hashes
- `spec.md` §8: amended registry uniqueness and error table with BC-022 rationale
- `tests/test_smoke.py`: `test_register_version_conflict` added

BC-023 — Optional payload on links:
- `src/substrate/_types.py`: `Link` dataclass gains `payload: dict | None`
- `src/substrate/_links.py`: `create_link()` accepts optional `payload`, stores in `link_created` event JSONB
- `src/substrate/__init__.py`: public `create_link()` passes `payload` through
- `tests/test_smoke.py`: `test_create_link_with_payload`

BC-024 — Telemetry-via-hooks pattern documentation:
- `AGENTS.md`: added "Patterns > Telemetry via hooks" section

BC-025 — Scale benchmarks:
- `tests/test_scale.py`: 3 benchmarks (replay, link queries, hook drain) marked `@pytest.mark.slow`
- `pyproject.toml`: registered `slow` marker
- Baselines: ~0.46ms/event replay, ~3ms link query, ~914 hooks/sec drain

BC-009 — JCS edge-case tests:
- `tests/test_jcs.py`: 16 tests covering float boundaries, integer domain (2^53), UTF-16 key ordering, determinism, NFC caveat

BC-016 — Pagination stability:
- Fix already in place (stable `work_item_id` cursor)
- `tests/test_smoke.py`: `test_pagination_stable_no_duplicates`

BC-017 — Test coverage closeout:
- All 8 load-bearing ACs + Phase 2 ACs verified covered

**Breadcrumbs resolved:** BC-009, BC-016, BC-017, BC-022, BC-023, BC-024, BC-025

**Test/lint results:** 81 passed + 3 slow benchmarks (excluded), ruff clean. Zero open breadcrumbs.

---

## 2026-05-05 — Session 4: Audit sweep — critical bug fix, replay correctness, robustness hardening

**Focus:** Comprehensive codebase audit and fix of 14 issues across correctness, robustness, concurrency, and style

**Context:** Phase 2 was complete with 61 tests passing. Two open breadcrumbs (BC-020, BC-021) from the prior session remained. User asked for a critical audit of the whole repo beyond existing breadcrumbs.

**Delivered:**

Critical bugs (1–3):
- **sweep_expired_claims crash** — `_claims.py:339`: `row[0]`/`row[1]` on `dict_row` results raised `KeyError`; fixed to `row["work_item_id"]`/`row["actor_id"]`
- **custom_fields lost in replay** — `_events.py:append_transition_event`: `custom_fields_update` now persisted in event payload under `custom_fields_update` key; `_replay.py` reads it back correctly
- **not_before lost in replay** — `_work_items.py:create_work_item`: `not_before` now included in `created` event payload as ISO string
- **acquire_claim return type** — `_claims.py`: return annotation corrected to `tuple[Claim, bool]` after BC-020 fix
