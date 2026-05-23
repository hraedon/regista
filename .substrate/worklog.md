# Substrate Worklog

Structured log of development sessions and milestones.

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
