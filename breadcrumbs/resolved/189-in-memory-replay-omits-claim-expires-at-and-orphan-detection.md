---
number: "189"
title: "In-memory replay parity: omits claim_expires_at comparison and orphan-event detection"
severity: high
status: implemented
kind: bug
author: claude
date: "2026-05-18"
tags: [backend-parity, replay, in-memory, debate-001]
related: ["131", "132", "133", "134", "135", "136", "137", "138", "139", "140", "141"]
---

# BC-189 — In-memory replay drifts from Postgres replay (claim_expires_at, orphan events)

## Problem

The dual-backend conformance promise (and `debate/001-backend-contract-single-source-of-truth.md`) is being eroded again. Two concrete drifts:

1. **`claim_expires_at` not compared.** Postgres `_replay._states_match` (`src/substrate/_replay.py:386-401`) and the in-memory equivalent (`src/substrate/_in_memory_replay.py:136-148`) both omit `claim_expires_at` from the state-equality check. A replay that disagrees on lease expiry will silently pass.
2. **No orphan-event detection in in-memory replay.** Postgres replay scans for events whose work-item rows are gone (`src/substrate/_replay.py:92-116`); the in-memory replay has no equivalent. A test that exercises an orphan-event path against in-memory will be green; the same scenario against Postgres will surface.

This is the same class as BC-131 through BC-141 — silent in-memory/Postgres drift. The breadcrumbs corpus already contains ~14 of these, which is itself the strongest argument for the Option-B contract extraction in `debate/001`.

## Proposed fix

Short-term (this BC):

- Add `claim_expires_at` to the comparison in both replays.
- Port `_replay`'s orphan-event scan into `_in_memory_replay`.

Long-term: this BC should be cited as motivation in any decision to accept `debate/001` — point-fixing each parity drift after the fact is unsustainable.

## Acceptance criteria

1. New test: in-memory replay disagrees on `claim_expires_at` → replay reports mismatch (mirrors Postgres behavior).
2. New test: orphan-event scenario produces equivalent diagnostics in both backends.
3. The diff-test from BC-131 era (if still present) is extended with both fields.

## Resolution

### Files changed

- **`src/substrate/_in_memory_replay.py`** — added `derived_claim_expires_at` tracking through all claim events (`claim_acquired`, `claim_stolen`, `claim_released`, `claim_expired`) and workflow transitions; added `_ts_equal()` for timezone-safe comparison; added `_ts_equal(derived_claim_expires_at, wi.get("claim_expires_at"))` to the drift check; ported the Postgres orphan-event scan (loop over `store.events.keys() - work_items.keys()`, split into halted vs. warning by whether the first event is `created`).

- **`src/substrate/_replay.py`** — added `_ts_equal()` helper (UTC-normalising); added `claim_expires_at` check to `_states_match()` and `_diff_fields()`; added `UTC` to imports.

- **`tests/test_in_memory_conformance.py`** — extended `TestConformanceReplay` with `test_replay_no_drift_with_active_claim` (both backends, claim acquired → replay clean); added `TestBC189ClaimExpiresAtDrift` (in-memory only, tampers `claim_expires_at` in projection and asserts drift is reported; also verifies clean replay after claim release); added `TestBC189OrphanEventDetection` (in-memory only, injects synthetic orphan events directly into `_store.events` and asserts `halted`/`warnings` are counted correctly).

### Timezone-handling decision

Both `_replay.py` (parsing event-payload ISO strings via `datetime.fromisoformat()`) and `_in_memory_replay.py` derive `claim_expires_at` from strings that originate from `datetime.now(UTC).isoformat()` — they will always carry a `+00:00` suffix, so both sides are tz-aware UTC. The `_ts_equal()` helper normalises to UTC before comparison; this handles any future mix of tz-aware/naive datetimes without silent mismatch.

### Existing parity test extended

`TestConformanceReplay` in `tests/test_in_memory_conformance.py` was extended (both backends via the `sub` fixture). Orphan-event scenarios were added as a dedicated `mem_sub` in-memory-only class because corrupting Postgres projection state post-facto would require raw SQL injection outside the fixture pattern.

### Follow-up: `claim_expires_at` comparison reverted

The first cut added `claim_expires_at` to `_states_match` and `_diff_fields` in both backends. Running the full suite surfaced `test_smoke.py::TestReplay::test_replay_no_drift` failing on a real drift, not a false positive: `heartbeat_claim` (`src/substrate/_claims.py:217-220`) mutates `work_items_current.claim_expires_at` directly without emitting an event, so the replay derivation cannot reconstruct it. The field is structurally non-replayable today.

The comparison addition was reverted (claim_expires_at removed from both `_states_match` / `_diff_fields` and the in-memory drift condition). A note was added in `_replay.py` pointing to BC-194, which captures the choice of whether to make heartbeats emit events.

Tests kept: `test_replay_no_drift_with_active_claim` (parity guard for clean replay after acquire — still valid because `claimed_by` and `attempt_number` are checked). Tests removed: `TestBC189ClaimExpiresAtDrift` (premise no longer holds). Tests kept: `TestBC189OrphanEventDetection` (the genuine parity gap this BC was filed for).
