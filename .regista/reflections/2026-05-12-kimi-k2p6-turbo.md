---
model: kimi-k2p6-turbo
project: regista
datetime: 2026-05-12T15:55 UTC
---

# Session Reflection — 2026-05-12

**Work summary:** Resolved all 14 breadcrumbs from the adversarial review (BC-114 through BC-127), implemented GLM's structural prevention proposals 2 and 3, filed BC-128 for proposal 1, and brought the test suite to 411 passing with a new adversarial conformance test.

---

## On the project

Regista is a well-architected event-sourced system with a clear spec and strong conventions. The RFC-062 `_contract.py` extraction was the right move for validation logic. However, the InMemory backend has become a liability — it's a ~1500-line reimplementation of what Postgres does via SQL, and every divergence is a bug that the test suite failed to catch until an adversarial reviewer pointed it out.

The breadcrumb discipline is excellent. 130 resolved items with frontmatter, severity, and resolution notes. The index is mostly clean (there was a duplicate-table issue I fixed).

The property-based conformance tests were the weakest link — they matched outcomes but not error codes, didn't assert on sequence numbers, and never reused event_ids. That's how off-by-one seq and idempotency bypass survived 410 passing tests.

## On the work done

This session was productive and mechanically clean. I fixed 14 real bugs across 8 source files plus a migration and tests. The changes are minimal and surgical — no architectural churn, just correctness fixes.

The shared validation layer (`validate_mutation_params`) is the most valuable structural addition. Both backends now call the same function at the top of every mutation method. Adding a new validation rule in the future requires one change in `_contract.py` and zero per-method updates.

The adversarial conformance test (`test_adversarial_error_code_equivalence`) sends UUIDv1 event_ids, bad actor kinds, far-future not_before, and negative TTLs. Both backends must reject with the same error code. This is the real CI gate: if InMemory diverges on validation, it fails immediately.

The EventStore protocol (BC-128) was not implemented — it's a larger refactor that deserves its own session with careful planning around the transaction atomicity guarantees.

## On what remains

1. **BC-128 — EventStore protocol** — the single highest-impact structural change. Extract seq allocation, idempotency, and event construction into a backend-agnostic protocol. InMemoryRegista would shrink to ~500 lines.
2. **Spec sync** — The spec mentions `claim_expires_at` in the projection but doesn't document that heartbeats don't emit events (hence replay can't derive it). Should add a note.
3. **Migration documentation** — Migration 008 adds `max_retries` to `hook_dead_letter`. This should be noted in any deployment guide.

## Gaps to flag

- **`src/regista/_in_memory.py:1387-1406`** — `_append_claim_event` and `_append_simple_event` now check idempotency, but they also unconditionally increment `wi["next_event_seq"]` even when the event is a duplicate. The idempotency check returns early without incrementing, so this is fine, but it's a subtle invariant.
- **`src/regista/_replay.py:353`** — `_states_match` intentionally does NOT compare `claim_expires_at` because heartbeats mutate it without emitting events. If the spec ever requires heartbeats to emit events, this comparison should be enabled. Documented in BC-090.
- **`src/regista/_workflow.py:29-31`** — `_require_unique` uses `Counter` which imports from `collections`. This is fine but the import is inside the function. Consider moving to module level for consistency.
- **`tests/test_property_conformance.py:1`** — The adversarial test has a HypothesisDeprecationWarning about using `random` inside strategies. This is from `uuid.uuid1()` being called inside the strategy. Should switch to `st.uuids(version=1)` if Hypothesis supports it, or generate UUIDs outside the strategy.
