# Plan 017 — Webhook/Witness Unification

**Status:** Implementation in progress
**Origin:** BC-269 (witness and webhook are near-duplicate patterns)
**Spec touched:** §19 (public API), migration 026

## Decisions (from design review)

1. **Option C — clean-slate merge.** Webhooks promoted to witness model. `_webhooks.py` becomes thin wrapper.
2. **Status: `paused` only.** Drop `failed` from CHECK constraints. All auto-pause uses `paused`.
3. **Fix `work_item_types` filter bug** (BC-272). Webhook filter reads wrong event field.
4. **Keep signing, rename header.** `X-AgentWake-Signature` → `X-Regista-Signature`. Constant-time comparison documented.
5. **Async delivery.** Webhook delivery uses witness receipt+delivery model (not synchronous on event-write).
6. **Breaking change acceptable.** No production users at meaningful scale.

## Implementation Steps

### Migration 026

1. Add `mode TEXT NOT NULL DEFAULT 'witness' CHECK (mode IN ('witness', 'push'))` to `witness_registrations`.
2. Change `witness_registrations.status` CHECK from `('active','paused','failed')` to `('active','paused')`.
3. Change `witness_receipts.status` CHECK to remove `'failed'` — use `'paused'` for terminal failures after max_retries.
4. Backfill: any existing `webhook_registrations` rows → insert into `witness_registrations` with `mode='push'`, `max_retries=1`, `event_filter` built from the webhook's `transitions`/`work_item_types`/`workflows` columns.
5. Drop `webhook_registrations` table.
6. Update `consecutive_failures` default to 0 if not already.

### _witness.py changes

1. `_validate_event_filter` — no change needed.
2. `register_witness` — add `mode` parameter (default `'witness'`).
3. `deliver_pending_receipts` — already handles retry and max_retries. For `mode='push'` endpoints, `max_retries=1` means a single failure marks the receipt as terminal. This is the fire-and-forget degenerate case.
4. Unify status: replace `'failed'` with `'paused'` everywhere. Log message already says "auto_paused".
5. `X-AgentWake-Signature` → `X-Regista-Signature` in delivery headers.

### _webhooks.py → thin wrapper

1. `register_webhook(url, ...)` → calls `register_witness(url, ..., mode='push', max_retries=1)`.
2. `list_webhooks(status)` → calls `list_witnesses(status)` filtered to `mode='push'`.
3. `unregister_webhook(id)` → calls `unregister_witness(id)`.
4. `pause_webhook(id)` → calls `pause_witness(id)`.
5. `resume_webhook(id)` → calls `reactivate_witness(id)` (which resets `consecutive_failures=0`).
6. `deliver_webhooks(event)` → calls `create_receipts_for_event(event)` (async delivery via maintenance thread handles the rest).
7. `_event_matches_webhook` → delegates to `event_matches_filter`.
8. Fix: read `work_item_type` from top-level event dict, not payload.

### _ops.py changes

1. `WebhookOps` → thin wrapper around `WitnessOps` with `mode='push'` filtering.
2. `register` → delegates to `WitnessOps.register` with `mode='push'`, `max_retries=1`.

### CLI changes

1. `regista webhook register/list/remove/pause/resume` → delegate to witness CLI with mode filter.
2. Mark as deprecated with stderr warning pointing at `regista witness`.

### Sidecar changes

1. Webhook routes delegate to witness operations.
2. Keep `/v1/webhooks/*` endpoints as aliases for now.
3. `X-AgentWake-Signature` → `X-Regista-Signature` in any signing code.

### Error codes

1. Remove uses of `WITNESS_NOT_FOUND` for webhook lookups. Use a unified code or keep `WITNESS_NOT_FOUND` since webhooks are now witness rows.

### Tests

1. Fix existing webhook tests to work with new model.
2. Add test for `work_item_types` filter against real `Event.to_dict()`.
3. Add test for auto-pause + resume resetting failure counter.
4. Verify `X-Regista-Signature` header in delivery tests.
