---
number: "202"
title: "sweep_expired_claims race with concurrent acquire_claim"
severity: high
status: proposed
kind: bug
author: adversarial-review
date: "2026-05-22"
tags: [claims, concurrency, sweep, race-condition]
related: ["114"]
---

# BC-202 — sweep_expired_claims race with concurrent acquire_claim

## Problem

In `_claims.py:317-359`, `sweep_expired_claims` does:
1. `DELETE FROM claims WHERE expires_at < %s RETURNING ...`
2. Iterate deleted rows, lock work-item, clear `claimed_by`, emit `claim_expired`

Between step 1 and step 2, a concurrent `acquire_claim` can INSERT a new claim for the same work-item. The `WHERE claimed_by = %s` guard (BC-114 fix) at line 336 mitigates this by checking the projection's `claimed_by` matches the prior actor. However, the window still exists:

- If the concurrent acquire commits before the sweep's UPDATE, `claimed_by` is the new actor → UPDATE doesn't match → correct
- If the concurrent acquire hasn't committed yet, the sweep's UPDATE sees the old `claimed_by` → matches → clears it → the new acquire's commit overwrites → projection may be inconsistent

Under high contention (many agents sweeping and claiming simultaneously), this can produce spurious `claim_expired` events or interfere with fresh claims.

## Proposed fix

After locking the work-item in the sweep loop, re-verify the claim is still expired by checking `claims` table (not just `work_items_current.claimed_by`). If a fresh claim exists, skip the work-item. This makes the sweep idempotent-safe under contention.
