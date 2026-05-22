---
number: "201"
title: "heartbeat_claim and release_claim do not null-check lock_work_item result"
severity: high
status: proposed
kind: bug
author: adversarial-review
date: "2026-05-22"
tags: [claims, null-safety, audit-trail]
related: []
---

# BC-201 — heartbeat_claim and release_claim do not null-check lock_work_item result

## Problem

In `_claims.py`, both `heartbeat_claim` (lines 188-266) and `release_claim` (lines 269-315) call `lock_work_item()` but never check if the result is `None`.

For `heartbeat_claim`:
- Line 199: `wi = lock_work_item(mgr, work_item_id)` — result unused except for event append at line 223-224
- Lines 250-258: TTL extension proceeds unconditionally, potentially extending a phantom claim

For `release_claim`:
- Line 279: `wi = lock_work_item(mgr, work_item_id)` — result checked only at line 300 for event append
- Lines 288-298: Claim deletion and projection update proceed even if `wi` is None
- Result: claim released but no audit event emitted

## Proposed fix

Raise `WORK_ITEM_NOT_FOUND` early when `lock_work_item` returns `None`, before any side effects. Both functions should fail fast on missing work-items rather than silently proceeding.
