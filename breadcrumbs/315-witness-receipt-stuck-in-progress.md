---
number: "315"
title: No recovery sweep for stuck in_progress witness receipts
severity: high
status: proposed
kind: bug
author: code-review
date: "2026-06-26"
tags: [witness, plan-013, maintenance]
related: ["312"]
---

## Problem

Witness receipts are marked `in_progress` in one transaction, then the
transaction commits. The HTTP delivery happens outside any transaction. If the
process crashes during delivery, receipts are permanently stuck in
`in_progress` — there is no sweep mechanism for witness receipts (unlike
`sweep_expired_hook_leases` for hooks). The maintenance thread
(`_maintenance.py`) only sweeps claims and hook leases, not witness receipts.

## Location

- `src/regista/_witness.py:440-454` (receipt marked in_progress, delivery outside txn)
- `src/regista/_maintenance.py` (no witness receipt sweep)

## Suggested Fix

Either:
(a) Add a `sweep_stuck_witness_receipts` method to the maintenance cycle that
    resets `in_progress` receipts older than a threshold back to `pending`.
(b) Use a lease timestamp (like `lease_expires_at` on hook_queue) and sweep
    receipts whose lease has expired.

Option (a) is simpler; option (b) is more robust.
