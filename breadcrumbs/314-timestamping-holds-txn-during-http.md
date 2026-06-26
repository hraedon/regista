---
number: "314"
title: trigger_timestamping holds a DB transaction open during HTTP call to TSA
severity: high
status: proposed
kind: bug
author: code-review
date: "2026-06-26"
tags: [timestamping, plan-012, connection-pool]
related: []
---

## Problem

`TimestampOps.trigger` wraps the entire `trigger_timestamping` call in
`self._mgr.transaction()`. The function inserts a batch row, then makes an HTTP
POST to an external TSA with a 30-second timeout, then updates the batch — all
within one transaction. The HTTP call blocks a pooled connection for up to 30
seconds, risking connection pool exhaustion and statement timeouts on
concurrent operations.

## Location

- `src/regista/_timestamping.py:501-599` (trigger_timestamping function)
- `src/regista/_ops.py:529-530` (TimestampOps.trigger wrapping in transaction)

## Suggested Fix

Split into two transactions:
1. Insert batch as `'pending'` and commit
2. Do the HTTP call outside any transaction
3. Update to `'confirmed'` in a new transaction

If the process crashes between steps 2 and 3, the pending batch can be
retried or cleaned up by a sweep mechanism.
