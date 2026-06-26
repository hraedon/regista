---
number: "316"
title: Concurrent trigger_timestamping calls can create duplicate TSA batches for the same events
severity: medium
status: proposed
kind: bug
author: adversarial-review
date: "2026-06-26"
tags: [timestamping, concurrency, plan-012]
related: ["314"]
---

## Problem

The event selection query in `trigger_timestamping` selects events with
`global_seq > max(last_global_seq WHERE status='confirmed')`. It does not
exclude events already covered by a pending batch. With the split-transaction
design (BC-314 fix), pending rows are visible between Phase 1 (insert) and
Phase 3 (confirm/fail), so concurrent callers or overlapping maintenance
cycles can select the same event range and submit duplicate TSA requests.

This wastes TSA quota and produces multiple pending/failed rows for the
same events.

## Location

- `src/regista/_timestamping.py` — event selection query

## Suggested Fix

Add a `NOT EXISTS` filter excluding events covered by pending batches:

```sql
WHERE global_seq > %s
  AND NOT EXISTS (
    SELECT 1 FROM tsp_batches b
    WHERE b.status = 'pending'
      AND events.global_seq BETWEEN b.first_global_seq AND b.last_global_seq
  )
ORDER BY global_seq LIMIT %s
```

Alternatively, use an advisory lock around the selection+insert phase.
