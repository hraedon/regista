---
number: "316"
title: Concurrent trigger_timestamping calls can create duplicate TSA batches for the same events
severity: medium
status: resolved
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

## Resolution

Fixed — two-layer defense against duplicate TSA batches:

1. **NOT EXISTS filter** in the event selection query excludes events already
   covered by a pending `tsp_batches` row. This prevents re-selection of events
   from a previous cycle whose batch is still pending (slow TSA, crash before
   confirm, etc.).

2. **Transaction-scoped advisory lock** (`pg_advisory_xact_lock`) serializes
   the selection+insert phase, preventing truly concurrent transactions from
   both selecting the same events. The lock auto-releases when the transaction
   commits (after INSERT), so it does not block the HTTP call to the TSA.

Recovery path unchanged: `sweep_stale_timestamp_batches` marks stale pending
batches as failed; the next `trigger_timestamping` call re-selects those events
since failed batches are excluded by both the `max(status='confirmed')` filter
and the `NOT EXISTS` (which only checks `status='pending'`).

3 new tests in `tests/test_timestamping.py::TestBC316ConcurrentTimestamping`:
- `test_pending_batch_prevents_reselection` — pending batch blocks re-selection
- `test_failed_batch_allows_reselection` — failed batch allows re-selection
- `test_pending_batch_allows_non_overlapping_events` — pending batch for seqs
  1-N does not block selecting seqs N+1 onward
