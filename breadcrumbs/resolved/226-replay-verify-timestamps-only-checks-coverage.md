---
number: "226"
title: "replay(verify_timestamps=True) only checks coverage, not token integrity"
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-24"
tags: [replay, timestamping, plan-012]
related: ["223", "225"]
---

# BC-226 — replay verify_timestamps only checks coverage

## Problem

The `verify_timestamps` parameter on `replay()` in `_replay.py:215-232` only checks that event sequences are covered by confirmed `tsp_batches` rows:

```python
if verify_timestamps:
    batch_rows = conn.execute(
        "SELECT first_event_seq, last_event_seq FROM tsp_batches "
        "WHERE status = 'confirmed'"
    ).fetchall()
    covered = set()
    for br in batch_rows:
        for seq in range(br["first_event_seq"], br["last_event_seq"] + 1):
            covered.add(seq)
    uncovered = []
    for evt in all_events:
        seq = evt["event_seq"]
        if seq not in covered:
            uncovered.append(seq)
```

It does **NOT**:
1. Verify TSA tokens against the event data (BC-223)
2. Verify Merkle proofs for individual events
3. Recompute the Merkle root from event IDs and compare with the stored root
4. Validate the TSA response structure or signature
5. Check that the `tsa_timestamp` in the batch is within a reasonable range

## Impact

The name `verify_timestamps` implies cryptographic verification, but it only performs a database-level coverage check. A compromised or corrupted `tsp_batches` row with `status='confirmed'` would pass this check. Combined with BC-223 (no real TSA verification), the timestamping feature provides a false sense of integrity.

## Recommendation

Either:
1. **Rename** to `check_timestamp_coverage` to accurately reflect what it does
2. **Implement real verification**: recompute Merkle roots, verify Merkle proofs, and verify TSA tokens (once BC-223 is fixed)

Option 1 is the quick fix. Option 2 is the correct long-term solution.

## Files

- `src/substrate/_replay.py:215-232`
