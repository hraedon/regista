---
number: "228"
title: "trigger_timestamping uses naive datetime.now() for batch timestamps instead of DB clock"
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-24"
tags: [timestamping, plan-012, datetime, consistency]
related: []
---

# BC-228 — trigger_timestamping uses naive datetime.now() for batch timestamps

## Problem

In `_timestamping.py:210-212`, `trigger_timestamping` uses `datetime.now()` (Python's local clock, no timezone) to populate `tsa_timestamp`, `submitted_at`, and `confirmed_at` on the returned `TimestampBatch` object:

```python
return TimestampBatch(
    ...
    tsa_timestamp=datetime.now(),      # naive, local clock
    submitted_at=datetime.now(),        # naive, local clock
    confirmed_at=datetime.now(),        # naive, local clock
    ...
)
```

However, the database uses `now()` (Postgres server clock) for the same fields in the `tsp_batches` table (lines 178, 201).

## Impact

1. **Clock skew:** If the Python process and Postgres server have different clocks (common in distributed/containerized deployments), the returned `TimestampBatch` object will have different timestamps than what's stored in the database. Tests comparing object timestamps with DB values will be flaky.

2. **No timezone:** `datetime.now()` without `UTC` produces a naive datetime. Other parts of the codebase (e.g., `_claims.py`) use `datetime.now(UTC)`. This inconsistency could cause comparison bugs.

3. **Non-deterministic:** The three `datetime.now()` calls will produce slightly different values (microseconds apart), unlike a single `SELECT now()` from the DB which returns one authoritative timestamp.

## Recommendation

1. Use `datetime.now(UTC)` for timezone-aware timestamps
2. Consider querying `SELECT now()` from the DB to get a single authoritative clock source
3. Alternatively, read the `submitted_at`/`confirmed_at` values back from the DB after the INSERT/UPDATE

## Files

- `src/substrate/_timestamping.py:210-212`
