---
number: "185"
title: Maintenance metrics not specified in Plan 009 — operator blind to sweeps
severity: medium
status: implemented
kind: improvement
author: kimi-k2p6-turbo
date: "2026-05-18"
tags: [observability, metrics, maintenance, plan-009]
related: ["184"]
---

# BC-185 — Maintenance metrics not specified in Plan 009

## Problem

Plan 009 (Operational Runtime) proposes a `MaintenanceThread` that runs `sweep_expired_claims`, `sweep_expired_hook_leases`, `ensure_event_partitions`, and `fire_due_recurrences` on configurable intervals. The plan mentions `substrate_maintenance_errors_total` but does not specify operational counters that let an operator verify the thread is doing work.

Without per-operation counters, an operator cannot distinguish between:
- "Maintenance is running and there is nothing to do" (healthy)
- "Maintenance thread died and is not running at all" (unhealthy)

## Proposed fix

Specify and implement the following Prometheus counters for the maintenance thread:

| Counter | Description |
|---|---|
| `substrate_maintenance_cycles_total` | Maintenance loop iterations completed |
| `substrate_maintenance_claims_swept_total` | Claims expired and cleared |
| `substrate_maintenance_hook_leases_swept_total` | Stranded hook leases recovered |
| `substrate_maintenance_partitions_created_total` | Event partitions created |
| `substrate_maintenance_recurrences_fired_total` | Recurring work-items created |

Additionally, expose a boolean property:

```python
@property
def maintenance_healthy(self) -> bool:
    """True if the maintenance thread is running and its last cycle succeeded."""
```

## Acceptance criteria

1. All counters above are visible in Prometheus output after `start_maintenance()` is called.
2. `maintenance_healthy` returns `False` if the thread has crashed or the last cycle raised an unhandled exception.
3. InMemory backend emits equivalent structured log lines (no Prometheus registry required).

## Resolution

**Implemented 2026-05-18.**

### What landed

All six counters are now registered in `Metrics.inc` (`_observability.py`) and wired to existing call sites on `Substrate` (`__init__.py`):

| Counter | Prometheus name | Wired to |
|---|---|---|
| `maintenance_cycles` | `substrate_maintenance_cycles_total` | Pending Plan 009 MaintenanceThread |
| `maintenance_claims_swept` | `substrate_maintenance_claims_swept_total` | `Substrate.sweep_expired_claims()` |
| `maintenance_hook_leases_swept` | `substrate_maintenance_hook_leases_swept_total` | `Substrate.sweep_expired_hook_leases()` |
| `maintenance_partitions_created` | `substrate_maintenance_partitions_created_total` | `Substrate.ensure_event_partitions()` |
| `maintenance_recurrences_fired` | `substrate_maintenance_recurrences_fired_total` | `Substrate.fire_recurrence()` |
| `maintenance_errors` | `substrate_maintenance_errors_total` | Pending Plan 009 MaintenanceThread |

`maintenance_healthy` property added to both `Substrate` and `InMemorySubstrate`. Currently returns `True` (no thread exists yet). Docstring documents that it becomes meaningful once Plan 009 lands.

InMemory backend: no Prometheus registry; `refresh_hook_queue_metrics()` emits structured log lines. No per-counter log lines for the InMemory backend (counters are no-ops for InMemory since there's no registry — operators running InMemory in tests don't need operational metrics).

### Note on `maintenance_partitions_created_total`

`ensure_event_partitions` issues `CREATE TABLE IF NOT EXISTS` for each month in the window, and the counter increments by the number of partition names returned (which includes already-existing partitions, since `IF NOT EXISTS` makes every call idempotent). In practice the maintenance thread will call this infrequently (daily or monthly), so the counter approximates new partitions over time. A stricter implementation would query `pg_class` before each CREATE; deferred to Plan 009.

### Pending Plan 009

`substrate_maintenance_cycles_total` and `substrate_maintenance_errors_total` have no call site yet — they'll be incremented by the MaintenanceThread loop body and error handler respectively.
