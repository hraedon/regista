---
number: "190"
title: "ensure_event_partitions is opt-in; missed cron silently spills writes to events_default"
severity: high
status: implemented
kind: bug
author: claude
date: "2026-05-18"
tags: [partitions, operations, observability, migration-010]
related: ["184", "185"]
---

# BC-190 — Event partition maintenance is silently optional

## Problem

`migrations/010_events_partition.sql:32` creates `events_default` as the catch-all partition. `src/substrate/_events.py:520-551` defines `ensure_event_partitions` (creates ~3 months ahead) but the function is invoked only from the CLI (`src/substrate/_cli.py`). There is no:

- Auto-run on `Substrate.__init__` or on first append after a boot.
- Startup check that warns if `events_default` is non-empty.
- Metric exposing the future-partition horizon (so an operator can alert before the horizon expires).

If an operator forgets to schedule the CLI command, writes land in `events_default`. That partition lacks the per-(event_id) and per-(work_item_id, event_seq) indexes the production partitions carry (and even when present, BC-148 left the global `event_id` story unresolved — see related RFC-034), so lookups degrade silently and idempotency checks scan the catch-all.

This is the same operator-blindness class as BC-184 (hook queue depth metric) and BC-185 (maintenance metrics) — substrate today assumes a competent, attentive operator and gives them nothing to be attentive *to*.

## Proposed fix

Two pieces, either of which mitigates:

1. **Auto-ensure on init.** `Substrate.__init__` calls `ensure_event_partitions(horizon=3 months)` unless an `auto_partition=False` opt-out is passed. Cheap, idempotent, no surprise behavior since today's "do nothing" is already the broken case.
2. **Startup spill warning + metric.** At init, `SELECT count(*) FROM events_default`; if non-zero, log a structured `warning("partitions.default_partition_non_empty", count=N)` and emit a Prometheus gauge `substrate_events_default_rows`. Add `substrate_events_partition_horizon_days` so alerts can fire before horizon expires.

Plan 009 (per BC-185) is the right home for (2). (1) should land in this BC.

## Acceptance criteria

1. Default `Substrate.__init__` ensures partitions for the next 3 months without operator action; test verifies the partitions exist after init.
2. Opt-out (`auto_partition=False`) is documented and respected.
3. `events_default` row count is observable via metric and logged at init if non-zero.

## Resolution

Implemented in `src/substrate/__init__.py` and `src/substrate/_events.py`.

**Init signature change (public API):**
- `Substrate.__init__` gains `auto_partition: bool = True` keyword argument.
- `Substrate.create_project` gains the same kwarg and passes it through.
- Both default to `True`, so existing call sites gain automatic partition
  maintenance with no code changes required (the prior "do nothing" default
  was the broken case).

**Auto-ensure logic (`_run_auto_partition`):**
- Called from `__init__` after `check_integrity` when `auto_partition=True`.
- Calls `ensure_event_partitions(months_ahead=3)` idempotently.
- Queries `SELECT count(*) FROM events_default`; if non-zero emits
  `log.warning("partitions.default_partition_non_empty", count=N, schema=...)`.
- Sets both Prometheus gauges (see below).

**`ensure_event_partitions` public method on `Substrate`:**
- Now also updates gauges after each explicit call (not just at init).

**Metrics added to `_observability.py`:**
- `substrate_events_default_rows` (Gauge, label: `project`) — number of rows
  in the catch-all partition; set at init and on each `ensure_event_partitions`
  call.
- `substrate_events_partition_horizon_days` (Gauge, label: `project`) — days
  until the upper bound of the latest named partition; set at same times.
- Both metrics are only registered when a `prometheus_registry` is provided
  (following the existing pattern in `Metrics.__init__`).

**Helper functions added to `_events.py`:**
- `count_events_default(conn)` — `SELECT count(*) FROM events_default`.
- `partition_horizon_days(conn)` — queries `pg_inherits` / `pg_get_expr` to
  find the latest named partition's upper bound date and returns days until it.

**In-memory backend:** `InMemorySubstrate` has no Postgres partitions; no
changes needed. The `auto_partition` kwarg is not added to `InMemorySubstrate`
since it has no concept of partition tables.

**Tests:** `tests/test_events_partition.py` — class `TestAutoPartitionOnInit`
with three tests verifying partitions exist after init, opt-out is respected,
and both Prometheus gauges are set correctly.
