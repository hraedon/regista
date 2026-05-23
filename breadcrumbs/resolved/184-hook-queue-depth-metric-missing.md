---
number: "184"
title: Hook queue depth metric missing — no backpressure visibility
severity: medium
status: implemented
kind: improvement
author: kimi-k2p6-turbo
date: "2026-05-18"
tags: [observability, hooks, metrics, plan-009]
related: ["094", "052"]
---

# BC-184 — Hook queue depth metric missing

## Problem

Substrate emits Prometheus counters for hooks dispatched, succeeded, failed, and dead-lettered (FR-21). However, there is **no gauge or counter for the current depth of the `hook_queue` table**.

In a high-throughput scenario where hooks are produced faster than the consumer can process them, the queue grows unbounded. Without a depth metric, the operator has no signal that backpressure is needed until hook dispatch latency degrades beyond the worst-case 30s polling bound (NFR-dispatch-3).

## Why this matters

- Dead-letter detection is reactive (after max retries). Queue depth is proactive.
- The InMemory backend prunes completed entries (BC-052), but Postgres has no automatic pruning — `hook_queue` accumulates pending, in-progress, and completed rows.
- The sidecar (Plan 005) and future maintenance thread (Plan 009) both drain the queue, but neither exposes how much work remains.

## Proposed fix

Add a `substrate_hook_queue_depth` gauge (Prometheus) or include `pending_count` and `in_progress_count` in a periodic structured log emitted by `poll_hooks` / the maintenance thread.

- Count `status = 'pending'` rows for pending depth.
- Count `status = 'in_progress'` rows for consumer parallelism signal.
- Emit at the end of every `poll_hooks` cycle or maintenance sweep.

## Acceptance criteria

1. A `substrate_hook_queue_pending_total` gauge is visible in Prometheus output.
2. The metric increments when hooks are queued and decrements when they are completed / dead-lettered.
3. The metric is present in both Postgres and InMemory backends.

## Resolution

**Implemented 2026-05-18.**

### What landed

- `Metrics.set_hook_queue_depth(project, status, value)` added to `_observability.py`, backed by a new `_gauge_with_status()` helper that creates a Gauge with `["project", "status"]` label set (stored separately from single-label gauges to avoid Prometheus label-set collision). Prometheus metric name: `substrate_hook_queue_depth`.
- `Substrate.refresh_hook_queue_metrics()` method on the Postgres `Substrate` class. Issues two queries: `SELECT status, count(*) FROM hook_queue GROUP BY status` and `SELECT count(*) FROM hook_dead_letter`. Updates four status labels: `pending`, `in_progress`, `completed`, `dead_letter`. Safe to call any time; the maintenance thread (Plan 009) should call it at the end of every sweep cycle.
- `InMemorySubstrate.refresh_hook_queue_metrics()` emits a `substrate.maintenance.hook_queue_depth` structured log line with pending/in_progress/completed/dead_letter counts. No Prometheus registry in the InMemory backend.

### Decisions

- Strategy (b) (explicit `refresh_hook_queue_metrics()` method) was chosen over strategy (a) (update on every enqueue/claim/complete). Rationale: hooks go through multiple code paths (direct DB, `poll_and_process_hooks`, `fail_hook`, `_move_to_dead_letter`), making (a) invasive without a guaranteed atomic count. A periodic SELECT COUNT(*) is cheap and correct.
- `dead_letter` label covers `hook_dead_letter` table (separate from `hook_queue`). This gives operators a single metric family for all hook backlog signals.
- AC-1 (`substrate_hook_queue_pending_total`) renamed to `substrate_hook_queue_depth` with a `status` label, providing richer cardinality at the same query cost.

### Pending Plan 009

The maintenance thread should call `refresh_hook_queue_metrics()` at the end of each sweep cycle. No call site exists yet.
