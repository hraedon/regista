---
number: "203"
title: "HookConsumer.is_running returns True when connection exhausted and processing stopped"
severity: high
status: proposed
kind: bug
author: adversarial-review
date: "2026-05-22"
tags: [hooks, health-check, observability]
related: ["120"]
---

# BC-203 — HookConsumer.is_running returns True when connection exhausted and processing stopped

## Problem

In `_hooks.py:478-576`, the hook consumer thread can exit its processing loop after exhausting connection retries (10 attempts). When this happens:

1. The thread is still alive briefly (in the `finally` block or between loop exit and thread termination)
2. `is_running` (line 461-462) checks `self._thread.is_alive()` — returns `True` during this window
3. `maintenance_healthy` in `__init__.py:459-465` returns `True` when `_maintenance_thread is None` or thread is stopped

The operator sees `is_running = True` and `maintenance_healthy = True` but hooks are silently not being consumed.

Similarly, if the initial connection attempts are exhausted (line 489-495), the method returns silently. The thread is alive (it's the thread target), `is_running` is `True`, but no hooks are being processed.

## Proposed fix

Track actual processing state separately from thread liveness:
- Add `_processing = True` at loop start, `_processing = False` at loop exit
- `is_running` should check both `thread.is_alive()` and `_processing`
- `maintenance_healthy` should distinguish "never started" from "stopped" from "healthy"
