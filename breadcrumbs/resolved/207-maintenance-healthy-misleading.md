---
number: "207"
title: "maintenance_healthy returns True when maintenance is stopped or never started"
severity: medium
status: proposed
kind: bug
author: adversarial-review
date: "2026-05-22"
tags: [maintenance, health-check, observability]
related: ["185", "203"]
---

# BC-207 — maintenance_healthy returns True when maintenance is stopped or never started

## Problem

In `__init__.py:459-465`:

```python
@property
def maintenance_healthy(self) -> bool:
    if self._maintenance_thread is None:
        return True
    if not self._maintenance_thread.is_running:
        return True
    return self._maintenance_thread.last_cycle_ok
```

- Returns `True` when `_maintenance_thread is None` (never started)
- Returns `True` when `is_running` is False (thread crashed and stopped)
- Returns `True` when thread is running and healthy

The operator cannot distinguish "never started" from "crashed and stopped" from "healthy and running". A monitoring system watching `maintenance_healthy` would miss a silently dead maintenance thread.

## Proposed fix

Return `False` when the thread has stopped unexpectedly. Consider a three-state return: `True` (healthy), `False` (crashed/stopped), `None` (never started). Or add a separate `maintenance_running` property.
