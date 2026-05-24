---
number: "227"
title: "HookConsumer._processing flag not reset on early return after connect exhaustion"
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-24"
tags: [hooks, concurrency, state-management]
related: []
---

# BC-227 — HookConsumer._processing flag not reset on early return

## Problem

In `_hooks.py:482`, `self._processing = True` is set at the start of `_run()`. If the initial connection loop exhausts `max_reconnect_attempts` (line 498 `return`), the function returns without resetting `_processing` to `False`.

The `finally` block at line 577 (`self._processing = False`) only executes if the code reaches the main processing loop past the initial connect phase.

```python
def _run(self) -> None:
    self._processing = True  # line 482
    # ... initial connect loop ...
    if reconnect_attempts >= max_reconnect_attempts:
        log.error(...)
        return  # line 498 — _processing stays True
    # ... main loop ...
    finally:
        self._processing = False  # line 577 — never reached
```

## Impact

`is_running` checks `_thread.is_alive()` which returns False after thread exit, so the property is correct. However, any code that inspects `_processing` directly (or if the object is reused after thread failure) would see stale state. This is a minor state inconsistency that could cause confusion in debugging.

## Recommendation

Add `self._processing = False` before the early return at line 498, or restructure to use a `try/finally` that covers the entire method body.

## Files

- `src/substrate/_hooks.py:482,498,577`
