---
number: "232"
title: "BC-227 test test_processing_false_after_connect_exhaustion reimplements _run instead of calling it"
severity: low
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-24"
tags: [tests, hooks, plan-011]
related: ["227"]
---

# BC-232 — BC-227 first test does not actually exercise the real fix

## Problem

In `tests/test_hook_consumer.py`, `TestBC227ProcessingFlagReset.test_processing_false_after_connect_exhaustion` defines a local `fast_run` function that hand-rolls a stripped-down version of the connect loop, then runs *that* in a thread. It never calls the real `consumer._run`.

```python
def fast_run(self_ref=consumer):
    self_ref._processing = True
    max_reconnect_attempts = 1
    ...
    if reconnect_attempts >= max_reconnect_attempts:
        self_ref._processing = False
        return
    ...

with patch.object(consumer, "_connect", side_effect=ConnectionError("refused")):
    t = threading.Thread(target=fast_run, daemon=True)
    t.start()
```

The test asserts `not consumer._processing` afterwards, which trivially passes because `fast_run` itself sets it to False. If a future edit to `_run` introduces a new early-return that forgets to clear `_processing`, this test would still pass.

The second test in the same class (`test_processing_false_after_stop_during_connect_loop`) does call the real `consumer._run`, so the underlying fix is not untested — but the connect-exhaustion path specifically is.

## Recommendation

Drive `_run` directly. Options:

1. Make `max_reconnect_attempts` a constructor argument or class attribute so a low value can be set in tests; then call `consumer._run()` with `_connect` patched to always raise.
2. Patch the constant in place (`with patch("substrate._hooks.MAX_RECONNECT_ATTEMPTS", 1):` or equivalent — depends on how the constant is referenced).
3. If the constant is a literal in `_run`, refactor to a class attribute first.

Then assert `consumer._processing is False` after the thread joins.

## Files

- `tests/test_hook_consumer.py` (`TestBC227ProcessingFlagReset`)
- `src/substrate/_hooks.py` (`HookConsumer._run`, max_reconnect_attempts handling)
