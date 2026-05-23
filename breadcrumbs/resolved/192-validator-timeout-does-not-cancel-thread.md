---
number: "192"
title: "Validator timeout leaks threads; ThreadPoolExecutor cancel_futures is misleading"
severity: medium
status: implemented
kind: bug
author: claude
date: "2026-05-18"
tags: [validators, hooks, resource-leak, concurrency]
related: []
---

# BC-192 — Validator timeout does not actually cancel the validator

## Problem

`src/substrate/_hooks.py:35-64` runs validators via `ThreadPoolExecutor` and `future.result(timeout=...)`. Python threads are not cancellable; on timeout the worker keeps running until it returns. `cancel_futures=True` only affects *unstarted* futures.

A pathological validator (infinite loop, slow computation, or hanging on a blocking call the AST safety check missed) accumulates one zombie thread per timeout. Repeated timeouts grow background threads unbounded, consuming memory and FDs.

Compounding: `check_validator_io_safety` (`src/substrate/_hooks.py:442+`) is heuristic — an AST walk of `__globals__` only catches direct top-level imports. It misses `__import__`, `importlib`, attribute-access into modules, calls through closures, and any indirect IO. The current contract therefore both *under-enforces* (heuristic) and *under-protects* (no actual cancellation when enforcement fails).

## Proposed fix

Choose one of:

1. **Run validators in a subprocess.** Real cancellation via `process.kill()` on timeout. Cost: per-call subprocess spawn (~ms) plus serialization. Acceptable if validators are rare or batched.
2. **Drop the safety theater.** Document validators as "trusted, cooperative, run in-process at your risk." Remove `check_validator_io_safety` and the timeout/executor entirely. Validator authors are responsible for not hanging. Simpler, honest, smaller code surface.
3. **Status quo + circuit breaker.** Keep the executor but track per-validator timeout counts; after N timeouts, refuse to invoke that validator until reset. Doesn't fix the leak, just bounds it.

(1) is the only option that delivers the contract the current code pretends to. (2) is the right call if no caller actually requires hard cancellation.

## Acceptance criteria

1. Decision recorded (which of 1/2/3) and reflected in the spec section on validators.
2. If (1): test that a validator running `while True: pass` is cancelled within `timeout + epsilon` and no zombie subprocess remains.
3. If (2): docs and spec updated; tests assert the old executor wrappers are gone.

## Resolution

**Option 2 chosen: drop the safety theater.** Validators are now trusted, synchronous, in-process — the contract substrate can actually enforce, not the one it pretended to.

**Files changed:**

- `src/substrate/_hooks.py`: `run_validator` body replaced with a direct `handler(ctx)` call. ThreadPoolExecutor, FuturesTimeout, ast, inspect, textwrap imports removed. `check_validator_io_safety` and `_IO_MODULES` deleted. Near-threshold soft-warning preserved (operator visibility), now logged as `validators.slow` with `soft_threshold_s` field instead of `validators.near_timeout`/`timeout_s` to reflect that it is informational only.
- `src/substrate/__init__.py`: `register_validator` no longer calls `check_validator_io_safety`. Docstring rewritten to state the trusted-code contract and the limits of Postgres `statement_timeout`. Public `transition` docstring's `Raises` block no longer lists `VALIDATOR_TIMEOUT`.
- `src/substrate/_in_memory.py`: `register_validator` no longer calls `check_validator_io_safety`.
- `src/substrate/_transition.py`: the `if e.code == ErrorCode.VALIDATOR_TIMEOUT` branch removed; comment explains why.
- `src/substrate/_errors.py`: `VALIDATOR_TIMEOUT` and `VALIDATOR_IO_UNSAFE` marked obsolete (kept in enum for back-compat with any client that pattern-matches on them).
- `spec.md` §FR-13 transition-validator bullet: rewritten to state the honest contract.
- `tests/test_validator_hardening.py`: rewritten. Removed `TestValidatorIODetection` (premise gone), `TestValidatorWatchdog::test_emits_near_timeout_on_slow_validator` (replaced with a does-not-raise variant), `TestStatementTimeout::test_validator_timeout_with_statement_timeout` (the Python-side wall-clock bound that test depended on is gone — `time.sleep(10)` no longer raises `VALIDATOR_TIMEOUT`), and `TestRegistrationIOSafetyIntegration` (registration no longer rejects I/O handlers). Added `TestTrustedValidatorContract` to pin the new behavior.

**Behavior change summary:** A validator that hangs (`time.sleep(N)`, `while True`) now hangs the transaction. A validator that does I/O is the caller's problem; substrate makes no claim to detect or prevent it. Postgres `statement_timeout = '5s'` set by `_transition.py` still protects against blocking DB operations made via the transaction's connection (real protection, not theater).

**No public API method signatures changed.** Two error codes (`VALIDATOR_TIMEOUT`, `VALIDATOR_IO_UNSAFE`) are now never raised by substrate but remain in the enum for back-compat.
