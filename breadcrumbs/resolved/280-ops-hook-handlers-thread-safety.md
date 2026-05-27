---
number: "280"
title: HookOps assigns _handlers dict non-atomically while consumer thread may iterate
severity: medium
status: implemented
kind: bug
author: comprehensive-review
date: "2026-05-27"
tags: [hooks, thread-safety]
related: []
---

`HookOps.register_handler()` sets `self._consumer._handlers = self._handlers`.
If the consumer thread is running and iterating over `_handlers` at the same
time, this could cause a `RuntimeError` (dictionary changed size during
iteration). The assignment is not atomic from the consumer's perspective.

Should use a lock or copy-on-write pattern with an atomic reference swap.
