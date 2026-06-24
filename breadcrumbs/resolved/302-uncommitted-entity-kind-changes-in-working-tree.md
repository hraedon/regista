---
number: "302"
title: "Pre-existing uncommitted entity_kind changes in working tree cause test failures"
severity: medium
status: proposed
kind: bug
author: glm-5.2
date: "2026-06-23"
tags: [entity-generalization, plan-022, uncommitted]
related: ["299"]
---

## Problem

The working tree at HEAD `2fc3816` contains uncommitted changes to
`_event_store.py`, `_events_api.py`, `_in_memory_events.py`, `_ops.py`, and
`__init__.py` that add an `entity_kind` parameter to `append_event` and related
functions. These changes appear to be a partial implementation of Plan 022 P5
(non-work-item entity kinds) that was left in the working tree without being
committed.

The changes break 8+ existing tests because they add `entity_kind` as a
keyword argument to `append_event()` in `__init__.py` and `_in_memory.py`, but
the downstream `EventOps.append()` and `in_memory_append_event()` don't accept
it (the corresponding changes to `_ops.py` and `_in_memory_events.py` were not
committed). The sidecar `append_event` route also passes `entity_kind` which
`Regista.append_event()` doesn't accept.

When a new session starts, `git stash` / `git checkout` is needed to clean
these up before tests pass. They should either be committed as a complete
change or reverted from the working tree.

## Discovery

Found during Plan 022 P3 implementation. The pre-existing changes caused
cascading test failures in sidecar, InMemory, and Postgres tests that took
significant time to isolate from the P3 changes.
