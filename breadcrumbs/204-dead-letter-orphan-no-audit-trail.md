---
number: "204"
title: "Dead-lettered hooks on orphaned events have no audit trail"
severity: high
status: proposed
kind: bug
author: adversarial-review
date: "2026-05-22"
tags: [hooks, dead-letter, audit-trail, events]
related: ["179"]
---

# BC-204 — Dead-lettered hooks on orphaned events have no audit trail

## Problem

In `_hooks.py:282-377`, `_move_to_dead_letter` handles the case where the original event is missing AND the work_item cannot be resolved from the payload. At lines 353-358, it logs a warning and returns without emitting a `hook_dead_lettered` event.

The hook is moved to `hook_dead_letter` table (line 290-316) but no event is recorded in the events table. This means:
- The event log is incomplete — there's no audit trail for hooks that dead-lettered on orphaned events
- Replay cannot detect or warn about dead-lettered hooks that had no event
- Telemetry based on events misses this failure mode

## Proposed fix

Always emit `hook_dead_lettered` event when a hook is dead-lettered, even if the work_item cannot be resolved. Use a sentinel work_item_id (e.g., the hook's own ID) or emit the event with `work_item_id = NULL` if the schema supports it. The audit trail must be complete.
