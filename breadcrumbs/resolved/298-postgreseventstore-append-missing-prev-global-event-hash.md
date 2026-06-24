---
number: "298"
title: PostgresEventStore.append() omits prev_global_event_hash from INSERT
severity: high
status: proposed
kind: bug
author: glm-5.2
date: "2026-06-23"
tags: [plan-022, global-chain, data-integrity, PostgresEventStore]
related: ["236"]
---

## Problem

`PostgresEventStore.append()` includes `prev_event_hash` in its INSERT (fixed in BC-236) but still omits `prev_global_event_hash`. Events created via `Regista.append_event()` (the public API path) will have `prev_global_event_hash = NULL` in the database even though the direct `_events.py` paths (`append_event`, `append_transition_event`) correctly persist it.

This is the same pattern as BC-236, just for the global chain field added in migration 030 (AP-012).

## Impact

1. Replay's global-chain verification (`_verify_hash_chain` on `prev_global_event_hash`) will see NULL for these events, breaking the global chain for the public API append path.
2. The `verify_timestamps` replay path may report false warnings for events that should be covered by a timestamp batch.

## Fix

Add `prev_global_event_hash` to `_EVENT_FIELDS`, the INSERT column list, and parameter list in `PostgresEventStore.append()`. Add a test via `Regista.append_event()` that the column is non-NULL.

## Discovery

Found during adversarial review of Plan 022 Phase 1 by Kimi K2.7 reviewer.
