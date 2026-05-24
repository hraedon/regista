---
number: "236"
title: PostgresEventStore.append() omitted prev_event_hash from INSERT
severity: high
status: resolved
kind: bug
author: glm-5.1
date: "2026-05-24"
tags: [bc-233, hash-chain, data-integrity]
related: ["233"]
---

## Problem

After BC-233 added `prev_event_hash` computation to the shared `_store_append()` function in `_event_store.py`, the `PostgresEventStore.append()` method did not include `prev_event_hash` in its INSERT statement. Events created via `Substrate.append_event()` (the public API, which uses `PostgresEventStore`) would have `prev_event_hash` computed correctly in memory but never persisted to the database — the column would remain NULL.

The direct Postgres paths (`_events.py:append_event` and `_events.py:append_transition_event`) were not affected because they have their own INSERT statements that already included `prev_event_hash` from the BC-233 implementation.

## Impact

Events written through `Substrate.append_event()` would have `prev_event_hash = NULL` in the database even though the in-memory `Event` object had the correct value. This means:

1. Replay would see NULL for `prev_event_hash` on these events and the hash chain would break (incrementing warnings).
2. Any downstream consumer reading from the database would see broken chains for these events.

The InMemory backend was unaffected because `InMemoryEventStore.append()` stores the full `Event` object directly.

## Fix

Added `prev_event_hash` to the `PostgresEventStore.append()` INSERT column list and parameter list, matching the pattern used in `_events.py`. Added a dedicated test `test_append_event_api_persists_prev_hash` to verify that the public `append_event` API correctly persists `prev_event_hash` through `PostgresEventStore`.