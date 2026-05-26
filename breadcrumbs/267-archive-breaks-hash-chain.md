---
number: "267"
title: "archive_events breaks hash chain and replay consistency"
severity: high
status: implemented
kind: bug
author: reflection
date: "2026-05-26"
tags: [archive, events, hash-chain, replay]
related: ["258"]
---

## Problem

`archive_events(before_timestamp)` deletes events from the `events` table after copying them to `events_archive`. This has two problems:

1. **Hash chain break**: If event B's `prev_event_hash` points to event A, and A is archived but B is not, B's hash chain reference becomes orphaned. Replay will log a warning for the chain break.

2. **Replay inconsistency**: `replay()` reads only from `events`. Archived events are invisible to replay, so the replayed projection will be incomplete for work-items that had events archived.

## Resolution

Changed `archive_events` to only archive complete work-items. The function finds work-items whose most recent event timestamp is before the cutoff, then moves ALL events for those work-items together. This preserves hash chain integrity within work-items and ensures replay only sees complete event histories.
