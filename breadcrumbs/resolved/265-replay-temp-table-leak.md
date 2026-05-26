---
number: "265"
title: Replay temp tables leak on exception
severity: low
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-26"
tags: [replay, resource-leak]
related: []
---

## Problem

`replay()` creates temporary tables (`work_items_current_replay_{tag}` and `replay_report_{tag}`) but does not clean them up on exception. `drop_old_replay_tables` exists but is not called within `replay()` itself. Stale tables accumulate if the caller doesn't clean up.

## Fix

Extracted replay logic into `_replay_inner()`. The main `replay()` function now wraps the call in `try/except` and calls `_drop_replay_tables(conn, replay_table, report_table)` on exception, using the specific tag (not a wildcard). The caller's existing `drop_old_replay_tables` call at the start of `replay()` in `__init__.py` continues to clean up stale tables from previous runs.
