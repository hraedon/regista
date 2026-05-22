---
number: "208"
title: "ISO 8601 P1M recurrence always means 31 days, not one calendar month"
severity: low
status: proposed
kind: bug
author: adversarial-review
date: "2026-05-22"
tags: [recurrence, iso8601, scheduling]
related: []
---

# BC-208 — ISO 8601 P1M recurrence always means 31 days, not one calendar month

## Problem

In `_recurrence.py:61-105`, ISO 8601 durations with months are converted via `relativedelta` to `timedelta` by computing `base + rd - base`. For `P1M`, this computes the timedelta between `1970-01-01` and `1970-02-01` (31 days). The result is always 31 days regardless of the actual calendar month.

This means `P1M` fires every 31 days, not every calendar month. `P1Y` fires every 365 days (not accounting for leap years). The semantics are subtly wrong for calendar-aware scheduling.

## Proposed fix

Document this behavior clearly. If calendar-aware scheduling is needed, the recurrence engine should use `relativedelta` directly for fire-time computation rather than converting to `timedelta`. For the current homelab scope, the 31-day approximation is acceptable but should be documented.
