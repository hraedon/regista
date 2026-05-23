---
number: "212"
title: "FR-10 references event_type column but actual column is transition"
severity: low
status: implemented
kind: bug
author: external-review
date: "2026-05-22"
tags: [spec-drift]
related: []
---

## Problem

`spec.md` line 124 (FR-10) says: `unique partial index (work_item_id) WHERE event_type = 'escalated'`

The actual column in the SQL schema (`migrations/001_initial.sql` line 12), the Event dataclass (`_types.py` line 76), and the migration (`003_escalation_idempotency.sql` line 1) all use `transition`, not `event_type`.

Every other reference in the spec correctly uses `transition` (lines 139, 332).

## Fix

Change `event_type` to `transition` on line 124.
