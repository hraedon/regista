---
number: "210"
title: "Recurrence system has zero Postgres integration tests"
severity: high
status: proposed
kind: improvement
author: adversarial-review
date: "2026-05-22"
tags: [recurrence, testing, postgres, parity]
related: ["209"]
---

# BC-210 — Recurrence system has zero Postgres integration tests

## Problem

All recurrence tests (Plan 003) use `InMemorySubstrate`. The following Postgres-specific code paths are untested:

- `register_recurrence_rule` INSERT with `FOR UPDATE` locking
- `due_recurrences` query with `status = 'active'` and `next_fire_at <= now()` filtering
- `fire_recurrence` with `FOR UPDATE` locking, `next_fire_at` updates, `count_remaining` decrement
- `cancel_recurrence_rule` and `update_recurrence_rule` with actual SQL
- `count_remaining` exhaustion setting status to `exhausted` (BC-166 fix)
- RRULE schedules with timezone-aware start times

This is the exact pattern that produced the Session 11-14 InMemory bug flood (30+ resolved breadcrumbs). The `_contract.py` extraction helps, but recurrence operations are NOT covered by the contract — they have their own SQL in `_recurrence.py`.

## Proposed fix

Add Postgres integration tests for recurrence, mirroring the InMemory tests. At minimum: register, due, fire, cancel, update, and exhaustion paths.
