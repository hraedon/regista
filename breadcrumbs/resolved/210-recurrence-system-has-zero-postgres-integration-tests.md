---
number: "210"
title: Recurrence system has zero Postgres integration tests
severity: high
status: implemented
kind: bug
author: substrate-agent
date: "2026-05-22"
tags: [recurrence, testing, postgres, integration]
related: ["209", "166", "164", "149"]
---

**Problem**
`tests/test_recurrence.py` contains only pure unit tests (compute_next_fire, validate_schedule, validate_template, parse_iso8601_duration) and InMemory-only tests. The Postgres integration paths in `src/substrate/_recurrence.py` and `_recurrence_api.py` are entirely untested via CI.

Untested Postgres paths:
- `Substrate.register_recurrence_rule` (parses schedule, inserts into `recurrence_rules` table)
- `Substrate.list_recurrence_rules` (with and without status filter)
- `Substrate.due_recurrences` (queries active rules with `next_fire_at <= now`)
- `Substrate.fire_recurrence` (creates work item, updates rule, handles idempotent retry)
- `Substrate.cancel_recurrence_rule` (updates status)
- `Substrate.update_recurrence_rule` (updates schedule_expr, template, status)
- Catchup policies (fire_once, skip, fire_all) via Postgres
- RRULE schedules via Postgres
- Count exhaustion and `exhausted` status transition via Postgres
- Error paths: RECURRENCE_RULE_NOT_FOUND, RECURRENCE_RULE_EXHAUSTED
- `not_before_offset_seconds` in template
- Custom fields from template populated into created work item

**Impact**
Recurrence is a Plan 003 / FR-28 feature but has no regression protection for the production Postgres backend. Bugs like BC-166 (count_remaining exhaustion) could recur on Postgres without detection.

**Resolution Criteria**
- [ ] Postgres fixture-based integration tests for all recurrence CRUD operations
- [ ] Tests for fire_recurrence work-item creation and custom fields
- [ ] Tests for catchup policies (fire_once, skip, fire_all) via Postgres
- [ ] Tests for count exhaustion / exhausted status
- [ ] Tests for cancel and update operations via Postgres
- [ ] All new tests pass alongside existing suite
