---
number: "276"
title: Zero test coverage for webhooks, archive, and several sidecar routes
severity: high
status: resolved
kind: bug
author: comprehensive-review
date: "2026-05-27"
tags: [testing, webhooks, archive, sidecar]
related: []
---

The following public API methods have **zero test coverage**:

- `register_webhook()` / `unregister_webhook()` / `list_webhooks()` — full
  webhook lifecycle
- `archive_events()` — archival with dry_run, FK cleanup, idempotency
- `sub.webhooks.*` and `sub.archive.*` facades

The following sidecar routes have **zero test coverage**:

- Links: `/create_link`, `/remove_link`
- Recurrence: all 5 endpoints
- Witnesses: all 7 endpoints
- Webhooks: all 5 endpoints
- `/update_not_before`, `/heartbeat_claim`
- `/archive_events`, `/create_work_items_batch`, `/compose_workflow`,
  `/read_events_since`

Migrations 021–026 have no direct test coverage.

Additionally, 19 test assertions use `pytest.raises(Exception, ...)` instead of
`pytest.raises(SubstrateError, ...)`, masking real bugs if a non-SubstrateError
is raised.

## Progress (2026-05-27)

**Completed:**
- Webhook lifecycle tests: `tests/test_webhooks_archive.py` — register, list, unregister, pause/resume, with workflows filter
- Archive events tests: `tests/test_webhooks_archive.py` — dry_run empty, dry_run with events, actual archive, idempotency
- Sidecar route tests added to `tests/sidecar/test_sidecar.py`:
  - `TestLinkRoutes` — create_link, remove_link
  - `TestUpdateNotBeforeRoute` — update_not_before
  - `TestHeartbeatClaimRoute` — heartbeat_claim
  - `TestWitnessRoutes` — register, list, delete, pause, resume, receipts, deliver, admin check
  - `TestRecurrenceRoutes` — register, list, cancel, fire/update admin checks
  - `TestBatchRoutes` — create_work_items_batch, empty list rejection
  - `TestReadEventsSinceRoute` — read_events_since
  - `TestComposeWorkflowRoute` — compose_workflow, admin check
- Fixed 19 `pytest.raises(Exception)` → `pytest.raises(SubstrateError)` across 8 test files
- Migration 021-026 direct tests: `tests/test_migrations_021_026.py` — 18 tests covering:
  - 021: witness receipt uniqueness index + duplicate rejection
  - 022: CHECK constraints on tsp_batches, witness_registrations, witness_receipts; hook_queue lease sweep index
  - 023: claims expires_at partial index
  - 024: events_archive table structure; webhook_registrations dropped by 026
  - 025: sign_secret column on witness_registrations
  - 026: mode column + CHECK constraint + default; unified status constraints (no 'failed'); mode index; register_witness returns mode
