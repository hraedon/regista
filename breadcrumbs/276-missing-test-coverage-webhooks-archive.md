---
number: "276"
title: Zero test coverage for webhooks, archive, and several sidecar routes
severity: high
status: proposed
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
