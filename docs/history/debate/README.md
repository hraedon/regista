# Active Debate

Structured positions on architectural and design questions that are not yet resolved to a breadcrumb or RFC. One file per topic. These are arguments and recommendations, not defects.

When a debate item is resolved (accepted or rejected), it should be:
- Accepted → move to a spec amendment, breadcrumb, or RFC with resolution note
- Rejected → move to `debate/resolved/` with rejection rationale
- Stale → close if no activity for 60 days

## Index

| # | Title | Position | Status |
|---|---|---|---|
| 001 | Backend contract single-source-of-truth | Adopt declarative contract (Option B from RFC-062) with property-based testing stopgap | **Resolved** — `_contract.py` (511 lines) + hypothesis tests shipped |
| 002 | Workflow composition | Re-evaluate `!include` deferral before Phase 4 YAML becomes unmaintainable | **Resolved** — `extends:` shipped as FR-29 (Plan 004) |

## Plans 007-009

| Plan | Title | Status |
|---|---|---|
| 007 | Public API facade decomposition | **Implemented** — `_ops.py` with 7 facade classes |
| 008 | Trust model hardening | **Implemented** — WS-1, WS-2, WS-3, WS-5 (WS-4 deferred) |
| 009 | Operational runtime | **Implemented** — `MaintenanceThread` + `start_maintenance()` |
