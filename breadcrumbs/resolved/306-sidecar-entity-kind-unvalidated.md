---
number: "306"
title: Sidecar append_event accepts arbitrary entity_kind without validation
severity: low
status: accepted
kind: design
author: adversarial-review
date: "2026-06-24"
tags: [sidecar, entity_kind, validation, entity-generalization]
related: ["282"]
---

## Description

The sidecar `AppendEventRequest` model accepts `entity_kind: str = "work_item"`
with no validation. When `entity_kind != "work_item"`, `_events_api.py` skips the
work_item existence check and workflow lookup, allowing events to be appended for a
random `work_item_id` with `workflow_name=""` and `workflow_version=0`.

## Impact

An authenticated API consumer can append events that are not bound to any workflow
or work item. Replay reports these as orphans (when the first transition is not
"created") and emits warnings. This pollutes the event log and weakens the
entity-generalization boundary.

## Suggested resolution

Either:
- Validate `entity_kind` against a registry of known kinds at the API boundary, or
- Require admin privileges for non-default `entity_kind` values, or
- Defer this until entity generalization (Plan 022 P5) is complete and entity
  kinds are fully defined.

## Files

- `src/regista/sidecar/models.py`
- `src/regista/sidecar/routes.py`
- `src/regista/_events_api.py`

## Resolution

Implemented validation at both the sidecar and core API boundaries:

- **Sidecar**: `AppendEventRequest.entity_kind` changed from `str = "work_item"` to `Literal["work_item"]`. Pydantic rejects unknown values with 422 before the route handler runs.
- **Core API**: `_events_api.py` validates `entity_kind` against `_ALLOWED_ENTITY_KINDS` (centralized in `_contract.py`, shared with InMemory backend) before any database interaction. Raises `INVALID_ARGUMENT` for unknown kinds.
- **InMemory**: Same validation in `InMemoryRegista.append_event()`.
- **Docstring**: Fixed `Regista.append_event()` docstring to say `"work_item" only` instead of `"work_item" or "session"`.

Tests: 7 tests covering sidecar, core API, and InMemory. Adversarial review (Kimi) caught the docstring regression and the lack of a shared source of truth for the allowed set — both fixed.
