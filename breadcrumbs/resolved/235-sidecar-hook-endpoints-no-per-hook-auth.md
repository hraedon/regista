---
number: "235"
title: Sidecar hook endpoints lack per-hook or per-work-item authorization
severity: medium
status: resolved
kind: improvement
author: adversarial-review
date: "2026-05-24"
tags: [sidecar, auth, hooks]
related: ["199"]
---

## Resolution

Implemented — `AuthenticatedActor` gains `allowed_workflows: tuple[str, ...] | None`
field. When `None`, the token is unrestricted (backward compatible). When set
to specific workflow names, `can_access_workflow()` enforces scoping.

- `TokenRegistry.from_file` parses `allowed_workflows` from YAML token entries
  with type validation (must be list of strings) and empty-list rejection
  (ambiguous — omit for unrestricted).
- `claim_hooks` route filters results to allowed workflows, releasing
  filtered-out hooks back to `pending` (not `in_progress`).
- `complete_hook` and `fail_hook` routes enforce 403 for disallowed workflows.
- 6 tests covering scoped/unscoped access, token parsing, and empty-list
  rejection.

Adversarial review (GLM) found two critical issues:
1. **C1 (stuck hooks):** Filtered-out hooks were left `in_progress` — fixed
   with `_release_hook()` that sets status back to `pending`.
2. **C2 (empty list = unrestricted):** `not self.allowed_workflows` was True
   for empty tuple — changed to `is None` check and reject empty lists at parse
   time.
3. **M1 (string-to-char-tuple):** `tuple("wf_a")` = `('w','f','_','a')` —
   added type validation in `from_file`.
---

## Observation

The sidecar's `/v1/hooks/claim`, `/v1/hooks/{hook_id}/complete`, and `/v1/hooks/{hook_id}/fail` endpoints only require a valid bearer token. Any authenticated caller can claim, complete, or fail any hook in the system regardless of which work item or workflow it belongs to.

BC-199 added deny-by-default auth middleware and admin role gating for privileged endpoints (register_workflow, replay, schema operations), but the hook lifecycle endpoints are open to all authenticated callers. In a multi-tenant or multi-team setup where different tokens are issued to different worker pools, one pool could claim hooks intended for another.

## Proposed

Add a `hook_queue.owner` field (or use `work_items_current.claimed_by` as a proxy) and enforce that only the token mapped to the owning actor can claim/complete/fail hooks for a given work item. Alternatively, add hook-specific token scoping via the TokenRegistry (e.g., `hooks:read`, `hooks:write` claims per workflow).
