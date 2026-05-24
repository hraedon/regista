---
number: "235"
title: Sidecar hook endpoints lack per-hook or per-work-item authorization
severity: medium
status: proposed
kind: improvement
author: adversarial-review
date: "2026-05-24"
tags: [sidecar, auth, hooks]
related: ["199"]
---

## Observation

The sidecar's `/v1/hooks/claim`, `/v1/hooks/{hook_id}/complete`, and `/v1/hooks/{hook_id}/fail` endpoints only require a valid bearer token. Any authenticated caller can claim, complete, or fail any hook in the system regardless of which work item or workflow it belongs to.

BC-199 added deny-by-default auth middleware and admin role gating for privileged endpoints (register_workflow, replay, schema operations), but the hook lifecycle endpoints are open to all authenticated callers. In a multi-tenant or multi-team setup where different tokens are issued to different worker pools, one pool could claim hooks intended for another.

## Proposed

Add a `hook_queue.owner` field (or use `work_items_current.claimed_by` as a proxy) and enforce that only the token mapped to the owning actor can claim/complete/fail hooks for a given work item. Alternatively, add hook-specific token scoping via the TokenRegistry (e.g., `hooks:read`, `hooks:write` claims per workflow).
