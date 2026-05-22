---
number: "199"
title: "Sidecar auth middleware is permissive by default; no role-based authorization"
severity: critical
status: proposed
kind: bug
author: adversarial-review
date: "2026-05-22"
tags: [sidecar, auth, security, rbac]
related: ["175", "176", "178"]
---

# BC-199 — Sidecar auth middleware is permissive by default; no role-based authorization

## Problem

The sidecar auth middleware in `sidecar/routes.py:57-76` allows requests without an `Authorization` header to pass through untouched. The `_get_actor()` guard catches missing actors on `/v1` routes, but the pattern is fragile: any route that forgets to call `_get_actor()` is completely unprotected.

More critically, admin endpoints (`sweep_expired_claims`, `sweep_expired_hook_leases`, `replay`, `requeue_dead_lettered_hook`) require only *any* valid token — there is no role-based authorization. Any authenticated user can sweep claims, replay events, or requeue dead-lettered hooks.

Additionally, the `OPTIONS` exception at line 64-65 means any request disguised as OPTIONS bypasses all checks.

## Proposed fix

1. Reject requests missing `Authorization` header by default (opt-in bypass for health/ready endpoints only).
2. Add role-based authorization for admin endpoints (e.g., `admin` role required for sweep/replay/requeue).
3. Consider middleware that applies to all routes, with explicit opt-out for unauthenticated endpoints.
