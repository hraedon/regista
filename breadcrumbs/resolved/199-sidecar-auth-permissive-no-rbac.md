---
number: "199"
title: "Sidecar auth middleware is permissive by default; no role-based authorization"
severity: high
status: implemented
kind: bug
author: adversarial-review
date: "2026-05-22"
tags: [sidecar, auth, security, rbac]
related: ["175", "176", "178"]
---

# BC-199 — Sidecar auth middleware is permissive by default; no role-based authorization

## Path to resolution

For other agents picking up similar work in the sidecar, the recipe used here:

1. **Make auth structural, not per-route.** Replace any "pass through on missing/invalid token" branch in `auth_middleware` with an early `JSONResponse(401)`. The `_get_actor()` per-route check stays as a defense-in-depth backstop but is no longer the primary gate. Test: a request to any `/v1` route without `Authorization: Bearer …` returns 401 *before* the route handler runs.
2. **Reuse the existing `allowed_roles` field** on `AuthenticatedActor` rather than introducing a new permission system. The pattern is already in `register_actor_role` (`routes.py:308`) — copy it into a `_require_admin(request)` helper next to `_get_actor`. Define `ADMIN_ROLE = "admin"` as a module constant so future role names are greppable.
3. **Pick the privileged endpoint list by blast radius, not by name.** "Admin" means "can force state changes that affect every actor." That's broader than the four endpoints originally listed in this breadcrumb — recurrence mutation and dead-letter inspection/recovery belong in the same bucket. Look for endpoints that don't take an `actor_id`-scoped argument and that change shared state.
4. **Remove the OPTIONS exemption** outright rather than narrowing it. The sidecar is not browser-facing; CORS preflight is not a use case. Keeping the exemption is a footgun for anyone who later adds a custom `OPTIONS` handler.
5. **Update test fixtures, not just tests.** The existing test token needs `admin` in `allowed_roles`, and a second non-admin token should be added so role-gating can be verified positively (403 on admin endpoints) and negatively (non-admin tokens still reach non-admin endpoints).
6. **Document the operator break** in the resolution. Token files are operator-owned; there is no migration. Existing tokens that called sweep/replay/dead-letter/recurrence-mutation endpoints will start receiving 403 until `admin` is added to their `allowed_roles`.

If applying this pattern to a future sibling concern (e.g., a `reader` or `operator` role short of `admin`), the same six steps apply with a different role constant — the middleware change is one-time and doesn't need redoing.

## Resolution

Severity downgraded from `critical` to `high` during implementation: the OPTIONS-bypass concern was overstated (see below).

### 1. Deny-by-default auth middleware

`auth_middleware` in `src/substrate/sidecar/routes.py` now returns 401 directly when a request to a `/v1` route is missing a `Bearer` token or presents an invalid token. Previously it would silently fall through to the route, relying on per-route `_get_actor()` calls to catch the gap. The new behaviour is structural: a route author cannot accidentally expose an unauthenticated `/v1` endpoint by forgetting to call `_get_actor()`.

Non-`/v1` paths (`/docs`, `/openapi.json`, `/`) remain reachable without auth — that's deliberate and consistent with BC-175's resolution, which made docs exposure opt-out via `SUBSTRATE_DISABLE_DOCS`.

### 2. Role-based authorization for privileged endpoints

Added an `_require_admin(request)` helper and applied it to operationally privileged endpoints. A token now requires `"admin"` in its `allowed_roles` to call:

- `POST /v1/sweep_expired_claims`
- `POST /v1/sweep_expired_hook_leases`
- `POST /v1/replay`
- `GET  /v1/dead_lettered_hooks`
- `POST /v1/requeue_dead_lettered_hook`
- `POST /v1/fire_recurrence`
- `POST /v1/cancel_recurrence_rule`
- `POST /v1/update_recurrence_rule`

This is a superset of the four endpoints BC-199 originally named; the recurrence-mutation and dead-letter endpoints have the same blast radius (they can force state changes that affect every actor) and were silently ungated.

The check reuses the existing `AuthenticatedActor.allowed_roles` field — no schema change. Mirrors the existing role-gating pattern in `register_actor_role` (`routes.py:308`).

### 3. OPTIONS exception

The original breadcrumb claimed "any request disguised as OPTIONS bypasses all checks." This overstated the risk: FastAPI routes are method-specific, so an OPTIONS request to a `POST`-only route returns 405 from the router, not the route's handler. There is no `OPTIONS` handler for any sensitive route.

That said, the exemption served no purpose (the sidecar is internal, not a browser-facing API needing CORS preflight) and was a footgun for anyone later adding a custom OPTIONS handler. **The OPTIONS exception has been removed**: OPTIONS requests to `/v1` now require the same Bearer token as any other method.

## Files changed

- `src/substrate/sidecar/routes.py` — deny-by-default `auth_middleware`, removed OPTIONS exemption, added `_require_admin` helper and `ADMIN_ROLE` constant, gated 8 privileged endpoints behind admin role.
- `tests/sidecar/test_sidecar.py` — extended token fixture to include a non-admin token; added tests for missing-Bearer-prefix 401, admin-required 403 on sweep/replay/dead-lettered-hooks endpoints, and that non-admin tokens still reach non-admin endpoints. Updated `test_unauthorized_role` to register an unallowed role other than `admin` (the primary test token now legitimately holds `admin`).

## Operator note

Existing token files must add `"admin"` to `allowed_roles` for any token expected to perform sweep, replay, dead-letter recovery, or recurrence mutation. Tokens lacking `admin` will receive 403 on those endpoints. There is no migration path because token files are operator-owned.
