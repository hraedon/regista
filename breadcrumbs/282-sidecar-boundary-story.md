---
number: "282"
title: "Sidecar boundary story: thin HTTP layer vs application server"
severity: medium
status: accepted
kind: design
author: glm-feedback
date: "2026-05-27"
tags: [sidecar, architecture, auth, rate-limiting]
related: ["235"]
---

## Problem

The sidecar has grown to 42 endpoints covering every Substrate method. It has bearer-token auth and rate limiting but delegates everything 1:1 to the core library. The boundary is unclear:

- **Thin HTTP translation layer**: Simple proxy, no business logic, auth is just actor identification.
- **Application server**: Own auth model, rate limiting, middleware, potential for non-1:1 endpoint mapping.

Currently it's awkwardly in between. It has auth middleware that identifies actors and enforces admin roles, but all business logic is delegated. Rate limiting is per-token but has no backpressure or circuit-breaker story.

## Design Questions

1. Should the sidecar ever compose multiple Substrate calls into a single endpoint?
2. Should it have its own persistence (e.g., for webhook delivery retries)?
3. Should auth be extended to support RBAC beyond the current admin/non-admin split?
4. Should the sidecar expose a different API shape than the Python library?

## Recommendation

Keep the sidecar as a thin HTTP translation layer. The 1:1 mapping is a strength — it means the HTTP API is predictable and matches the Python API exactly. Auth and rate limiting are operational concerns that belong in a proxy, not in the library.

If the sidecar needs to grow beyond 1:1 mapping, extract a separate `substrate-server` package with its own domain model.

## Resolution

_(pending)_
