---
number: "275"
title: Sidecar async route handlers block the event loop with synchronous DB I/O
severity: medium
status: implemented
kind: improvement
author: comprehensive-review
date: "2026-05-27"
tags: [sidecar, performance, async]
related: ["276"]
---

All sidecar route handlers are declared as `async def`, which makes FastAPI run
them on the main event loop. Every handler calls into `substrate.*` which
performs synchronous psycopg database I/O, blocking the entire async server for
the duration of each query.

Under concurrent load, this serializes all requests and defeats the purpose of
using an async framework. The fix is to either:

1. Change all route handlers to plain `def` (FastAPI runs them in a threadpool)
2. Use `asyncio.to_thread()` / `run_in_threadpool()` for blocking calls

Option 1 is the simpler change. Option 2 gives more control over which calls
are offloaded.
