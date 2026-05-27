---
number: "278"
title: Heartbeat coalescing logic differs between Postgres and InMemory backends
severity: medium
status: implemented
kind: bug
author: comprehensive-review
date: "2026-05-27"
tags: [claims, in-memory-parity]
related: ["194"]
---

The Postgres backend (`_claims.py`) compares `now - last_emitted` to
`threshold` for heartbeat coalescing, while the InMemory backend
(`_in_memory_claims.py`) compares `new_expires_at - last_emitted` to
`threshold`. These produce different results:

- Postgres: measures wall-clock time since last emitted event
- InMemory: measures the difference between new expiry and last emitted time

This divergence means the same sequence of heartbeat calls can produce
different event emission patterns depending on which backend is used.
