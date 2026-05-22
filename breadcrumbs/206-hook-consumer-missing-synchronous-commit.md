---
number: "206"
title: "HookConsumer._connect does not set synchronous_commit = on"
severity: medium
status: proposed
kind: bug
author: adversarial-review
date: "2026-05-22"
tags: [hooks, durability, postgres, connection]
related: []
---

# BC-206 — HookConsumer._connect does not set synchronous_commit = on

## Problem

In `_hooks.py:464-476`, the hook consumer creates its own connection via `psycopg.connect()` (not through the ConnectionPool), and does NOT call `_configure_session()` which sets `synchronous_commit = on`.

The spec (NFR-durability-1) says "substrate sets this per session on its own connections." The main pool uses `_configure_session` which sets this, but the hook consumer's connection bypasses this.

Postgres defaults `synchronous_commit` to `on`, so this is safe in practice, but the code doesn't enforce the spec's durability guarantee. If someone changes the Postgres default or if a connection pool middleware overrides it, hook state changes (complete, fail, dead-letter) could lose WAL durability.

## Proposed fix

Call `_configure_session(conn)` after creating the hook consumer's connection, or at minimum execute `SET synchronous_commit = on` on the connection.
