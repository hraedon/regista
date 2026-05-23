---
number: "188"
title: "ConnectionManager.connect() does not SET search_path — replay-table cleanup runs against the wrong schema"
severity: high
status: implemented
kind: bug
author: claude
date: "2026-05-18"
tags: [connection, schema, replay, multi-project, isolation]
related: ["173"]
---

# BC-188 — `connect()` omits `SET LOCAL search_path`

## Problem

`ConnectionManager.transaction()` (`src/substrate/_connection.py:104-113`) issues `SET LOCAL search_path TO {schema}` on every checkout. `ConnectionManager.connect()` (`src/substrate/_connection.py:97-101`) does not. The session search_path remains the pool's default (typically `"$user", public`).

The only in-tree call site of `connect()` (rather than `transaction()`) is `Substrate.__init__` / replay-table cleanup at `src/substrate/__init__.py` (≈ `with self._mgr.connect() as conn: drop_old_replay_tables(conn, ...)`). Inside `_replay.drop_old_replay_tables` (`src/substrate/_replay.py:17-28`), the SELECT against `pg_tables` filters by `schemaname=%s` correctly, but the subsequent `DROP TABLE IF EXISTS {tablename}` uses an unqualified `psycopg.sql.Identifier`. Postgres resolves the unqualified name against the session search_path.

Consequences in a DB hosting multiple project schemas:

- Replay-table cleanup silently no-ops (the target schema isn't on the search_path) → orphan tables accumulate.
- Worse, if a same-named relation exists in `public`, the DROP hits `public` instead → cross-project data loss.

This is the kind of "second-consumer assumption" defect that becomes a tenant-bleed bug as soon as substrate is embedded in anything that isn't a single-project sf2 process.

## Proposed fix

Either:

1. **(Preferred)** Make `connect()` also `SET LOCAL search_path TO {schema}` — symmetric with `transaction()`. Document that `connect()` is for DDL/admin and `transaction()` is for data ops, both isolated to the configured schema. *Caveat:* `SET LOCAL` requires a transaction, so `connect()` would have to open one for the SET. An alternative is `SET search_path` (session-scoped) executed once per checkout — but then a returned-to-pool connection retains the value, which is fine if the pool is per-Substrate-instance.
2. Qualify the DROP in `_replay.drop_old_replay_tables` with the schema (`{schema}.{tablename}`) and audit every other `connect()`-using site for the same assumption.

(1) is safer because future code added against `connect()` inherits the guarantee. (2) is a point-fix.

## Acceptance criteria

1. A regression test sets up two schemas in one DB with same-named replay tables; `drop_old_replay_tables` against schema A leaves schema B untouched.
2. `connect()` documentation explicitly states the search_path guarantee.
3. Any other `connect()` call sites that issue schema-relative SQL are either migrated to `transaction()` or schema-qualified.

## Resolution

Option 1 (preferred) was implemented.

**Files changed:**

- `src/substrate/_connection.py` (lines 96-110): `connect()` now executes `SET search_path TO {schema}` (session-scoped) followed by `conn.commit()` before yielding. `SET LOCAL` was not used because no enclosing transaction block exists at that level; session-scoped `SET` is safe because every pool checkout immediately overrides the path, so the next caller is unaffected. Added docstring documenting the guarantee.

- `tests/test_bc188_connect_search_path.py` (new file): Two regression tests — (1) `test_drop_old_replay_tables_does_not_touch_sibling_schema` creates two schemas each with a same-named replay table, calls `drop_old_replay_tables` against schema A, and asserts schema B's table is untouched; (2) `test_connect_sets_search_path_session` asserts `SHOW search_path` returns the configured project schema after `connect()`.

**Call-site audit:** `grep -rn "_mgr.connect("` found exactly one call site — `Substrate.replay()` in `src/substrate/__init__.py:911`. No other `connect()` callers issue schema-relative SQL.

**Caveat:** None. Session-scoped `SET` is safe with the existing per-`Substrate`-instance pool because each instance owns one schema and pool connections are not shared across instances.
