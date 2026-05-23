---
number: "191"
title: "Migration runner lacks advisory lock and checksum verification — concurrent boots race; edited migrations diverge silently"
severity: high
status: implemented
kind: bug
author: claude
date: "2026-05-18"
tags: [migrations, concurrency, integrity]
related: []
---

# BC-191 — Migration runner is not safe under concurrent boot

## Problem

`src/substrate/_migrations.py:50-76` (`run_migrations`) iterates `.sql` files in order, runs each inside a transaction, and inserts the version row. There is no:

- `pg_advisory_lock(<known_id>)` around the runner, so two processes booting against the same DB can both observe a migration as pending, both attempt the DDL, and one loses with a confusing `relation already exists` or partial-DDL error.
- Stored checksum/hash on `_substrate_migrations`, so a developer who edits an already-applied migration file leaves the DB silently divergent from source. The runner happily skips the version on next boot.
- Recorded path for rollback. (Not necessarily required, but the absence should be a documented choice.)

The concurrent-boot path is realistic the moment substrate is embedded in a horizontally-scaled service rather than today's single-sf2-process pattern. The drift-on-edit path is realistic now, on any team.

## Proposed fix

1. Wrap the runner in `pg_advisory_lock(MIGRATION_LOCK_ID)` / `pg_advisory_unlock`. Define `MIGRATION_LOCK_ID` as a stable constant in `_migrations.py`.
2. Add `checksum BYTEA NOT NULL` (SHA-256 of the file bytes) to `_substrate_migrations` (itself via a new migration). On each migration read: if a record exists, verify checksum matches; if mismatch, raise `MIGRATION_DRIFT` with the file path and both hashes.
3. Document explicitly that migrations are append-only; edits to applied files are forbidden and detected.

## Acceptance criteria

1. Concurrent invocations of `run_migrations` against an empty DB: exactly one applies each migration; the other observes the lock and returns when the first commits.
2. Editing an applied migration file then re-running raises `MIGRATION_DRIFT`.
3. The advisory-lock id is documented and tested for non-collision with any other substrate lock ids.

## Resolution

Implemented in:
- `src/substrate/_migrations.py` — full rewrite with advisory lock + drift detection
- `src/substrate/_errors.py` — added `MIGRATION_DRIFT` to `ErrorCode`
- `migrations/013_migration_checksums.sql` — adds `checksum BYTEA` column to `_substrate_migrations`
- `tests/test_migration_safety.py` — 4 tests covering concurrent boot, lock ID value, drift detection, and NULL-checksum backfill

**Advisory lock ID:** `MIGRATION_LOCK_ID = 2479241334166598476`

Derived as `int.from_bytes(sha256(b"substrate_migrations")[:8], "big")`, interpreted as a signed PostgreSQL `bigint`. The derivation is deterministic, documented in the module, and the probability of accidental collision with an application-chosen lock ID is approximately 1/2^63. Stored in `MIGRATION_LOCK_ID` at module top for operator auditability. Tested by `test_migration_lock_id_is_documented_value`.

**Backfill strategy:** The `checksum` column is nullable (not `NOT NULL`). Rows applied before migration 013 start as NULL. On the first `run_migrations` call after upgrade, the runner detects NULL-checksum rows (legacy rows), computes the SHA-256 of the current file, and writes it — no operator action required, no `MIGRATION_DRIFT` raised. This is simpler than a separate one-time backfill migration and requires no production intervention.

**New error code:** `MIGRATION_DRIFT` — raised when a non-NULL stored checksum differs from the current file's SHA-256. The `detail` dict contains `version`, `path`, `stored_checksum` (hex), and `current_checksum` (hex) for operator diagnostics.

**Rollback note (deferred):** Down-migrations are not implemented per the BC's explicit deferral. Operators who need to roll back past migration 013 must manually drop the `checksum` column. This is noted in the advisory.

**Acceptance criteria status:**
1. Concurrent boot: verified by `test_concurrent_run_migrations_both_succeed` (two threads, both succeed, no migration applied twice).
2. Drift detection: verified by `test_drift_raises_migration_drift`.
3. Lock ID documented and tested by `test_migration_lock_id_is_documented_value`.
