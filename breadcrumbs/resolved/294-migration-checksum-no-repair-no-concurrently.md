---
number: "294"
title: "migration runner is checksum-locked with no repair path and no CONCURRENTLY mode"
severity: low
status: accepted
kind: design
author: adversarial-review
date: "2026-05-31"
tags: [migrations]
related: []
---

## Problem

`run_migrations` (`src/regista/_migrations.py:75-178`) commits each pending
migration in its own transaction (good — incremental progress). But:

1. Any edit to an already-applied migration file raises `MIGRATION_DRIFT`
   (`_migrations.py:141-152`) with **no down/repair/override path** and no
   whitespace-/comment-only allowance. Routine reformatting of an old migration
   bricks `schema init` / `schema status` for every existing deployment.
   Migrations 027 (recreate `events_archive`) and 028 (rename) show migrations
   do get edited in practice, so this is a live foot-gun.

2. Each migration runs inside an implicit transaction (`conn.execute(sql)`
   under `mgr.transaction()`, line 164-165), so `CREATE INDEX CONCURRENTLY`
   — the natural zero-downtime path for indexing the ever-growing `events`
   table — cannot be used; it errors inside a transaction block.

## Suggested fix

Add an explicit, audited checksum-override / repair command; document that
migrations are immutable once shipped (and that fixes ship as new migrations);
and reserve a non-transactional migration mode (autocommit) for `CONCURRENTLY`
index builds.

## Resolution

Implemented both suggested fixes:

1. **Checksum repair**: `repair_checksums(mgr)` function in `_migrations.py` updates stored checksums to match current file checksums for already-applied migrations. Acquires the advisory lock to serialize with concurrent migration runs. Logs each repair at warning level for audit trail. CLI command: `regista schema repair-checksums`.

2. **Autocommit mode**: Migration files annotated with `-- regista: autocommit` (checked in first 5 lines, whitespace-tolerant) execute outside a transaction block, enabling `CREATE INDEX CONCURRENTLY`. The migration row is recorded in a separate transaction after the migration SQL succeeds.

Adversarial review (GLM) caught three issues: `repair_checksums` missing advisory lock (TOCTOU race), CLI using `_resolve_config` instead of `_require_config` (missing-config crash), and CLI missing `RegistaError` handling. All three fixed.

Tests: 4 tests covering repair-with-drift, repair-no-drift, autocommit migration mode, and CLI command.
