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
