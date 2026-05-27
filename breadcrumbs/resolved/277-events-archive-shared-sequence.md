---
number: "277"
title: events_archive shares global_seq sequence with events table
severity: medium
status: resolved
kind: design
author: comprehensive-review
date: "2026-05-27"
tags: [migration, archive]
related: []
---

Migration 024 creates `events_archive` via `LIKE events INCLUDING ALL`, which
copies the `DEFAULT nextval('events_global_seq_seq')` for `global_seq`. This
means both tables share the same PostgreSQL sequence.

If code ever inserts into `events_archive` without providing `global_seq`, it
would consume from the shared sequence, creating gaps in `events.global_seq`.
Additionally, the sequence is `OWNED BY events.global_seq` (migration 017),
so dropping `events` would cascade-drop the sequence, breaking `events_archive`.

`INCLUDING ALL` also copies all indexes, creating unnecessary write/storage
overhead for an append-only archive table.

**Fix:** Create `events_archive` with `LIKE events INCLUDING DEFAULTS` instead,
then explicitly add only the needed indexes. Or reset the `global_seq` default
to not use the shared sequence.

## Resolution (2026-05-27)

Migration 027 recreates `events_archive` with plain `LIKE events` (copies columns + types + NOT NULL only, no defaults), then restores non-sequence defaults (`timestamp`, `scheme_id`) and adds only needed indexes (`events_archive_pkey`, `idx_events_archive_work_item_id`, `idx_events_archive_timestamp`). Archive `global_seq` column now has no default — values come from the source events table. 4 tests in `tests/test_migrations_021_026.py::TestMigration027ArchiveSequenceFix`.
