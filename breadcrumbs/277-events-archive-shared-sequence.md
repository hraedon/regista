---
number: "277"
title: events_archive shares global_seq sequence with events table
severity: medium
status: proposed
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
