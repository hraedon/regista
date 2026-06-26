---
number: "310"
title: replay reads events and live projection in separate statements under READ COMMITTED — scoped and full replay can report false drift under concurrent writes
severity: high
status: proposed
kind: bug
author: glm-5.2 (WI-003 adversarial review)
date: "2026-06-26"
tags: [replay, concurrency, isolation]
related: ["309"]
---

## Problem

`Regista.replay()` (and the InMemory equivalent) runs inside `_mgr.transaction()`,
which uses Postgres's default `READ COMMITTED` isolation. Under `READ COMMITTED`
each statement sees a snapshot as of that statement's start, so a single replay
issues several independent snapshots:

1. the `work_items_current` existence / id scan (`_replay.py` `_replay_inner`),
2. the `events` scan,
3. the per-item live `work_items_current` SELECT,
4. (full replay) the `event_chain_head` SELECT.

A concurrent transition that commits **between** these statements is visible to
some reads and not others. Concretely for **scoped replay** (WI-003): the events
SELECT may observe an event appended by a concurrent commit, while the
per-item live-row SELECT (or the existence check) observes the pre-commit
projection — producing a spurious `replayed_drift`, a spurious `halted`, or a
missed drift. The same class of inconsistency affects full replay.

This is not introduced by WI-003 (the `work_item_id` scoping); the global replay
path has always had it. But it is more acute for the scoped diagnostic because
an operator runs a single-item check precisely to get a trustworthy per-item
verdict, often under live load (e.g. dossier's per-issue integrity badge).

## Fix options

- **Scoped only (cheap):** when `work_item_id` is set, take
  `SELECT ... FROM work_items_current WHERE work_item_id = %s FOR UPDATE` at the
  start of the scoped replay. This serializes against concurrent transitions on
  that one row and gives a consistent events/live view for the duration. Lock
  duration is one item, so it is cheap.
- **All replay (correct):** run the replay transaction at
  `REPEATABLE READ` (`SET TRANSACTION ISOLATION LEVEL REPEATABLE READ`) so every
  statement in the transaction shares one snapshot. This is the principled fix
  and also removes the inconsistency for full replay, at the cost of a slightly
  longer-lived snapshot.

Either fix should be covered by a concurrency test: a scoped replay running
while a second connection appends a transition event to the same work item must
not produce a spurious drift/halt or crash.

## Not blocking

Pre-existing. WI-003 (per-work-item scoped replay) shipped with a fix for the
related corruption-masking case (events exist but projection row missing now
reports `halted` instead of `WORK_ITEM_NOT_FOUND`) but deliberately left the
isolation gap for a dedicated change, since the proper fix (REPEATABLE READ)
touches the whole replay path, not just scoping.

## Resolution

Implemented the "All replay (correct)" option: replay now runs at REPEATABLE READ isolation via `ConnectionManager.transaction_repeatable_read()`. This ensures every statement in the replay transaction shares one snapshot, preventing spurious drift/halt from concurrent writes.

Spec §17.1 amended: mutating transactions remain READ COMMITTED; replay (read-only) is the sole exception at REPEATABLE READ.

Adversarial review (Kimi) caught that `SET TRANSACTION ISOLATION LEVEL` after `_verify_ssl()` SELECT breaks `require_ssl=True` deployments. Fixed by using `conn.isolation_level` attribute (set before transaction block, reset in finally) and rolling back the SSL probe's implicit transaction.

Tests: 5 tests including a concurrency test that writes from a second connection during replay and verifies the snapshot doesn't see the new event.
