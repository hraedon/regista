---
number: "290"
title: "archive_events orphans work_items_current projection rows; replay silently skips archived items"
severity: high
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-31"
tags: [archive, replay, durability]
related: ["267", "258"]
---

## Resolution

Chose **fix option (a)**: archival now deletes the `work_items_current`
projection row in the same transaction that archives the events, and first
copies the row into a new `work_items_archive` table so archived state stays
queryable.

Option (b) (replay reading `events UNION ALL events_archive`) was rejected: it
would have left the live projection row in place — including the phantom
`claimable_now=True` row the breadcrumb warns about — and made replay re-scan
the entire archive on every call, defeating the point of archival. Option (a)
keeps the invariant honest: *every live projection row is derivable from the
live event log*. After archive, both the events and the projection row are
gone, so replay correctly has nothing to derive and reports zero drift.

What changed:
- `src/regista/_archive.py` (rewritten) — materializes the candidate set into a
  temp table up front (so the predicate is captured before the deletes empty
  `events`/`work_items_current`), copies events to `events_archive` and the
  projection rows to `work_items_archive`, deletes FK referrers (`hook_queue`,
  `witness_receipts`, `claims`) per BC-267 ordering, then deletes the events
  and finally the `work_items_current` rows — all in one transaction.
- `migrations/029_work_items_archive.sql` (new) — `work_items_archive` table
  (`LIKE work_items_current`, plain LIKE per the BC-277 pattern, with pkey +
  workflow/state index).

Proven by `tests/test_webhooks_archive.py::TestArchiveEvents::test_archive_actual`
(rewritten): archives a terminal item, then asserts the live events are gone,
the projection row is gone (no phantom claimable row), the events survive in
`events_archive`, and `sub.replay().replayed_drift == 0`.

The previously-passing `test_archive_actual` encoded the bug — it asserted
`read_events == 0` as success with no replay/projection check. That assertion
was corrected. The dry-run/idempotent tests were also updated to drive items to
the terminal `done` state first (required by the BC-293 guard).

In-memory parity note: `InMemoryRegista` has no `archive_events` method at all
— archival is a Postgres-only feature — so there is no in-memory replay parity
gap introduced here. The in-memory replay never had archived items to skip.

## Problem

`archive_events` (`src/regista/_archive.py:13-92`) archives whole work-items
(`GROUP BY work_item_id HAVING max(timestamp) < before`) and correctly deletes
`hook_queue` and `witness_receipts` FK referrers before deleting from `events`
(this is the BC-267 fix). **But it never touches `work_items_current`** —
confirmed: `grep work_items_current src/regista/_archive.py` returns nothing.

After archival:

1. The projection row remains, with `last_event_seq` / `current_state` /
   `claimed_by` pointing at events that no longer exist in `events`.
2. `replay()` (`src/regista/_replay.py:132-185`) reads **only** from `events`
   (never `events_archive`). For an archived work-item it finds zero events and
   hits `if not events: continue` (line 184), **silently skipping** the item.

Consequences:
- The projection row is no longer derivable from the live event log,
  violating the headline guarantee (README:13, AGENTS.md:20: "fully derivable
  from the event log via replay"). The single most important durability claim
  is void for any archived item.
- `replay()` returns `replayed_ok` without ever re-verifying archived items'
  signatures or hash chain — the tamper-evidence guarantee silently lapses for
  archived history.
- A still-`claimable` projection row can point at an item whose history is
  gone; `query_work_items(claimable_now=True)` may hand out a phantom.

Note: resolved BC-267's resolution note asserts archival "ensures replay only
sees complete event histories." That is true *within* `events`, but the note
does not address the orphaned projection or replay's blindness to
`events_archive`; the live behavior still breaks derivability.

## Why tests don't catch it

`tests/test_webhooks_archive.py::test_archive_actual` archives a work-item and
asserts `read_events == 0` — i.e. it asserts the orphaning happened and calls
it success. No test runs `replay()` after an archive, and none checks the
projection row is gone or still derivable.

## Suggested fix

Either (a) delete the `work_items_current` rows in the same archive
transaction (and, if a queryable archived projection is wanted, move them to an
archive projection table), or (b) make `replay()` and the `prev_event_hash`
predecessor lookup read `events UNION ALL events_archive` so archived items
stay replayable and verifiable. Add a test that archives a terminal item and
asserts `replay().replayed_drift == 0` (or that the projection row is gone).
