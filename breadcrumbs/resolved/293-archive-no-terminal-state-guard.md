---
number: "293"
title: "archive_events has no terminal-state guard; can archive dormant non-terminal work items"
severity: low
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-31"
tags: [archive]
related: ["290"]
---

## Resolution

`archive_events` now restricts candidates to work-items whose `current_state`
is a declared terminal state of their pinned workflow version, joining
`work_items_current` with `workflow_registry` and matching `current_state`
against `definition -> 'terminal_states'` (the JSONB array stored at workflow
registration). A dormant-but-non-terminal item — e.g. one parked in a
non-terminal state, or with a future `not_before` — is no longer archivable
purely because its last event is old.

What changed:
- `src/regista/_archive.py` — candidate selection (`_SELECT_CANDIDATES`) is now
  `work_items_current JOIN workflow_registry` filtered by
  `current_state IN (jsonb_array_elements_text(definition -> 'terminal_states'))`
  in addition to the existing `max(timestamp) < before` dormancy check.

Proven by
`tests/test_webhooks_archive.py::TestArchiveEvents::test_archive_skips_non_terminal_dormant_item`:
creates an item left in the non-terminal initial state `new`, runs
`archive_events` with a far-future cutoff, and asserts both the events and the
`work_items_current` row survive.

## Problem

`archive_events` (`src/regista/_archive.py:24-30`) selects work items purely by
`max(timestamp) < before`. There is no check that the work item is in a
declared terminal state. A long-dormant but still-live item — e.g. scheduled
work with a future `not_before` whose last event is old, or an item parked in a
non-terminal state with no recent activity — will be archived and removed from
`events`.

Combined with BC-290 (orphaned projection + replay skips archived items), such
an item vanishes from the event log while its `work_items_current` row still
claims it is active and potentially `claimable_now`.

## Suggested fix

Restrict archival to work items whose `current_state` is a declared terminal
state of their pinned workflow version (join `work_items_current` +
`workflow_registry`), not just by timestamp age.
