---
number: "291"
title: "sweep_expired_claims deletes claims before locking the work item (ordering inversion vs acquire)"
severity: medium
status: fixed
kind: bug
author: adversarial-review
date: "2026-05-31"
tags: [concurrency, claims, sweep]
related: []
---

## Problem

`sweep_expired_claims` (`src/regista/_claims.py:326-375`) runs
`DELETE FROM claims WHERE expires_at < now RETURNING work_item_id, actor_id`
**first**, then loops per-row to `lock_work_item()` and re-check.

Every other claim path (`acquire_claim`, `heartbeat_claim`, `release_claim`)
locks the `work_items_current` row with `FOR UPDATE` **before** touching
`claims`. The sweep inverts this: it deletes the expired `claims` row before
taking the work-item lock.

Race window: a concurrent `acquire_claim` can take the work-item lock in the
gap after the sweep's `DELETE` commits its read snapshot but before the sweep
locks/updates the work item. The acquirer reads no `claims` row (just deleted),
so `resolve_claim_acquire` (`_contract.py:294-367`) sees
`claim_actor_id=None` and returns `action="acquire"` (clean acquire) instead of
`action="steal"` — losing prior-actor / attempt-number accounting. The
`fresh_claim` re-check (`_claims.py:341-346`) only prevents the sweep from
clobbering a claim the racer has *already re-inserted*; it does not restore
steal accounting, and a `claim_expired` event can still be appended for an item
that is freshly claimed by commit time, producing `claim_expired` ordered
*after* `claim_acquired` in the per-item log.

Latent today because the maintenance sweep is single-threaded on a 30s timer,
but it is a genuine lost-update / event-ordering hazard the moment a second
sweeper or a hot acquire races it.

## Why tests don't catch it

`tests/test_concurrency.py` only races simultaneous *acquire* and concurrent
*appends/transitions*. Nothing races a sweep against acquire/steal on an
expired claim.

## Suggested fix

Lock the work-item row first, then re-read and conditionally delete the expired
claim under that lock (mirror `acquire_claim`'s lock-then-read order). Or do
the whole sweep as a single
`DELETE ... USING work_items_current ... WHERE ... FOR UPDATE` so the work-item
lock is held across the delete. Add a sweep-vs-acquire race test.
