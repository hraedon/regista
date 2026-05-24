---
number: "231"
title: "trigger_timestamping treats event_seq as global, but it is per-work-item — batching model is incoherent"
severity: high
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-24"
tags: [timestamping, plan-012, schema, architecture]
related: ["198", "230"]
resolution_plan: "plans/014-global-event-seq.md"
---

# BC-231 — trigger_timestamping treats event_seq as global

## Problem

`trigger_timestamping` in `_timestamping.py:259-301` computes batches by:

```python
row = conn.execute(
    "SELECT MAX(last_event_seq) AS max_seq FROM work_items_current"
).fetchone()
max_seq = row["max_seq"] or 0

batch_row = conn.execute(
    "SELECT MAX(last_event_seq) AS max_seq FROM tsp_batches WHERE status = 'confirmed'"
).fetchone()
last_confirmed_seq = batch_row["max_seq"] or 0

if last_confirmed_seq >= max_seq:
    return None

start_seq = last_confirmed_seq + 1
rows = conn.execute(
    "SELECT event_id, event_seq, timestamp FROM events "
    "WHERE event_seq >= %s ORDER BY event_seq LIMIT %s",
    [start_seq, config.batch_size],
).fetchall()
```

This treats `event_seq` as a globally-ordered, gap-free sequence over the whole `events` table.

`event_seq` is per-work-item. From `migrations/001_initial.sql`:

```sql
UNIQUE (work_item_id, event_seq)
```

and AGENTS.md: *"Gap-free `event_seq` per work-item, allocated under canonical row lock."*

`events` does not carry any global sequence (no BIGSERIAL, no logical clock column). The only BIGSERIAL columns in the schema are on `hook_queue` / `hook_dead_letter`.

## Consequences

1. **`WHERE event_seq >= start_seq`** returns one row from every work item that has reached that local seq. With N work items, a single batch can sample N events that share `event_seq = 5` from N different work items, instead of "the next batch_size events ordered by time."
2. **`MAX(last_event_seq) FROM work_items_current`** returns the largest per-WI sequence anywhere — for a deployment with one long-running WI and many short ones, this is meaningless as a global high-water mark.
3. **`MAX(last_event_seq) FROM tsp_batches`** is comparing to a value that itself was derived from a single ambiguous WI seq.
4. **The current Plan 012 model — `(first_event_seq, last_event_seq, event_count)` on tsp_batches — cannot identify a globally-ordered batch of events** because no global order exists in the schema.

This passes the existing tests because they use a single work item. Multi-WI deployments will silently produce nonsense batches.

## Recommendation

Two coherent paths; pick one, then redo BC-230's re-derivation accordingly:

**Option A — add a global sequence to `events`.**
- New column `events.global_seq BIGSERIAL UNIQUE NOT NULL` (or a separate sequence allocated under transaction).
- Rewrite `trigger_timestamping` and `tsp_batches` to use `global_seq`.
- Replay reconstructs Merkle leaves in `global_seq` order.

**Option B — drop the range model; store the leaf set explicitly.**
- `tsp_batches.event_ids UUID[]` (or a child table `tsp_batch_members`).
- Merkle root is computed over the explicit set.
- Replay re-derives the root from `tsp_batches.event_ids` and confirms each event still exists with the same `event_id`.
- No global sequence required.

Option B composes better with substrate's existing per-WI model and is what the Merkle implementation already does — it sorts by `event_id.bytes`, not by sequence. Range fields become redundant once the leaf set is stored.

In either option, BC-230's "re-derive Merkle root at replay" becomes meaningful.

## Files

- `src/substrate/_timestamping.py:259-301` (`trigger_timestamping`)
- `migrations/*tsp*.sql` (tsp_batches schema)
- `plans/012-rfc3161-timestamping.md` (batching model needs amendment)

## Resolution

Accepted Option A (add `events.global_seq BIGSERIAL`). Option B (explicit
leaf-set per batch) was considered and rejected because Option A gives
intrinsic coverage proofs (gaps in `global_seq` are visible without a
separate audit), range-scan replay instead of N-lookup set membership, and
matches the well-known LSN/offset pattern. The standard contention concern
against monotonic BIGSERIAL inserts is irrelevant below ~10k inserts/sec
sustained, which substrate is nowhere near; the migration path *if* that
ever changes (hash-sharded sequences or ULIDs) is well-trodden and does not
need to be designed for now.

Per-WI `event_seq`, `work_items_current.last_event_seq`, and the
`expected_event_seq` optimistic-concurrency check all stay as-is — they are
correct concepts and load-bearing elsewhere.

See **plans/014-global-event-seq.md** for the implementation plan, risk
tiers, and rollout.
