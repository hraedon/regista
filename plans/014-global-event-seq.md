# Plan 014 — Global event sequence for coherent batch timestamping

**Status:** Draft RFC
**Owner:** regista
**Spec touched:** §17 (signing/integrity), Plan 012 §3.1 / §4 / §5.4
**Resolves:** BC-231 (per-WI `event_seq` makes batching incoherent), unblocks the BC-230 multi-WI case
**Related:** BC-198, BC-226, BC-230

## 1. Problem (one paragraph)

`tsp_batches` identifies batch membership by `(first_event_seq, last_event_seq)` and `trigger_timestamping` selects events by `WHERE event_seq >= start ORDER BY event_seq LIMIT n`. But `event_seq` is per-work-item (`UNIQUE (work_item_id, event_seq)`, allocated under canonical row lock). With multiple work items, a single "range" matches one row per WI per seq, batches don't reflect global order, and `MAX(last_event_seq)` is a meaningless high-water mark. Tests pass only because they use one WI.

## 2. Decision

Add a global monotonic sequence to `events` (`global_seq BIGSERIAL UNIQUE NOT NULL`) and rewrite the batching, replay, and inclusion-verification paths to use it. Per-WI `event_seq` stays exactly as-is — it's load-bearing elsewhere (`work_items_current.last_event_seq`, optimistic concurrency via `expected_event_seq`, replay state reconstruction).

Option B from BC-231 (explicit leaf set per batch) was considered and rejected: A gives intrinsic coverage proofs (gaps in `global_seq` are visible without a separate audit), range-scan replay instead of N-lookup set membership, and matches the well-known LSN/offset pattern. The contention concern against A (hot rightmost B-tree leaf on monotonic insert) is irrelevant below ~10k inserts/sec sustained, which regista is not near.

## 3. Schema change

New migration `017_events_global_seq.sql`:

```sql
ALTER TABLE events
    ADD COLUMN global_seq BIGINT;

-- Backfill in insertion order. event_id is a UUID PK; we backfill by
-- (timestamp, event_id) which is the closest stable proxy for arrival order
-- on an existing installation. Greenfield deploys are unaffected.
WITH ordered AS (
    SELECT event_id,
           ROW_NUMBER() OVER (ORDER BY timestamp, event_id) AS rn
    FROM events
)
UPDATE events e SET global_seq = ordered.rn
FROM ordered WHERE e.event_id = ordered.event_id;

ALTER TABLE events ALTER COLUMN global_seq SET NOT NULL;

CREATE SEQUENCE events_global_seq_seq
    AS BIGINT
    START WITH 1
    INCREMENT BY 1
    CACHE 100;

-- Initialize the sequence past the backfilled max so new inserts continue cleanly.
SELECT setval(
    'events_global_seq_seq',
    COALESCE((SELECT MAX(global_seq) FROM events), 0) + 1,
    false
);

ALTER TABLE events
    ALTER COLUMN global_seq SET DEFAULT nextval('events_global_seq_seq');

ALTER SEQUENCE events_global_seq_seq OWNED BY events.global_seq;

ALTER TABLE events ADD CONSTRAINT events_global_seq_unique UNIQUE (global_seq);

-- tsp_batches: switch range columns to global_seq. Drop old per-WI columns —
-- nothing outside _timestamping.py / _replay.py reads them.
ALTER TABLE tsp_batches
    ADD COLUMN first_global_seq BIGINT,
    ADD COLUMN last_global_seq  BIGINT;

-- Existing rows in dev/homelab deployments cannot be meaningfully migrated
-- (the seq numbers they hold are per-WI). For safety, mark them unverifiable.
UPDATE tsp_batches SET status = 'superseded' WHERE status IN ('pending','confirmed','failed');

ALTER TABLE tsp_batches DROP COLUMN first_event_seq;
ALTER TABLE tsp_batches DROP COLUMN last_event_seq;
ALTER TABLE tsp_batches ALTER COLUMN first_global_seq SET NOT NULL;
ALTER TABLE tsp_batches ALTER COLUMN last_global_seq  SET NOT NULL;
```

Notes:
- `CACHE 100` keeps `nextval()` cheap across concurrent inserts.
- The `'superseded'` status for pre-existing `tsp_batches` rows is intentional: their per-WI seqs cannot be re-interpreted as global. Operators get a clean "old batches no longer verifiable, new batches start fresh" semantic. If you have production data you actually trust, write a one-off backfill script — but regista currently has no such deployment.
- `last_event_seq` on `work_items_current` is untouched. It is the per-WI concept and remains correct.

## 4. Code changes

### 4.1 Event insert path (low risk)
- `src/regista/_event_store.py:273` — `INSERT INTO events (...)`: do **not** list `global_seq`; rely on the column default (`nextval`). One-line: no change needed if the column list is explicit and omits `global_seq`. Verify SELECTs that round-trip events do not need `global_seq` (they don't — it's not in the `Event` dataclass and shouldn't be).
- `src/regista/_in_memory_work_items.py` (and any in-memory event store): add a module-level monotonic counter for `global_seq` assigned on commit. Used only by replay / timestamping in tests.

### 4.2 `trigger_timestamping` (medium risk — load-bearing rewrite)
`src/regista/_timestamping.py:223-329`. Replace the per-WI `event_seq` arithmetic with:

```python
batch_row = conn.execute(
    "SELECT MAX(last_global_seq) AS max_seq FROM tsp_batches WHERE status = 'confirmed'"
).fetchone()
last_confirmed_seq = batch_row["max_seq"] or 0

rows = conn.execute(
    "SELECT event_id, global_seq, timestamp FROM events "
    "WHERE global_seq > %s ORDER BY global_seq LIMIT %s",
    [last_confirmed_seq, config.batch_size],
).fetchall()
if not rows:
    return None

first_global_seq = rows[0]["global_seq"]
last_global_seq  = rows[-1]["global_seq"]
```

Drop the `SELECT MAX(last_event_seq) FROM work_items_current` query entirely — it was always the wrong concept. Insert into `tsp_batches` with `(first_global_seq, last_global_seq)` instead.

`_rehydrate_event_ids` (line 332) — change signature and query to use `global_seq`.

`list_batches` — same column change in row unpacking.

### 4.3 Replay verification (medium risk)
`src/regista/_replay.py:226-294`. The current code groups events by `event_seq`, which produces wrong leaf sets in multi-WI batches. Rewrite:

```python
batch_rows = conn.execute(
    "SELECT first_global_seq, last_global_seq, merkle_root, tsa_token "
    "FROM tsp_batches WHERE status = 'confirmed'"
).fetchall()

event_ids_by_global_seq: dict[int, uuid.UUID] = {
    evt["global_seq"]: evt["event_id"] for evt in all_events
}

covered: set[int] = set()
for br in batch_rows:
    first_seq = br["first_global_seq"]
    last_seq  = br["last_global_seq"]
    leaf_ids = [
        event_ids_by_global_seq[s]
        for s in range(first_seq, last_seq + 1)
        if s in event_ids_by_global_seq
    ]
    covered.update(range(first_seq, last_seq + 1))
    # ... existing merkle/tsa verification using leaf_ids ...
```

The `_EVENT_FIELDS` list (`_replay.py:41`) needs `global_seq` added, and the main `SELECT … FROM events ORDER BY work_item_id, event_seq` stays — replay still walks per-WI for state reconstruction. Only the timestamping section keys off `global_seq`.

The "uncovered events" warning now reports `global_seq` instead of `event_seq`.

### 4.4 Plan 012 amendment (docs)
Patch `plans/012-rfc3161-timestamping.md` §3.1, §4 (schema table + inclusion query), §5.4 (replay): replace `event_seq` ranges with `global_seq` ranges. Note "see Plan 014 for the global_seq introduction" at the top.

### 4.5 AGENTS.md
Add one line under the events-table description: `global_seq BIGSERIAL` — global monotonic order across all work items, used by timestamping and any cross-WI cursor.

## 5. Tests

New / updated:
- `tests/test_event_store.py` — assert `global_seq` is monotonic and gap-free across inserts that span multiple WIs.
- `tests/test_timestamping.py` — multi-WI batch test: insert events to 3 WIs interleaved, trigger a batch, assert the batch contains the next N events in `global_seq` order regardless of WI, and that `compute_merkle_root` over those `event_id`s matches the stored root.
- `tests/test_timestamping.py` — coverage proof: confirm consecutive confirmed batches tile `[1, MAX(global_seq)]` with no gaps and no overlap.
- `tests/test_replay.py` — `verify_timestamps=True` with multi-WI events: passes when untouched; fires `replay.merkle_root_mismatch` when an event's `event_id` is mutated.
- `tests/test_migrations.py` (or equivalent) — backfill produces a unique, monotonic `global_seq` over `(timestamp, event_id)` order on an existing fixture.

## 6. Risk tiers (for delegation)

| Tier | Task | Notes |
|---|---|---|
| Low | Migration 017 SQL | Mechanical; review for the `CACHE 100` and `SET DEFAULT nextval(...)` patterns. |
| Low | AGENTS.md + plan 012 amendment | Pure docs. |
| Low | Add `global_seq` to `_EVENT_FIELDS` and any SELECT lists that round-trip events to replay. | Mechanical. |
| Low | In-memory store: monotonic counter for `global_seq`. | One module-level int + one assignment in `commit_event`. |
| Medium | Rewrite `trigger_timestamping` + `_rehydrate_event_ids` + `list_batches` column names. | Local, well-bounded, well-tested. |
| Medium | Rewrite the `verify_timestamps` block in `_replay.py`. | The current code already does the BC-230 recomputation; this just swaps the keying. |
| Higher | Multi-WI integration tests (timestamping + replay). | Need to construct multi-WI fixtures interleaved in time; small but easy to get subtly wrong. |
| Higher | Backfill semantics + the `'superseded'` decision on existing `tsp_batches` rows. | Decide whether to keep `'superseded'` or just `DELETE FROM tsp_batches`. Has user-facing implications — keep human in the loop. |

A weaker model can safely take the Low tier as a single batched change; the Medium tier is fine for Kimi/GLM/Sonnet given the rewrites are well-scoped and tested. The Higher tier is worth a careful pass.

## 7. Rollout

Regista has no production deployments. Single migration, no feature flag. Land migration + code + tests in one PR, regenerate CHANGELOG, mark BC-231 as `resolved` and add a follow-up note on BC-230 confirming the multi-WI case is now actually checked.

## 8. Out of scope

- Hash-sharded sequences, ULID-based IDs, table partitioning — all premature. Documented as the migration path *if* regista ever hits the contention wall.
- Changing per-WI `event_seq` semantics or removing `work_items_current.last_event_seq`. Neither needs to move.
- Replacing the range model in `tsp_batches` with an explicit leaf-set table (BC-231 Option B). Not pursued; the global-seq range is sufficient and intrinsically auditable.
