# Plan 001 — Month-Partitioning the `events` Table

Status: Proposed
Scope: Regista core schema. Per-project, applied to each project schema (BR-13).
Spec anchors: §16 "Schema partitioning policy — Deferred with flexibility" (`spec.md:338`); deferred-items list (`spec.md:494`); §16 trigger threshold note (`spec.md:517`); §10 retention statement (`spec.md:238`).

## 1. Motivation

The `events` table (`migrations/001_initial.sql:1-17`) is append-only and grows monotonically. At homelab scale (≤100k events/project) a single heap is fine, but `spec.md:338` and `spec.md:517` flag month-partitioning as the agreed move once any project exceeds ~1M events. This plan is the *enabling* groundwork: it converts `events` into a `PARTITION BY RANGE (timestamp)` parent so that future archival, drop-old-partition, or cold-storage export can attach to a stable structure.

Explicitly **not solved** by this plan:
- No public-API change. `Regista.append_event`, `read_events`, `replay` continue to behave identically (BR-03, BR-11 still hold).
- No archival, no S3 export, no retention policy enforcement — those are downstream work that *depends* on partitioning being in place.
- No change to event semantics, signing, canonicalization, or `event_seq` allocation.

The win is operational: range-pruned queries on `timestamp` (already used by `read_events_by_time_range`, `_events.py:389-403`), bounded per-partition index size, and a future cheap `DETACH PARTITION` for archival.

## 2. Approach

**Declarative partitioning, `PARTITION BY RANGE (timestamp)`.** Postgres 15+ is pinned (`spec.md:519`) so we have working declarative partitioning, default partitions, and `ATTACH … CONCURRENTLY`-style flows. Inheritance partitioning is rejected: no constraint exclusion benefits over declarative, no FK or unique-index ergonomics, and tooling (`pg_partman`, `pg_dump`) treats declarative as first-class.

**Granularity:** monthly. Daily would multiply partition count (~365/yr/project × N projects); yearly defeats the point of bounded indexes. Monthly aligns with `spec.md`'s naming and is the standard pg_partman default.

**Partition naming:** `events_yYYYY_mMM` (e.g. `events_y2026_m05`). Sortable, unambiguous, no locale issues.

**Default partition:** `events_default`. Catches stragglers (clock-skewed inserts, backfill with old timestamps, or a missed pre-creation run). Monitoring must alert when `events_default` has non-zero rows — that indicates a missed `CREATE PARTITION` or an unexpected timestamp.

**Partition creation cadence:** in-app scheduled task, not pg_partman, not OS cron.
- pg_partman is excellent but adds an extension dependency that conflicts with regista's "library, not daemon, minimal infra" stance (`spec.md:336`).
- OS cron lives outside regista's deployment unit; regista is imported into the host process and shouldn't require external schedulers.
- A new method `Regista.ensure_event_partitions(months_ahead: int = 3)` is idempotent, safe to call from the host's existing periodic loop (the same place `sweep_expired_claims` is called today), and works equally well inside a `start_hook_consumer`-style background thread. Pre-create 3 months ahead; the operation is `CREATE TABLE IF NOT EXISTS … PARTITION OF events FOR VALUES FROM (…) TO (…)`.

## 3. Migration Strategy

Per-project (one schema at a time), packaged as `migrations/010_events_partition.sql` + a Python migration helper (the runner already exists at `src/regista/_migrations.py`). Two paths:

**Path A — small table (<100k rows), maintenance window acceptable (the homelab default today):**
1. `BEGIN`.
2. `ALTER TABLE events RENAME TO events_legacy`.
3. Recreate `events` as `PARTITION BY RANGE (timestamp)` with identical columns and the `(work_item_id, event_seq)` unique constraint (which must now include `timestamp` — see §4).
4. Create `events_default` and partitions covering the legacy data's `[min(timestamp), max(timestamp)+1 month)` range plus 3 months forward.
5. `INSERT INTO events SELECT * FROM events_legacy`.
6. Recreate indexes (§4) and the `hook_queue.event_id` FK (must be dropped + recreated; see §4).
7. `DROP TABLE events_legacy`.
8. `COMMIT`.

Single transaction; takes a brief exclusive lock; acceptable at regista's current scale.

**Path B — large table, no downtime:** Build the new partitioned table alongside, double-write via a trigger on legacy `events` for the cutover window, backfill in batches, swap names under a short lock, drop trigger. Documented but deferred — Path A is sufficient today and will be sufficient until the spec trigger fires (1M events). When Path B is needed, write it as a separate plan.

Schema-per-project (BR-13) means the migration runs once per `Regista(...).migrate()` call against each project's schema. No cross-schema coordination needed; `SET LOCAL search_path` already scopes DDL (`_connection.py:86`).

## 4. Code Changes

**SQL constraints:**
- Postgres requires the partition key to be part of every unique index. The existing `UNIQUE (work_item_id, event_seq)` (`001_initial.sql:16`) must become `UNIQUE (work_item_id, event_seq, timestamp)`. This is *safe*: `(work_item_id, event_seq)` remains globally unique by construction (allocated under row lock, `_events.py` seq logic), so adding `timestamp` doesn't weaken the invariant. The unique index continues to support `read_events` by-work-item queries.
- The `PRIMARY KEY (event_id)` must similarly become `PRIMARY KEY (event_id, timestamp)`. This is the only breaking-shaped change; consumers don't reference event PK shape, but `hook_queue.event_id REFERENCES events (event_id)` (`001_initial.sql:64`) **cannot** point at a partitioned table's non-unique single-column constraint. Options: (a) drop the FK and rely on application-level integrity, or (b) keep the FK by also adding a unique index on `event_id` alone — Postgres rejects this on a partitioned table because the partition key must be included. We take (a): drop the FK in migration 010, document the loss, and add an integrity check in `replay()` that flags orphan `hook_queue` rows. The hook queue is short-lived (drained continuously), so practical orphan risk is low.
- The `escalation_idempotency` unique index `idx_events_one_escalated` (`migrations/003_escalation_idempotency.sql:1`) is *partial* and on `(work_item_id)`. It must also include `timestamp` to live on a partitioned table, or be re-expressed. Recommended: include `timestamp` and rely on the `transition = 'escalated'` predicate; uniqueness across partitions for a given `work_item_id` is what matters and is preserved by the partial predicate combined with one-escalation-per-work-item business logic (already enforced at append time, `_claims.py:158`).

**Indexes:** all existing indexes (`idx_events_actor_id`, `idx_events_timestamp`, `idx_events_transition`, `idx_events_workflow`, `idx_events_link_type` from `migrations/007_performance_indexes.sql`) are recreated as *local* (per-partition) indexes automatically by Postgres when declared on the parent.

**Note on the supposed `events.work_item_id → work_items.id` FK:** no such FK exists today (verify `001_initial.sql:1-17`); `events` references no other table. So no FK-from-events to drop. The reverse direction (`claims.work_item_id REFERENCES work_items_current`) is unaffected.

**Python layer:** no required changes. All event SQL (`_events.py`, `_event_store.py`, `_replay.py`, `_hooks.py`, `_claims.py:158`, `_links.py:161-167`, `_work_items.py:290-295`) operates on the `events` name; partition routing is transparent. The new `Regista.ensure_event_partitions(months_ahead: int = 3)` method is additive.

## 5. Operational Concerns

- **Partition creation automation:** host calls `ensure_event_partitions()` on the same cadence as `sweep_expired_claims` (e.g. every 5 minutes is overkill but cheap; daily suffices).
- **Monitoring:** new Prometheus gauge `regista_events_partitions_total{project}` and `regista_events_default_partition_rows{project}`. The latter alerts at `> 0`.
- **What breaks if a partition is missing:** inserts into a timestamp with no covering partition land in `events_default`. Reads still work (Postgres scans all partitions including default). The failure mode is *silent correctness* (data is captured) but *operationally noisy* (default partition grows unbounded). The monitoring gauge converts this into a visible alert.
- **Backups:** `pg_dump` of a schema handles partitioned tables natively. No change.
- **Replay cost:** unchanged — replay scans by `work_item_id`, which is index-supported per partition.

## 6. Test Approach

- **Unit (in-memory backend untouched, Postgres backend exercised):**
  - Append events with timestamps spanning 3+ months; verify each row lands in the expected partition via `pg_partition_tree('events')`.
  - Append an event with a far-future timestamp; verify it lands in `events_default` and the monitoring counter increments.
  - `ensure_event_partitions()` idempotency: call twice, verify no duplicate-partition errors.
- **Query correctness:**
  - `read_events_by_time_range` across a partition boundary returns the same rows as today's heap query; compare against an in-memory oracle.
  - `EXPLAIN (ANALYZE)` on `read_events_by_time_range` shows partition pruning (`Subplans Removed`).
- **Migration test:** seed a non-partitioned `events` table with 10k rows spanning 4 months, run migration 010, verify row count, signature re-verification (FR-15) on a sample, and that `replay()` produces identical `ReplayReport` to pre-migration.
- **Conformance:** existing 300-test suite plus the property-based conformance tests in `tests/test_property_conformance.py` must pass unchanged — the contract surface is unaltered.

## 7. Open Questions / Risks

1. **Dropping the `hook_queue.event_id` FK.** Loss of referential integrity at the DB layer is real. Alternative: keep `hook_queue` un-partitioned and accept that `event_id` joins back to `events` only via composite key — but then the FK still can't be expressed. Recommend accepting the drop and compensating in replay.
2. **`idx_events_one_escalated` partial unique index across partitions.** Postgres enforces uniqueness per-partition, not globally. The append-time check in `_claims.py:158` already guards this; we should add an explicit test that two `escalated` events for the same work-item, written into *different* partitions, are still rejected by the application logic.
3. **Schema-per-project at scale.** With N projects × M months of partitions, partition count is N×M. At 30 projects × 36 months = 1080 partitions. Postgres handles this, but `pg_dump` and planner overhead grow. Document the ceiling.
4. **Partition key choice.** `timestamp` (event wall-clock) vs `event_seq`: `event_seq` is per-work-item, not global, so unusable. `timestamp` it is. Edge case: clock skew producing slight backwards-in-time inserts — handled by default partition + monitoring.
5. **Per-project pre-creation horizon.** 3 months ahead is conservative. If a host process dies and no replacement runs `ensure_event_partitions` for >3 months, new events land in `events_default`. Acceptable; alert covers it.

## 8. Out of Scope

- Archival of old partitions (no `DETACH PARTITION` + cold storage logic).
- S3 / object-storage export.
- Retention policy enforcement (deletion of old data).
- A CLI for partition operations.
- Partitioning of `hook_queue`, `hook_dead_letter`, or `work_items_current`.
- Path B (no-downtime migration) implementation — documented, not built.
- Cross-schema or global partition management tooling.
