-- Migration 040: Add work_item_ids and event_ids to event_segments (Plan 028 Finding 2).
--
-- work_item_ids: the work-item UUIDs whose events are included in the segment.
--   Used by seal_segment to skip work-items already covered by an existing
--   segment (replacing the high-water mark filter that was incompatible with
--   terminal-only sealing).
--
-- event_ids: the UUIDs of every event in the segment.  Used by verify_segment
--   to read exactly the segment's events — not every event in the global_seq
--   range, which may include events from non-terminal work-items that were
--   excluded from the segment.

ALTER TABLE event_segments ADD COLUMN IF NOT EXISTS work_item_ids UUID[] NOT NULL DEFAULT '{}';
ALTER TABLE event_segments ADD COLUMN IF NOT EXISTS event_ids UUID[] NOT NULL DEFAULT '{}';

-- Backfill existing segments from the events table so that deduplication and
-- verification work correctly for segments created before this migration.
UPDATE event_segments s
SET
    work_item_ids = COALESCE((
        SELECT ARRAY_AGG(DISTINCT e.work_item_id)
        FROM events e
        WHERE e.global_seq BETWEEN s.first_global_seq AND s.last_global_seq
        AND e.entity_kind != 'segment'
    ), '{}'::UUID[]),
    event_ids = COALESCE((
        SELECT ARRAY_AGG(e.event_id ORDER BY e.global_seq)
        FROM events e
        WHERE e.global_seq BETWEEN s.first_global_seq AND s.last_global_seq
    ), '{}'::UUID[])
WHERE s.work_item_ids = '{}';


