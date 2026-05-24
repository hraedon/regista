-- Plan 014: Add global_seq to events for coherent batch timestamping.
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

-- tsp_batches: switch range columns to global_seq. Drop old per-WI columns.
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
