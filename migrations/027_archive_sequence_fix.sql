-- BC-277: Fix events_archive sharing global_seq sequence with events table.
-- LIKE events INCLUDING ALL copied DEFAULT nextval('events_global_seq_seq'),
-- meaning both tables share one sequence and dropping events would cascade-drop it.
-- Recreate with plain LIKE (columns + types + NOT NULL only, no defaults),
-- then restore non-sequence defaults and add needed indexes.

DROP TABLE IF EXISTS events_archive;

CREATE TABLE events_archive (
    LIKE events
);

-- Restore non-sequence defaults that the archive needs
ALTER TABLE events_archive ALTER COLUMN timestamp SET DEFAULT now();
ALTER TABLE events_archive ALTER COLUMN scheme_id SET DEFAULT 'hmac-sha256';

-- Primary key on event_id for archive lookups
CREATE UNIQUE INDEX events_archive_pkey ON events_archive (event_id);

-- Index on work_item_id for per-work-item archive queries
CREATE INDEX idx_events_archive_work_item_id ON events_archive (work_item_id);

-- Index on timestamp for before_timestamp filtering in archive_events
CREATE INDEX idx_events_archive_timestamp ON events_archive (timestamp);
