-- Plan 022 Phase 1: Entity generalization + crypto-agility envelope v4.
--
-- Adds entity_kind, entity_id, and hash_alg columns to the events table.
-- work_item_id is retained as a compat column through a deprecation window.
-- Existing rows are backfilled: entity_kind='work_item', entity_id=work_item_id,
-- hash_alg='sha-256'.
--
-- The UNIQUE(work_item_id, event_seq) constraint is replaced with
-- UNIQUE(entity_kind, entity_id, event_seq) to support future entity kinds.
-- work_item_id remains for read compat but is no longer the uniqueness key.

ALTER TABLE events ADD COLUMN entity_kind TEXT NOT NULL DEFAULT 'work_item';
ALTER TABLE events ADD COLUMN entity_id UUID;
ALTER TABLE events ADD COLUMN hash_alg TEXT NOT NULL DEFAULT 'sha-256';

UPDATE events SET entity_id = work_item_id;

ALTER TABLE events ALTER COLUMN entity_id SET NOT NULL;

ALTER TABLE events_archive ADD COLUMN IF NOT EXISTS entity_kind TEXT NOT NULL DEFAULT 'work_item';
ALTER TABLE events_archive ADD COLUMN IF NOT EXISTS entity_id UUID;
ALTER TABLE events_archive ADD COLUMN IF NOT EXISTS hash_alg TEXT NOT NULL DEFAULT 'sha-256';

UPDATE events_archive SET entity_id = work_item_id WHERE entity_id IS NULL;

ALTER TABLE events DROP CONSTRAINT IF EXISTS events_work_item_id_event_seq_key;

ALTER TABLE events ADD CONSTRAINT events_entity_event_seq_key
    UNIQUE (entity_kind, entity_id, event_seq);

CREATE INDEX IF NOT EXISTS idx_events_entity ON events (entity_kind, entity_id, event_seq);
CREATE INDEX IF NOT EXISTS idx_events_archive_entity ON events_archive (entity_kind, entity_id, event_seq);

CREATE OR REPLACE FUNCTION regista_set_entity_id()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.entity_id IS NULL THEN
        NEW.entity_id = NEW.work_item_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER events_set_entity_id
    BEFORE INSERT ON events
    FOR EACH ROW
    EXECUTE FUNCTION regista_set_entity_id();
