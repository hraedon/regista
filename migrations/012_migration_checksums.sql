-- BC-191: Add checksum column to _substrate_migrations for drift detection.
-- The column is BYTEA and nullable so that pre-existing rows (applied before
-- this migration) start with NULL. The runner treats a NULL stored checksum
-- as a "legacy row": it computes and writes the checksum on first pass rather
-- than raising MIGRATION_DRIFT. This keeps the runner simpler than a separate
-- backfill step and requires no operator action on existing production DBs.
ALTER TABLE _substrate_migrations
    ADD COLUMN IF NOT EXISTS checksum BYTEA;
