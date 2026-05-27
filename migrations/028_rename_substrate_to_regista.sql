-- Plan 018 (substrate → regista rename):
--   1. Rename workflow_registry.substrate_version → regista_version.
--   2. Rename _substrate_migrations → _regista_migrations (if old table exists).

ALTER TABLE workflow_registry RENAME COLUMN substrate_version TO regista_version;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = '_substrate_migrations') THEN
        ALTER TABLE _substrate_migrations RENAME TO _regista_migrations;
    END IF;
END $$;
