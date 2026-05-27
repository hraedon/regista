-- Plan 017: Webhook/witness unification
-- BC-269: Merge webhook_registrations into witness_registrations with mode column

-- 1. Add mode column to witness_registrations
ALTER TABLE witness_registrations
    ADD COLUMN IF NOT EXISTS mode TEXT NOT NULL DEFAULT 'witness';

-- 2. Add CHECK constraint for mode
ALTER TABLE witness_registrations
    ADD CONSTRAINT chk_witness_mode CHECK (mode IN ('witness', 'push'));

-- 3. Backfill any existing 'failed' rows to 'paused' BEFORE adding constraints
UPDATE witness_registrations SET status = 'paused' WHERE status = 'failed';
UPDATE witness_receipts SET status = 'paused' WHERE status = 'failed';

-- 4. Unify status: replace 'failed' with 'paused' in CHECK constraints
-- witness_registrations
ALTER TABLE witness_registrations DROP CONSTRAINT IF EXISTS chk_witness_registrations_status;
ALTER TABLE witness_registrations ADD CONSTRAINT chk_witness_registrations_status
    CHECK (status IN ('active', 'paused'));

-- witness_receipts
ALTER TABLE witness_receipts DROP CONSTRAINT IF EXISTS chk_witness_receipts_status;
ALTER TABLE witness_receipts ADD CONSTRAINT chk_witness_receipts_status
    CHECK (status IN ('pending', 'in_progress', 'confirmed', 'paused'));

-- tsp_batches (unchanged from 022, but verify)
-- tsp_batches.status CHECK already uses ('pending','confirmed','failed','superseded') — keep as-is

-- 5. Migrate webhook_registrations into witness_registrations (if table exists)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'webhook_registrations') THEN
        INSERT INTO witness_registrations (
            witness_id, url, headers, event_filter, status, max_failures,
            consecutive_failures, max_retries, mode, created_at, updated_at
        )
        SELECT
            webhook_id,
            url,
            headers,
            jsonb_build_object(
                'transitions', transitions,
                'work_item_types', work_item_types,
                'workflows', workflows
            ),
            CASE WHEN status = 'failed' THEN 'paused' ELSE status END,
            max_failures,
            failure_count,
            1,  -- max_retries=1 for fire-and-forget
            'push',
            created_at,
            created_at
        FROM webhook_registrations;

        DROP TABLE webhook_registrations;
    END IF;
END $$;

-- 6. Add sign_secret to witness_registrations if not present (from migration 025)
ALTER TABLE witness_registrations
    ADD COLUMN IF NOT EXISTS sign_secret BYTEA;

-- 7. Index on mode for listing
CREATE INDEX IF NOT EXISTS idx_witness_registrations_mode
    ON witness_registrations (mode);
