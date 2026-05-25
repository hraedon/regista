ALTER TABLE tsp_batches ADD CONSTRAINT chk_tsp_batches_status
    CHECK (status IN ('pending', 'confirmed', 'failed', 'superseded'));

ALTER TABLE witness_registrations ADD CONSTRAINT chk_witness_registrations_status
    CHECK (status IN ('active', 'paused', 'failed'));

ALTER TABLE witness_receipts ADD CONSTRAINT chk_witness_receipts_status
    CHECK (status IN ('pending', 'in_progress', 'confirmed', 'failed'));

DROP INDEX IF EXISTS idx_witness_receipts_witness_event;

CREATE INDEX idx_hook_queue_lease_sweep
    ON hook_queue (lease_expires_at)
    WHERE status = 'in_progress';
