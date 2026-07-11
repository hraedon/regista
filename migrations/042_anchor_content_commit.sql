-- Plan 019 F-1/F-3: Content-committing anchor and retry state.
--
-- F-1: The anchor now commits to the global chain head (sha256 of
-- canonical_envelope + signature) rather than a Merkle root of event UUIDs.
-- The binding fields (project_name, envelope_version, hash_algorithm) are
-- stored on the receipt so verification can recompute the anchor from live
-- events without ambiguity.
--
-- F-3: Add 'retryable' to the status CHECK constraint so transient failures
-- can be retried without creating a duplicate receipt.

ALTER TABLE anchor_receipts
    ADD COLUMN IF NOT EXISTS project_name TEXT,
    ADD COLUMN IF NOT EXISTS envelope_version INTEGER,
    ADD COLUMN IF NOT EXISTS hash_algorithm TEXT;

ALTER TABLE anchor_receipts DROP CONSTRAINT IF EXISTS anchor_receipts_status_check;
ALTER TABLE anchor_receipts ADD CONSTRAINT anchor_receipts_status_check
    CHECK (status IN ('pending', 'committed', 'confirmed', 'failed', 'retryable'));
