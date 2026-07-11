-- Plan 019: Transparency-log anchoring.
--
-- Stores Merkle-root anchor receipts published to an external append-only log
-- (OpenTimestamps/Bitcoin, RFC 3161 TSA, or an operator-controlled file).
-- Mirrors tsp_batches (migration 016) but targets an external anchor rather
-- than a TSA token, and tracks the async upgrade path (pending -> confirmed)
-- for calendar-based providers like OpenTimestamps.
CREATE TABLE anchor_receipts (
    receipt_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider          TEXT NOT NULL,
    merkle_root       BYTEA NOT NULL,
    status            TEXT NOT NULL CHECK (status IN ('pending','committed','confirmed','failed')),
    receipt_bytes     BYTEA,
    target_global_seq BIGINT,
    submitted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_at      TIMESTAMPTZ,
    failure_count     INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT
);

CREATE INDEX idx_anchor_receipts_status ON anchor_receipts (status)
    WHERE status IN ('pending', 'committed');
CREATE INDEX idx_anchor_receipts_root ON anchor_receipts (merkle_root);
CREATE INDEX idx_anchor_receipts_seq ON anchor_receipts (target_global_seq);

-- One in-flight receipt per (provider, merkle_root). Prevents duplicate
-- inserts when concurrent trigger_anchoring invocations (e.g. CLI + maintenance
-- thread) race on the same latest_confirmed_seq window and compute the same
-- root. create_anchor_receipt catches UniqueViolation and treats it as a
-- no-op (the race winner has already persisted the receipt).
CREATE UNIQUE INDEX idx_anchor_receipts_provider_root_unique
    ON anchor_receipts (provider, merkle_root);
