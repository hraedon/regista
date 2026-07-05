-- Plan 028: Event-log retention and archival without breaking the chain.
--
-- event_segments records a sealed contiguous range of the global event chain.
-- Each segment captures the first and last global_seq, the first_event_prev_hash
-- (the global-chain hash the first event chains from), and the head_hash (the
-- hash of the last event's canonical_envelope + signature).  Together these
-- allow replay to bridge across archived ranges without orphan warnings.
--
-- The seal_signature is the HMAC/Ed25519 signature over the canonical seal
-- payload, proving the segment was sealed by a trusted key.  The seal_event_id
-- references the 'segment_sealed' event appended to the events table in the
-- same transaction, so the seal is itself part of the auditable event log.

CREATE TABLE IF NOT EXISTS event_segments (
    segment_id          UUID        PRIMARY KEY,
    first_global_seq    BIGINT      NOT NULL,
    last_global_seq     BIGINT      NOT NULL,
    first_event_id      UUID        NOT NULL,
    last_event_id       UUID        NOT NULL,
    first_event_prev_hash BYTEA,
    head_hash           BYTEA      NOT NULL,
    event_count         INTEGER     NOT NULL,
    min_timestamp       TIMESTAMPTZ NOT NULL,
    max_timestamp       TIMESTAMPTZ NOT NULL,
    seal_signature      BYTEA       NOT NULL,
    seal_event_id       UUID        NOT NULL,
    archive_path        TEXT,
    archived            BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_segment_event_count CHECK (event_count > 0),
    CONSTRAINT chk_segment_seq_order   CHECK (first_global_seq <= last_global_seq)
);

CREATE INDEX IF NOT EXISTS idx_event_segments_first_global_seq
    ON event_segments (first_global_seq);

CREATE INDEX IF NOT EXISTS idx_event_segments_last_global_seq
    ON event_segments (last_global_seq);

CREATE INDEX IF NOT EXISTS idx_event_segments_first_event_prev_hash
    ON event_segments (first_event_prev_hash);

CREATE INDEX IF NOT EXISTS idx_event_segments_head_hash
    ON event_segments (head_hash);
