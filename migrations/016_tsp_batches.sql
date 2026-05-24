-- Plan 012: RFC 3161 Timestamping on Event Batches
CREATE TABLE tsp_batches (
    batch_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    merkle_root    BYTEA NOT NULL,
    first_event_seq INTEGER NOT NULL,
    last_event_seq  INTEGER NOT NULL,
    first_event_at  TIMESTAMPTZ NOT NULL,
    last_event_at   TIMESTAMPTZ NOT NULL,
    event_count     INTEGER NOT NULL,
    tsa_token       BYTEA,
    tsa_timestamp   TIMESTAMPTZ,
    submitted_at    TIMESTAMPTZ,
    confirmed_at    TIMESTAMPTZ,
    status          TEXT NOT NULL DEFAULT 'pending',
    error_message   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tsp_batches_status ON tsp_batches (status);
CREATE INDEX idx_tsp_batches_confirmed ON tsp_batches (confirmed_at)
    WHERE status = 'confirmed';
