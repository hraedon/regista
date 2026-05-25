-- Plan 013: Witness/co-signature post-append hooks
-- Two tables: witness_registrations (config) and witness_receipts (delivery tracking)

CREATE TABLE witness_registrations (
    witness_id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    url                    TEXT NOT NULL,
    headers                JSONB,
    event_filter           JSONB,
    status                 TEXT NOT NULL DEFAULT 'active',
    max_failures           INTEGER NOT NULL DEFAULT 10,
    consecutive_failures   INTEGER NOT NULL DEFAULT 0,
    max_retries            INTEGER NOT NULL DEFAULT 3,
    last_success_at        TIMESTAMPTZ,
    last_failure_at        TIMESTAMPTZ,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE witness_receipts (
    receipt_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    witness_id          UUID NOT NULL REFERENCES witness_registrations(witness_id),
    event_id            UUID NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending',
    retry_count         INTEGER NOT NULL DEFAULT 0,
    submitted_at        TIMESTAMPTZ,
    last_attempt_at     TIMESTAMPTZ,
    confirmed_at        TIMESTAMPTZ,
    witness_signature   BYTEA,
    witness_response    JSONB,
    error_message       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_witness_registrations_status
    ON witness_registrations (status);
CREATE INDEX idx_witness_receipts_pending
    ON witness_receipts (witness_id, status)
    WHERE status = 'pending';
CREATE INDEX idx_witness_receipts_event
    ON witness_receipts (event_id);
CREATE INDEX idx_witness_receipts_witness_event
    ON witness_receipts (witness_id, event_id);