-- Regista kernel — fresh schema baseline (proposed line: kernel_schema_version 1).
--
-- Plan 032 F1 calls for "a fresh, clearly versioned schema baseline. No chain of
-- migrations through trust-system schemas is required." This is that baseline,
-- built to settle the §5 extract-versus-sever question with running code.
--
-- The two constraints this exists to remove, both from 001_initial.sql:
--   events.key_id    TEXT  NOT NULL
--   events.signature BYTEA NOT NULL
-- and project_identity, whose NOT NULL trust_domain_id / genesis_event_id /
-- principal_id / key_id / key_fingerprint made opening a project impossible
-- without a cryptographic ceremony.
--
-- What remains is a hash chain, kept for CONSISTENCY only. Per Plan 032 §3:
-- "Unkeyed hashes must never be presented as authenticity evidence." prev_event_hash
-- detects accidental gaps, reordering and truncation on replay. It does not
-- establish who wrote a row, and a party who can write the table can rewrite the
-- chain. The trusted-host/database-administrator boundary is the contract.

CREATE TABLE kernel_meta (
    id                    BOOLEAN PRIMARY KEY DEFAULT TRUE,
    kernel_schema_version INTEGER NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT kernel_meta_singleton CHECK (id)
);

CREATE TABLE workflow_registry (
    workflow_name TEXT    NOT NULL,
    version       INTEGER NOT NULL,
    definition    JSONB   NOT NULL,
    content_hash  BYTEA   NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workflow_name, version)
);

CREATE TABLE work_items_current (
    work_item_id     UUID PRIMARY KEY,
    workflow_name    TEXT    NOT NULL,
    workflow_version INTEGER NOT NULL,
    work_item_type   TEXT    NOT NULL,
    current_state    TEXT    NOT NULL,
    custom_fields    JSONB   NOT NULL DEFAULT '{}',
    last_event_seq   INTEGER NOT NULL,
    next_event_seq   INTEGER NOT NULL,
    last_event_at    TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (workflow_name, workflow_version)
        REFERENCES workflow_registry (workflow_name, version)
);

CREATE INDEX idx_wic_state    ON work_items_current (current_state);
CREATE INDEX idx_wic_workflow ON work_items_current (workflow_name, workflow_version);
CREATE INDEX idx_wic_type     ON work_items_current (work_item_type);

-- Events. No key_id, no signature: an event is attributed, not authenticated.
-- actor_id is caller-supplied attribution, exactly as Plan 032 §1 states.
CREATE TABLE events (
    event_id        UUID PRIMARY KEY,
    work_item_id    UUID    NOT NULL REFERENCES work_items_current (work_item_id),
    event_seq       INTEGER NOT NULL,
    actor_id        TEXT    NOT NULL,
    actor_kind      TEXT    NOT NULL CHECK (actor_kind IN ('agent', 'human', 'system')),
    transition      TEXT,
    payload         JSONB   NOT NULL DEFAULT '{}',
    payload_hash    BYTEA   NOT NULL,
    prev_event_hash BYTEA,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (work_item_id, event_seq)
);

CREATE INDEX idx_events_actor      ON events (actor_id);
CREATE INDEX idx_events_occurred   ON events (occurred_at);
CREATE INDEX idx_events_transition ON events (transition);

-- Durable leases. attempt_number is the fencing token, and Plan 032 §1 requires
-- it be exposed through the public API and required for lease-protected writes.
CREATE TABLE claims (
    work_item_id   UUID PRIMARY KEY REFERENCES work_items_current (work_item_id),
    actor_id       TEXT    NOT NULL,
    attempt_number INTEGER NOT NULL,
    acquired_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_claims_expiry ON claims (expires_at);

-- Monotonic per-item attempt counter. Survives claim rows being deleted, so a
-- fencing token is never reissued after a takeover.
CREATE TABLE claim_attempts (
    work_item_id UUID PRIMARY KEY REFERENCES work_items_current (work_item_id),
    last_attempt INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE links (
    source_id UUID NOT NULL REFERENCES work_items_current (work_item_id),
    target_id UUID NOT NULL REFERENCES work_items_current (work_item_id),
    link_type TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (source_id, target_id, link_type),
    CONSTRAINT links_no_self CHECK (source_id <> target_id)
);

CREATE INDEX idx_links_target ON links (target_id, link_type);

CREATE TABLE idempotency_keys (
    idempotency_key TEXT PRIMARY KEY,
    work_item_id    UUID    NOT NULL,
    event_id        UUID    NOT NULL,
    request_hash    BYTEA   NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
