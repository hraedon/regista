CREATE TABLE events (
    event_id UUID PRIMARY KEY,
    work_item_id UUID NOT NULL,
    event_seq INTEGER NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('agent', 'human', 'system')),
    actor_metadata JSONB,
    key_id TEXT NOT NULL,
    workflow_name TEXT,
    workflow_version INTEGER,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    transition TEXT,
    payload JSONB,
    payload_canonical_hash BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    UNIQUE (work_item_id, event_seq)
);

CREATE INDEX idx_events_actor_id ON events (actor_id);
CREATE INDEX idx_events_timestamp ON events (timestamp);
CREATE INDEX idx_events_transition ON events (transition);
CREATE INDEX idx_events_workflow ON events (workflow_name, workflow_version);

CREATE TABLE project_identity (
    id                  BOOLEAN PRIMARY KEY DEFAULT TRUE,
    project_instance_id UUID NOT NULL UNIQUE,
    trust_domain_id     UUID NOT NULL,
    genesis_event_id    UUID NOT NULL UNIQUE,
    genesis_event_hash  BYTEA NOT NULL,
    principal_id        TEXT NOT NULL,
    key_id              TEXT NOT NULL,
    scheme_id           TEXT NOT NULL CHECK (scheme_id = 'ed25519'),
    key_fingerprint     TEXT NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT project_identity_singleton CHECK (id)
);

CREATE TABLE work_items_current (
    work_item_id UUID PRIMARY KEY,
    workflow_name TEXT NOT NULL,
    workflow_version INTEGER NOT NULL,
    work_item_type TEXT NOT NULL,
    current_state TEXT NOT NULL,
    custom_fields JSONB NOT NULL DEFAULT '{}',
    needs_review BOOLEAN NOT NULL DEFAULT false,
    not_before TIMESTAMPTZ,
    last_event_seq INTEGER NOT NULL,
    last_event_at TIMESTAMPTZ NOT NULL,
    next_event_seq INTEGER NOT NULL,
    claimed_by TEXT,
    claim_expires_at TIMESTAMPTZ
);

CREATE INDEX idx_wic_workflow_state ON work_items_current (workflow_name, workflow_version, current_state);
CREATE INDEX idx_wic_claimed_by ON work_items_current (claimed_by) WHERE claimed_by IS NOT NULL;
CREATE INDEX idx_wic_needs_review ON work_items_current (needs_review) WHERE needs_review = true;
CREATE INDEX idx_wic_not_before ON work_items_current (not_before) WHERE not_before IS NOT NULL;

CREATE TABLE claims (
    work_item_id UUID PRIMARY KEY REFERENCES work_items_current (work_item_id),
    actor_id TEXT NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    attempt_number INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE workflow_registry (
    workflow_name TEXT NOT NULL,
    version INTEGER NOT NULL,
    substrate_version TEXT NOT NULL,
    definition JSONB NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workflow_name, version)
);

CREATE TABLE hook_queue (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL REFERENCES events (event_id),
    hook_name TEXT NOT NULL,
    hook_type TEXT NOT NULL CHECK (hook_type IN ('sync', 'async')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'completed', 'failed')),
    payload JSONB,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    next_retry_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE hook_dead_letter (
    id BIGSERIAL PRIMARY KEY,
    event_id UUID NOT NULL,
    hook_name TEXT NOT NULL,
    hook_type TEXT NOT NULL,
    payload JSONB,
    retry_count INTEGER NOT NULL,
    error_message TEXT,
    dead_lettered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    original_hook_queue_id BIGINT
);
