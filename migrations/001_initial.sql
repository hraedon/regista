-- Regista 0.8.0 fresh baseline.
--
-- This is a deliberate scope break from 0.7.2: the trust-domain, signing,
-- bundle, witness, hook, recurrence, principal-custody, and suite schemas are
-- gone. There is no migration chain behind this file and no supported in-place
-- upgrade from earlier versions. Initialization creates this schema on an empty
-- destination and refuses old or unknown schemas before writing.

CREATE TABLE events (
    event_id UUID PRIMARY KEY,
    work_item_id UUID NOT NULL,
    entity_kind TEXT NOT NULL DEFAULT 'work_item',
    entity_id UUID NOT NULL,
    event_seq INTEGER NOT NULL,
    actor_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('agent', 'human', 'system')),
    actor_metadata JSONB,
    workflow_name TEXT,
    workflow_version INTEGER,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
    transition TEXT,
    payload JSONB,
    on_behalf_of JSONB,
    UNIQUE (entity_kind, entity_id, event_seq)
);

CREATE INDEX idx_events_actor_id ON events (actor_id);
CREATE INDEX idx_events_timestamp ON events (timestamp);
CREATE INDEX idx_events_transition ON events (transition);
CREATE INDEX idx_events_workflow ON events (workflow_name, workflow_version);
CREATE INDEX idx_events_work_item ON events (work_item_id, event_seq);

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
    claim_expires_at TIMESTAMPTZ,
    attempt_number INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_wic_workflow_state ON work_items_current (workflow_name, workflow_version, current_state);
CREATE INDEX idx_wic_claimed_by ON work_items_current (claimed_by) WHERE claimed_by IS NOT NULL;
CREATE INDEX idx_wic_needs_review ON work_items_current (needs_review) WHERE needs_review = true;
CREATE INDEX idx_wic_not_before ON work_items_current (not_before) WHERE not_before IS NOT NULL;
CREATE INDEX idx_work_items_custom_fields_gin
    ON work_items_current USING GIN (custom_fields jsonb_path_ops);

CREATE TABLE claims (
    work_item_id UUID PRIMARY KEY REFERENCES work_items_current (work_item_id),
    actor_id TEXT NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    attempt_number INTEGER NOT NULL DEFAULT 1,
    last_heartbeat_emitted_at TIMESTAMPTZ
);

CREATE INDEX idx_claims_expires_at ON claims (expires_at);

CREATE TABLE workflow_registry (
    workflow_name TEXT NOT NULL,
    version INTEGER NOT NULL,
    regista_version TEXT NOT NULL,
    definition JSONB NOT NULL,
    content_hash BYTEA,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (workflow_name, version)
);

CREATE TABLE actor_roles (
    actor_id TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (actor_id, role)
);