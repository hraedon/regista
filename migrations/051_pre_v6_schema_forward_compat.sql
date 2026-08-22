-- 0.7.2: apply the schema changes that the 0.6.0 cutover placed directly in
-- migration 001. Fresh v6 schemas already have this shape; pre-v6 schemas need
-- forward DDL so migration 049's already-installed epoch-boundary trigger has
-- its referenced relation before writes resume, and so a workflow-less genesis
-- event can be inserted.

ALTER TABLE events ALTER COLUMN workflow_name DROP NOT NULL;
ALTER TABLE events ALTER COLUMN workflow_version DROP NOT NULL;
ALTER TABLE events_archive ALTER COLUMN workflow_name DROP NOT NULL;
ALTER TABLE events_archive ALTER COLUMN workflow_version DROP NOT NULL;

CREATE TABLE IF NOT EXISTS project_identity (
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
