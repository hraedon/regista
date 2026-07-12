-- Plan 031 Phase 1+2: Durable principal lifecycle operations.
--
-- Stores prepared lifecycle operations, possession challenges, approvals,
-- effective receipts, and reconciliation state.  The lifecycle_operations
-- table is the durable counterpart of the in-memory PrincipalLifecycle
-- state: prepare persists here, commit transitions to 'committed', and
-- effective receipts transition to 'effective' or 'partially_effective'.
--
-- These are per-project tables (live in the project's schema) because
-- lifecycle operations are scoped to a single project.

CREATE TABLE IF NOT EXISTS lifecycle_operations (
    operation_id            UUID         PRIMARY KEY,
    idempotency_key          TEXT         NOT NULL UNIQUE,
    operation_type           TEXT         NOT NULL,
    state                    TEXT         NOT NULL,
    project                  TEXT         NOT NULL,
    principal_id             TEXT         NOT NULL,
    principal_kind           TEXT         NOT NULL,
    actor_id                 TEXT         NOT NULL,
    reason                   TEXT         NOT NULL,
    requested_authority      TEXT         NOT NULL,
    policy_version           TEXT         NOT NULL,
    digest_value             TEXT         NOT NULL,
    digest_algorithm         TEXT         NOT NULL,
    digest_version           TEXT         NOT NULL,
    public_key               BYTEA,
    fingerprint              TEXT,
    scheme                   TEXT,
    custody_mode             TEXT,
    old_key_id               TEXT,
    identity_binding_digest  TEXT,
    protected_options        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at               TIMESTAMPTZ  NOT NULL,
    expires_at               TIMESTAMPTZ  NOT NULL,
    committed_at             TIMESTAMPTZ,
    receipt_key_id           TEXT
);

ALTER TABLE lifecycle_operations
    DROP CONSTRAINT IF EXISTS chk_lifecycle_op_type;
ALTER TABLE lifecycle_operations
    ADD CONSTRAINT chk_lifecycle_op_type CHECK (
        operation_type IN ('enrollment', 'rotation', 'revocation')
    );

ALTER TABLE lifecycle_operations
    DROP CONSTRAINT IF EXISTS chk_lifecycle_op_state;
ALTER TABLE lifecycle_operations
    ADD CONSTRAINT chk_lifecycle_op_state CHECK (
        state IN (
            'draft', 'prepared', 'awaiting_proof', 'awaiting_approval',
            'approved', 'committing', 'committed', 'effective',
            'partially_effective', 'failed', 'expired', 'cancelled',
            'repair_required', 'superseded'
        )
    );

ALTER TABLE lifecycle_operations
    DROP CONSTRAINT IF EXISTS chk_lifecycle_op_kind;
ALTER TABLE lifecycle_operations
    ADD CONSTRAINT chk_lifecycle_op_kind CHECK (
        principal_kind IN ('human', 'agent', 'service', 'break_glass')
    );

CREATE INDEX IF NOT EXISTS ix_lifecycle_ops_principal
    ON lifecycle_operations (principal_id);

CREATE INDEX IF NOT EXISTS ix_lifecycle_ops_project_principal
    ON lifecycle_operations (project, principal_id);

CREATE INDEX IF NOT EXISTS ix_lifecycle_ops_state
    ON lifecycle_operations (state);


CREATE TABLE IF NOT EXISTS lifecycle_challenges (
    challenge_id     UUID         PRIMARY KEY,
    operation_id     UUID         NOT NULL REFERENCES lifecycle_operations(operation_id),
    operation_digest TEXT         NOT NULL,
    project          TEXT         NOT NULL,
    principal_id     TEXT         NOT NULL,
    fingerprint      TEXT         NOT NULL,
    scheme           TEXT         NOT NULL,
    verifier_nonce   TEXT         NOT NULL,
    issued_at        TIMESTAMPTZ  NOT NULL,
    expires_at       TIMESTAMPTZ  NOT NULL,
    used             BOOLEAN      NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS ix_lifecycle_challenges_op
    ON lifecycle_challenges (operation_id);


CREATE TABLE IF NOT EXISTS lifecycle_approvals (
    approval_id        UUID         PRIMARY KEY,
    operation_id       UUID         NOT NULL REFERENCES lifecycle_operations(operation_id),
    operation_digest   TEXT         NOT NULL,
    approver_id        TEXT         NOT NULL,
    approver_kind      TEXT         NOT NULL,
    approval_digest    TEXT         NOT NULL,
    step_up_evidence   TEXT,
    reason             TEXT         NOT NULL DEFAULT '',
    approved_at        TIMESTAMPTZ  NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_lifecycle_approvals_op
    ON lifecycle_approvals (operation_id);

CREATE INDEX IF NOT EXISTS ix_lifecycle_approvals_approver
    ON lifecycle_approvals (approver_id);


CREATE TABLE IF NOT EXISTS lifecycle_effective_receipts (
    operation_id     UUID         PRIMARY KEY REFERENCES lifecycle_operations(operation_id),
    operation_digest  TEXT         NOT NULL,
    project          TEXT         NOT NULL,
    principal_id     TEXT         NOT NULL,
    fingerprint      TEXT         NOT NULL,
    client_type      TEXT         NOT NULL,
    client_version   TEXT         NOT NULL,
    status           TEXT         NOT NULL,
    observed_at      TIMESTAMPTZ  NOT NULL
);

ALTER TABLE lifecycle_effective_receipts
    DROP CONSTRAINT IF EXISTS chk_lifecycle_eff_status;
ALTER TABLE lifecycle_effective_receipts
    ADD CONSTRAINT chk_lifecycle_eff_status CHECK (
        status IN ('effective', 'committed_not_effective', 'rejected')
    );

CREATE INDEX IF NOT EXISTS ix_lifecycle_eff_receipts_principal
    ON lifecycle_effective_receipts (principal_id);
