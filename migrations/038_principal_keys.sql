-- Plan 026 WI-1.1: Principal → public-key registry.
--
-- Binds a principal_id to one or more public keys with validity windows,
-- enabling per-actor cryptographic non-repudiation.  Each principal can
-- have multiple key entries for rotation; old keys stay valid for their
-- historical events while new signing uses the latest active key.
--
-- This is a per-project table (lives in the project's schema) because a
-- principal's signing identity is scoped to a project.  A shared-catalog
-- option can be added later if principals span projects (Plan 026 §3).
--
-- Registration/rotation/revocation events are emitted as signed regista
-- events (actor_id = "system" or the enrolling principal), so the registry
-- itself is auditable.

CREATE TABLE IF NOT EXISTS principal_keys (
    principal_id    TEXT        NOT NULL,
    key_id          TEXT        NOT NULL,
    scheme          TEXT        NOT NULL DEFAULT 'ed25519',
    public_key      BYTEA       NOT NULL,
    fingerprint     TEXT        NOT NULL,
    status          TEXT        NOT NULL DEFAULT 'active',
    valid_from      TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_to        TIMESTAMPTZ,
    registered_by   TEXT        NOT NULL,
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    revoked_reason  TEXT,

    PRIMARY KEY (principal_id, key_id)
);

ALTER TABLE principal_keys
    ADD CONSTRAINT chk_principal_key_status CHECK (
        status IN ('active', 'revoked', 'superseded')
    );

ALTER TABLE principal_keys
    ADD CONSTRAINT chk_principal_key_scheme CHECK (
        scheme IN ('hmac-sha256', 'ed25519')
    );

CREATE UNIQUE INDEX IF NOT EXISTS uq_principal_keys_one_active
    ON principal_keys (principal_id)
    WHERE status = 'active';
