CREATE TABLE IF NOT EXISTS action_delegation_credentials (
    credential_id uuid PRIMARY KEY,
    credential_hash text NOT NULL UNIQUE,
    document jsonb NOT NULL,
    canonical_document bytea NOT NULL,
    first_event_id uuid NOT NULL,
    first_event_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT action_delegation_hash_shape CHECK (
        credential_hash ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT action_delegation_first_event_hash_shape CHECK (
        first_event_hash ~ '^sha256:[0-9a-f]{64}$'
    )
);

CREATE OR REPLACE FUNCTION refuse_action_delegation_credential_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'action delegation credentials are immutable'
        USING ERRCODE = '55000';
END;
$$;

DROP TRIGGER IF EXISTS action_delegation_credentials_immutable
    ON action_delegation_credentials;

CREATE TRIGGER action_delegation_credentials_immutable
BEFORE UPDATE OR DELETE ON action_delegation_credentials
FOR EACH ROW EXECUTE FUNCTION refuse_action_delegation_credential_mutation();
