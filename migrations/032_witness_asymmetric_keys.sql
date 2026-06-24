-- BC-297: asymmetric witness keys for independently-verifiable co-signing.
-- Witnesses may register an Ed25519 public key; returned signatures are then
-- verified against it instead of being stored unverified.

ALTER TABLE witness_registrations
    ADD COLUMN IF NOT EXISTS public_key BYTEA,
    ADD COLUMN IF NOT EXISTS key_scheme TEXT NOT NULL DEFAULT 'hmac-sha256';

ALTER TABLE witness_registrations
    ADD CONSTRAINT chk_witness_key_scheme CHECK (
        key_scheme IN ('hmac-sha256', 'ed25519')
    );

ALTER TABLE witness_registrations
    ADD CONSTRAINT chk_witness_pubkey_for_ed25519 CHECK (
        key_scheme != 'ed25519' OR public_key IS NOT NULL
    );

ALTER TABLE witness_receipts
    ADD COLUMN IF NOT EXISTS witness_scheme TEXT;
