-- Plan 031 / WI-273: persist the authority selected for a lifecycle operation.
--
-- The binding is part of the prepared operation, not an inferred commit-time
-- default.  NULL is retained for historical/pre-contract rows; such a row is
-- refused by the v6 lifecycle commit path rather than upgraded by guesswork.

ALTER TABLE lifecycle_operations
    ADD COLUMN IF NOT EXISTS authority_binding JSONB;

ALTER TABLE lifecycle_operations
    ADD COLUMN IF NOT EXISTS new_key_id TEXT;

ALTER TABLE lifecycle_operations
    ADD COLUMN IF NOT EXISTS root_signatures JSONB NOT NULL DEFAULT '[]'::jsonb;

ALTER TABLE lifecycle_operations
    ADD COLUMN IF NOT EXISTS old_key_signature BYTEA;
