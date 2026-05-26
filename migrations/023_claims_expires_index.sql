-- BC-266: Index for sweep_expired_claims query
CREATE INDEX IF NOT EXISTS idx_claims_expires_at ON claims (expires_at) WHERE expires_at IS NOT NULL;
