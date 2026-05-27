-- Add optional HMAC signing secret to webhook registrations.
-- When set, substrate computes HMAC-SHA256(sign_secret, body) and sends
-- the signature as X-AgentWake-Signature: sha256=<hex> on every delivery.
-- This enables agent-wake's gating layer to verify webhook payloads.
ALTER TABLE webhook_registrations
    ADD COLUMN IF NOT EXISTS sign_secret BYTEA;
