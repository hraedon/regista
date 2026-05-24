-- Plan 011: Add scheme_id column to events for pluggable signing.
ALTER TABLE events ADD COLUMN scheme_id TEXT NOT NULL DEFAULT 'hmac-sha256';
