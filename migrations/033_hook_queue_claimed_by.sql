ALTER TABLE hook_queue ADD COLUMN IF NOT EXISTS claimed_by TEXT;
UPDATE hook_queue SET status = 'pending', lease_expires_at = NULL, claimed_by = NULL, updated_at = now() WHERE status = 'in_progress';
