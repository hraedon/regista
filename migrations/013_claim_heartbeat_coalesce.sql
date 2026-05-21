-- BC-194: Add last_heartbeat_emitted_at to claims for heartbeat-event coalescing.
ALTER TABLE claims ADD COLUMN last_heartbeat_emitted_at TIMESTAMPTZ;
