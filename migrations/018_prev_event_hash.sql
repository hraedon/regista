-- BC-233: Add prev_event_hash to events for tamper-evident hash chaining.
ALTER TABLE events
    ADD COLUMN prev_event_hash BYTEA;
