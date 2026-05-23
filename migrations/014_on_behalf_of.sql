-- BC-197: Add delegation chain to events for on-behalf-of tracking.
ALTER TABLE events ADD COLUMN on_behalf_of JSONB;
