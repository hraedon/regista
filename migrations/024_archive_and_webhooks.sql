-- BC-258: Events archive table
CREATE TABLE IF NOT EXISTS events_archive (
    LIKE events INCLUDING ALL
);

-- BC-261: Webhook registrations
CREATE TABLE IF NOT EXISTS webhook_registrations (
    webhook_id UUID PRIMARY KEY,
    url TEXT NOT NULL,
    headers JSONB,
    transitions TEXT[],
    work_item_types TEXT[],
    workflows TEXT[],
    status TEXT NOT NULL DEFAULT 'active',
    failure_count INTEGER NOT NULL DEFAULT 0,
    max_failures INTEGER NOT NULL DEFAULT 10,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT chk_webhook_status CHECK (status IN ('active', 'paused', 'failed'))
);

CREATE INDEX IF NOT EXISTS idx_webhook_registrations_status ON webhook_registrations (status) WHERE status = 'active';
