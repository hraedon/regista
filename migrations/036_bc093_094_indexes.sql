DROP INDEX IF EXISTS idx_events_link_type;
DROP INDEX IF EXISTS idx_hook_queue_poll;

CREATE INDEX IF NOT EXISTS idx_events_link_created_type
    ON events (work_item_id, ((payload)->>'link_type'))
    WHERE transition = 'link_created';

CREATE INDEX IF NOT EXISTS idx_events_link_removed_type
    ON events (work_item_id, ((payload)->>'link_type'))
    WHERE transition = 'link_removed';

CREATE INDEX IF NOT EXISTS idx_hook_queue_pending_poll
    ON hook_queue (next_retry_at, id)
    WHERE status = 'pending';
