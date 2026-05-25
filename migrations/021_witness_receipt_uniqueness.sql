-- BC-238: Prevent duplicate receipts for the same (witness_id, event_id) pair

CREATE UNIQUE INDEX idx_witness_receipts_witness_event_unique
    ON witness_receipts (witness_id, event_id);