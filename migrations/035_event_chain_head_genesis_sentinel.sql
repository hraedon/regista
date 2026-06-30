-- Plan 024 gap: eliminate the genesis race in _lock_global_chain_head.
--
-- event_chain_head (migration 030) declared head_hash / head_event_id NOT NULL,
-- so the row only exists once the first event has been appended. Before that,
-- `SELECT ... FOR UPDATE` has no row to lock: two concurrent first-events in a
-- fresh schema can both observe an empty table, both acquire prev=NULL, and
-- produce two genesis events — silently forking the global chain.
--
-- Fix: pre-seed a singleton "genesis sentinel" row (head_hash = NULL) at
-- migration time so FOR UPDATE always has a row to lock. The columns must
-- become nullable to admit the sentinel. _lock_global_chain_head returns None
-- (genesis) when head_hash is NULL; once the first event lands it is updated
-- to real values via the existing INSERT ... ON CONFLICT DO UPDATE path.
--
-- Idempotent: ON CONFLICT DO NOTHING leaves any existing head row untouched, so
-- schemas that already have events are unaffected.
--
-- Deploy note: this migration and the `_lock_global_chain_head` change in
-- `_events.py` must ship together. The sentinel stores head_hash = NULL; the
-- old code did `bytes(row["head_hash"])` unconditionally, which TypeErrors on
-- NULL. New code returns None for a NULL head_hash. Applying the migration
-- without the code update breaks the first append in every fresh schema
-- (loudly). The reverse (code without migration) is safe — it degrades to the
-- pre-fix behaviour (no sentinel, genesis race still possible).

ALTER TABLE event_chain_head ALTER COLUMN head_hash DROP NOT NULL;
ALTER TABLE event_chain_head ALTER COLUMN head_event_id DROP NOT NULL;

INSERT INTO event_chain_head (id, head_hash, head_event_id)
VALUES (TRUE, NULL, NULL)
ON CONFLICT (id) DO NOTHING;
