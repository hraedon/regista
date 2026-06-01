-- BC-290: archive_events orphaned work_items_current projection rows.
-- Archival deletes events but never touched work_items_current, leaving a
-- projection row no longer derivable from the live event log (replay skipped
-- archived items) and potentially handing out a phantom claimable row.
--
-- Fix option (a): archival now deletes the projection row in the same
-- transaction. To preserve a queryable record of archived items, the row is
-- first copied into work_items_archive (mirrors the events_archive pattern).
--
-- Plain LIKE copies columns + types + NOT NULL only (no defaults, no sequence
-- coupling), matching the BC-277 treatment of events_archive.

CREATE TABLE IF NOT EXISTS work_items_archive (
    LIKE work_items_current
);

CREATE UNIQUE INDEX IF NOT EXISTS work_items_archive_pkey
    ON work_items_archive (work_item_id);

CREATE INDEX IF NOT EXISTS idx_work_items_archive_workflow_state
    ON work_items_archive (workflow_name, workflow_version, current_state);
