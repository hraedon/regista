from __future__ import annotations

from datetime import datetime
from typing import cast

import structlog
from psycopg.sql import SQL

from ._connection import ConnectionManager
from ._events import _lock_global_chain_head

log = structlog.get_logger()


# BC-290 / BC-293: archival candidates are work-items that are
#   (a) dormant — every event older than the cutoff, and
#   (b) terminal — current_state is a declared terminal state of the
#       work-item's pinned workflow version.
#
# (a) alone (the original behaviour) let a dormant-but-live item — e.g. a
# future not_before, or one parked in a non-terminal state — be archived and
# vanish from the live log while its work_items_current row still claimed it
# was active and potentially claimable. The terminal-state join (BC-293) gates
# archival to genuinely completed work.
#
# Selecting candidates requires joining work_items_current (current_state) with
# workflow_registry (terminal_states), so the candidate set is expressed
# against work_items_current rather than a bare GROUP BY over events.
_SELECT_CANDIDATES = (
    "SELECT wic.work_item_id FROM work_items_current wic "
    "JOIN workflow_registry wr "
    "  ON wr.workflow_name = wic.workflow_name "
    "  AND wr.version = wic.workflow_version "
    "WHERE wic.current_state IN ("
    "  SELECT jsonb_array_elements_text(wr.definition -> 'terminal_states')"
    ") "
    "AND wic.work_item_id IN ("
    "  SELECT work_item_id FROM events "
    "  GROUP BY work_item_id HAVING max(timestamp) < %s"
    ")"
)

_RECHECK_CANDIDATE = (
    "DELETE FROM _archive_candidates c "
    "WHERE NOT EXISTS ("
    "  SELECT 1 FROM work_items_current wic "
    "  JOIN workflow_registry wr "
    "    ON wr.workflow_name = wic.workflow_name "
    "    AND wr.version = wic.workflow_version "
    "  WHERE wic.work_item_id = c.work_item_id "
    "  AND wic.current_state IN ("
    "    SELECT jsonb_array_elements_text(wr.definition -> 'terminal_states')"
    "  ) "
    "  AND wic.work_item_id IN ("
    "    SELECT work_item_id FROM events "
    "    GROUP BY work_item_id HAVING max(timestamp) < %s"
    "  )"
    ")"
)


def archive_events(
    mgr: ConnectionManager,
    schema: str,
    before_timestamp: datetime,
    *,
    dry_run: bool = False,
) -> int:
    with mgr.transaction() as conn:
        # Materialize the candidate set once, up front. It must be captured
        # before any deletes because the selection predicate reads from events
        # (and work_items_current), both of which this function then empties.
        conn.execute(
            SQL(
                "CREATE TEMP TABLE _archive_candidates ON COMMIT DROP AS "
                + _SELECT_CANDIDATES
            ),
            [before_timestamp],
        )

        # Event writers lock a work item before they lock the global sentinel.
        # Take candidate projection rows first, then the sentinel; acquiring
        # them in the opposite order could deadlock with an in-flight writer.
        # Re-check after taking both locks because a writer may have committed
        # a newer, non-terminal event while the row lock was being acquired.
        conn.execute(
            SQL(
                "SELECT wic.work_item_id FROM work_items_current wic "
                "JOIN _archive_candidates c ON c.work_item_id = wic.work_item_id "
                "FOR UPDATE"
            )
        )
        _lock_global_chain_head(conn)
        conn.execute(SQL(_RECHECK_CANDIDATE), [before_timestamp])

        count = cast(
            int,
            conn.execute(
                SQL(
                    "SELECT count(*) AS c FROM events "
                    "WHERE work_item_id IN (SELECT work_item_id FROM _archive_candidates)"
                )
            ).fetchone()["c"],  # type: ignore[index]
        )

        if dry_run or count == 0:
            return count

        conn.execute(
            SQL(
                "INSERT INTO events_archive "
                "SELECT * FROM events "
                "WHERE work_item_id IN (SELECT work_item_id FROM _archive_candidates)"
            )
        )
        # BC-290: preserve a queryable record of the archived projection rows,
        # then remove them from the live projection so it stays fully derivable
        # from the live event log.
        conn.execute(
            SQL(
                "INSERT INTO work_items_archive "
                "SELECT * FROM work_items_current "
                "WHERE work_item_id IN (SELECT work_item_id FROM _archive_candidates)"
            )
        )
        # BC-267: delete FK referrers before deleting the events they point at.
        conn.execute(
            SQL(
                "DELETE FROM hook_queue WHERE event_id IN ("
                "  SELECT event_id FROM events "
                "  WHERE work_item_id IN (SELECT work_item_id FROM _archive_candidates)"
                ")"
            )
        )
        conn.execute(
            SQL(
                "DELETE FROM witness_receipts WHERE event_id IN ("
                "  SELECT event_id FROM events "
                "  WHERE work_item_id IN (SELECT work_item_id FROM _archive_candidates)"
                ")"
            )
        )
        # claims has an FK to work_items_current; clear any residual rows for
        # archived items before deleting the projection rows. Terminal items
        # should not hold a live claim, but this keeps the delete safe.
        conn.execute(
            SQL(
                "DELETE FROM claims "
                "WHERE work_item_id IN (SELECT work_item_id FROM _archive_candidates)"
            )
        )
        conn.execute(
            SQL(
                "DELETE FROM events "
                "WHERE work_item_id IN (SELECT work_item_id FROM _archive_candidates)"
            )
        )
        # BC-290: drop the now-orphaned projection rows in the same transaction.
        conn.execute(
            SQL(
                "DELETE FROM work_items_current "
                "WHERE work_item_id IN (SELECT work_item_id FROM _archive_candidates)"
            )
        )

    log.info(
        "events.archived",
        project=schema,
        count=count,
        before=before_timestamp.isoformat(),
    )
    return count
