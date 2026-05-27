from __future__ import annotations

from datetime import datetime

import structlog
from psycopg.sql import SQL

from ._connection import ConnectionManager

log = structlog.get_logger()


def archive_events(
    mgr: ConnectionManager,
    schema: str,
    before_timestamp: datetime,
    *,
    dry_run: bool = False,
) -> int:
    with mgr.transaction() as conn:
        count = conn.execute(
            SQL(
                "SELECT count(*) AS c FROM events "
                "WHERE work_item_id IN ("
                "  SELECT work_item_id FROM events "
                "  GROUP BY work_item_id HAVING max(timestamp) < %s"
                ")"
            ),
            [before_timestamp],
        ).fetchone()["c"]

        if dry_run:
            return count

        if count == 0:
            return 0

        conn.execute(
            SQL(
                "INSERT INTO events_archive "
                "SELECT * FROM events "
                "WHERE work_item_id IN ("
                "  SELECT work_item_id FROM events "
                "  GROUP BY work_item_id HAVING max(timestamp) < %s"
                ")"
            ),
            [before_timestamp],
        )
        conn.execute(
            SQL(
                "DELETE FROM hook_queue "
                "WHERE event_id IN ("
                "  SELECT event_id FROM events "
                "  WHERE work_item_id IN ("
                "    SELECT work_item_id FROM events "
                "    GROUP BY work_item_id HAVING max(timestamp) < %s"
                "  )"
                ")"
            ),
            [before_timestamp],
        )
        conn.execute(
            SQL(
                "DELETE FROM witness_receipts "
                "WHERE event_id IN ("
                "  SELECT event_id FROM events "
                "  WHERE work_item_id IN ("
                "    SELECT work_item_id FROM events "
                "    GROUP BY work_item_id HAVING max(timestamp) < %s"
                "  )"
                ")"
            ),
            [before_timestamp],
        )
        conn.execute(
            SQL(
                "DELETE FROM events "
                "WHERE work_item_id IN ("
                "  SELECT work_item_id FROM events "
                "  GROUP BY work_item_id HAVING max(timestamp) < %s"
                ")"
            ),
            [before_timestamp],
        )

    log.info(
        "events.archived",
        project=schema,
        count=count,
        before=before_timestamp.isoformat(),
    )
    return count
