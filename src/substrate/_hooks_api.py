from __future__ import annotations

from psycopg.sql import SQL

from ._connection import ConnectionManager
from ._hooks import requeue_dead_lettered_hook as _core_requeue
from ._keys import KeySet
from ._observability import Metrics
from ._types import DeadLetterEntry


def refresh_hook_queue_metrics(mgr: ConnectionManager, metrics: Metrics, project: str) -> None:
    with mgr.transaction() as conn:
        counts = conn.execute(
            SQL(
                "SELECT status, COUNT(*) FROM hook_queue WHERE status IN "
                "('pending', 'in_progress', 'completed') GROUP BY status"
            )
        ).fetchall()
        status_counts = {"pending": 0, "in_progress": 0, "completed": 0}
        for row in counts:
            status_counts[row["status"]] = row["count"]

        dead_count = conn.execute(
            SQL("SELECT COUNT(*) FROM hook_dead_letter")
        ).fetchone()["count"]

        for status, count in status_counts.items():
            metrics.set_hook_queue_depth(project, status, count)
        metrics.set_hook_queue_depth(project, "dead_letter", dead_count)


def list_dead_lettered_hooks(mgr: ConnectionManager, limit: int = 100) -> list[DeadLetterEntry]:
    with mgr.transaction() as conn:
        rows = conn.execute(
            SQL(
                "SELECT id, event_id, hook_name, hook_type, payload, retry_count, "
                "max_retries, error_message, dead_lettered_at, original_hook_queue_id "
                "FROM hook_dead_letter ORDER BY dead_lettered_at DESC LIMIT %s"
            ),
            [limit],
        ).fetchall()
        return [
            DeadLetterEntry(
                id=r["id"],
                event_id=r["event_id"],
                hook_name=r["hook_name"],
                hook_type=r["hook_type"],
                payload=r["payload"],
                retry_count=r["retry_count"],
                max_retries=r["max_retries"],
                error_message=r["error_message"],
                dead_lettered_at=r["dead_lettered_at"],
                original_hook_queue_id=r["original_hook_queue_id"],
            )
            for r in rows
        ]


def requeue_dead_lettered_hook(
    mgr: ConnectionManager,
    channel: str,
    key_set: KeySet,
    metrics: Metrics,
    project: str,
    dead_letter_id: int,
) -> None:
    with mgr.transaction() as conn:
        _core_requeue(conn, dead_letter_id, channel, key_set)

