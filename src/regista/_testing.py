from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.sql import SQL, Identifier

from ._connection import DictConn, validate_project_name

__all__ = [
    "drop_project_schema",
    "event_count",
    "fetch_events",
    "fetch_work_item_row",
    "raw_transaction",
    "schema_exists",
    "table_exists",
]


@contextmanager
def raw_transaction(regista: Any) -> Generator[DictConn, None, None]:
    with regista._mgr.transaction() as conn:
        yield conn


@contextmanager
def _project_connection(dsn: str, project: str) -> Generator[DictConn, None, None]:
    validate_project_name(project)
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        conn.execute(SQL("SET search_path TO {}").format(Identifier(project)))
        yield conn


def schema_exists(dsn: str, project: str) -> bool:
    """Whether the Postgres schema for *project* exists."""
    validate_project_name(project)
    with psycopg.connect(dsn, autocommit=True) as conn:
        row = conn.execute(
            "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s",
            [project],
        ).fetchone()
        return row is not None


def table_exists(dsn: str, project: str, table: str) -> bool:
    """Whether *table* exists in *project*'s schema."""
    validate_project_name(project)
    with psycopg.connect(dsn, autocommit=True) as conn:
        row = conn.execute(
            "SELECT to_regclass(%s) IS NOT NULL AS present",
            [f"{project}.{table}"],
        ).fetchone()
        return bool(row[0]) if row is not None else False


def fetch_work_item_row(
    dsn: str, project: str, work_item_id: str
) -> dict[str, Any] | None:
    """Return the ``work_items_current`` projection row for a work-item."""
    with _project_connection(dsn, project) as conn:
        row = conn.execute(
            "SELECT * FROM work_items_current WHERE work_item_id = %s",
            [work_item_id],
        ).fetchone()
        return dict(row) if row is not None else None


def event_count(
    dsn: str, project: str, work_item_id: str | None = None
) -> int:
    """Count events in a project, optionally scoped to one work-item."""
    with _project_connection(dsn, project) as conn:
        if work_item_id is None:
            row = conn.execute("SELECT count(*) AS n FROM events").fetchone()
        else:
            row = conn.execute(
                "SELECT count(*) AS n FROM events WHERE work_item_id = %s",
                [work_item_id],
            ).fetchone()
        return int(row["n"]) if row is not None else 0


def fetch_events(
    dsn: str, project: str, work_item_id: str | None = None
) -> list[dict[str, Any]]:
    """Return events in ``event_seq`` order, optionally scoped to one work-item."""
    with _project_connection(dsn, project) as conn:
        if work_item_id is None:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY event_seq"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM events WHERE work_item_id = %s ORDER BY event_seq",
                [work_item_id],
            ).fetchall()
        return [dict(r) for r in rows]


def drop_project_schema(dsn: str, project: str) -> None:
    """Drop the Postgres schema for a project and unregister it from the catalog.

    Also removes the project's row from the ``public.projects`` catalog so the
    schema drop is a full unregister, not just a ``DROP SCHEMA``. Leaving the
    catalog row behind let the test suite accumulate one stale entry per test
    project — tens of thousands in a shared instance — which ``run_doctor``
    then iterated serially.

    Args:
        dsn: Postgres connection string.
        project: Project (schema) name to drop.
    """
    validate_project_name(project)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(Identifier(project)))
        try:
            conn.execute(
                SQL("DELETE FROM {} WHERE schema_name = %s").format(
                    Identifier("public", "projects")
                ),
                [project],
            )
        except psycopg.errors.UndefinedTable:
            pass
