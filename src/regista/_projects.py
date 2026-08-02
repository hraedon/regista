"""Projects catalog — shared-schema registry of regista projects (Plan 012).

The catalog lives in ``public.projects`` and is the authoritative source of
truth for which projects exist and who owns each one.  It is the project-level
counterpart to Plan 004's work-item-level team ownership.

All functions take a raw ``psycopg.Connection`` (not a ``ConnectionManager``)
because the catalog is cross-project state in the ``public`` schema — it must
be reachable regardless of the caller's ``search_path``.  Callers pass a
connection from ``mgr.connect()`` or ``mgr.transaction()``; the schema-qualified
``public.projects`` table name makes the query independent of ``search_path``.
"""

from __future__ import annotations

from datetime import UTC
from typing import Any

from psycopg.sql import SQL, Identifier

from ._connection import DictConn
from ._types import ProjectCatalogEntry

_CATALOG_TABLE = SQL("{}.{}").format(Identifier("public"), Identifier("projects"))


def ensure_catalog_table(conn: DictConn) -> None:
    """Create ``public.projects`` if it does not exist.

    Idempotent — safe to call from every project's migration runner.
    """
    conn.execute(
        SQL(
            "CREATE TABLE IF NOT EXISTS {tbl} ("
            "schema_name TEXT PRIMARY KEY, "
            "display_name TEXT, "
            "owner_actor_id TEXT, "
            "created_by TEXT, "
            "created_at TIMESTAMPTZ NOT NULL DEFAULT now()"
            ")"
        ).format(tbl=_CATALOG_TABLE)
    )


def register_project(
    conn: DictConn,
    schema_name: str,
    display_name: str | None = None,
    owner_actor_id: str | None = None,
    created_by: str | None = None,
) -> ProjectCatalogEntry:
    """Insert or update a project's catalog row.

    Uses ``ON CONFLICT (schema_name) DO UPDATE`` so calling this on an
    already-registered project updates its ``display_name`` / ``owner`` /
    ``created_by`` without error.  ``created_at`` is preserved on update.
    """
    ensure_catalog_table(conn)
    row = conn.execute(
        SQL(
            "INSERT INTO {tbl} (schema_name, display_name, owner_actor_id, created_by) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (schema_name) DO UPDATE SET "
            "display_name = EXCLUDED.display_name, "
            "owner_actor_id = EXCLUDED.owner_actor_id, "
            "created_by = EXCLUDED.created_by "
            "RETURNING schema_name, display_name, owner_actor_id, created_by, created_at"
        ).format(tbl=_CATALOG_TABLE),
        [schema_name, display_name, owner_actor_id, created_by],
    ).fetchone()
    assert row is not None
    return _row_to_entry(row)


def list_catalog_projects(conn: DictConn) -> list[ProjectCatalogEntry]:
    """Return all registered projects, ordered by schema_name."""
    ensure_catalog_table(conn)
    rows = conn.execute(
        SQL(
            "SELECT schema_name, display_name, owner_actor_id, created_by, created_at "
            "FROM {tbl} ORDER BY schema_name"
        ).format(tbl=_CATALOG_TABLE)
    ).fetchall()
    return [_row_to_entry(r) for r in rows]


def get_catalog_project(conn: DictConn, schema_name: str) -> ProjectCatalogEntry | None:
    """Return one project's catalog row, or ``None`` if not registered."""
    ensure_catalog_table(conn)
    row = conn.execute(
        SQL(
            "SELECT schema_name, display_name, owner_actor_id, created_by, created_at "
            "FROM {tbl} WHERE schema_name = %s"
        ).format(tbl=_CATALOG_TABLE),
        [schema_name],
    ).fetchone()
    return _row_to_entry(row) if row else None


def set_catalog_owner(
    conn: DictConn,
    schema_name: str,
    owner_actor_id: str | None,
    updated_by: str | None = None,
) -> ProjectCatalogEntry:
    """Set or clear the owner for a project.

    Auto-registers the project if it is not yet in the catalog (upsert).
    ``updated_by`` is recorded in ``created_by`` (the row's last-modified-by
    field in MVP — a separate ``updated_by`` column is a later refinement).
    """
    ensure_catalog_table(conn)
    row = conn.execute(
        SQL(
            "INSERT INTO {tbl} (schema_name, owner_actor_id, created_by) "
            "VALUES (%s, %s, %s) "
            "ON CONFLICT (schema_name) DO UPDATE SET "
            "owner_actor_id = EXCLUDED.owner_actor_id, "
            "created_by = EXCLUDED.created_by "
            "RETURNING schema_name, display_name, owner_actor_id, created_by, created_at"
        ).format(tbl=_CATALOG_TABLE),
        [schema_name, owner_actor_id, updated_by],
    ).fetchone()
    assert row is not None
    return _row_to_entry(row)


def _row_to_entry(row: dict[str, Any]) -> ProjectCatalogEntry:
    created_at = row["created_at"]
    if created_at is not None and created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    return ProjectCatalogEntry(
        schema_name=row["schema_name"],
        display_name=row["display_name"],
        owner_actor_id=row["owner_actor_id"],
        created_by=row["created_by"],
        created_at=created_at,
    )
