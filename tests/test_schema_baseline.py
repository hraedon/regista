from __future__ import annotations

import os
import uuid

import psycopg
import pytest
from psycopg.sql import SQL, Identifier

from regista import Regista, RegistaError
from regista._errors import ErrorCode
from regista._testing import (
    drop_project_schema,
    schema_exists,
    table_exists,
)
from regista._version_info import SCHEMA_VERSION

_DEFAULT_DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"


def _resolve_dsn() -> str:
    try:
        import conftest
    except ImportError:
        return os.environ.get("REGISTA_TEST_DSN", _DEFAULT_DSN)
    return getattr(conftest, "DSN", os.environ.get("REGISTA_TEST_DSN", _DEFAULT_DSN))


DSN = _resolve_dsn()

BASELINE_TABLES = (
    "events",
    "work_items_current",
    "claims",
    "workflow_registry",
    "actor_roles",
    "_regista_migrations",
)


def _new_project(prefix: str) -> str:
    return f"kbl_{prefix}_{uuid.uuid4().hex[:10]}"


def _create_raw_schema(project: str, statements: list[str]) -> None:
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(SQL("CREATE SCHEMA {}").format(Identifier(project)))
        conn.execute(SQL("SET search_path TO {}").format(Identifier(project)))
        for stmt in statements:
            conn.execute(stmt)


def _table_row_count(project: str, table: str) -> int:
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(SQL("SET search_path TO {}").format(Identifier(project)))
        row = conn.execute(
            SQL("SELECT count(*) FROM {}").format(Identifier(table))
        ).fetchone()
        assert row is not None
        return int(row[0])


def test_schema_version_is_one() -> None:
    assert SCHEMA_VERSION == 1


def test_create_project_applies_single_baseline() -> None:
    project = _new_project("fresh")
    try:
        sub = Regista.create_project(DSN, project)
        try:
            assert sub.project == project
        finally:
            sub.close()

        assert schema_exists(DSN, project)
        for table in BASELINE_TABLES:
            assert table_exists(DSN, project, table), f"missing {table}"

        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute(SQL("SET search_path TO {}").format(Identifier(project)))
            rows = conn.execute(
                "SELECT version FROM _regista_migrations ORDER BY version"
            ).fetchall()
        assert [r[0] for r in rows] == [1]
    finally:
        drop_project_schema(DSN, project)


def test_open_existing_project_succeeds(sub: Regista) -> None:
    reopened = Regista(DSN, sub.project)
    try:
        assert reopened.project == sub.project
    finally:
        reopened.close()


def test_open_missing_project_raises_clear_error() -> None:
    project = _new_project("missing")
    with pytest.raises(RegistaError) as exc_info:
        Regista(DSN, project)
    assert exc_info.value.code is ErrorCode.DB_NOT_FOUND


def test_untracked_events_schema_is_refused_without_mutation() -> None:
    project = _new_project("untracked")
    try:
        _create_raw_schema(
            project,
            [
                "CREATE TABLE events (event_id UUID PRIMARY KEY)",
            ],
        )
        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute(SQL("SET search_path TO {}").format(Identifier(project)))
            conn.execute(
                "INSERT INTO events (event_id) VALUES (%s)",
                [str(uuid.uuid4())],
            )

        with pytest.raises(RegistaError) as exc_info:
            Regista.create_project(DSN, project)

        assert exc_info.value.code is ErrorCode.UNSUPPORTED_SCHEMA_VERSION
        assert table_exists(DSN, project, "events")
        assert _table_row_count(project, "events") == 1
        assert not table_exists(DSN, project, "_regista_migrations")
    finally:
        drop_project_schema(DSN, project)


def test_unknown_schema_version_is_refused_without_mutation() -> None:
    project = _new_project("v99")
    try:
        _create_raw_schema(
            project,
            [
                "CREATE TABLE events (event_id UUID PRIMARY KEY)",
                (
                    "CREATE TABLE _regista_migrations ("
                    "version INTEGER PRIMARY KEY, "
                    "applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
                ),
            ],
        )
        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute(SQL("SET search_path TO {}").format(Identifier(project)))
            conn.execute(
                "INSERT INTO events (event_id) VALUES (%s)",
                [str(uuid.uuid4())],
            )
            conn.execute("INSERT INTO _regista_migrations (version) VALUES (99)")

        with pytest.raises(RegistaError) as exc_info:
            Regista.create_project(DSN, project)

        assert exc_info.value.code is ErrorCode.UNSUPPORTED_SCHEMA_VERSION
        assert _table_row_count(project, "events") == 1
        assert _table_row_count(project, "_regista_migrations") == 1
    finally:
        drop_project_schema(DSN, project)
