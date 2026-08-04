from __future__ import annotations

import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.sql import SQL, Identifier

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from regista.testing import drop_project_schema

DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test_wi242"
KEY_PATH = str(Path(__file__).parent / "test_keys.json")
WORKFLOW_PATH = str(Path(__file__).parent / "test_workflow.yaml")

# Session-level read-only DSN.
DSN_RO = DSN + "?options=-c%20default_transaction_read_only%3Don"


def _create_project():
    project = f"wi242_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    return sub, project


def _setup_work_item(sub):
    sub.register_actor_role("agent-1", "agent")
    wi, _ = sub.create_work_item(
        "test_workflow", "feature", "agent-1",
        custom_fields={"title": "wi242"},
    )
    sub.transition(
        wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"},
    )
    return wi.work_item_id


class TestReplayNoResidue:
    def test_replay_leaves_no_permanent_replay_tables(self):
        sub, project = _create_project()
        try:
            _setup_work_item(sub)
            report = sub.replay()
            assert report.replayed_ok >= 1
            assert report.replayed_drift == 0
            # No permanent replay tables left in the project schema.
            with psycopg.connect(DSN) as conn:
                rows = conn.execute(
                    "SELECT tablename FROM pg_tables WHERE schemaname = %s "
                    "AND (tablename LIKE 'work_items_current_replay_%%' "
                    "OR tablename LIKE 'replay_report_%%')",
                    [project],
                ).fetchall()
            assert len(rows) == 0, f"permanent residue: {[r[0] for r in rows]}"
        finally:
            sub.close()
            drop_project_schema(DSN, project)


class TestReplayReadOnly:
    def test_replay_works_under_read_only(self):
        sub, project = _create_project()
        try:
            _setup_work_item(sub)
            sub.close()
            # Reconnect read-only and replay.
            sub_ro = Regista(DSN_RO, project, KEY_PATH, read_only=True)
            try:
                report = sub_ro.replay()
                assert report.replayed_ok >= 1
                assert report.replayed_drift == 0
                assert report.table_name is None  # in-memory: no temp table
            finally:
                sub_ro.close()
        finally:
            drop_project_schema(DSN, project)


class TestConnectReadOnly:
    def test_read_only_connect_succeeds_on_migrated_schema(self):
        sub, project = _create_project()
        sub.close()
        try:
            sub_ro = Regista(DSN_RO, project, KEY_PATH, read_only=True)
            try:
                assert sub_ro.project == project
            finally:
                sub_ro.close()
        finally:
            drop_project_schema(DSN, project)

    def test_read_only_connect_fails_closed_on_missing_schema(self):
        with pytest.raises(RegistaError) as exc:
            Regista(DSN_RO, "does_not_exist_schema_xyz", KEY_PATH, read_only=True)
        assert exc.value.code == ErrorCode.DB_NOT_FOUND

    def test_read_only_connect_fails_closed_on_missing_migrations_table(self):
        sub, project = _create_project()
        sub.close()
        # Drop the migrations table so the schema exists but is unmigrated.
        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute(
                SQL("DROP TABLE {}._regista_migrations").format(Identifier(project))
            )
        try:
            with pytest.raises(RegistaError) as exc:
                Regista(DSN_RO, project, KEY_PATH, read_only=True)
            assert exc.value.code == ErrorCode.MIGRATION_REQUIRED
        finally:
            drop_project_schema(DSN, project)

    def test_normal_connect_creates_migrations_table(self):
        sub, project = _create_project()
        sub.close()
        drop_project_schema(DSN, project)
        # Create an empty schema (no migrations table).
        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute(SQL("CREATE SCHEMA {}").format(Identifier(project)))
        try:
            # Normal connect converges schema by creating _regista_migrations.
            with pytest.raises(RegistaError) as exc:
                Regista(DSN, project, KEY_PATH)
            # Migrations are pending (table created empty) -> MIGRATION_REQUIRED.
            assert exc.value.code == ErrorCode.MIGRATION_REQUIRED
            with psycopg.connect(DSN) as conn:
                row = conn.execute(
                    "SELECT 1 FROM information_schema.tables "
                    "WHERE table_schema = %s AND table_name = '_regista_migrations'",
                    [project],
                ).fetchone()
            assert row is not None, "_regista_migrations should have been created"
        finally:
            drop_project_schema(DSN, project)
