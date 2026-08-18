from __future__ import annotations

import os
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.rows import dict_row
from psycopg.sql import SQL, Identifier

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from regista._replay import replay as _replay_fn
from regista.testing import drop_project_schema

DSN = os.environ.get(
    "REGISTA_TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)
KEY_PATH = str(Path(__file__).parent / "test_keys.json")
WORKFLOW_PATH = str(Path(__file__).parent / "test_workflow.yaml")

# Session-level read-only DSN.
DSN_RO = DSN + "?options=-c%20default_transaction_read_only%3Don"


def _can_run() -> bool:
    try:
        conn = psycopg.connect(DSN, connect_timeout=2)
        conn.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _can_run(),
    reason="Postgres not available at regista_test DSN",
)


def _create_project(tmp_path):
    """A project on a clean v6 epoch, plus the keyset a read-only reconnect needs.

    The keyset is returned because the read-only handles below reconnect with their
    own ``Regista``: replay verifies Ed25519 signatures against the key file, so the
    reconnect must load the same actor-role keyset that wrote the events, not
    ``tests/test_keys.json``.
    """

    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project = f"wi242_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path)
    sub = Regista.create_project(DSN, project, keyset.path)
    # Genesis before the workflow registration, which emits a signed
    # `workflow_registered` event.
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    return sub, project, keyset


def _setup_work_item(sub):
    sub.register_actor_role("agent:worker", "agent")
    wi, _ = sub.create_work_item(
        "test_workflow", "feature", "agent:worker",
        custom_fields={"title": "wi242"},
    )
    sub.transition(
        wi.work_item_id, "start", "agent:worker", actor_metadata={"role": "agent"},
    )
    return wi.work_item_id


class TestReplayNoResidue:
    def test_replay_leaves_no_permanent_replay_tables(self, tmp_path):
        sub, project, _keyset = _create_project(tmp_path)
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
    def test_replay_works_under_read_only(self, tmp_path):
        sub, project, keyset = _create_project(tmp_path)
        try:
            _setup_work_item(sub)
            sub.close()
            # Reconnect read-only and replay.
            sub_ro = Regista(DSN_RO, project, keyset.path, read_only=True)
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
    def test_read_only_connect_succeeds_on_migrated_schema(self, tmp_path):
        sub, project, keyset = _create_project(tmp_path)
        sub.close()
        try:
            sub_ro = Regista(DSN_RO, project, keyset.path, read_only=True)
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

    def test_read_only_connect_fails_closed_on_missing_migrations_table(self, tmp_path):
        sub, project, keyset = _create_project(tmp_path)
        sub.close()
        # Drop the migrations table so the schema exists but is unmigrated.
        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute(
                SQL("DROP TABLE {}._regista_migrations").format(Identifier(project))
            )
        try:
            with pytest.raises(RegistaError) as exc:
                Regista(DSN_RO, project, keyset.path, read_only=True)
            assert exc.value.code == ErrorCode.MIGRATION_REQUIRED
        finally:
            drop_project_schema(DSN, project)

    def test_normal_connect_creates_migrations_table(self, tmp_path):
        sub, project, keyset = _create_project(tmp_path)
        sub.close()
        drop_project_schema(DSN, project)
        # Create an empty schema (no migrations table).
        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute(SQL("CREATE SCHEMA {}").format(Identifier(project)))
        try:
            # Normal connect converges schema by creating _regista_migrations.
            with pytest.raises(RegistaError) as exc:
                Regista(DSN, project, keyset.path)
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


class TestReplayEntriesPortable:
    """F1: per-item results must be reachable via `entries` in BOTH modes."""

    def test_normal_mode_populates_entries(self, tmp_path):
        sub, project, _keyset = _create_project(tmp_path)
        try:
            _setup_work_item(sub)
            report = sub.replay()
            # Normal mode: entries is the portable access path and must be
            # populated (not left empty while only table_name is set).
            assert len(report.entries) >= 1, "entries empty in normal mode"
            assert report.table_name is not None
            categories = {e.category for e in report.entries}
            assert categories == {"replayed_ok"}, f"surprise categories: {categories}"
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_read_only_mode_populates_entries(self, tmp_path):
        sub, project, keyset = _create_project(tmp_path)
        try:
            _setup_work_item(sub)
            sub.close()
            sub_ro = Regista(DSN_RO, project, keyset.path, read_only=True)
            try:
                report = sub_ro.replay()
                assert report.table_name is None
                assert len(report.entries) >= 1, "entries empty in read-only mode"
            finally:
                sub_ro.close()
        finally:
            drop_project_schema(DSN, project)

    def test_entries_round_trip_with_warnings(self, tmp_path):
        """F4: per-item warnings are carried on each entry in both modes."""
        sub, project, _keyset = _create_project(tmp_path)
        try:
            _setup_work_item(sub)
            report = sub.replay()
            assert len(report.entries) >= 1, "entries must be populated"
            for e in report.entries:
                assert hasattr(e, "warnings"), "entry missing warnings field"
                assert isinstance(e.warnings, int)
        finally:
            sub.close()
            drop_project_schema(DSN, project)


class TestReplayTempTablesDropped:
    """F3: temp tables must be dropped on the success path, not only on error.

    The concern: a verify-loop daemon reuses pooled connections whose session
    lives for the process lifetime (pool_max_lifetime=None). Without a finally-
    drop, each replay leaks two temp tables on that session forever.
    """

    def test_no_temp_table_residue_after_success(self, tmp_path):
        # Use ONE dedicated connection so we can inspect the same session before
        # and after. We drive the internal replay function directly with a
        # KeySet taken from a live Regista handle.
        sub, project, _keyset = _create_project(tmp_path)
        try:
            _setup_work_item(sub)
            key_set = sub._keys
            schema = sub._mgr.schema
            sub.close()

            with psycopg.connect(DSN, row_factory=dict_row) as conn:
                # Mirror transaction_repeatable_read(): scope search_path to the
                # project schema so unqualified table references resolve.
                conn.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
                report = _replay_fn(conn, schema, project, key_set)
                table_name = report.table_name
                assert table_name is not None
                # The temp table must NOT exist on this same session after a
                # successful replay (finally-drop), proving no residue.
                row = conn.execute(
                    "SELECT 1 FROM pg_class WHERE relname = %s", [table_name]
                ).fetchone()
                assert row is None, (
                    f"temp table {table_name} leaked on the session after success"
                )
        finally:
            drop_project_schema(DSN, project)
