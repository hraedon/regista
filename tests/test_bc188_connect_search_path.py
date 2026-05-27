from __future__ import annotations

import uuid
from pathlib import Path

import psycopg

from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")


class TestConnectSetsSearchPath:
    """BC-188 regression: connect() must scope DROP to the configured schema."""

    def test_drop_old_replay_tables_does_not_touch_sibling_schema(self):
        """Two schemas each own a same-named replay table.

        drop_old_replay_tables called against schema A must leave schema B's
        table untouched.
        """
        from regista import Regista
        from regista._replay import drop_old_replay_tables

        schema_a = f"bc188_a_{uuid.uuid4().hex[:8]}"
        schema_b = f"bc188_b_{uuid.uuid4().hex[:8]}"

        sub_a = Regista.create_project(DSN, schema_a, KEY_PATH)
        sub_b = Regista.create_project(DSN, schema_b, KEY_PATH)

        shared_table = "work_items_current_replay_bc188test"

        try:
            with psycopg.connect(DSN) as raw:
                raw.execute(
                    f"CREATE TABLE IF NOT EXISTS {schema_a}.{shared_table} (id int)"
                )
                raw.execute(
                    f"CREATE TABLE IF NOT EXISTS {schema_b}.{shared_table} (id int)"
                )
                raw.commit()

            with sub_a._mgr.connect() as conn:
                drop_old_replay_tables(conn, schema_a)
                conn.commit()

            with psycopg.connect(DSN) as raw:
                row_a = raw.execute(
                    "SELECT 1 FROM pg_tables WHERE schemaname = %s AND tablename = %s",
                    [schema_a, shared_table],
                ).fetchone()
                row_b = raw.execute(
                    "SELECT 1 FROM pg_tables WHERE schemaname = %s AND tablename = %s",
                    [schema_b, shared_table],
                ).fetchone()

            assert row_a is None, (
                f"Table {schema_a}.{shared_table} should have been dropped"
            )
            assert row_b is not None, (
                f"Table {schema_b}.{shared_table} must NOT be dropped — cross-schema contamination"
            )

        finally:
            sub_a.close()
            sub_b.close()
            drop_project_schema(DSN, schema_a)
            drop_project_schema(DSN, schema_b)

    def test_connect_sets_search_path_session(self):
        """connect() must set search_path so unqualified SQL resolves to the project schema."""
        from regista import Regista

        project = f"bc188_sp_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        try:
            with sub._mgr.connect() as conn:
                row = conn.execute(
                    "SHOW search_path"
                ).fetchone()
                search_path = row["search_path"] if row else ""
            assert project in search_path, (
                f"Expected project schema {project!r} in search_path, got {search_path!r}"
            )
        finally:
            sub.close()
            drop_project_schema(DSN, project)
