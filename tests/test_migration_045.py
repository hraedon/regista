"""Migration 045 (P1.4): the dead-subsystem tables are dropped, guardedly.

tsp_batches (016), anchor_receipts (041) and event_segments (039) belong to
subsystems P1.4 deleted. Zero rows existed estate-wide (preflight-s1), so the
migration drops the tables — but refuses (P14_DROP_REFUSED_NONEMPTY) if any
table holds rows, because silently dropping rows would destroy audit
evidence. Both directions are proven here: the drop on a fresh store, and the
refusal on a nonempty table.
"""
from __future__ import annotations

import uuid
from pathlib import Path

import psycopg
import pytest
from _helpers import DSN

from regista import Regista
from regista._testing import drop_project_schema

KEY_PATH = "tests/test_keys.json"

MIGRATION_045 = (
    Path(__file__).parent.parent / "migrations" / "045_drop_dead_subsystem_tables.sql"
)


@pytest.fixture(scope="module")
def project():
    name = f"mig_045_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, name, KEY_PATH)
    sub.close()
    yield name
    drop_project_schema(DSN, name)


def _table_exists(conn, schema: str, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = %s AND table_name = %s",
        [schema, table],
    ).fetchone()
    return row is not None


class TestMigration045DropsDeadSubsystemTables:
    @pytest.mark.parametrize(
        "table", ["tsp_batches", "anchor_receipts", "event_segments"]
    )
    def test_table_is_gone_on_a_fresh_store(self, project, table):
        with psycopg.connect(DSN) as conn:
            assert not _table_exists(conn, project, table), (
                f"{table} still exists after migration 045"
            )

    def test_nonempty_table_refuses_the_drop(self, project):
        """The guard is a refusal, not a warning: a nonempty table is audit
        evidence and must be exported and adjudicated, never silently
        dropped. Recreate a nonempty tsp_batches and re-run the 045 SQL."""
        sql = MIGRATION_045.read_text()
        # Commit the nonempty table first: in the real migration flow the
        # table pre-exists the (transactional) migration, so the refusal must
        # roll back only the drop attempt, never the evidence.
        with psycopg.connect(DSN) as conn:
            conn.execute(f'SET search_path TO "{project}"')
            conn.execute(
                "CREATE TABLE tsp_batches (batch_id UUID PRIMARY KEY, note TEXT)"
            )
            conn.execute(
                "INSERT INTO tsp_batches (batch_id, note) VALUES (%s, 'evidence')",
                [uuid.uuid4()],
            )
            conn.commit()
        with psycopg.connect(DSN) as conn:
            conn.execute(f'SET search_path TO "{project}"')
            with pytest.raises(psycopg.errors.CheckViolation) as exc_info:
                conn.execute(sql)
            assert "P14_DROP_REFUSED_NONEMPTY" in str(exc_info.value)
        # The refusal aborted the transaction: the table (and its row) survive.
        with psycopg.connect(DSN) as conn:
            conn.execute(f'SET search_path TO "{project}"')
            row = conn.execute("SELECT count(*) AS n FROM tsp_batches").fetchone()
            assert row[0] == 1, "the refused drop must leave the evidence intact"
        # Clean up so the schema drop fixture is exact about what it removes.
        with psycopg.connect(DSN) as conn:
            conn.execute(f'SET search_path TO "{project}"')
            conn.execute("DROP TABLE tsp_batches")
