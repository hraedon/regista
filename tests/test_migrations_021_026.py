"""Direct test coverage for migrations 021-026 (BC-276)."""
from __future__ import annotations

import uuid

import psycopg
import pytest
from psycopg.sql import SQL, Identifier

from regista import Regista
from regista._testing import drop_project_schema

DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = "tests/test_keys.json"
WORKFLOW_PATH = "tests/test_workflow.yaml"


def _column_exists(conn, schema: str, table: str, column: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_schema = %s AND table_name = %s AND column_name = %s",
        [schema, table, column],
    ).fetchone()
    return row is not None


def _index_exists(conn, schema: str, index_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM pg_indexes "
        "WHERE schemaname = %s AND indexname = %s",
        [schema, index_name],
    ).fetchone()
    return row is not None


def _constraint_exists(conn, schema: str, table: str, constraint_name: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM information_schema.table_constraints "
        "WHERE table_schema = %s AND table_name = %s AND constraint_name = %s",
        [schema, table, constraint_name],
    ).fetchone()
    return row is not None


def _table_exists(conn, schema: str, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM information_schema.tables "
        "WHERE table_schema = %s AND table_name = %s",
        [schema, table],
    ).fetchone()
    return row is not None


@pytest.fixture(scope="module")
def project():
    name = f"mig_021_026_{uuid.uuid4().hex[:8]}"
    yield name
    drop_project_schema(DSN, name)


@pytest.fixture(scope="module")
def sub(project):
    s = Regista.create_project(DSN, project, KEY_PATH)
    with open(WORKFLOW_PATH) as f:
        s.register_workflow(f.read())
    yield s
    s.close()


@pytest.fixture(scope="module")
def schema(project, sub):
    return project


class TestMigration021WitnessReceiptUniqueness:
    def test_unique_index_exists(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _index_exists(conn, schema, "idx_witness_receipts_witness_event_unique")

    def test_duplicate_receipt_rejected(self, schema, sub):
        import uuid as _uuid

        sub.register_witness(
            url="https://example.com/witness",
            headers={"X-Test": "value"},
        )
        witnesses = sub.list_witnesses()
        witness_id = _uuid.UUID(witnesses[0]["witness_id"])

        event_id = _uuid.uuid4()
        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
            conn.execute(
                "INSERT INTO witness_receipts (receipt_id, witness_id, event_id) "
                "VALUES (%s, %s, %s)",
                [_uuid.uuid4(), witness_id, event_id],
            )
            with pytest.raises(psycopg.errors.UniqueViolation):
                conn.execute(
                    "INSERT INTO witness_receipts (receipt_id, witness_id, event_id) "
                    "VALUES (%s, %s, %s)",
                    [_uuid.uuid4(), witness_id, event_id],
                )


class TestMigration022AdversarialReviewFixes:
    def test_tsp_batches_status_check(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _constraint_exists(conn, schema, "tsp_batches", "chk_tsp_batches_status")

    def test_witness_registrations_status_check(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _constraint_exists(
                conn, schema, "witness_registrations", "chk_witness_registrations_status"
            )

    def test_witness_receipts_status_check(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _constraint_exists(
                conn, schema, "witness_receipts", "chk_witness_receipts_status"
            )

    def test_hook_queue_lease_sweep_index(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _index_exists(conn, schema, "idx_hook_queue_lease_sweep")


class TestMigration023ClaimsExpiresIndex:
    def test_claims_expires_at_index(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _index_exists(conn, schema, "idx_claims_expires_at")


class TestMigration024ArchiveAndWebhooks:
    def test_events_archive_table_exists(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _table_exists(conn, schema, "events_archive")

    def test_events_archive_has_same_columns_as_events(self, schema):
        with psycopg.connect(DSN, row_factory=psycopg.rows.dict_row) as conn:
            events_cols = conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = 'events' "
                "ORDER BY ordinal_position",
                [schema],
            ).fetchall()
            archive_cols = conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = 'events_archive' "
                "ORDER BY ordinal_position",
                [schema],
            ).fetchall()
            assert [r["column_name"] for r in events_cols] == [
                r["column_name"] for r in archive_cols
            ]

    def test_webhook_registrations_table_dropped_by_026(self, schema):
        with psycopg.connect(DSN) as conn:
            assert not _table_exists(conn, schema, "webhook_registrations")


class TestMigration027ArchiveSequenceFix:
    def test_archive_global_seq_not_shared_with_events(self, schema):
        with psycopg.connect(DSN, row_factory=psycopg.rows.dict_row) as conn:
            events_default = conn.execute(
                "SELECT column_default FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = 'events' "
                "AND column_name = 'global_seq'",
                [schema],
            ).fetchone()
            archive_default = conn.execute(
                "SELECT column_default FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = 'events_archive' "
                "AND column_name = 'global_seq'",
                [schema],
            ).fetchone()
            assert events_default["column_default"] is not None
            assert "nextval" in events_default["column_default"]
            assert archive_default["column_default"] is None

    def test_archive_has_event_id_index(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _index_exists(conn, schema, "events_archive_pkey")

    def test_archive_has_work_item_id_index(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _index_exists(conn, schema, "idx_events_archive_work_item_id")

    def test_archive_has_timestamp_index(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _index_exists(conn, schema, "idx_events_archive_timestamp")


class TestMigration025WebhookSignSecret:
    def test_sign_secret_column_on_witness_registrations(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _column_exists(conn, schema, "witness_registrations", "sign_secret")


class TestMigration026WebhookWitnessUnification:
    def test_mode_column_exists(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _column_exists(conn, schema, "witness_registrations", "mode")

    def test_mode_check_constraint(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _constraint_exists(conn, schema, "witness_registrations", "chk_witness_mode")

    def test_mode_default_is_witness(self, schema):
        with psycopg.connect(DSN, row_factory=psycopg.rows.dict_row) as conn:
            row = conn.execute(
                "SELECT column_default FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = 'witness_registrations' "
                "AND column_name = 'mode'",
                [schema],
            ).fetchone()
            assert row is not None
            assert "witness" in row["column_default"]

    def test_witness_status_constraint_excludes_failed(self, schema):
        with psycopg.connect(DSN) as conn:
            conn.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO witness_registrations "
                    "(witness_id, url, status, mode) "
                    "VALUES (gen_random_uuid(), 'https://test.com', 'active', 'witness')"
                )
            conn.commit()

            with pytest.raises(psycopg.errors.CheckViolation):
                with conn.cursor() as cur:
                    cur.execute(
                        "INSERT INTO witness_registrations "
                        "(witness_id, url, status, mode) "
                        "VALUES (gen_random_uuid(), 'https://test.com', 'failed', 'witness')"
                    )
                conn.commit()

    def test_witness_receipts_status_constraint_excludes_failed(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _constraint_exists(
                conn, schema, "witness_receipts", "chk_witness_receipts_status"
            )

    def test_mode_index_exists(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _index_exists(conn, schema, "idx_witness_registrations_mode")

    def test_register_witness_with_mode(self, schema, sub):
        import uuid as _uuid

        witness_id = sub.register_witness(
            url="https://example.com/witness-mode-test",
            headers={"X-Test": "value"},
        )
        assert isinstance(witness_id, _uuid.UUID)
        witnesses = sub.list_witnesses()
        match = [w for w in witnesses if w["witness_id"] == str(witness_id)]
        assert len(match) == 1
        assert match[0]["mode"] == "witness"


class TestMigration029WorkItemsArchive:
    def test_work_items_archive_table_exists(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _table_exists(conn, schema, "work_items_archive")

    def test_work_items_archive_has_same_columns_as_current(self, schema):
        with psycopg.connect(DSN, row_factory=psycopg.rows.dict_row) as conn:
            current_cols = conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = 'work_items_current' "
                "ORDER BY ordinal_position",
                [schema],
            ).fetchall()
            archive_cols = conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = 'work_items_archive' "
                "ORDER BY ordinal_position",
                [schema],
            ).fetchall()
            assert [r["column_name"] for r in current_cols] == [
                r["column_name"] for r in archive_cols
            ]

    def test_work_items_archive_has_pkey(self, schema):
        with psycopg.connect(DSN) as conn:
            assert _index_exists(conn, schema, "work_items_archive_pkey")
