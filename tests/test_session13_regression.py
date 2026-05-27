from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._testing import raw_transaction
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture(scope="module")
def regista():
    from regista import Regista

    project = f"test_regression_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


def _create_feature(regista, title="regression"):
    wi, _ = regista.create_work_item(
        workflow_name="test_workflow",
        work_item_type="feature",
        actor_id="agent-1",
        custom_fields={"title": title},
    )
    return wi


class TestSweepRaceCondition:
    def test_sweep_does_not_clobber_new_claim(self, regista):
        wi = _create_feature(regista, "sweep-race")
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=1)

        expired_at = datetime.now(UTC) - timedelta(seconds=10)
        with raw_transaction(regista) as conn:
            from psycopg.sql import SQL

            conn.execute(
                SQL("UPDATE claims SET expires_at = %s WHERE work_item_id = %s"),
                [expired_at, wi.work_item_id],
            )
            conn.execute(
                SQL(
                    "UPDATE work_items_current SET claim_expires_at = %s "
                    "WHERE work_item_id = %s"
                ),
                [expired_at, wi.work_item_id],
            )

        regista.sweep_expired_claims()

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.claimed_by is None
        assert refreshed.claim_expires_at is None

    def test_sweep_preserves_claim_reacquired_between_delete_and_lock(self, regista):
        wi = _create_feature(regista, "sweep-race-2")
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=1)

        expired_at = datetime.now(UTC) - timedelta(seconds=10)
        with raw_transaction(regista) as conn:
            from psycopg.sql import SQL

            conn.execute(
                SQL("UPDATE claims SET expires_at = %s WHERE work_item_id = %s"),
                [expired_at, wi.work_item_id],
            )
            conn.execute(
                SQL(
                    "UPDATE work_items_current SET claim_expires_at = %s, claimed_by = 'agent-2' "
                    "WHERE work_item_id = %s"
                ),
                [datetime.now(UTC) + timedelta(seconds=300), wi.work_item_id],
            )

        regista.sweep_expired_claims()

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.claimed_by == "agent-2"


class TestBeforeSeqOrdering:
    def test_before_seq_returns_ascending_order(self, regista):
        wi = _create_feature(regista, "before-seq-order")
        regista.transition(wi.work_item_id, "start", "agent-1",
                            actor_metadata={"role": "agent"})

        events = regista.read_events(
            work_item_id=wi.work_item_id, before_seq=3, limit=10,
        )

        seqs = [e.event_seq for e in events]
        assert seqs == sorted(seqs), f"Expected ascending order, got {seqs}"

    def test_before_seq_excludes_at_and_above(self, regista):
        wi = _create_feature(regista, "before-seq-excl")
        regista.transition(wi.work_item_id, "start", "agent-1",
                            actor_metadata={"role": "agent"})

        events = regista.read_events(
            work_item_id=wi.work_item_id, before_seq=1,
        )

        for e in events:
            assert e.event_seq < 1


class TestTtlSecondsValidation:
    def test_acquire_rejects_zero_ttl(self, regista):
        wi = _create_feature(regista, "ttl-zero")
        with pytest.raises(RegistaError) as exc_info:
            regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=0)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_acquire_rejects_negative_ttl(self, regista):
        wi = _create_feature(regista, "ttl-neg")
        with pytest.raises(RegistaError) as exc_info:
            regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=-5)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_heartbeat_rejects_zero_ttl(self, regista):
        wi = _create_feature(regista, "ttl-heartbeat")
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        with pytest.raises(RegistaError) as exc_info:
            regista.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=0)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT


class TestValidateFieldUpdateRejectsUnknownType:
    def test_rejects_undeclared_type(self):
        from regista._workflow import validate_field_update

        wf_def = {
            "work_item_types": [{"name": "feature", "custom_fields": []}],
            "transitions": [],
        }
        with pytest.raises(RegistaError) as exc_info:
            validate_field_update(wf_def, "nonexistent_type", {"foo": "bar"})
        assert exc_info.value.code == ErrorCode.WORK_ITEM_TYPE_NOT_DECLARED
