from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from substrate._errors import SubstrateError
from substrate.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture(scope="module")
def substrate():
    from substrate import Substrate

    project = f"test_idem_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestAC24IdempotencyMismatch:
    def test_same_event_id_different_transition_rejected(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-24 mismatch"},
        )

        eid = uuid.uuid4()
        substrate.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="custom_event_a",
            event_id=eid,
        )

        with pytest.raises(SubstrateError, match="IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD"):
            substrate.append_event(
                work_item_id=wi.work_item_id,
                actor_id="agent-1",
                transition="custom_event_b",
                event_id=eid,
            )

    def test_same_event_id_different_actor_rejected(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-24 actor mismatch"},
        )

        eid = uuid.uuid4()
        substrate.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="custom_event",
            event_id=eid,
        )

        with pytest.raises(SubstrateError, match="IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD"):
            substrate.append_event(
                work_item_id=wi.work_item_id,
                actor_id="agent-2",
                transition="custom_event",
                event_id=eid,
            )

    def test_idempotent_retry_returns_original(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-24 happy retry"},
        )

        eid = uuid.uuid4()
        e1 = substrate.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="custom_event",
            event_id=eid,
        )
        e2 = substrate.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="custom_event",
            event_id=eid,
        )
        assert e1.event_id == e2.event_id
        assert e1.event_seq == e2.event_seq


class TestAC25ExpectedEventSeq:
    def test_expected_seq_mismatch_rejected(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-25"},
        )

        with pytest.raises(SubstrateError, match="CONCURRENT_MODIFICATION"):
            substrate.append_event(
                work_item_id=wi.work_item_id,
                actor_id="agent-1",
                transition="custom_event",
                expected_event_seq=99,
            )

    def test_expected_seq_match_accepted(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-25 ok"},
        )

        evt = substrate.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="custom_event",
            expected_event_seq=2,
        )
        assert evt.event_seq == 2

    def test_expected_seq_on_transition(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
            custom_fields={"title": "AC-25 transition"},
        )

        with pytest.raises(SubstrateError, match="CONCURRENT_MODIFICATION"):
            substrate.transition(
                work_item_id=wi.work_item_id,
                transition_name="start",
                actor_id="agent-1",
                actor_metadata={"role": "agent"},
                expected_event_seq=99,
            )
