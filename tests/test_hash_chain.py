from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from substrate.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def substrate():
    from substrate import Substrate

    project = f"test_hash_chain_{__import__('uuid').uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestBC233HashChain:
    def test_first_event_has_no_prev_hash(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "first"},
        )
        evts = substrate.read_events(work_item_id=wi.work_item_id, limit=1)
        assert evts[0].prev_event_hash is None

    def test_second_event_includes_prev_hash(self, substrate):
        sub = substrate
        sub.register_actor_role("agent-1", "agent")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "chain"},
        )
        # transition creates a second event through the transition path
        sub.transition(
            wi.work_item_id,
            "start",
            "agent-1",
            actor_metadata={"role": "agent"},
        )
        evts = sub.read_events(work_item_id=wi.work_item_id)
        assert len(evts) == 2
        first = evts[0]
        second = evts[1]
        assert second.prev_event_hash is not None
        expected = hashlib.sha256(
            first.canonical_envelope + first.signature
        ).digest()
        assert second.prev_event_hash == expected

    def test_replay_hash_chain_check(self, substrate):
        sub = substrate
        sub.register_actor_role("agent-1", "agent")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "replay"},
        )
        sub.transition(
            wi.work_item_id,
            "start",
            "agent-1",
            actor_metadata={"role": "agent"},
        )
        report = sub.replay()
        assert report.halted == 0
        assert report.warnings == 0

    def test_broken_chain_detected(self, substrate):
        sub = substrate
        sub.register_actor_role("agent-1", "agent")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "tamper"},
        )
        sub.transition(
            wi.work_item_id,
            "start",
            "agent-1",
            actor_metadata={"role": "agent"},
        )

        # Tamper with the second event's prev_event_hash
        with sub._mgr.connect() as conn:
            conn.execute(
                "UPDATE events SET prev_event_hash = %s "
                "WHERE work_item_id = %s AND event_seq = 2",
                [b"\x00" * 32, wi.work_item_id],
            )

        report = sub.replay()
        assert report.warnings >= 1
