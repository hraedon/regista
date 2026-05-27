from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def regista():
    from regista import Regista

    project = f"test_hash_chain_{__import__('uuid').uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestBC233HashChain:
    def test_first_event_has_no_prev_hash(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "first"},
        )
        evts = regista.read_events(work_item_id=wi.work_item_id, limit=1)
        assert evts[0].prev_event_hash is None

    def test_second_event_includes_prev_hash(self, regista):
        sub = regista
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

    def test_replay_hash_chain_check(self, regista):
        sub = regista
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

    def test_broken_chain_detected(self, regista):
        sub = regista
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

    def test_append_event_api_persists_prev_hash(self, regista):
        sub = regista
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "append"},
        )
        sub.append_event(
            wi.work_item_id,
            "agent-1",
            transition="note",
            payload={"msg": "hello"},
        )
        evts = sub.read_events(work_item_id=wi.work_item_id)
        assert len(evts) == 2
        assert evts[0].prev_event_hash is None
        assert evts[1].prev_event_hash is not None
        expected = hashlib.sha256(
            evts[0].canonical_envelope + evts[0].signature
        ).digest()
        assert evts[1].prev_event_hash == expected

    def test_multi_event_chain(self, regista):
        sub = regista
        sub.register_actor_role("agent-1", "agent")
        sub.register_actor_role("reviewer-1", "reviewer")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "multi"},
        )
        sub.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )
        sub.transition(
            wi.work_item_id, "submit_review", "agent-1",
            actor_metadata={"role": "agent"},
        )
        sub.transition(
            wi.work_item_id, "approve", "reviewer-1",
            actor_metadata={"role": "reviewer"},
        )

        evts = regista.read_events(work_item_id=wi.work_item_id)
        assert len(evts) >= 3

        assert evts[0].prev_event_hash is None

        for i in range(1, len(evts)):
            prev = evts[i - 1]
            cur = evts[i]
            assert cur.prev_event_hash is not None
            expected = hashlib.sha256(
                prev.canonical_envelope + prev.signature
            ).digest()
            assert cur.prev_event_hash == expected

        report = sub.replay()
        assert report.halted == 0
        assert report.warnings == 0


class TestBC233HashChainInMemory:
    def test_first_event_has_no_prev_hash(self):
        sub = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "first"},
        )
        evts = sub.read_events(work_item_id=wi.work_item_id, limit=1)
        assert evts[0].prev_event_hash is None

    def test_second_event_includes_prev_hash(self):
        sub = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        sub.register_actor_role("agent-1", "agent")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "chain"},
        )
        sub.transition(
            wi.work_item_id, "start", "agent-1",
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

    def test_multi_event_chain(self):
        sub = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        sub.register_actor_role("agent-1", "agent")
        sub.register_actor_role("reviewer-1", "reviewer")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "multi"},
        )
        sub.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )
        sub.transition(
            wi.work_item_id, "submit_review", "agent-1",
            actor_metadata={"role": "agent"},
        )
        sub.transition(
            wi.work_item_id, "approve", "reviewer-1",
            actor_metadata={"role": "reviewer"},
        )

        evts = sub.read_events(work_item_id=wi.work_item_id)
        assert len(evts) >= 3

        assert evts[0].prev_event_hash is None

        for i in range(1, len(evts)):
            prev = evts[i - 1]
            cur = evts[i]
            assert cur.prev_event_hash is not None
            expected = hashlib.sha256(
                prev.canonical_envelope + prev.signature
            ).digest()
            assert cur.prev_event_hash == expected

    def test_chain_without_keys(self):
        sub = InMemoryRegista(project="test")
        sub.register_workflow_file(WORKFLOW_PATH)
        sub.register_actor_role("agent-1", "agent")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "nokeys"},
        )
        sub.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )

        evts = sub.read_events(work_item_id=wi.work_item_id)
        assert len(evts) == 2
        assert evts[0].prev_event_hash is None
        assert evts[1].prev_event_hash is not None
