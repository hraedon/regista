from __future__ import annotations

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
