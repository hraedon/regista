from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture(scope="module")
def regista():
    from regista import Regista

    project = f"test_recovery_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestHookMissRecovery:
    def test_read_events_since_returns_events_after_cursor(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Recovery test"},
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        created = events[0]

        for i in range(5):
            regista.append_event(
                wi.work_item_id, "agent-1",
                transition=f"note_{i}",
                payload={"idx": i},
            )

        since = regista.read_events_since(
            wi.work_item_id,
            after_seq=created.event_seq,
        )
        seqs = [e.event_seq for e in since]
        assert seqs == list(range(created.event_seq + 1, created.event_seq + 6))
        for e in since:
            assert e.event_seq > created.event_seq

    def test_read_events_since_with_no_new_events(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Recovery empty"},
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        latest = events[-1]

        since = regista.read_events_since(
            wi.work_item_id,
            after_seq=latest.event_seq,
        )
        assert since == []

    def test_read_events_since_pagination(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Recovery page"},
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        created = events[0]

        for i in range(10):
            regista.append_event(
                wi.work_item_id, "agent-1",
                transition=f"note_{i}",
                payload={"idx": i},
            )

        page1 = regista.read_events_since(
            wi.work_item_id,
            after_seq=created.event_seq,
            limit=3,
        )
        assert len(page1) == 3
        assert page1[0].event_seq == created.event_seq + 1
        assert page1[-1].event_seq == created.event_seq + 3

        page2 = regista.read_events_since(
            wi.work_item_id,
            after_seq=page1[-1].event_seq,
            limit=3,
        )
        assert len(page2) == 3
        assert page2[0].event_seq == created.event_seq + 4
        assert page2[-1].event_seq == created.event_seq + 6

        page3 = regista.read_events_since(
            wi.work_item_id,
            after_seq=page2[-1].event_seq,
            limit=3,
        )
        assert len(page3) == 3
        assert page3[0].event_seq == created.event_seq + 7
        assert page3[-1].event_seq == created.event_seq + 9

        page4 = regista.read_events_since(
            wi.work_item_id,
            after_seq=page3[-1].event_seq,
            limit=3,
        )
        assert len(page4) == 1
        assert page4[0].event_seq == created.event_seq + 10
