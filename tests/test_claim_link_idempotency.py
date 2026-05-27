from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._errors import RegistaError
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture(scope="module")
def regista():
    from regista import Regista

    project = f"test_claim_link_idem_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestClaimIdempotency:
    def test_acquire_claim_same_event_id_no_duplicate_events(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "claim idem"},
        )

        eid = uuid.uuid4()
        regista.acquire_claim(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            ttl_seconds=60,
            event_id=eid,
        )
        events_after_first = regista.read_events(work_item_id=wi.work_item_id)
        first_count = len(events_after_first)

        regista.acquire_claim(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            ttl_seconds=60,
            event_id=eid,
        )
        events_after_second = regista.read_events(work_item_id=wi.work_item_id)

        assert len(events_after_second) == first_count

    def test_release_claim_event_id_dedup(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "release idem"},
        )

        regista.acquire_claim(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            ttl_seconds=60,
        )

        eid = uuid.uuid4()
        regista.release_claim(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            event_id=eid,
        )

        events_after = regista.read_events(work_item_id=wi.work_item_id)
        release_count = sum(1 for e in events_after if e.transition == "claim_released")
        assert release_count == 1


class TestLinkIdempotency:
    def test_create_link_same_event_id_no_duplicate_events(self, regista):
        wi1, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "link from"},
        )
        wi2, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "link to"},
        )

        eid = uuid.uuid4()
        regista.create_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="blocks",
            actor_id="agent-1",
            event_id=eid,
        )
        events_after_first = regista.read_events(work_item_id=wi1.work_item_id)
        first_count = len(events_after_first)

        regista.create_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="blocks",
            actor_id="agent-1",
            event_id=eid,
        )
        events_after_second = regista.read_events(work_item_id=wi1.work_item_id)

        assert len(events_after_second) == first_count

    def test_remove_link_same_event_id_no_duplicate_events(self, regista):
        wi1, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "rm from"},
        )
        wi2, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "rm to"},
        )

        regista.create_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="blocks",
            actor_id="agent-1",
        )

        eid = uuid.uuid4()
        regista.remove_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="blocks",
            actor_id="agent-1",
            event_id=eid,
        )
        events_after_first = regista.read_events(work_item_id=wi1.work_item_id)
        first_count = len(events_after_first)

        with pytest.raises(RegistaError, match="LINK_NOT_FOUND"):
            regista.remove_link(
                from_work_item_id=wi1.work_item_id,
                to_work_item_id=wi2.work_item_id,
                link_type="blocks",
                actor_id="agent-1",
                event_id=eid,
            )

        events_after_second = regista.read_events(work_item_id=wi1.work_item_id)
        assert len(events_after_second) == first_count
