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

    project = f"test_claim_link_idem_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestClaimIdempotency:
    def test_acquire_claim_same_event_id_no_duplicate_events(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "claim idem"},
        )

        eid = uuid.uuid4()
        substrate.acquire_claim(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            ttl_seconds=60,
            event_id=eid,
        )
        events_after_first = substrate.read_events(work_item_id=wi.work_item_id)
        first_count = len(events_after_first)

        substrate.acquire_claim(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            ttl_seconds=60,
            event_id=eid,
        )
        events_after_second = substrate.read_events(work_item_id=wi.work_item_id)

        assert len(events_after_second) == first_count

    def test_release_claim_event_id_dedup(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "release idem"},
        )

        substrate.acquire_claim(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            ttl_seconds=60,
        )

        eid = uuid.uuid4()
        substrate.release_claim(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            event_id=eid,
        )

        events_after = substrate.read_events(work_item_id=wi.work_item_id)
        release_count = sum(1 for e in events_after if e.transition == "claim_released")
        assert release_count == 1


class TestLinkIdempotency:
    def test_create_link_same_event_id_no_duplicate_events(self, substrate):
        wi1, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "link from"},
        )
        wi2, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "link to"},
        )

        eid = uuid.uuid4()
        substrate.create_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="blocks",
            actor_id="agent-1",
            event_id=eid,
        )
        events_after_first = substrate.read_events(work_item_id=wi1.work_item_id)
        first_count = len(events_after_first)

        substrate.create_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="blocks",
            actor_id="agent-1",
            event_id=eid,
        )
        events_after_second = substrate.read_events(work_item_id=wi1.work_item_id)

        assert len(events_after_second) == first_count

    def test_remove_link_same_event_id_no_duplicate_events(self, substrate):
        wi1, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "rm from"},
        )
        wi2, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "rm to"},
        )

        substrate.create_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="blocks",
            actor_id="agent-1",
        )

        eid = uuid.uuid4()
        substrate.remove_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="blocks",
            actor_id="agent-1",
            event_id=eid,
        )
        events_after_first = substrate.read_events(work_item_id=wi1.work_item_id)
        first_count = len(events_after_first)

        with pytest.raises(SubstrateError, match="LINK_NOT_FOUND"):
            substrate.remove_link(
                from_work_item_id=wi1.work_item_id,
                to_work_item_id=wi2.work_item_id,
                link_type="blocks",
                actor_id="agent-1",
                event_id=eid,
            )

        events_after_second = substrate.read_events(work_item_id=wi1.work_item_id)
        assert len(events_after_second) == first_count
