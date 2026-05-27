from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from substrate._errors import SubstrateError
from substrate.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def substrate():
    from substrate import Substrate

    project = f"test_e2e_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestEndToEndAgentPipeline:
    def test_full_agent_pipeline(self, substrate):
        substrate.register_actor_role("worker-1", "agent")
        substrate.register_actor_role("reviewer-1", "reviewer")

        page = substrate.query_work_items(
            workflow_name="test_workflow",
            current_states=["new"],
            claimable_now=True,
        )
        assert len(page.items) == 0

        wi, create_evt = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="worker-1",
            actor_metadata={"role": "agent", "model": "test-model"},
            custom_fields={"title": "E2E feature", "priority": "high"},
        )
        assert wi.current_state == "new"
        assert create_evt.transition == "created"

        page = substrate.query_work_items(
            workflow_name="test_workflow",
            current_states=["new"],
            claimable_now=True,
        )
        assert any(w.work_item_id == wi.work_item_id for w in page.items)

        claim = substrate.acquire_claim(wi.work_item_id, "worker-1", ttl_seconds=300)
        assert claim.actor_id == "worker-1"
        assert claim.attempt_number == 1

        claimed_page = substrate.query_work_items(
            workflow_name="test_workflow",
            claimed_by="worker-1",
        )
        assert any(w.work_item_id == wi.work_item_id for w in claimed_page.items)

        substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="worker-1",
            actor_metadata={"role": "agent"},
            custom_fields={"metadata": {"branch": "feature/e2e"}},
        )

        refreshed = substrate.get_work_item(wi.work_item_id)
        assert refreshed.current_state == "in_progress"
        assert refreshed.custom_fields["metadata"]["branch"] == "feature/e2e"
        assert refreshed.claimed_by is None

        claim = substrate.acquire_claim(wi.work_item_id, "worker-1", ttl_seconds=300)
        assert claim.attempt_number == 2

        substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="submit_review",
            actor_id="worker-1",
            actor_metadata={"role": "agent"},
        )

        refreshed = substrate.get_work_item(wi.work_item_id)
        assert refreshed.current_state == "review"

        claim = substrate.acquire_claim(wi.work_item_id, "reviewer-1", ttl_seconds=300)
        assert claim.attempt_number == 3

        review_page = substrate.query_work_items(
            workflow_name="test_workflow",
            current_states=["review"],
        )
        assert any(w.work_item_id == wi.work_item_id for w in review_page.items)

        substrate.acquire_claim(wi.work_item_id, "reviewer-1", ttl_seconds=300)

        substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="approve",
            actor_id="reviewer-1",
            actor_metadata={"role": "reviewer"},
        )

        refreshed = substrate.get_work_item(wi.work_item_id)
        assert refreshed.current_state == "done"
        assert refreshed.claimed_by is None

        events = substrate.read_events(work_item_id=wi.work_item_id)
        transitions = [e.transition for e in events]
        assert "created" in transitions
        assert "start" in transitions
        assert "submit_review" in transitions
        assert "approve" in transitions
        assert "claim_acquired" in transitions

        report = substrate.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0
        assert report.replayed_ok >= 1

    def test_not_before_deferral_and_reclaim(self, substrate):
        future = datetime.now(UTC) + timedelta(hours=1)

        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Deferred work"},
            not_before=future,
        )

        with pytest.raises(SubstrateError, match="not_before"):
            substrate.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)

        past = datetime.now(UTC) - timedelta(seconds=1)
        substrate.update_not_before(wi.work_item_id, past, "agent-1")

        claim = substrate.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        assert claim.actor_id == "agent-1"

        report = substrate.replay()
        assert report.replayed_drift == 0

    def test_linked_work_items_with_lifecycle(self, substrate):
        blocker, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Blocker feature"},
        )
        blocked, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Blocked feature"},
        )

        link = substrate.create_link(
            from_work_item_id=blocker.work_item_id,
            to_work_item_id=blocked.work_item_id,
            link_type="blocks",
            actor_id="agent-1",
            payload={"reason": "Depends on API design"},
        )
        assert link.payload["reason"] == "Depends on API design"

        linked_page = substrate.query_work_items(
            workflow_name="test_workflow",
            has_link_type="blocks",
        )
        assert any(w.work_item_id == blocker.work_item_id for w in linked_page.items)

        substrate.transition(
            blocker.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )
        substrate.transition(
            blocker.work_item_id, "submit_review", "agent-1",
            actor_metadata={"role": "agent"},
        )
        substrate.transition(
            blocker.work_item_id, "approve", "reviewer-1",
            actor_metadata={"role": "reviewer"},
        )

        substrate.remove_link(
            from_work_item_id=blocker.work_item_id,
            to_work_item_id=blocked.work_item_id,
            link_type="blocks",
            actor_id="agent-1",
        )

        report = substrate.replay()
        assert report.replayed_drift == 0

    def test_actor_role_enforcement_in_pipeline(self, substrate):
        substrate.register_actor_role("strict-worker", "reviewer")

        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="strict-worker",
            custom_fields={"title": "Role enforced"},
        )

        with pytest.raises(SubstrateError, match="ACTOR_ROLE_NOT_AUTHORIZED"):
            substrate.transition(
                wi.work_item_id, "start", "strict-worker",
                actor_metadata={"role": "agent"},
            )

        substrate.unregister_actor_role("strict-worker", "reviewer")
        substrate.register_actor_role("strict-worker", "agent")

        substrate.transition(
            wi.work_item_id, "start", "strict-worker",
            actor_metadata={"role": "agent"},
        )

        refreshed = substrate.get_work_item(wi.work_item_id)
        assert refreshed.current_state == "in_progress"

        report = substrate.replay()
        assert report.replayed_drift == 0
