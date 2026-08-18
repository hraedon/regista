from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from _helpers import DSN
from _v6_fixtures import make_v6_keyset, open_v6_epoch

from regista._errors import RegistaError
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

#: Canonical principal ids (TRUST-DOMAIN.md §2.1). The pre-epoch spellings were
#: "worker-1" / "agent-1" (one lone agent per test), "reviewer-1" and
#: "strict-worker" — all bare legacy names the v6 ingress refuses.
#:
#: A principal id and a *workflow role* are different things, which
#: `test_actor_role_enforcement_in_pipeline` depends on: ``STRICT`` is registered as
#: a reviewer, refused the agent-only transition, then re-registered as an agent.
#: Its principal id never changes, and that is the point.
WORKER = "agent:worker"
REVIEWER = "human:reviewer"
STRICT = "agent:reviewer"


@pytest.fixture
def regista(tmp_path):
    from regista import Regista

    project = f"test_e2e_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path)
    sub = Regista.create_project(DSN, project, keyset.path)
    # Genesis first: `register_workflow_file` emits the signed `workflow_registered`
    # event admission gate 1 requires, and there is no epoch before this line.
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestEndToEndAgentPipeline:
    def test_full_agent_pipeline(self, regista):
        regista.register_actor_role(WORKER, "agent")
        regista.register_actor_role(REVIEWER, "reviewer")

        page = regista.query_work_items(
            workflow_name="test_workflow",
            current_states=["new"],
            claimable_now=True,
        )
        assert len(page.items) == 0

        wi, create_evt = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            # `model` is a *producer* field and the v6 envelope refuses it inside
            # actor.metadata: producer identity is a property of the running
            # process, published once by `open_v6_epoch`, not restated per event.
            actor_metadata={"role": "agent"},
            custom_fields={"title": "E2E feature", "priority": "high"},
        )
        assert wi.current_state == "new"
        assert create_evt.transition == "created"

        page = regista.query_work_items(
            workflow_name="test_workflow",
            current_states=["new"],
            claimable_now=True,
        )
        assert any(w.work_item_id == wi.work_item_id for w in page.items)

        claim = regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        assert claim.actor_id == WORKER
        assert claim.attempt_number == 1

        claimed_page = regista.query_work_items(
            workflow_name="test_workflow",
            claimed_by=WORKER,
        )
        assert any(w.work_item_id == wi.work_item_id for w in claimed_page.items)

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id=WORKER,
            actor_metadata={"role": "agent"},
            custom_fields={"metadata": {"branch": "feature/e2e"}},
        )

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.current_state == "in_progress"
        assert refreshed.custom_fields["metadata"]["branch"] == "feature/e2e"
        assert refreshed.claimed_by is None

        claim = regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        assert claim.attempt_number == 2

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="submit_review",
            actor_id=WORKER,
            actor_metadata={"role": "agent"},
        )

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.current_state == "review"

        claim = regista.acquire_claim(wi.work_item_id, REVIEWER, ttl_seconds=300)
        assert claim.attempt_number == 3

        review_page = regista.query_work_items(
            workflow_name="test_workflow",
            current_states=["review"],
        )
        assert any(w.work_item_id == wi.work_item_id for w in review_page.items)

        regista.acquire_claim(wi.work_item_id, REVIEWER, ttl_seconds=300)

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="approve",
            actor_id=REVIEWER,
            actor_metadata={"role": "reviewer"},
        )

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.current_state == "done"
        assert refreshed.claimed_by is None

        events = regista.read_events(work_item_id=wi.work_item_id)
        transitions = [e.transition for e in events]
        assert "created" in transitions
        assert "start" in transitions
        assert "submit_review" in transitions
        assert "approve" in transitions
        assert "claim_acquired" in transitions

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0
        assert report.replayed_ok >= 1

    def test_not_before_deferral_and_reclaim(self, regista):
        future = datetime.now(UTC) + timedelta(hours=1)

        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "Deferred work"},
            not_before=future,
        )

        with pytest.raises(RegistaError, match="not_before"):
            regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)

        past = datetime.now(UTC) - timedelta(seconds=1)
        regista.update_not_before(wi.work_item_id, past, WORKER)

        claim = regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        assert claim.actor_id == WORKER

        report = regista.replay()
        assert report.replayed_drift == 0

    def test_linked_work_items_with_lifecycle(self, regista):
        blocker, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "Blocker feature"},
        )
        blocked, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "Blocked feature"},
        )

        link = regista.create_link(
            from_work_item_id=blocker.work_item_id,
            to_work_item_id=blocked.work_item_id,
            link_type="blocks",
            actor_id=WORKER,
            payload={"reason": "Depends on API design"},
        )
        assert link.payload["reason"] == "Depends on API design"

        linked_page = regista.query_work_items(
            workflow_name="test_workflow",
            has_link_type="blocks",
        )
        assert any(w.work_item_id == blocker.work_item_id for w in linked_page.items)

        regista.transition(
            blocker.work_item_id, "start", WORKER,
            actor_metadata={"role": "agent"},
        )
        regista.transition(
            blocker.work_item_id, "submit_review", WORKER,
            actor_metadata={"role": "agent"},
        )
        regista.transition(
            blocker.work_item_id, "approve", REVIEWER,
            actor_metadata={"role": "reviewer"},
        )

        regista.remove_link(
            from_work_item_id=blocker.work_item_id,
            to_work_item_id=blocked.work_item_id,
            link_type="blocks",
            actor_id=WORKER,
        )

        report = regista.replay()
        assert report.replayed_drift == 0

    def test_actor_role_enforcement_in_pipeline(self, regista):
        regista.register_actor_role(STRICT, "reviewer")

        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=STRICT,
            custom_fields={"title": "Role enforced"},
        )

        with pytest.raises(RegistaError, match="ACTOR_ROLE_NOT_AUTHORIZED"):
            regista.transition(
                wi.work_item_id, "start", STRICT,
                actor_metadata={"role": "agent"},
            )

        regista.unregister_actor_role(STRICT, "reviewer")
        regista.register_actor_role(STRICT, "agent")

        regista.transition(
            wi.work_item_id, "start", STRICT,
            actor_metadata={"role": "agent"},
        )

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.current_state == "in_progress"

        report = regista.replay()
        assert report.replayed_drift == 0
