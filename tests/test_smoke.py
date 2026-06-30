from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture(scope="module")
def regista():
    from regista import Regista

    project = f"test_smoke_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    # Register in the fixture so any subset of tests (e.g. -k filtered runs)
    # works without depending on TestWorkflow.test_register_workflow ordering.
    sub.register_workflow_file(WORKFLOW_PATH)
    sub.register_actor_role("agent-1", "agent")
    sub.register_actor_role("reviewer-1", "reviewer")
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestWorkflow:
    def test_register_workflow(self, regista):
        result = regista.register_workflow_file(WORKFLOW_PATH)
        assert result.name == "test_workflow"
        assert result.version == 1

    def test_register_idempotent(self, regista):
        yaml_content = Path(WORKFLOW_PATH).read_text()
        r1 = regista.register_workflow(yaml_content)
        r2 = regista.register_workflow(yaml_content)
        assert r1.name == r2.name
        assert r1.version == r2.version

    def test_register_version_conflict(self, regista):
        yaml_content = Path(WORKFLOW_PATH).read_text()
        regista.register_workflow(yaml_content)
        modified = yaml_content.replace("attempt_threshold: 3", "attempt_threshold: 5")
        with pytest.raises(RegistaError) as exc_info:
            regista.register_workflow(modified)
        assert exc_info.value.code == ErrorCode.WORKFLOW_VERSION_CONFLICT

    def test_register_invalid_yaml(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.register_workflow(":::invalid yaml:::")
        assert exc_info.value.code == ErrorCode.WORKFLOW_VALIDATION_FAILED


class TestWorkItem:
    def test_create_work_item(self, regista):
        wi, evt = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            actor_metadata={"role": "agent", "model": "gpt-4"},
            custom_fields={"title": "Test feature", "priority": "high"},
        )
        assert wi.current_state == "new"
        assert wi.work_item_type == "feature"
        assert wi.custom_fields["title"] == "Test feature"
        assert evt.transition == "created"
        assert evt.event_seq == 1

    def test_create_with_invalid_type(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="nonexistent",
                actor_id="agent-1",
            )
        assert exc_info.value.code == ErrorCode.WORK_ITEM_TYPE_NOT_DECLARED

    def test_create_with_invalid_field(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="bug",
                actor_id="agent-1",
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION


class TestTransition:
    def _create_feature(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
            custom_fields={"title": "Test"},
        )
        return wi

    def test_valid_transition(self, regista):
        wi = self._create_feature(regista)
        evt = regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )
        assert evt.transition == "start"
        assert evt.event_seq == 2

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed is not None
        assert refreshed.current_state == "in_progress"

    def test_invalid_transition(self, regista):
        wi = self._create_feature(regista)
        with pytest.raises(RegistaError) as exc_info:
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="approve",
                actor_id="agent-1",
                actor_metadata={"role": "agent"},
            )
        assert exc_info.value.code == ErrorCode.INVALID_TRANSITION

    def test_role_not_permitted(self, regista):
        wi = self._create_feature(regista)
        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="submit_review",
                actor_id="agent-1",
                actor_metadata={"role": "reviewer"},
            )
        assert exc_info.value.code == ErrorCode.ROLE_NOT_PERMITTED

    def test_full_lifecycle(self, regista):
        wi = self._create_feature(regista)
        regista.transition(wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"})
        regista.transition(
            wi.work_item_id, "submit_review", "agent-1", actor_metadata={"role": "agent"}
        )
        regista.transition(
            wi.work_item_id, "approve", "reviewer-1", actor_metadata={"role": "reviewer"}
        )

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.current_state == "done"


class TestEvents:
    def test_read_by_work_item(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Events test"},
        )
        regista.transition(wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"})

        events = regista.read_events(work_item_id=wi.work_item_id)
        assert len(events) == 2
        assert events[0].transition == "created"
        assert events[1].transition == "start"


class TestClaims:
    def test_acquire_and_release(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Claim test"},
        )

        claim = regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        assert claim.actor_id == "agent-1"
        assert claim.attempt_number == 1

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.claimed_by == "agent-1"

        regista.release_claim(wi.work_item_id, "agent-1")
        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.claimed_by is None

    def test_claim_contested(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Contested"},
        )

        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)

        with pytest.raises(RegistaError) as exc_info:
            regista.acquire_claim(wi.work_item_id, "agent-2", ttl_seconds=300)
        assert exc_info.value.code == "CLAIM_CONTESTED"

    def test_heartbeat(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Heartbeat"},
        )

        claim1 = regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=60)
        claim2 = regista.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        assert claim2.expires_at > claim1.expires_at


class TestQuery:
    def test_query_by_workflow(self, regista):
        regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Query test"},
        )

        page = regista.query_work_items(workflow_name="test_workflow", page_size=10)
        assert len(page.items) >= 1
        assert all(wi.workflow_name == "test_workflow" for wi in page.items)

    def test_query_by_state(self, regista):
        page = regista.query_work_items(
            workflow_name="test_workflow",
            current_states=["new"],
        )
        assert all(wi.current_state == "new" for wi in page.items)

    def test_query_claimable_now(self, regista):
        page = regista.query_work_items(
            workflow_name="test_workflow",
            claimable_now=True,
        )
        for wi in page.items:
            assert wi.claimed_by is None
            assert wi.claim_expires_at is None

    def test_pagination_stable_no_duplicates(self, regista):
        for i in range(5):
            regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": f"Page test {i}"},
            )

        seen_ids = set()
        cursor = None
        while True:
            page = regista.query_work_items(
                workflow_name="test_workflow",
                current_states=["new"],
                cursor=cursor,
                page_size=2,
            )
            for wi in page.items:
                assert wi.work_item_id not in seen_ids
                seen_ids.add(wi.work_item_id)
            if not page.has_more:
                break
            cursor = page.cursor
        assert len(seen_ids) >= 5


class TestLinks:
    def test_create_and_remove_link(self, regista):
        wi1, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Feature 1"},
        )
        wi2, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="bug",
            actor_id="agent-1",
            custom_fields={"severity": "major"},
        )

        link = regista.create_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="fixes",
            actor_id="agent-1",
        )
        assert link.link_type == "fixes"

        regista.remove_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="fixes",
            actor_id="agent-1",
        )

        events = regista.read_events(work_item_id=wi1.work_item_id)
        link_removed = [
            e
            for e in events
            if e.transition == "link_removed"
            and (e.payload or {}).get("link_type") == "fixes"
            and (e.payload or {}).get("to_work_item_id") == str(wi2.work_item_id)
        ]
        assert len(link_removed) == 1

    def test_create_link_with_payload(self, regista):
        wi1, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Feature 1"},
        )
        wi2, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="bug",
            actor_id="agent-1",
            custom_fields={"severity": "major"},
        )

        link = regista.create_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="fixes",
            actor_id="agent-1",
            payload={"rationale": "Bug caused by missing null check", "priority": "high"},
        )
        assert link.payload == {"rationale": "Bug caused by missing null check", "priority": "high"}


class TestIdempotency:
    def test_event_idempotency(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Idempotency"},
        )

        eid = uuid.uuid4()
        e1 = regista.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="custom_event",
            event_id=eid,
        )
        e2 = regista.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="custom_event",
            event_id=eid,
        )
        assert e1.event_id == e2.event_id
        assert e1.event_seq == e2.event_seq


class TestReplay:
    def test_replay_no_drift(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Replay test"},
        )
        regista.transition(wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"})

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0
