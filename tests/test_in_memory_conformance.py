from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")
WORKFLOW_YAML = Path(WORKFLOW_PATH).read_text()


@pytest.fixture(params=["real", "in_memory"])
def sub(request):
    if request.param == "real":
        from regista import Regista

        project = f"test_conf_{uuid.uuid4().hex[:8]}"
        s = Regista.create_project(DSN, project, KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)
        yield s
        s.close()
        drop_project_schema(DSN, project)
    else:
        s = InMemoryRegista(project="test")
        s.register_workflow_file(WORKFLOW_PATH)
        yield s
        s.close()


class TestConformanceWorkflow:
    def test_register_and_idempotent(self, sub):
        v = sub.register_workflow(WORKFLOW_YAML)
        assert v.name == "test_workflow"
        assert v.version == 1
        v2 = sub.register_workflow(WORKFLOW_YAML)
        assert v2.version == v.version

    def test_register_version_conflict(self, sub):
        sub.register_workflow(WORKFLOW_YAML)
        modified = WORKFLOW_YAML.replace("attempt_threshold: 3", "attempt_threshold: 99")
        with pytest.raises(RegistaError) as exc_info:
            sub.register_workflow(modified)
        assert exc_info.value.code == ErrorCode.WORKFLOW_VERSION_CONFLICT


class TestConformanceWorkItem:
    def test_create_and_get(self, sub):
        wi, evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        assert wi.work_item_type == "feature"
        assert wi.current_state == "new"
        assert evt.transition == "created"

        fetched = sub.get_work_item(wi.work_item_id)
        assert fetched is not None
        assert fetched.work_item_id == wi.work_item_id

    def test_create_missing_required_field(self, sub):
        with pytest.raises(RegistaError) as exc_info:
            sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION

    def test_create_unknown_type(self, sub):
        with pytest.raises(RegistaError) as exc_info:
            sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="nonexistent",
                actor_id="agent-1",
            )
        assert exc_info.value.code == ErrorCode.WORK_ITEM_TYPE_NOT_DECLARED


class TestConformanceTransition:
    def test_valid_transition(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        evt = sub.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )
        assert evt.transition == "start"
        updated = sub.get_work_item(wi.work_item_id)
        assert updated.current_state == "in_progress"

    def test_invalid_transition(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.transition(wi.work_item_id, "approve", "agent-1")
        assert exc_info.value.code == ErrorCode.INVALID_TRANSITION

    def test_role_not_permitted(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        sub.transition(wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"})
        sub.transition(
            wi.work_item_id, "submit_review", "agent-1",
            actor_metadata={"role": "agent"},
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.transition(
                wi.work_item_id, "approve", "agent-1",
                actor_metadata={"role": "agent"},
            )
        assert exc_info.value.code == ErrorCode.ROLE_NOT_PERMITTED

    def test_transition_via_append_blocked(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.append_event(wi.work_item_id, "agent-1", transition="start")
        assert exc_info.value.code == ErrorCode.TRANSITION_VIA_APPEND_BLOCKED

    def test_custom_fields_update_on_transition(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        sub.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
            custom_fields={"priority": "high"},
        )
        updated = sub.get_work_item(wi.work_item_id)
        assert updated.custom_fields["priority"] == "high"
        assert updated.custom_fields["title"] == "test"


class TestConformanceEvents:
    def test_read_events_by_work_item(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        evts = sub.read_events(work_item_id=wi.work_item_id)
        assert len(evts) >= 1
        assert evts[0].transition == "created"

    def test_read_events_by_actor(self, sub):
        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="unique-agent-x",
            custom_fields={"title": "test"},
        )
        evts = sub.read_events(actor_id="unique-agent-x")
        assert len(evts) >= 1

    def test_event_idempotency(self, sub):
        eid = uuid.uuid4()
        _wi1, evt1 = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
            event_id=eid,
        )
        assert evt1.event_id == eid

    def test_read_events_composite_work_item_and_transition(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "composite"},
        )
        sub.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )
        evts = sub.read_events(
            work_item_id=wi.work_item_id, transition="created",
        )
        assert len(evts) == 1
        assert all(e.transition == "created" for e in evts)

        evts = sub.read_events(
            work_item_id=wi.work_item_id, transition="start",
        )
        assert len(evts) == 1
        assert all(e.transition == "start" for e in evts)

    def test_read_events_composite_actor_and_transition(self, sub):
        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="composite-agent",
            custom_fields={"title": "composite actor"},
        )
        evts = sub.read_events(
            actor_id="composite-agent", transition="created",
        )
        assert len(evts) == 1
        assert all(
            e.actor_id == "composite-agent" and e.transition == "created"
            for e in evts
        )


class TestConformanceClaims:
    def test_acquire_and_release(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        claim = sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        assert claim.actor_id == "agent-1"
        assert claim.attempt_number == 1

        updated = sub.get_work_item(wi.work_item_id)
        assert updated.claimed_by == "agent-1"

        sub.release_claim(wi.work_item_id, "agent-1")
        updated = sub.get_work_item(wi.work_item_id)
        assert updated.claimed_by is None

    def test_claim_contested(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        with pytest.raises(RegistaError) as exc_info:
            sub.acquire_claim(wi.work_item_id, "agent-2", ttl_seconds=300)
        assert exc_info.value.code == ErrorCode.CLAIM_CONTESTED

    def test_heartbeat(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        claim1 = sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=60)
        claim2 = sub.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=120)
        assert claim2.expires_at > claim1.expires_at

    def test_claim_releases_on_transition(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        sub.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )
        updated = sub.get_work_item(wi.work_item_id)
        assert updated.claimed_by is None


class TestConformanceLinks:
    def test_create_and_query(self, sub):
        wi1, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "a"},
        )
        wi2, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "b"},
        )
        link = sub.create_link(
            wi1.work_item_id, wi2.work_item_id, "blocks",
            actor_id="agent-1",
        )
        assert link.link_type == "blocks"

        page = sub.query_work_items(has_link_type="blocks")
        ids = [wi.work_item_id for wi in page.items]
        assert wi1.work_item_id in ids


class TestConformanceActorRoles:
    def test_register_and_enforce(self, sub):
        sub.register_actor_role("agent-1", "agent")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        sub.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )
        updated = sub.get_work_item(wi.work_item_id)
        assert updated.current_state == "in_progress"

    def test_role_rejects_unauthorized(self, sub):
        sub.register_actor_role("agent-1", "reviewer")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.transition(
                wi.work_item_id, "start", "agent-1",
                actor_metadata={"role": "agent"},
            )
        assert exc_info.value.code == ErrorCode.ACTOR_ROLE_NOT_AUTHORIZED


class TestConformanceQuery:
    def test_query_by_state(self, sub):
        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "a"},
        )
        page = sub.query_work_items(current_states=["new"])
        assert len(page.items) >= 1

    def test_query_by_workflow(self, sub):
        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "a"},
        )
        page = sub.query_work_items(workflow_name="test_workflow")
        assert len(page.items) >= 1

    def test_query_with_cursor(self, sub):
        for i in range(5):
            sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": f"item-{i}"},
            )
        page1 = sub.query_work_items(page_size=2)
        assert len(page1.items) == 2
        assert page1.has_more
        page2 = sub.query_work_items(cursor=page1.cursor, page_size=2)
        assert len(page2.items) == 2


class TestConformanceReplay:
    def test_replay_no_drift(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        sub.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )
        report = sub.replay()
        assert report.replayed_drift == 0
        assert report.replayed_ok >= 1

    def test_replay_no_drift_with_active_claim(self, sub):
        """An active claim must not trigger drift. (claim_expires_at is excluded
        from comparison per BC-189; this guards against future regressions where
        claimed_by or attempt_number diverge on claim acquisition.)"""
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "claim-replay"},
        )
        sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        report = sub.replay()
        assert report.replayed_drift == 0
        assert report.replayed_ok >= 1


class TestConformanceUpdateNotBefore:
    def test_set_and_clear(self, sub):
        from datetime import UTC, datetime, timedelta

        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "test"},
        )
        future = datetime.now(UTC) + timedelta(hours=1)
        sub.update_not_before(wi.work_item_id, future, "agent-1")
        updated = sub.get_work_item(wi.work_item_id)
        assert updated.not_before is not None

        sub.update_not_before(wi.work_item_id, None, "agent-1")
        updated = sub.get_work_item(wi.work_item_id)
        assert updated.not_before is None


class TestConformanceCustomFieldFilter:
    def test_custom_field_filter(self, sub):
        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "cf-query", "priority": "high"},
        )
        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "cf-query", "priority": "low"},
        )
        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "other"},
        )

        page = sub.query_work_items(
            custom_field_filters={"title": "cf-query", "priority": "high"},
        )
        assert len(page.items) == 1
        assert page.items[0].custom_fields["title"] == "cf-query"
        assert page.items[0].custom_fields["priority"] == "high"

    def test_custom_field_filter_unknown_key(self, sub):
        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "exists"},
        )
        page = sub.query_work_items(
            custom_field_filters={"no_such_key": "value"},
        )
        assert len(page.items) == 0

    def test_custom_field_filter_nested_json_containment(self, sub):
        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={
                "title": "nested-test",
                "metadata": {"env": "prod", "region": "us-east", "tags": ["a", "b"]},
            },
        )
        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={
                "title": "other-nested",
                "metadata": {"env": "staging", "region": "eu-west"},
            },
        )
        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "no-metadata"},
        )

        page = sub.query_work_items(
            custom_field_filters={"metadata": {"env": "prod"}},
        )
        assert len(page.items) == 1
        assert page.items[0].custom_fields["title"] == "nested-test"

        page = sub.query_work_items(
            custom_field_filters={"metadata": {"env": "staging", "region": "eu-west"}},
        )
        assert len(page.items) == 1
        assert page.items[0].custom_fields["title"] == "other-nested"

        page = sub.query_work_items(
            custom_field_filters={"metadata": {}},
        )
        assert len(page.items) == 2


# ---------------------------------------------------------------------------
# BC-189: in-memory-only tests for claim_expires_at drift and orphan events
# ---------------------------------------------------------------------------

@pytest.fixture
def mem_sub():
    """Standalone InMemoryRegista fixture (not parameterized, no Postgres needed)."""
    s = InMemoryRegista(project="bc189")
    s.register_workflow_file(WORKFLOW_PATH)
    yield s
    s.close()


class TestBC189OrphanEventDetection:
    """Verify that orphan-event detection in in-memory replay mirrors Postgres behaviour."""

    def test_orphan_with_created_event_counts_as_halted(self, mem_sub):
        """An orphan work-item whose first event is 'created' is halted (WI-266),
        matching the Postgres backend's whole-store verdict."""
        from regista._types import Event

        orphan_id = uuid.uuid4()
        # Inject a synthetic 'created' event directly into the event store
        # without adding a work-item entry — simulates a deleted work-item row.
        evt = Event(
            event_id=uuid.uuid4(),
            work_item_id=orphan_id,
            event_seq=1,
            actor_id="agent-orphan",
            actor_kind="agent",
            actor_metadata=None,
            key_id="in-memory",
            workflow_name="test_workflow",
            workflow_version=1,
            timestamp=datetime.now(UTC),
            transition="created",
            payload={"initial_state": "new", "custom_fields": {"title": "orphan"}},
            payload_canonical_hash=b"\x00" * 32,
            signature=b"\x00" * 32,
            canonical_envelope=None,
        )
        mem_sub._store.events.setdefault(orphan_id, []).append(evt)
        # Explicitly ensure no work-item row exists
        mem_sub._work_items.pop(orphan_id, None)

        report = mem_sub.replay()
        # WI-266: an orphan with a 'created' event is a halt, not a warning.
        assert report.halted >= 1
        assert report.warnings == 0

    def test_orphan_without_created_event_counts_as_halted(self, mem_sub):
        """An orphan work-item whose events do NOT start with 'created' is halted."""
        from regista._types import Event

        orphan_id = uuid.uuid4()
        # Inject only a non-created event — no 'created' event at seq 1
        evt = Event(
            event_id=uuid.uuid4(),
            work_item_id=orphan_id,
            event_seq=2,
            actor_id="agent-orphan",
            actor_kind="agent",
            actor_metadata=None,
            key_id="in-memory",
            workflow_name="test_workflow",
            workflow_version=1,
            timestamp=datetime.now(UTC),
            transition="start",
            payload={},
            payload_canonical_hash=b"\x00" * 32,
            signature=b"\x00" * 32,
            canonical_envelope=None,
        )
        mem_sub._store.events.setdefault(orphan_id, []).append(evt)
        mem_sub._work_items.pop(orphan_id, None)

        report = mem_sub.replay()
        assert report.halted >= 1


class TestHeartbeatActorKindConformance:
    def test_heartbeat_actor_kind_emitted_real(self, sub):
        key_set = getattr(sub, "_key_set", None) or getattr(sub, "_keys", None)
        if key_set is None:
            pytest.skip("key_set required for event emission")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="human-1",
            custom_fields={"title": "actor_kind conformance"},
        )
        sub.acquire_claim(wi.work_item_id, "human-1", ttl_seconds=300, actor_kind="human")
        sub.heartbeat_claim(wi.work_item_id, "human-1", ttl_seconds=300, actor_kind="human")
        events = sub.read_events(work_item_id=wi.work_item_id)
        heartbeat_events = [e for e in events if e.transition == "claim_heartbeat"]
        assert len(heartbeat_events) == 1
        assert heartbeat_events[0].actor_kind == "human"

    def test_heartbeat_actor_kind_emitted_in_memory_with_keys(self):
        s = InMemoryRegista(project="test_im_keys", hmac_key_path=KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)
        try:
            wi, _ = s.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="human-1",
                custom_fields={"title": "actor_kind im conformance"},
            )
            s.acquire_claim(wi.work_item_id, "human-1", ttl_seconds=300, actor_kind="human")
            s.heartbeat_claim(wi.work_item_id, "human-1", ttl_seconds=300, actor_kind="human")
            events = s.read_events(work_item_id=wi.work_item_id)
            heartbeat_events = [e for e in events if e.transition == "claim_heartbeat"]
            assert len(heartbeat_events) == 1
            assert heartbeat_events[0].actor_kind == "human"
        finally:
            s.close()
