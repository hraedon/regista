from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from substrate._errors import ErrorCode, SubstrateError
from substrate._testing import raw_transaction
from substrate.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def substrate():
    from substrate import Substrate

    project = f"test_gaps_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestTransitionViaAppendBlocked:
    def test_append_event_rejects_workflow_transition_name(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Blocked append"},
        )
        with pytest.raises(SubstrateError) as exc_info:
            substrate.append_event(
                work_item_id=wi.work_item_id,
                actor_id="agent-1",
                transition="start",
            )
        assert exc_info.value.code == ErrorCode.TRANSITION_VIA_APPEND_BLOCKED

    def test_append_event_allows_custom_transition(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Custom event"},
        )
        evt = substrate.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="custom_note",
        )
        assert evt.transition == "custom_note"


class TestWorkItemNotFound:
    def test_transition_on_nonexistent_work_item(self, substrate):
        with pytest.raises(SubstrateError) as exc_info:
            substrate.transition(
                work_item_id=uuid.uuid4(),
                transition_name="start",
                actor_id="agent-1",
            )
        assert exc_info.value.code == ErrorCode.WORK_ITEM_NOT_FOUND

    def test_append_event_on_nonexistent_work_item(self, substrate):
        with pytest.raises(SubstrateError) as exc_info:
            substrate.append_event(
                work_item_id=uuid.uuid4(),
                actor_id="agent-1",
                transition="note",
            )
        assert exc_info.value.code == ErrorCode.WORK_ITEM_NOT_FOUND


class TestWorkItemNotFoundClaims:
    def test_heartbeat_on_nonexistent_work_item(self, substrate):
        with pytest.raises(SubstrateError) as exc_info:
            substrate.heartbeat_claim(uuid.uuid4(), "agent-1", ttl_seconds=300)
        assert exc_info.value.code == ErrorCode.WORK_ITEM_NOT_FOUND

    def test_release_on_nonexistent_work_item(self, substrate):
        with pytest.raises(SubstrateError) as exc_info:
            substrate.release_claim(uuid.uuid4(), "agent-1")
        assert exc_info.value.code == ErrorCode.WORK_ITEM_NOT_FOUND


class TestClaimNotFound:
    def test_heartbeat_on_unclaimed_work_item(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "No claim heartbeat"},
        )
        with pytest.raises(SubstrateError) as exc_info:
            substrate.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        assert exc_info.value.code == ErrorCode.CLAIM_NOT_FOUND

    def test_release_on_unclaimed_work_item(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "No claim release"},
        )
        with pytest.raises(SubstrateError) as exc_info:
            substrate.release_claim(wi.work_item_id, "agent-1")
        assert exc_info.value.code == ErrorCode.CLAIM_NOT_FOUND


class TestSweepExpiredClaims:
    def test_sweep_removes_expired_claims(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Sweep test"},
        )
        substrate.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)

        with raw_transaction(substrate) as conn:
            conn.execute(
                "UPDATE claims SET expires_at = now() - interval '1 second' "
                "WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        swept = substrate.sweep_expired_claims()
        assert swept >= 1

        refreshed = substrate.get_work_item(wi.work_item_id)
        assert refreshed.claimed_by is None

    def test_sweep_emits_claim_expired_events(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Sweep events"},
        )
        substrate.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)

        with raw_transaction(substrate) as conn:
            conn.execute(
                "UPDATE claims SET expires_at = now() - interval '1 second' "
                "WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        substrate.sweep_expired_claims()

        events = substrate.read_events(work_item_id=wi.work_item_id)
        expired_events = [e for e in events if e.transition == "claim_expired"]
        assert len(expired_events) >= 1

    def test_sweep_returns_zero_when_no_expired(self, substrate):
        swept = substrate.sweep_expired_claims()
        assert swept == 0


class TestWorkflowSemanticErrors:
    def test_no_initial_state_rejected(self, substrate):
        yaml_content = """\
name: bad_workflow
version: 1
substrate_version: "0.1.0"

states:
  - name: new
    initial: false
  - name: done
    terminal: true

transitions:
  - name: start
    from: new
    to: done
    allowed_roles: [agent]

roles:
  - name: agent

work_item_types:
  - name: feature
    custom_fields:
      - name: title
        type: string
        required: true

link_types: []
"""
        with pytest.raises(SubstrateError) as exc_info:
            substrate.register_workflow(yaml_content)
        assert exc_info.value.code in (
            ErrorCode.WORKFLOW_SEMANTIC_ERROR,
            ErrorCode.WORKFLOW_VALIDATION_FAILED,
        )

    def test_unreachable_state_rejected(self, substrate):
        yaml_content = """\
name: bad_workflow2
version: 1
substrate_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: orphan
  - name: done
    terminal: true

transitions:
  - name: finish
    from: new
    to: done
    allowed_roles: [agent]

roles:
  - name: agent

work_item_types:
  - name: feature
    custom_fields:
      - name: title
        type: string
        required: true

link_types: []
"""
        with pytest.raises(SubstrateError) as exc_info:
            substrate.register_workflow(yaml_content)
        assert exc_info.value.code == ErrorCode.WORKFLOW_SEMANTIC_ERROR
        assert "nreachable" in exc_info.value.message

    def test_undeclared_role_in_transition_rejected(self, substrate):
        yaml_content = """\
name: bad_workflow3
version: 1
substrate_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: done
    terminal: true

transitions:
  - name: start
    from: new
    to: done
    allowed_roles: [nonexistent_role]

roles:
  - name: agent

work_item_types:
  - name: feature
    custom_fields:
      - name: title
        type: string
        required: true

link_types: []
"""
        with pytest.raises(SubstrateError) as exc_info:
            substrate.register_workflow(yaml_content)
        assert exc_info.value.code == ErrorCode.WORKFLOW_SEMANTIC_ERROR
        assert "nonexistent_role" in exc_info.value.message


class TestExpectedAttemptNumber:
    def test_heartbeat_rejects_stale_attempt_number(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Stale attempt"},
        )
        substrate.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)

        with pytest.raises(SubstrateError) as exc_info:
            substrate.heartbeat_claim(
                wi.work_item_id, "agent-1", ttl_seconds=300,
                expected_attempt_number=99,
            )
        assert exc_info.value.code == ErrorCode.CLAIM_LOST

    def test_heartbeat_accepts_correct_attempt_number(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Correct attempt"},
        )
        claim = substrate.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)

        renewed = substrate.heartbeat_claim(
            wi.work_item_id, "agent-1", ttl_seconds=600,
            expected_attempt_number=claim.attempt_number,
        )
        assert renewed.expires_at > claim.expires_at


class TestReadEventsFilters:
    def test_read_events_by_actor(self, substrate):
        substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="unique-filter-agent",
            custom_fields={"title": "Actor filter"},
        )

        events = substrate.read_events(actor_id="unique-filter-agent")
        assert len(events) >= 1
        assert all(e.actor_id == "unique-filter-agent" for e in events)

    def test_read_events_by_transition(self, substrate):
        _wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Transition filter"},
        )

        events = substrate.read_events(transition="created")
        assert len(events) >= 1
        assert all(e.transition == "created" for e in events)

    def test_read_events_by_time_range(self, substrate):
        now = datetime.now(UTC)
        start = now - timedelta(hours=1)
        end = now + timedelta(hours=1)

        events = substrate.read_events(start=start, end=end)
        assert isinstance(events, list)

    def test_read_events_no_filters_returns_empty(self, substrate):
        events = substrate.read_events()
        assert events == []

    def test_read_events_before_seq_requires_work_item_id(self, substrate):
        with pytest.raises(SubstrateError) as exc_info:
            substrate.read_events(before_seq=5)
        assert exc_info.value.code == ErrorCode.INVALID_FILTER

    def test_read_events_start_without_end_rejected(self, substrate):
        with pytest.raises(SubstrateError) as exc_info:
            substrate.read_events(start=datetime.now(UTC))
        assert exc_info.value.code == ErrorCode.INVALID_FILTER

    def test_read_events_end_without_start_rejected(self, substrate):
        with pytest.raises(SubstrateError) as exc_info:
            substrate.read_events(end=datetime.now(UTC))
        assert exc_info.value.code == ErrorCode.INVALID_FILTER


class TestQueryWorkItemsFilters:
    def test_query_by_needs_review(self, substrate):
        page = substrate.query_work_items(
            workflow_name="test_workflow",
            needs_review=True,
        )
        for wi in page.items:
            assert wi.needs_review is True

    def test_query_by_workflow_version(self, substrate):
        page = substrate.query_work_items(
            workflow_name="test_workflow",
            workflow_version=1,
        )
        for wi in page.items:
            assert wi.workflow_version == 1

    def test_query_by_work_item_types(self, substrate):
        substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Type filter test"},
        )

        page = substrate.query_work_items(
            workflow_name="test_workflow",
            work_item_types=["feature"],
        )
        assert len(page.items) >= 1
        assert all(wi.work_item_type == "feature" for wi in page.items)


class TestCustomFieldFilterQuery:
    def test_single_key_match(self, substrate):
        substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "alpha"},
        )
        substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "beta"},
        )

        page = substrate.query_work_items(
            workflow_name="test_workflow",
            custom_field_filters={"title": "alpha"},
        )
        assert len(page.items) >= 1
        assert all(wi.custom_fields.get("title") == "alpha" for wi in page.items)

    def test_multi_key_and(self, substrate):
        substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "gamma", "priority": "high"},
        )
        substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "gamma", "priority": "low"},
        )

        page = substrate.query_work_items(
            workflow_name="test_workflow",
            custom_field_filters={"title": "gamma", "priority": "high"},
        )
        assert len(page.items) == 1
        assert page.items[0].custom_fields["title"] == "gamma"
        assert page.items[0].custom_fields["priority"] == "high"

    def test_unknown_key_empty_result(self, substrate):
        substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "delta"},
        )

        page = substrate.query_work_items(
            workflow_name="test_workflow",
            custom_field_filters={"nonexistent_field": "value"},
        )
        assert len(page.items) == 0

    def test_cursor_pagination_with_filter(self, substrate):
        for i in range(5):
            substrate.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": "paged", "priority": "high"},
            )
        substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "other"},
        )

        seen_ids = set()
        cursor = None
        while True:
            page = substrate.query_work_items(
                workflow_name="test_workflow",
                custom_field_filters={"title": "paged"},
                cursor=cursor,
                page_size=2,
            )
            for wi in page.items:
                assert wi.custom_fields["title"] == "paged"
                assert wi.work_item_id not in seen_ids
                seen_ids.add(wi.work_item_id)
            if not page.has_more:
                break
            cursor = page.cursor
        assert len(seen_ids) == 5


class TestHmacKeyPathRequired:
    def test_substrate_init_rejects_none_key_path(self):
        with pytest.raises(SubstrateError) as exc_info:
            from substrate import Substrate

            Substrate(DSN, "nonexistent_project", hmac_key_path=None)
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID
