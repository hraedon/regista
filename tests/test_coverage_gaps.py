from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._testing import raw_transaction
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def regista():
    from regista import Regista

    project = f"test_gaps_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestTransitionViaAppendBlocked:
    def test_append_event_rejects_workflow_transition_name(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Blocked append"},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.append_event(
                work_item_id=wi.work_item_id,
                actor_id="agent-1",
                transition="start",
            )
        assert exc_info.value.code == ErrorCode.TRANSITION_VIA_APPEND_BLOCKED

    def test_append_event_allows_custom_transition(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Custom event"},
        )
        evt = regista.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="custom_note",
        )
        assert evt.transition == "custom_note"


class TestWorkItemNotFound:
    def test_transition_on_nonexistent_work_item(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.transition(
                work_item_id=uuid.uuid4(),
                transition_name="start",
                actor_id="agent-1",
            )
        assert exc_info.value.code == ErrorCode.WORK_ITEM_NOT_FOUND

    def test_append_event_on_nonexistent_work_item(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.append_event(
                work_item_id=uuid.uuid4(),
                actor_id="agent-1",
                transition="note",
            )
        assert exc_info.value.code == ErrorCode.WORK_ITEM_NOT_FOUND


class TestWorkItemNotFoundClaims:
    def test_heartbeat_on_nonexistent_work_item(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.heartbeat_claim(uuid.uuid4(), "agent-1", ttl_seconds=300)
        assert exc_info.value.code == ErrorCode.WORK_ITEM_NOT_FOUND

    def test_release_on_nonexistent_work_item(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.release_claim(uuid.uuid4(), "agent-1")
        assert exc_info.value.code == ErrorCode.WORK_ITEM_NOT_FOUND


class TestClaimNotFound:
    def test_heartbeat_on_unclaimed_work_item(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "No claim heartbeat"},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        assert exc_info.value.code == ErrorCode.CLAIM_NOT_FOUND

    def test_release_on_unclaimed_work_item(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "No claim release"},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.release_claim(wi.work_item_id, "agent-1")
        assert exc_info.value.code == ErrorCode.CLAIM_NOT_FOUND


class TestSweepExpiredClaims:
    def test_sweep_removes_expired_claims(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Sweep test"},
        )
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE claims SET expires_at = now() - interval '1 second' "
                "WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        swept = regista.sweep_expired_claims()
        assert swept >= 1

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.claimed_by is None

    def test_sweep_emits_claim_expired_events(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Sweep events"},
        )
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE claims SET expires_at = now() - interval '1 second' "
                "WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        regista.sweep_expired_claims()

        events = regista.read_events(work_item_id=wi.work_item_id)
        expired_events = [e for e in events if e.transition == "claim_expired"]
        assert len(expired_events) >= 1

    def test_sweep_returns_zero_when_no_expired(self, regista):
        swept = regista.sweep_expired_claims()
        assert swept == 0


class TestWorkflowSemanticErrors:
    def test_no_initial_state_rejected(self, regista):
        yaml_content = """\
name: bad_workflow
version: 1
regista_version: "0.1.0"

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
        with pytest.raises(RegistaError) as exc_info:
            regista.register_workflow(yaml_content)
        assert exc_info.value.code in (
            ErrorCode.WORKFLOW_SEMANTIC_ERROR,
            ErrorCode.WORKFLOW_VALIDATION_FAILED,
        )

    def test_unreachable_state_rejected(self, regista):
        yaml_content = """\
name: bad_workflow2
version: 1
regista_version: "0.1.0"

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
        with pytest.raises(RegistaError) as exc_info:
            regista.register_workflow(yaml_content)
        assert exc_info.value.code == ErrorCode.WORKFLOW_SEMANTIC_ERROR
        assert "nreachable" in exc_info.value.message

    def test_undeclared_role_in_transition_rejected(self, regista):
        yaml_content = """\
name: bad_workflow3
version: 1
regista_version: "0.1.0"

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
        with pytest.raises(RegistaError) as exc_info:
            regista.register_workflow(yaml_content)
        assert exc_info.value.code == ErrorCode.WORKFLOW_SEMANTIC_ERROR
        assert "nonexistent_role" in exc_info.value.message


class TestExpectedAttemptNumber:
    def test_heartbeat_rejects_stale_attempt_number(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Stale attempt"},
        )
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)

        with pytest.raises(RegistaError) as exc_info:
            regista.heartbeat_claim(
                wi.work_item_id, "agent-1", ttl_seconds=300,
                expected_attempt_number=99,
            )
        assert exc_info.value.code == ErrorCode.CLAIM_LOST

    def test_heartbeat_accepts_correct_attempt_number(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Correct attempt"},
        )
        claim = regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)

        renewed = regista.heartbeat_claim(
            wi.work_item_id, "agent-1", ttl_seconds=600,
            expected_attempt_number=claim.attempt_number,
        )
        assert renewed.expires_at > claim.expires_at


class TestReadEventsFilters:
    def test_read_events_by_actor(self, regista):
        regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="unique-filter-agent",
            custom_fields={"title": "Actor filter"},
        )

        events = regista.read_events(actor_id="unique-filter-agent")
        assert len(events) >= 1
        assert all(e.actor_id == "unique-filter-agent" for e in events)

    def test_read_events_by_transition(self, regista):
        _wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Transition filter"},
        )

        events = regista.read_events(transition="created")
        assert len(events) >= 1
        assert all(e.transition == "created" for e in events)

    def test_read_events_by_time_range(self, regista):
        now = datetime.now(UTC)
        start = now - timedelta(hours=1)
        end = now + timedelta(hours=1)

        events = regista.read_events(start=start, end=end)
        assert isinstance(events, list)

    def test_read_events_no_filters_returns_empty(self, regista):
        events = regista.read_events()
        assert events == []

    def test_read_events_before_seq_requires_work_item_id(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.read_events(before_seq=5)
        assert exc_info.value.code == ErrorCode.INVALID_FILTER

    def test_read_events_start_without_end_rejected(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.read_events(start=datetime.now(UTC))
        assert exc_info.value.code == ErrorCode.INVALID_FILTER

    def test_read_events_end_without_start_rejected(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.read_events(end=datetime.now(UTC))
        assert exc_info.value.code == ErrorCode.INVALID_FILTER


class TestQueryWorkItemsFilters:
    def test_query_by_needs_review(self, regista):
        page = regista.query_work_items(
            workflow_name="test_workflow",
            needs_review=True,
        )
        for wi in page.items:
            assert wi.needs_review is True

    def test_query_by_workflow_version(self, regista):
        page = regista.query_work_items(
            workflow_name="test_workflow",
            workflow_version=1,
        )
        for wi in page.items:
            assert wi.workflow_version == 1

    def test_query_by_work_item_types(self, regista):
        regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Type filter test"},
        )

        page = regista.query_work_items(
            workflow_name="test_workflow",
            work_item_types=["feature"],
        )
        assert len(page.items) >= 1
        assert all(wi.work_item_type == "feature" for wi in page.items)


class TestCustomFieldFilterQuery:
    def test_single_key_match(self, regista):
        regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "alpha"},
        )
        regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "beta"},
        )

        page = regista.query_work_items(
            workflow_name="test_workflow",
            custom_field_filters={"title": "alpha"},
        )
        assert len(page.items) >= 1
        assert all(wi.custom_fields.get("title") == "alpha" for wi in page.items)

    def test_multi_key_and(self, regista):
        regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "gamma", "priority": "high"},
        )
        regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "gamma", "priority": "low"},
        )

        page = regista.query_work_items(
            workflow_name="test_workflow",
            custom_field_filters={"title": "gamma", "priority": "high"},
        )
        assert len(page.items) == 1
        assert page.items[0].custom_fields["title"] == "gamma"
        assert page.items[0].custom_fields["priority"] == "high"

    def test_unknown_key_empty_result(self, regista):
        regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "delta"},
        )

        page = regista.query_work_items(
            workflow_name="test_workflow",
            custom_field_filters={"nonexistent_field": "value"},
        )
        assert len(page.items) == 0

    def test_cursor_pagination_with_filter(self, regista):
        for i in range(5):
            regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": "paged", "priority": "high"},
            )
        regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "other"},
        )

        seen_ids = set()
        cursor = None
        while True:
            page = regista.query_work_items(
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
    def test_regista_init_rejects_none_key_path(self):
        with pytest.raises(RegistaError) as exc_info:
            from regista import Regista

            Regista(DSN, "nonexistent_project", hmac_key_path=None)
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID


class TestHeartbeatActorKind:
    def test_heartbeat_emits_correct_actor_kind(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="human-1",
            custom_fields={"title": "Actor kind test"},
        )
        regista.acquire_claim(wi.work_item_id, "human-1", ttl_seconds=300, actor_kind="human")
        regista.heartbeat_claim(wi.work_item_id, "human-1", ttl_seconds=300, actor_kind="human")
        events = regista.read_events(work_item_id=wi.work_item_id)
        heartbeat_events = [e for e in events if e.transition == "claim_heartbeat"]
        assert len(heartbeat_events) == 1
        assert heartbeat_events[0].actor_kind == "human"

    def test_heartbeat_defaults_to_agent(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Default kind"},
        )
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        regista.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        events = regista.read_events(work_item_id=wi.work_item_id)
        heartbeat_events = [e for e in events if e.transition == "claim_heartbeat"]
        assert len(heartbeat_events) == 1
        assert heartbeat_events[0].actor_kind == "agent"


class TestCloseBehavior:
    def test_close_is_idempotent(self, regista):
        regista.close()
        regista.close()

    def test_operation_after_close_raises(self, regista):
        regista.close()
        with pytest.raises(RegistaError) as exc_info:
            regista.get_work_item(uuid.uuid4())
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_pool_healthy_true_when_open(self, regista):
        assert regista.pool_healthy is True

    def test_pool_healthy_false_after_close(self, regista):
        regista.close()
        assert regista.pool_healthy is False


class TestHookNotFound:
    def test_complete_hook_not_found(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.complete_hook(999999)
        assert exc_info.value.code == ErrorCode.HOOK_NOT_FOUND

    def test_fail_hook_not_found(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.fail_hook(999999, "error")
        assert exc_info.value.code == ErrorCode.HOOK_NOT_FOUND


class TestDeadLetterLimit:
    def test_list_dead_lettered_hooks_respects_limit(self, regista):
        from datetime import UTC, datetime

        with raw_transaction(regista) as conn:
            for i in range(10):
                conn.execute(
                    "INSERT INTO hook_dead_letter "
                    "(event_id, hook_name, hook_type, payload, retry_count, "
                    "max_retries, error_message, dead_lettered_at, original_hook_queue_id) "
                    "VALUES (%s, %s, %s, NULL, %s, %s, %s, %s, %s)",
                    [
                        uuid.uuid4(), f"test_hook_{i}", "event",
                        3, 3, "test error", datetime.now(UTC), i + 1000,
                    ],
                )
        result = regista.list_dead_lettered_hooks(limit=5)
        assert len(result) == 5
        all_entries = regista.list_dead_lettered_hooks(limit=100)
        assert len(all_entries) == 10
