from __future__ import annotations

import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from substrate._errors import SubstrateError
from substrate._testing import raw_transaction
from substrate.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

WORKFLOW_V2 = """\
name: test_workflow
version: 2
substrate_version: "0.1.0"

states:
  - name: new
    initial: true
  - name: in_progress
  - name: review
  - name: done
    terminal: true

transitions:
  - name: start
    from: new
    to: in_progress
    allowed_roles: [agent]
    validator: validate_start
  - name: submit_review
    from: in_progress
    to: review
    allowed_roles: [agent]
    hooks: [notify_reviewer]
  - name: approve
    from: review
    to: done
    allowed_roles: [reviewer]

roles:
  - name: agent
  - name: reviewer

work_item_types:
  - name: feature
    custom_fields:
      - name: title
        type: string
        required: true
        ui_visible: true

link_types:
  - name: blocks
    source_type: feature
    target_type: feature

attempt_threshold: 3
"""


@pytest.fixture(scope="module")
def substrate():
    from substrate import Substrate

    project = f"test_phase2_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestEscalation:
    def test_no_escalation_below_threshold(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Esc test 1"},
        )

        substrate.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=1)
        import time
        time.sleep(1.1)

        substrate.acquire_claim(wi.work_item_id, "agent-2", ttl_seconds=1)
        time.sleep(1.1)

        refreshed = substrate.get_work_item(wi.work_item_id)
        assert refreshed is not None
        assert not refreshed.needs_review

    def test_escalation_at_threshold(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Esc test 2"},
        )

        import time
        substrate.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=1)
        time.sleep(1.1)

        substrate.acquire_claim(wi.work_item_id, "agent-2", ttl_seconds=1)
        time.sleep(1.1)

        substrate.acquire_claim(wi.work_item_id, "agent-3", ttl_seconds=300)

        refreshed = substrate.get_work_item(wi.work_item_id)
        assert refreshed is not None
        assert refreshed.needs_review

        events = substrate.read_events(work_item_id=wi.work_item_id)
        escalated = [e for e in events if e.transition == "escalated"]
        assert len(escalated) == 1
        assert escalated[0].payload["attempt_number"] == 3
        assert escalated[0].payload["threshold"] == 3

    def test_escalation_idempotent(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Esc idempotent"},
        )

        import time
        substrate.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=1)
        time.sleep(1.1)

        substrate.acquire_claim(wi.work_item_id, "agent-2", ttl_seconds=1)
        time.sleep(1.1)

        substrate.acquire_claim(wi.work_item_id, "agent-3", ttl_seconds=1)
        time.sleep(1.1)

        substrate.acquire_claim(wi.work_item_id, "agent-4", ttl_seconds=300)

        events = substrate.read_events(work_item_id=wi.work_item_id)
        escalated = [e for e in events if e.transition == "escalated"]
        assert len(escalated) == 1


class TestValidators:
    @pytest.fixture(autouse=True)
    def setup(self, substrate):
        substrate.register_workflow(WORKFLOW_V2)

    def test_validator_success(self, substrate):
        substrate.register_validator("validate_start", lambda ctx: None)

        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Validator test"},
        )

        evt = substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )
        assert evt.transition == "start"

    def test_validator_failure_rolls_back(self, substrate):
        def _fail(ctx):
            raise ValueError("validation failed")

        substrate.register_validator("validate_start", _fail)

        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Validator fail"},
        )

        with pytest.raises(SubstrateError, match="VALIDATOR_FAILED"):
            substrate.transition(
                work_item_id=wi.work_item_id,
                transition_name="start",
                actor_id="agent-1",
                actor_metadata={"role": "agent"},
            )

        refreshed = substrate.get_work_item(wi.work_item_id)
        assert refreshed is not None
        assert refreshed.current_state == "new"

    # test_validator_timeout removed per BC-192 — Python-side wall-clock
    # bound on validators was dropped (Option 2: trusted code). A slow
    # validator now hangs the transaction; see tests/test_validator_hardening.py
    # for the trusted-contract assertions.

    def test_validator_not_registered_warns(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "No validator"},
        )

        substrate._validators.pop("validate_start", None)

        evt = substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )
        assert evt.transition == "start"


class TestAsyncHooks:
    @pytest.fixture(autouse=True)
    def setup(self, substrate):
        substrate.register_workflow(WORKFLOW_V2)

    def test_hook_enqueued_on_transition(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Hook test"},
        )

        substrate.register_validator("validate_start", lambda ctx: None)

        substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )

        substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="submit_review",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )

        with raw_transaction(substrate) as conn:
            rows = conn.execute(
                "SELECT * FROM hook_queue WHERE hook_name = 'notify_reviewer' "
                "ORDER BY id"
            ).fetchall()

        assert len(rows) >= 1
        assert rows[0]["hook_name"] == "notify_reviewer"
        assert rows[0]["status"] == "pending"

    def test_hook_consumed_and_completed(self, substrate):
        processed = []

        def handler(ctx):
            processed.append(ctx.hook_name)

        substrate.register_hook_handler("notify_reviewer", handler)

        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Hook consume"},
        )

        substrate.register_validator("validate_start", lambda ctx: None)

        substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )

        substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="submit_review",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )

        count = substrate.poll_hooks()
        assert count >= 1
        assert "notify_reviewer" in processed

    def test_hook_retry_on_failure(self, substrate):
        call_count = 0

        def failing_handler(ctx):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise RuntimeError("temporary failure")

        substrate.register_hook_handler("notify_reviewer", failing_handler)

        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Hook retry"},
        )

        substrate.register_validator("validate_start", lambda ctx: None)

        substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )

        substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="submit_review",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )

        from datetime import UTC, datetime, timedelta

        with raw_transaction(substrate) as conn:
            conn.execute(
                "UPDATE hook_queue SET next_retry_at = %s WHERE status = 'pending'",
                [datetime.now(UTC) - timedelta(seconds=1)],
            )

        substrate.poll_hooks()
        assert call_count >= 1

    def test_hook_dead_lettered_after_max_retries(self, substrate):
        always_fail_count = 0

        def always_fail(ctx):
            nonlocal always_fail_count
            always_fail_count += 1
            raise RuntimeError("permanent failure")

        substrate.register_hook_handler("notify_reviewer", always_fail)

        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Dead letter"},
        )

        substrate.register_validator("validate_start", lambda ctx: None)

        substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )

        substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="submit_review",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )

        from datetime import UTC, datetime, timedelta

        with raw_transaction(substrate) as conn:
            conn.execute(
                "UPDATE hook_queue SET retry_count = 2, next_retry_at = %s "
                "WHERE status = 'pending'",
                [datetime.now(UTC) - timedelta(seconds=1)],
            )

        substrate.poll_hooks()

        dead = substrate.list_dead_lettered_hooks()
        matching = [d for d in dead if d.hook_name == "notify_reviewer"]
        assert len(matching) >= 1


class TestDeadLetterRequeue:
    def test_requeue_dead_lettered_hook(self, substrate):
        substrate.register_workflow(WORKFLOW_V2)
        substrate.register_validator("validate_start", lambda ctx: None)

        def always_fail(ctx):
            raise RuntimeError("fail")

        substrate.register_hook_handler("notify_reviewer", always_fail)

        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Requeue test"},
        )

        substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )

        substrate.transition(
            work_item_id=wi.work_item_id,
            transition_name="submit_review",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )

        from datetime import UTC, datetime, timedelta

        with raw_transaction(substrate) as conn:
            conn.execute(
                "UPDATE hook_queue SET retry_count = 2, next_retry_at = %s "
                "WHERE status = 'pending'",
                [datetime.now(UTC) - timedelta(seconds=1)],
            )

        substrate.poll_hooks()

        dead = substrate.list_dead_lettered_hooks()
        target = None
        for d in dead:
            if d.hook_name == "notify_reviewer":
                target = d
                break
        assert target is not None

        substrate.requeue_dead_lettered_hook(target.id)

        with raw_transaction(substrate) as conn:
            rows = conn.execute(
                "SELECT * FROM hook_queue WHERE event_id = %s AND hook_name = %s",
                [target.event_id, target.hook_name],
            ).fetchall()
        assert len(rows) >= 1
        assert rows[0]["retry_count"] == 0

    def test_requeue_nonexistent_fails(self, substrate):
        with pytest.raises(SubstrateError, match="HOOK_NOT_FOUND"):
            substrate.requeue_dead_lettered_hook(999999)


class TestValidateActorMetadata:
    def test_null_metadata(self, substrate):
        wi, evt = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Lint test"},
        )
        evt = substrate.read_events(work_item_id=wi.work_item_id)[0]
        evt_null = replace(evt, actor_metadata=None)
        issues = substrate.validate_actor_metadata(evt_null)
        assert any("null" in i for i in issues)

    def test_missing_recommended_fields(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Lint fields"},
        )
        events = substrate.read_events(work_item_id=wi.work_item_id)
        evt = replace(events[0], actor_metadata={"role": "agent"})
        issues = substrate.validate_actor_metadata(evt)
        assert any("model" in i for i in issues)
        assert any("provider" in i for i in issues)
        assert any("role_source" in i for i in issues)

    def test_invalid_role_source(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Lint role"},
        )
        events = substrate.read_events(work_item_id=wi.work_item_id)
        evt = replace(
            events[0],
            actor_metadata={"model": "gpt-4", "provider": "openai", "role_source": "hacked"},
        )
        issues = substrate.validate_actor_metadata(evt)
        assert any("role_source" in i for i in issues)

    def test_schema_validation(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Lint schema"},
        )
        events = substrate.read_events(work_item_id=wi.work_item_id)
        evt = replace(
            events[0],
            actor_metadata={"model": "gpt-4", "provider": "openai", "role_source": "config"},
        )
        schema = {
            "type": "object",
            "required": ["model", "nonexistent_field"],
        }
        issues = substrate.validate_actor_metadata(evt, expected_schema=schema)
        assert any("nonexistent_field" in i for i in issues)

    def test_clean_metadata_no_issues(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Lint clean"},
        )
        events = substrate.read_events(work_item_id=wi.work_item_id)
        evt = replace(
            events[0],
            actor_metadata={"model": "gpt-4", "provider": "openai", "role_source": "config"},
        )
        issues = substrate.validate_actor_metadata(evt)
        assert len(issues) == 0
