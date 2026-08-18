from __future__ import annotations

import uuid
from dataclasses import replace
from pathlib import Path

import pytest
from _helpers import DSN
from _v6_fixtures import ACTOR_PRINCIPALS, make_v6_keyset, open_v6_epoch

from regista._errors import ErrorCode, RegistaError
from regista._testing import raw_transaction
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

#: Canonical principal ids (TRUST-DOMAIN.md §2.1). The pre-epoch spellings were
#: ``agent-1`` … ``agent-4``; a bare legacy name is refused at v6 ingress.
#:
#: Escalation here is driven by *distinct* claimants stealing an expired claim, and
#: ``attempt_threshold: 3`` plus the idempotence case needs **four** of them. The
#: default five would supply that count only by casting two humans as claimants, so
#: two extra ``agent:`` principals are declared instead — same list passed to
#: ``make_v6_keyset`` and ``open_v6_epoch``, which is the invariant that keeps
#: KEY_BINDING_UNRESOLVED honest.
AGENT_1 = "agent:worker"
AGENT_2 = "agent:reviewer"
AGENT_3 = "agent:worker-three"
AGENT_4 = "agent:worker-four"
PRINCIPALS = (*ACTOR_PRINCIPALS, AGENT_3, AGENT_4)

WORKFLOW_V2 = """\
name: test_workflow
version: 2
regista_version: "0.1.0"

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
def regista(tmp_path_factory):
    from regista import Regista

    project = f"test_phase2_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path_factory.mktemp("phase2_keys"), principals=PRINCIPALS)
    sub = Regista.create_project(DSN, project, keyset.path)
    # Genesis first: `register_workflow_file` emits the signed `workflow_registered`
    # event admission gate 1 requires, and before `open_v6_epoch` there is no epoch
    # to append it to (the registration silently degrades to a row-only write, and
    # the confusion surfaces later as WORKFLOW_REGISTRATION_UNRESOLVED).
    open_v6_epoch(sub, keyset, principals=PRINCIPALS)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestEscalation:
    def test_no_escalation_below_threshold(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Esc test 1"},
        )

        regista.acquire_claim(wi.work_item_id, AGENT_1, ttl_seconds=1)
        import time
        time.sleep(1.1)

        regista.acquire_claim(wi.work_item_id, AGENT_2, ttl_seconds=1)
        time.sleep(1.1)

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed is not None
        assert not refreshed.needs_review

    def test_escalation_at_threshold(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Esc test 2"},
        )

        import time
        regista.acquire_claim(wi.work_item_id, AGENT_1, ttl_seconds=1)
        time.sleep(1.1)

        regista.acquire_claim(wi.work_item_id, AGENT_2, ttl_seconds=1)
        time.sleep(1.1)

        regista.acquire_claim(wi.work_item_id, AGENT_3, ttl_seconds=300)

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed is not None
        assert refreshed.needs_review

        events = regista.read_events(work_item_id=wi.work_item_id)
        escalated = [e for e in events if e.transition == "escalated"]
        assert len(escalated) == 1
        assert escalated[0].payload["attempt_number"] == 3
        assert escalated[0].payload["threshold"] == 3

    def test_escalation_idempotent(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Esc idempotent"},
        )

        import time
        regista.acquire_claim(wi.work_item_id, AGENT_1, ttl_seconds=1)
        time.sleep(1.1)

        regista.acquire_claim(wi.work_item_id, AGENT_2, ttl_seconds=1)
        time.sleep(1.1)

        regista.acquire_claim(wi.work_item_id, AGENT_3, ttl_seconds=1)
        time.sleep(1.1)

        regista.acquire_claim(wi.work_item_id, AGENT_4, ttl_seconds=300)

        events = regista.read_events(work_item_id=wi.work_item_id)
        escalated = [e for e in events if e.transition == "escalated"]
        assert len(escalated) == 1


class TestValidators:
    @pytest.fixture(autouse=True)
    def setup(self, regista):
        regista.register_workflow(WORKFLOW_V2)

    def test_validator_success(self, regista):
        regista.register_validator("validate_start", lambda ctx: None)

        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Validator test"},
        )

        evt = regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id=AGENT_1,
            actor_metadata={"role": "agent"},
        )
        assert evt.transition == "start"

    def test_validator_failure_rolls_back(self, regista):
        def _fail(ctx):
            raise ValueError("validation failed")

        regista.register_validator("validate_start", _fail)

        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Validator fail"},
        )

        with pytest.raises(RegistaError, match="VALIDATOR_FAILED"):
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="start",
                actor_id=AGENT_1,
                actor_metadata={"role": "agent"},
            )

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed is not None
        assert refreshed.current_state == "new"

    # test_validator_timeout removed per BC-192 — Python-side wall-clock
    # bound on validators was dropped (Option 2: trusted code). A slow
    # validator now hangs the transaction; see tests/test_validator_hardening.py
    # for the trusted-contract assertions.

    def test_validator_not_registered_fails_closed(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "No validator"},
        )

        regista._validators.pop("validate_start", None)

        with pytest.raises(RegistaError) as exc_info:
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="start",
                actor_id=AGENT_1,
                actor_metadata={"role": "agent"},
            )
        assert exc_info.value.code == ErrorCode.VALIDATOR_NOT_REGISTERED
        assert regista.get_work_item(wi.work_item_id).current_state == "new"


class TestAsyncHooks:
    @pytest.fixture(autouse=True)
    def setup(self, regista):
        regista.register_workflow(WORKFLOW_V2)

    def test_hook_enqueued_on_transition(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Hook test"},
        )

        regista.register_validator("validate_start", lambda ctx: None)

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id=AGENT_1,
            actor_metadata={"role": "agent"},
        )

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="submit_review",
            actor_id=AGENT_1,
            actor_metadata={"role": "agent"},
        )

        with raw_transaction(regista) as conn:
            rows = conn.execute(
                "SELECT * FROM hook_queue WHERE hook_name = 'notify_reviewer' "
                "ORDER BY id"
            ).fetchall()

        assert len(rows) >= 1
        assert rows[0]["hook_name"] == "notify_reviewer"
        assert rows[0]["status"] == "pending"

    def test_hook_consumed_and_completed(self, regista):
        processed = []

        def handler(ctx):
            processed.append(ctx.hook_name)

        regista.register_hook_handler("notify_reviewer", handler)

        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Hook consume"},
        )

        regista.register_validator("validate_start", lambda ctx: None)

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id=AGENT_1,
            actor_metadata={"role": "agent"},
        )

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="submit_review",
            actor_id=AGENT_1,
            actor_metadata={"role": "agent"},
        )

        count = regista.poll_hooks()
        assert count >= 1
        assert "notify_reviewer" in processed

    def test_hook_retry_on_failure(self, regista):
        call_count = 0

        def failing_handler(ctx):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise RuntimeError("temporary failure")

        regista.register_hook_handler("notify_reviewer", failing_handler)

        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Hook retry"},
        )

        regista.register_validator("validate_start", lambda ctx: None)

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id=AGENT_1,
            actor_metadata={"role": "agent"},
        )

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="submit_review",
            actor_id=AGENT_1,
            actor_metadata={"role": "agent"},
        )

        from datetime import UTC, datetime, timedelta

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE hook_queue SET next_retry_at = %s WHERE status = 'pending'",
                [datetime.now(UTC) - timedelta(seconds=1)],
            )

        regista.poll_hooks()
        assert call_count >= 1

    def test_hook_dead_lettered_after_max_retries(self, regista):
        always_fail_count = 0

        def always_fail(ctx):
            nonlocal always_fail_count
            always_fail_count += 1
            raise RuntimeError("permanent failure")

        regista.register_hook_handler("notify_reviewer", always_fail)

        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Dead letter"},
        )

        regista.register_validator("validate_start", lambda ctx: None)

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id=AGENT_1,
            actor_metadata={"role": "agent"},
        )

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="submit_review",
            actor_id=AGENT_1,
            actor_metadata={"role": "agent"},
        )

        from datetime import UTC, datetime, timedelta

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE hook_queue SET retry_count = 2, next_retry_at = %s "
                "WHERE status = 'pending'",
                [datetime.now(UTC) - timedelta(seconds=1)],
            )

        regista.poll_hooks()

        dead = regista.list_dead_lettered_hooks()
        matching = [d for d in dead if d.hook_name == "notify_reviewer"]
        assert len(matching) >= 1


class TestDeadLetterRequeue:
    def test_requeue_dead_lettered_hook(self, regista):
        regista.register_workflow(WORKFLOW_V2)
        regista.register_validator("validate_start", lambda ctx: None)

        def always_fail(ctx):
            raise RuntimeError("fail")

        regista.register_hook_handler("notify_reviewer", always_fail)

        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Requeue test"},
        )

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id=AGENT_1,
            actor_metadata={"role": "agent"},
        )

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="submit_review",
            actor_id=AGENT_1,
            actor_metadata={"role": "agent"},
        )

        from datetime import UTC, datetime, timedelta

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE hook_queue SET retry_count = 2, next_retry_at = %s "
                "WHERE status = 'pending'",
                [datetime.now(UTC) - timedelta(seconds=1)],
            )

        regista.poll_hooks()

        dead = regista.list_dead_lettered_hooks()
        target = None
        for d in dead:
            if d.hook_name == "notify_reviewer":
                target = d
                break
        assert target is not None

        regista.requeue_dead_lettered_hook(target.id)

        with raw_transaction(regista) as conn:
            rows = conn.execute(
                "SELECT * FROM hook_queue WHERE event_id = %s AND hook_name = %s",
                [target.event_id, target.hook_name],
            ).fetchall()
        assert len(rows) >= 1
        assert rows[0]["retry_count"] == 0

    def test_requeue_nonexistent_fails(self, regista):
        with pytest.raises(RegistaError, match="HOOK_NOT_FOUND"):
            regista.requeue_dead_lettered_hook(999999)


class TestValidateActorMetadata:
    def test_null_metadata(self, regista):
        wi, evt = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Lint test"},
        )
        evt = regista.read_events(work_item_id=wi.work_item_id)[0]
        evt_null = replace(evt, actor_metadata=None)
        issues = regista.validate_actor_metadata(evt_null)
        assert any("null" in i for i in issues)

    def test_missing_recommended_fields(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Lint fields"},
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        evt = replace(events[0], actor_metadata={"role": "agent"})
        issues = regista.validate_actor_metadata(evt)
        assert any("model" in i for i in issues)
        assert any("provider" in i for i in issues)
        assert any("role_source" in i for i in issues)

    def test_invalid_role_source(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Lint role"},
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        evt = replace(
            events[0],
            actor_metadata={"model": "gpt-4", "provider": "openai", "role_source": "hacked"},
        )
        issues = regista.validate_actor_metadata(evt)
        assert any("role_source" in i for i in issues)

    def test_schema_validation(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Lint schema"},
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        evt = replace(
            events[0],
            actor_metadata={"model": "gpt-4", "provider": "openai", "role_source": "config"},
        )
        schema = {
            "type": "object",
            "required": ["model", "nonexistent_field"],
        }
        issues = regista.validate_actor_metadata(evt, expected_schema=schema)
        assert any("nonexistent_field" in i for i in issues)

    def test_clean_metadata_no_issues(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=AGENT_1,
            custom_fields={"title": "Lint clean"},
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        evt = replace(
            events[0],
            actor_metadata={"model": "gpt-4", "provider": "openai", "role_source": "config"},
        )
        issues = regista.validate_actor_metadata(evt)
        assert len(issues) == 0
