from __future__ import annotations

import uuid
from pathlib import Path

from substrate.testing import InMemorySubstrate

TESTS_DIR = Path(__file__).parent
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"


class TestBC278HeartbeatCoalescingParity:
    def test_in_memory_uses_wall_clock_not_expiry_for_coalesce(self):
        sub = InMemorySubstrate(hmac_key_path=KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        wi, _ = sub.create_work_item("test_workflow", "feature", "agent-1",
                                     custom_fields={"title": "bc-278"})

        sub.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=600)

        import time
        time.sleep(0.1)

        sub.heartbeat_claim(wi.work_item_id, "agent-1", ttl_seconds=600, coalesce_threshold=0.01)

        events = sub.read_events(work_item_id=wi.work_item_id)
        heartbeat_events = [e for e in events if e.transition == "claim_heartbeat"]
        assert len(heartbeat_events) >= 1


class TestBC279ReplayWarnsOnUnknownTransitions:
    def test_postgres_replay_warns_on_unknown_transition(self):
        from substrate import Substrate
        from substrate.testing import drop_project_schema

        project = f"test_bc279_{uuid.uuid4().hex[:8]}"
        sub = Substrate.create_project(DSN, project, KEY_PATH)
        try:
            sub.register_workflow_file(WORKFLOW_PATH)
            wi, _ = sub.create_work_item("test_workflow", "feature", "agent-1",
                                         custom_fields={"title": "bc-279-pg"})

            sub.append_event(
                work_item_id=wi.work_item_id,
                actor_id="agent-1",
                transition="unknown_transition_xyz",
                payload={"note": "manually appended"},
            )

            report = sub.replay()
            assert report.warnings >= 1
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_in_memory_replay_warns_on_unknown_transition(self):
        sub = InMemorySubstrate(hmac_key_path=KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        wi, _ = sub.create_work_item("test_workflow", "feature", "agent-1",
                                     custom_fields={"title": "bc-279-im"})

        sub.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="unknown_transition_abc",
            payload={"note": "manually appended"},
        )

        report = sub.replay()
        assert report.warnings >= 1


class TestBC280HookHandlersCopyOnWrite:
    def test_register_handler_uses_new_dict(self):
        sub = InMemorySubstrate(hmac_key_path=KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)

        old_handlers = sub._hook_handlers
        sub.register_hook_handler("on_finish", lambda ctx: None)

        new_handlers = sub._hook_handlers
        assert new_handlers is not old_handlers
        assert "on_finish" in new_handlers

    def test_register_handler_preserves_existing(self):
        sub = InMemorySubstrate(hmac_key_path=KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)

        sub.register_hook_handler("handler_a", lambda ctx: None)
        sub.register_hook_handler("handler_b", lambda ctx: None)

        handlers = sub._hook_handlers
        assert "handler_a" in handlers
        assert "handler_b" in handlers

    def test_register_validator_uses_new_dict(self):
        sub = InMemorySubstrate(hmac_key_path=KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)

        old_validators = sub._validators
        sub.register_validator("start", lambda wi, payload: None)

        new_validators = sub._validators
        assert new_validators is not old_validators
        assert "start" in new_validators

