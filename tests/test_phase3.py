from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from regista._errors import RegistaError
from regista._testing import KeySet, raw_transaction, replay_fn
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def regista():
    from regista import Regista

    project = f"test_phase3_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestActorRoles:
    def test_register_and_list_roles(self, regista):
        regista.register_actor_role("agent-1", "agent")
        regista.register_actor_role("agent-1", "reviewer")

        roles = regista.list_actor_roles(actor_id="agent-1")
        assert len(roles) == 2
        role_names = {r.role for r in roles}
        assert role_names == {"agent", "reviewer"}

    def test_register_duplicate_role_is_idempotent(self, regista):
        regista.register_actor_role("agent-2", "agent")
        regista.register_actor_role("agent-2", "agent")
        roles = regista.list_actor_roles(actor_id="agent-2")
        role_names = {r.role for r in roles}
        assert role_names == {"agent"}

    def test_unregister_role(self, regista):
        regista.register_actor_role("agent-3", "agent")
        regista.unregister_actor_role("agent-3", "agent")

        roles = regista.list_actor_roles(actor_id="agent-3")
        assert len(roles) == 0

    def test_unregister_nonexistent_role_raises(self, regista):
        with pytest.raises(RegistaError, match="ACTOR_ROLE_NOT_REGISTERED"):
            regista.unregister_actor_role("agent-4", "agent")

    def test_list_all_roles(self, regista):
        regista.register_actor_role("list-a-1", "agent")
        regista.register_actor_role("list-a-2", "reviewer")

        roles = regista.list_actor_roles()
        assert len(roles) >= 2

    def test_role_enforcement_rejects_unauthorized(self, regista):
        regista.register_actor_role("enforce-1", "reviewer")

        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="enforce-1",
            custom_fields={"title": "Enforcement test"},
        )

        with pytest.raises(RegistaError, match="ACTOR_ROLE_NOT_AUTHORIZED"):
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="start",
                actor_id="enforce-1",
                actor_metadata={"role": "agent"},
            )

    def test_role_enforcement_allows_authorized(self, regista):
        regista.register_actor_role("enforce-2", "agent")

        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="enforce-2",
            custom_fields={"title": "Allowed test"},
        )

        evt = regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="enforce-2",
            actor_metadata={"role": "agent"},
        )
        assert evt.transition == "start"

    def test_no_registered_roles_trusts_claim(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="unregistered-agent",
            custom_fields={"title": "Trust test"},
        )

        evt = regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="unregistered-agent",
            actor_metadata={"role": "agent"},
        )
        assert evt.transition == "start"

    def test_role_enforcement_detail_in_error(self, regista):
        regista.register_actor_role("detail-1", "reviewer")

        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="detail-1",
            custom_fields={"title": "Detail test"},
        )

        with pytest.raises(RegistaError, match="Allowed roles") as exc_info:
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="start",
                actor_id="detail-1",
                actor_metadata={"role": "agent"},
            )
        assert "detail-1" in str(exc_info.value)
        assert "agent" in str(exc_info.value)

    def test_register_actor_role_rejects_overlong_actor_id(self, regista):
        long_id = "x" * 256
        with pytest.raises(RegistaError, match="INVALID_ARGUMENT"):
            regista.register_actor_role(long_id, "agent")

    def test_unregister_actor_role_rejects_overlong_actor_id(self, regista):
        long_id = "x" * 256
        with pytest.raises(RegistaError, match="INVALID_ARGUMENT"):
            regista.unregister_actor_role(long_id, "agent")


class TestContinueOnRevokedReplay:
    def test_replay_halts_on_revoked_without_flag(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Revoke halt test"},
        )

        events = regista.read_events(work_item_id=wi.work_item_id)
        original_key_id = events[0].key_id

        revoked_key_data = {
            "keys": [
                {
                    "key_id": original_key_id,
                    "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
                    "status": "revoked",
                },
            ]
        }

        revoked_key_path = TESTS_DIR / f"test_keys_cor_{uuid.uuid4().hex[:8]}.json"
        try:
            revoked_key_path.write_text(json.dumps(revoked_key_data))

            revoked_key_set = KeySet(str(revoked_key_path))

            with raw_transaction(regista) as conn:
                report = replay_fn(
                    conn, regista._mgr.schema, regista.project, revoked_key_set,
                    continue_on_revoked=False,
                )
                assert report.halted >= 1
        finally:
            revoked_key_path.unlink(missing_ok=True)

    def test_replay_continues_on_revoked_with_flag(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Revoke continue test"},
        )

        events = regista.read_events(work_item_id=wi.work_item_id)
        original_key_id = events[0].key_id

        revoked_key_data = {
            "keys": [
                {
                    "key_id": original_key_id,
                    "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
                    "status": "revoked",
                },
            ]
        }

        revoked_key_path = TESTS_DIR / f"test_keys_cor2_{uuid.uuid4().hex[:8]}.json"
        try:
            revoked_key_path.write_text(json.dumps(revoked_key_data))

            revoked_key_set = KeySet(str(revoked_key_path))

            with raw_transaction(regista) as conn:
                report = replay_fn(
                    conn, regista._mgr.schema, regista.project, revoked_key_set,
                    continue_on_revoked=True,
                )
                assert report.halted == 0
                assert report.warnings >= 1
        finally:
            revoked_key_path.unlink(missing_ok=True)

    def test_replay_revoked_key_with_wrong_secret_halts(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Revoked bad secret"},
        )

        events = regista.read_events(work_item_id=wi.work_item_id)
        original_key_id = events[0].key_id

        bad_secret = "YmFkIHNlY3JldCB0aGF0IGRvZXMgbm90IG1hdGNo"
        revoked_key_data = {
            "keys": [
                {
                    "key_id": original_key_id,
                    "secret": bad_secret,
                    "status": "revoked",
                },
            ]
        }

        revoked_key_path = TESTS_DIR / f"test_keys_cor3_{uuid.uuid4().hex[:8]}.json"
        try:
            revoked_key_path.write_text(json.dumps(revoked_key_data))

            revoked_key_set = KeySet(str(revoked_key_path))

            with raw_transaction(regista) as conn:
                report = replay_fn(
                    conn, regista._mgr.schema, regista.project, revoked_key_set,
                    continue_on_revoked=True,
                )
                assert report.halted >= 1
        finally:
            revoked_key_path.unlink(missing_ok=True)

    def test_replay_unknown_key_with_continue_on_revoked_skips(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Unknown key skip"},
        )

        regista.read_events(work_item_id=wi.work_item_id)

        unknown_key_data = {
            "keys": [
                {
                    "key_id": "completely-different-key",
                    "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
                    "status": "active",
                },
            ]
        }

        unknown_key_path = TESTS_DIR / f"test_keys_cor4_{uuid.uuid4().hex[:8]}.json"
        try:
            unknown_key_path.write_text(json.dumps(unknown_key_data))

            unknown_key_set = KeySet(str(unknown_key_path))

            with raw_transaction(regista) as conn:
                report = replay_fn(
                    conn, regista._mgr.schema, regista.project, unknown_key_set,
                    continue_on_revoked=True,
                )
                assert report.halted == 0
                assert report.warnings >= 1
        finally:
            unknown_key_path.unlink(missing_ok=True)

    def test_public_replay_api_accepts_flag(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Public API flag test"},
        )
        regista.transition(
            wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"},
        )

        report = regista.replay(continue_on_revoked=True)
        assert report.replayed_drift == 0
        assert report.halted == 0
        assert report.warnings == 0

    def test_replay_report_warnings_default_zero(self, regista):
        _wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "No warnings test"},
        )

        report = regista.replay()
        assert report.warnings == 0


class TestUpdateNotBefore:
    def test_set_not_before(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Not before test"},
        )
        assert wi.not_before is None

        future = datetime.now(UTC) + timedelta(hours=24)
        evt = regista.update_not_before(
            wi.work_item_id, future, "agent-1",
        )
        assert evt.transition == "not_before_set"

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.not_before is not None

    def test_clear_not_before(self, regista):
        future = datetime.now(UTC) + timedelta(hours=24)
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Clear not before"},
            not_before=future,
        )
        assert wi.not_before is not None

        regista.update_not_before(wi.work_item_id, None, "agent-1")

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.not_before is None

    def test_not_before_set_replays_correctly(self, regista):
        future = datetime.now(UTC) + timedelta(hours=24)
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Replay not before"},
            not_before=future,
        )

        later = future + timedelta(hours=48)
        regista.update_not_before(wi.work_item_id, later, "agent-1")

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_not_before_blocks_claim(self, regista):
        future = datetime.now(UTC) + timedelta(hours=1)
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Block claim"},
            not_before=future,
        )

        with pytest.raises(RegistaError, match="not_before"):
            regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)

    def test_not_before_update_event_idempotent(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Idempotent not before"},
        )

        eid = uuid.uuid4()
        future = datetime.now(UTC) + timedelta(hours=1)

        e1 = regista.update_not_before(
            wi.work_item_id, future, "agent-1", event_id=eid,
        )
        e2 = regista.update_not_before(
            wi.work_item_id, future, "agent-1", event_id=eid,
        )
        assert e1.event_id == e2.event_id


class TestCustomFieldValidationAtTransition:
    def test_valid_field_update(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Field update test", "priority": "medium"},
        )

        evt = regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
            custom_fields={"priority": "high"},
        )
        assert evt.transition == "start"

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.custom_fields["priority"] == "high"

    def test_invalid_enum_value_rejected(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Bad enum test"},
        )

        with pytest.raises(RegistaError, match="not in enum"):
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="start",
                actor_id="agent-1",
                actor_metadata={"role": "agent"},
                custom_fields={"priority": "invalid_value"},
            )

    def test_unknown_field_rejected(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Unknown field test"},
        )

        with pytest.raises(RegistaError, match="Unknown field"):
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="start",
                actor_id="agent-1",
                actor_metadata={"role": "agent"},
                custom_fields={"nonexistent_field": "value"},
            )

    def test_wrong_type_rejected(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Type test"},
        )

        with pytest.raises(RegistaError, match="expects string"):
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="start",
                actor_id="agent-1",
                actor_metadata={"role": "agent"},
                custom_fields={"title": 12345},
            )

    def test_json_field_accepts_complex(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "JSON test"},
        )

        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
            custom_fields={"metadata": {"nested": True, "count": 42}},
        )

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.custom_fields["metadata"]["nested"] is True
