from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def regista():
    from regista import Regista

    project = f"test_remain_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestNotBeforeFuture:
    def test_claim_blocked_by_not_before(self, regista):
        future = datetime.now(UTC) + timedelta(hours=1)
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Future not before"},
            not_before=future,
        )

        with pytest.raises(RegistaError) as exc_info:
            regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        assert exc_info.value.code == ErrorCode.NOT_BEFORE_FUTURE


class TestWorkItemTypeNotDeclared:
    def test_create_rejects_undeclared_type(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="nonexistent_type",
                actor_id="agent-1",
                custom_fields={"title": "Bad type"},
            )
        assert exc_info.value.code == ErrorCode.WORK_ITEM_TYPE_NOT_DECLARED


class TestWorkflowNotRegistered:
    def test_create_rejects_unknown_workflow(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.create_work_item(
                workflow_name="nonexistent_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": "Unknown workflow"},
            )
        assert exc_info.value.code == ErrorCode.WORKFLOW_NOT_REGISTERED


class TestLinkCrossProject:
    def test_link_cross_workflow_rejected(self, regista):
        wf2 = (
            "name: other_workflow\n"
            "version: 1\n"
            "regista_version: '0.1.0'\n"
            "\n"
            "states:\n"
            "  - name: new\n"
            "    initial: true\n"
            "  - name: done\n"
            "    terminal: true\n"
            "\n"
            "transitions:\n"
            "  - name: finish\n"
            "    from: new\n"
            "    to: done\n"
            "    allowed_roles: [agent]\n"
            "\n"
            "roles:\n"
            "  - name: agent\n"
            "\n"
            "work_item_types:\n"
            "  - name: task\n"
            "    custom_fields: []\n"
            "link_types: []\n"
        )
        regista.register_workflow(wf2)

        wi1, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "A"},
        )
        wi2, _ = regista.create_work_item(
            workflow_name="other_workflow",
            work_item_type="task",
            actor_id="agent-1",
        )

        with pytest.raises(RegistaError) as exc_info:
            regista.create_link(
                from_work_item_id=wi1.work_item_id,
                to_work_item_id=wi2.work_item_id,
                link_type="fixes",
                actor_id="agent-1",
            )
        assert exc_info.value.code == ErrorCode.LINK_CROSS_PROJECT


class TestCustomFieldViolation:
    def test_missing_required_field_on_create(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="bug",
                actor_id="agent-1",
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION

    def test_unknown_field_on_create(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": "Ok", "nonexistent": "bad"},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION

    def test_wrong_type_on_create(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": 123},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION

    def test_invalid_enum_on_create(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": "Ok", "priority": "super_high"},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION

    def test_custom_field_violation_on_transition(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "Field test"},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="start",
                actor_id="agent-1",
                actor_metadata={"role": "agent"},
                custom_fields={"title": 9999},
            )
        assert exc_info.value.code == ErrorCode.CUSTOM_FIELD_VIOLATION


class TestDbNotFound:
    def test_connect_without_create_rejects(self, regista):
        from regista import Regista

        project = f"nonexistent_{uuid.uuid4().hex[:8]}"
        with pytest.raises(RegistaError) as exc_info:
            Regista(DSN, project, KEY_PATH)
        assert exc_info.value.code == ErrorCode.DB_NOT_FOUND
