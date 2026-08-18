from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from regista.testing import InMemoryRegista

DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(Path(__file__).parent / "test_keys.json")

WORKFLOW_YAML = """\
name: test_plan008
version: 1
regista_version: "0.1.0"

states:
  - name: pending
    initial: true
  - name: in_progress
    terminal: true

transitions:
  - name: start
    from: pending
    to: in_progress
    allowed_roles:
      - worker

roles:
  - name: worker

work_item_types:
  - name: task
    custom_fields: []
"""


@pytest.fixture
def pg_project(tmp_path):
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project_name = f"plan008_ws1_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path)
    sub = Regista.create_project(DSN, project_name, keyset.path)
    # `register_workflow` emits a signed `workflow_registered` event, so the epoch
    # has to be open before it runs.
    open_v6_epoch(sub, keyset)
    sub.register_workflow(WORKFLOW_YAML)
    yield sub
    sub.close()
    from regista.testing import drop_project_schema

    drop_project_schema(DSN, project_name)


@pytest.fixture
def pg_project_strict(tmp_path):
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project_name = f"plan008_strict_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path)
    sub = Regista.create_project(DSN, project_name, keyset.path, strict_roles=True)
    open_v6_epoch(sub, keyset)
    sub.register_workflow(WORKFLOW_YAML)
    yield sub
    sub.close()
    from regista.testing import drop_project_schema

    drop_project_schema(DSN, project_name)


def _v6_in_memory(tmp_path, **kwargs):
    """An ``InMemoryRegista`` on a clean v6 epoch, ``WORKFLOW_YAML`` registered."""

    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    keyset = make_v6_keyset(tmp_path)
    sub = InMemoryRegista(hmac_key_path=keyset.path, **kwargs)
    open_v6_epoch(sub, keyset)
    sub.register_workflow(WORKFLOW_YAML)
    return sub


class TestPostgresStrictRoles:
    def test_default_allows_unregistered_actor(self, pg_project):
        sub = pg_project
        wi, _ = sub.create_work_item(
            "test_plan008", "task", "agent:worker",
            actor_metadata={"role": "worker"},
        )
        evt = sub.transition(
            wi.work_item_id, "start", "agent:worker",
            actor_metadata={"role": "worker"},
        )
        assert evt.transition == "start"

    def test_strict_rejects_unregistered_actor(self, pg_project_strict):
        sub = pg_project_strict
        wi, _ = sub.create_work_item(
            "test_plan008", "task", "agent:worker",
            actor_metadata={"role": "worker"},
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.transition(
                wi.work_item_id, "start", "agent:worker",
                actor_metadata={"role": "worker"},
            )
        assert exc_info.value.code == ErrorCode.ACTOR_ROLE_NOT_AUTHORIZED
        assert "no registered roles" in exc_info.value.message

    def test_strict_allows_registered_actor(self, pg_project_strict):
        sub = pg_project_strict
        sub.register_actor_role("agent:worker", "worker")
        wi, _ = sub.create_work_item(
            "test_plan008", "task", "agent:worker",
            actor_metadata={"role": "worker", "role_source": "config"},
        )
        evt = sub.transition(
            wi.work_item_id, "start", "agent:worker",
            actor_metadata={"role": "worker", "role_source": "config"},
        )
        assert evt.transition == "start"

    def test_strict_rejects_prompt_role_source(self, pg_project_strict):
        sub = pg_project_strict
        sub.register_actor_role("agent:worker", "worker")
        wi, _ = sub.create_work_item(
            "test_plan008", "task", "agent:worker",
            actor_metadata={"role": "worker", "role_source": "config"},
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.transition(
                wi.work_item_id, "start", "agent:worker",
                actor_metadata={"role": "worker", "role_source": "prompt"},
            )
        assert exc_info.value.code == ErrorCode.ACTOR_ROLE_NOT_AUTHORIZED
        assert "role_source" in exc_info.value.message


class TestInMemoryStrictRoles:
    def test_default_allows_unregistered_actor(self, tmp_path):
        sub = _v6_in_memory(tmp_path)
        wi, _ = sub.create_work_item(
            "test_plan008", "task", "agent:worker",
            actor_metadata={"role": "worker"},
        )
        evt = sub.transition(
            wi.work_item_id, "start", "agent:worker",
            actor_metadata={"role": "worker"},
        )
        assert evt.transition == "start"

    def test_strict_rejects_unregistered_actor(self, tmp_path):
        sub = _v6_in_memory(tmp_path, strict_roles=True)
        wi, _ = sub.create_work_item(
            "test_plan008", "task", "agent:worker",
            actor_metadata={"role": "worker"},
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.transition(
                wi.work_item_id, "start", "agent:worker",
                actor_metadata={"role": "worker"},
            )
        assert exc_info.value.code == ErrorCode.ACTOR_ROLE_NOT_AUTHORIZED
        assert "no registered roles" in exc_info.value.message

    def test_strict_allows_registered_actor(self, tmp_path):
        sub = _v6_in_memory(tmp_path, strict_roles=True)
        sub.register_actor_role("agent:worker", "worker")
        wi, _ = sub.create_work_item(
            "test_plan008", "task", "agent:worker",
            actor_metadata={"role": "worker", "role_source": "config"},
        )
        evt = sub.transition(
            wi.work_item_id, "start", "agent:worker",
            actor_metadata={"role": "worker", "role_source": "config"},
        )
        assert evt.transition == "start"

    def test_strict_rejects_prompt_role_source(self, tmp_path):
        sub = _v6_in_memory(tmp_path, strict_roles=True)
        sub.register_actor_role("agent:worker", "worker")
        wi, _ = sub.create_work_item(
            "test_plan008", "task", "agent:worker",
            actor_metadata={"role": "worker", "role_source": "config"},
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.transition(
                wi.work_item_id, "start", "agent:worker",
                actor_metadata={"role": "worker", "role_source": "prompt"},
            )
        assert exc_info.value.code == ErrorCode.ACTOR_ROLE_NOT_AUTHORIZED
        assert "role_source" in exc_info.value.message
