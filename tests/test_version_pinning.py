from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._testing import raw_transaction
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

WF_V1 = (
    "name: versioned_wf\n"
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
)

WF_V2 = (
    "name: versioned_wf\n"
    "version: 2\n"
    "regista_version: '0.1.0'\n"
    "\n"
    "states:\n"
    "  - name: new\n"
    "    initial: true\n"
    "  - name: in_progress\n"
    "  - name: done\n"
    "    terminal: true\n"
    "\n"
    "transitions:\n"
    "  - name: start\n"
    "    from: new\n"
    "    to: in_progress\n"
    "    allowed_roles: [agent]\n"
    "  - name: finish\n"
    "    from: in_progress\n"
    "    to: done\n"
    "    allowed_roles: [agent]\n"
    "  - name: shortcut\n"
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
)


ACTOR = "agent:worker"


@pytest.fixture
def regista(tmp_path):
    from regista import Regista
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project = f"test_ac12_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path)
    sub = Regista.create_project(DSN, project, keyset.path)
    # Genesis before registration: `register_workflow` emits the signed
    # `workflow_registered` event admission gate 1 requires and is a silent no-op
    # before genesis.
    open_v6_epoch(sub, keyset)
    sub.register_workflow(WF_V1)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestAC12PinnedVersionIsolation:
    def test_v1_work_item_rejects_v2_only_transition(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="versioned_wf",
            work_item_type="task",
            actor_id=ACTOR,
        )

        with raw_transaction(regista) as conn:
            row = conn.execute(
                "SELECT workflow_version FROM work_items_current WHERE work_item_id = %s",
                [wi.work_item_id],
            ).fetchone()
        assert row["workflow_version"] == 1

        regista.register_workflow(WF_V2)

        with pytest.raises(RegistaError) as exc_info:
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="shortcut",
                actor_id=ACTOR,
                actor_metadata={"role": "agent"},
            )
        assert exc_info.value.code == ErrorCode.INVALID_TRANSITION
        assert "v1" in exc_info.value.message

    def test_v2_work_item_accepts_shortcut(self, regista):
        regista.register_workflow(WF_V2)

        wi, _ = regista.create_work_item(
            workflow_name="versioned_wf",
            work_item_type="task",
            actor_id=ACTOR,
        )

        with raw_transaction(regista) as conn:
            row = conn.execute(
                "SELECT workflow_version FROM work_items_current WHERE work_item_id = %s",
                [wi.work_item_id],
            ).fetchone()
        assert row["workflow_version"] == 2

        evt = regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="shortcut",
            actor_id=ACTOR,
            actor_metadata={"role": "agent"},
        )
        assert evt.transition == "shortcut"

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.current_state == "done"

    def test_v1_work_item_uses_v1_transitions(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="versioned_wf",
            work_item_type="task",
            actor_id=ACTOR,
        )

        regista.register_workflow(WF_V2)

        evt = regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="finish",
            actor_id=ACTOR,
            actor_metadata={"role": "agent"},
        )
        assert evt.transition == "finish"

        refreshed = regista.get_work_item(wi.work_item_id)
        assert refreshed.current_state == "done"
