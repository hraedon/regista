from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def regista(tmp_path):
    from regista import Regista
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project = f"test_links_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path)
    sub = Regista.create_project(DSN, project, keyset.path)
    # `register_workflow_file` emits a signed `workflow_registered` event, so the
    # epoch has to be open before it runs.
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestLinkErrorPaths:
    def test_disallowed_link_type_rejected(self, regista):
        wi1, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent:worker",
            custom_fields={"title": "A"},
        )
        wi2, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="bug",
            actor_id="agent:worker",
            custom_fields={"severity": "major"},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.create_link(
                from_work_item_id=wi2.work_item_id,
                to_work_item_id=wi1.work_item_id,
                link_type="blocks",
                actor_id="agent:worker",
            )
        assert exc_info.value.code == ErrorCode.LINK_TYPE_NOT_ALLOWED

    def test_link_target_not_found_rejected(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent:worker",
            custom_fields={"title": "A"},
        )
        phantom = uuid.uuid4()
        with pytest.raises(RegistaError) as exc_info:
            regista.create_link(
                from_work_item_id=wi.work_item_id,
                to_work_item_id=phantom,
                link_type="blocks",
                actor_id="agent:worker",
            )
        assert exc_info.value.code == ErrorCode.LINK_TARGET_NOT_FOUND

    def test_remove_nonexistent_link_rejected(self, regista):
        wi1, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent:worker",
            custom_fields={"title": "A"},
        )
        wi2, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="bug",
            actor_id="agent:worker",
            custom_fields={"severity": "major"},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.remove_link(
                from_work_item_id=wi1.work_item_id,
                to_work_item_id=wi2.work_item_id,
                link_type="fixes",
                actor_id="agent:worker",
            )
        assert exc_info.value.code == ErrorCode.LINK_NOT_FOUND

    def test_link_removed_event_emitted(self, regista):
        wi1, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent:worker",
            custom_fields={"title": "A"},
        )
        wi2, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="bug",
            actor_id="agent:worker",
            custom_fields={"severity": "major"},
        )
        regista.create_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="fixes",
            actor_id="agent:worker",
        )

        events_before = regista.read_events(work_item_id=wi1.work_item_id)
        link_events_before = [e for e in events_before if e.transition == "link_created"]
        assert len(link_events_before) == 1

        regista.remove_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="fixes",
            actor_id="agent:worker",
        )

        events_after = regista.read_events(work_item_id=wi1.work_item_id)
        link_removed = [e for e in events_after if e.transition == "link_removed"]
        assert len(link_removed) == 1

        link_created = [e for e in events_after if e.transition == "link_created"]
        assert len(link_created) == 1
