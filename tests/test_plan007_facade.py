from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from regista._types import Claim, Event, Link, WorkItem
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture(scope="module")
def regista(tmp_path_factory):
    from regista import Regista
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project = f"test_p007_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path_factory.mktemp("p007_keys"))
    sub = Regista.create_project(DSN, project, keyset.path)
    # The clean v6 epoch first: `register_workflow_file` emits the signed
    # `workflow_registered` event admission gate 1 requires, and there is no epoch
    # to append it to before `open_v6_epoch` returns.
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


def _read_workflow_yaml():
    return Path(WORKFLOW_PATH).read_text()


class TestFacadePropertiesCached:
    def test_workflow_ops_cached(self, regista):
        ops1 = regista.workflows
        ops2 = regista.workflows
        assert ops1 is ops2

    def test_work_item_ops_cached(self, regista):
        ops1 = regista.work_items
        ops2 = regista.work_items
        assert ops1 is ops2

    def test_event_ops_cached(self, regista):
        ops1 = regista.events
        ops2 = regista.events
        assert ops1 is ops2

    def test_claim_ops_cached(self, regista):
        ops1 = regista.claims
        ops2 = regista.claims
        assert ops1 is ops2

    def test_link_ops_cached(self, regista):
        ops1 = regista.links
        ops2 = regista.links
        assert ops1 is ops2

    def test_hook_ops_cached(self, regista):
        ops1 = regista.hooks
        ops2 = regista.hooks
        assert ops1 is ops2

    def test_recurrence_ops_cached(self, regista):
        ops1 = regista.recurrence
        ops2 = regista.recurrence
        assert ops1 is ops2


class TestWorkflowOpsFacade:
    def test_register_via_facade(self, regista):
        yaml_content = _read_workflow_yaml()
        result = regista.workflows.register(yaml_content)
        assert result.name == "test_workflow"
        assert result.version == 1

    def test_get_via_facade(self, regista):
        wf = regista.workflows.get("test_workflow", 1)
        assert wf.name == "test_workflow"

    def test_register_file_via_facade(self, regista):
        result = regista.workflows.register_file(WORKFLOW_PATH)
        assert result.name == "test_workflow"


class TestWorkItemOpsFacade:
    def test_create_via_facade(self, regista):
        wi, evt = regista.work_items.create(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "facade-test"},
        )
        assert isinstance(wi, WorkItem)
        assert isinstance(evt, Event)
        assert wi.work_item_type == "feature"
        assert wi.current_state == "new"

    def test_get_via_facade(self, regista):
        wi, _ = regista.work_items.create(
            "test_workflow", "bug", "agent:worker",
            custom_fields={"severity": "major"},
        )
        found = regista.work_items.get(wi.work_item_id)
        assert found is not None
        assert found.work_item_id == wi.work_item_id

    def test_query_via_facade(self, regista):
        regista.work_items.create(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "query-test"},
        )
        page = regista.work_items.query(
            workflow_name="test_workflow",
            work_item_types=["feature"],
            page_size=10,
        )
        assert len(page.items) > 0
        assert all(wi.work_item_type == "feature" for wi in page.items)

    def test_update_not_before_via_facade(self, regista):
        wi, _ = regista.work_items.create(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "nb-test"},
        )
        future = datetime(2027, 1, 1, tzinfo=UTC)
        evt = regista.work_items.update_not_before(
            wi.work_item_id, future, "agent:worker",
        )
        assert isinstance(evt, Event)
        assert evt.transition == "not_before_set"


class TestEventOpsFacade:
    def test_append_via_facade(self, regista):
        wi, _ = regista.work_items.create(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "evt-test"},
        )
        evt = regista.events.append(
            wi.work_item_id, "agent:worker",
            transition="note", payload={"msg": "hello"},
        )
        assert isinstance(evt, Event)
        assert evt.transition == "note"

    def test_read_via_facade(self, regista):
        wi, _ = regista.work_items.create(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "read-test"},
        )
        regista.events.append(
            wi.work_item_id, "agent:worker",
            transition="log", payload={"k": "v"},
        )
        events = regista.events.read(work_item_id=wi.work_item_id)
        assert len(events) >= 2

    def test_read_since_via_facade(self, regista):
        wi, create_evt = regista.work_items.create(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "since-test"},
        )
        after = create_evt.event_seq
        regista.events.append(
            wi.work_item_id, "agent:worker",
            transition="log2", payload={"k": "v2"},
        )
        events = regista.events.read_since(wi.work_item_id, after)
        assert len(events) >= 1


class TestClaimOpsFacade:
    def test_acquire_via_facade(self, regista):
        wi, _ = regista.work_items.create(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "claim-test"},
        )
        claim = regista.claims.acquire(wi.work_item_id, "agent:worker")
        assert isinstance(claim, Claim)
        assert claim.actor_id == "agent:worker"

    def test_heartbeat_via_facade(self, regista):
        wi, _ = regista.work_items.create(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "hb-test"},
        )
        regista.claims.acquire(wi.work_item_id, "agent:worker")
        claim = regista.claims.heartbeat(wi.work_item_id, "agent:worker")
        assert isinstance(claim, Claim)

    def test_release_via_facade(self, regista):
        wi, _ = regista.work_items.create(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "rel-test"},
        )
        regista.claims.acquire(wi.work_item_id, "agent:worker")
        regista.claims.release(wi.work_item_id, "agent:worker")
        found = regista.work_items.get(wi.work_item_id)
        assert found.claimed_by is None

    def test_sweep_expired_via_facade(self, regista):
        swept = regista.claims.sweep_expired()
        assert isinstance(swept, int)


class TestLinkOpsFacade:
    def test_create_and_remove_via_facade(self, regista):
        wi1, _ = regista.work_items.create(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "link-src"},
        )
        wi2, _ = regista.work_items.create(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "link-dst"},
        )
        link = regista.links.create(
            wi1.work_item_id, wi2.work_item_id, "blocks", "agent:worker",
        )
        assert isinstance(link, Link)
        assert link.link_type == "blocks"

        regista.links.remove(
            wi1.work_item_id, wi2.work_item_id, "blocks", "agent:worker",
        )


class TestBackwardCompatibility:
    def test_old_create_work_item(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "compat-test"},
        )
        assert isinstance(wi, WorkItem)

    def test_old_append_event(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "compat-evt"},
        )
        evt = regista.append_event(
            wi.work_item_id, "agent:worker",
            transition="note", payload={"x": 1},
        )
        assert isinstance(evt, Event)

    def test_old_acquire_claim(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "compat-claim"},
        )
        claim = regista.acquire_claim(wi.work_item_id, "agent:worker")
        assert isinstance(claim, Claim)

    def test_old_create_link(self, regista):
        wi1, _ = regista.create_work_item(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "compat-link1"},
        )
        wi2, _ = regista.create_work_item(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "compat-link2"},
        )
        link = regista.create_link(
            wi1.work_item_id, wi2.work_item_id, "blocks", "agent:worker",
        )
        assert isinstance(link, Link)

    def test_old_register_workflow(self, regista):
        yaml_content = _read_workflow_yaml()
        result = regista.register_workflow(yaml_content)
        assert result.name == "test_workflow"

    def test_old_query_work_items(self, regista):
        page = regista.query_work_items(
            workflow_name="test_workflow",
            page_size=5,
        )
        assert len(page.items) >= 0

    def test_old_read_events(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "compat-rev"},
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        assert len(events) >= 1

    def test_facade_equals_old_api(self, regista):
        wi, _create_evt = regista.create_work_item(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "eq-test"},
        )
        evts_old = regista.read_events(work_item_id=wi.work_item_id)
        evts_new = regista.events.read(work_item_id=wi.work_item_id)
        assert len(evts_old) == len(evts_new)
        assert [e.event_id for e in evts_old] == [e.event_id for e in evts_new]

        found_old = regista.get_work_item(wi.work_item_id)
        found_new = regista.work_items.get(wi.work_item_id)
        assert found_old.work_item_id == found_new.work_item_id
