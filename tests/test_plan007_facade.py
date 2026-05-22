from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from substrate._types import Claim, Event, Link, WorkItem
from substrate.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture(scope="module")
def substrate():
    from substrate import Substrate

    project = f"test_p007_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


def _read_workflow_yaml():
    return Path(WORKFLOW_PATH).read_text()


class TestFacadePropertiesCached:
    def test_workflow_ops_cached(self, substrate):
        ops1 = substrate.workflows
        ops2 = substrate.workflows
        assert ops1 is ops2

    def test_work_item_ops_cached(self, substrate):
        ops1 = substrate.work_items
        ops2 = substrate.work_items
        assert ops1 is ops2

    def test_event_ops_cached(self, substrate):
        ops1 = substrate.events
        ops2 = substrate.events
        assert ops1 is ops2

    def test_claim_ops_cached(self, substrate):
        ops1 = substrate.claims
        ops2 = substrate.claims
        assert ops1 is ops2

    def test_link_ops_cached(self, substrate):
        ops1 = substrate.links
        ops2 = substrate.links
        assert ops1 is ops2

    def test_hook_ops_cached(self, substrate):
        ops1 = substrate.hooks
        ops2 = substrate.hooks
        assert ops1 is ops2

    def test_recurrence_ops_cached(self, substrate):
        ops1 = substrate.recurrence
        ops2 = substrate.recurrence
        assert ops1 is ops2


class TestWorkflowOpsFacade:
    def test_register_via_facade(self, substrate):
        yaml_content = _read_workflow_yaml()
        result = substrate.workflows.register(yaml_content)
        assert result.name == "test_workflow"
        assert result.version == 1

    def test_get_via_facade(self, substrate):
        wf = substrate.workflows.get("test_workflow", 1)
        assert wf.name == "test_workflow"

    def test_register_file_via_facade(self, substrate):
        result = substrate.workflows.register_file(WORKFLOW_PATH)
        assert result.name == "test_workflow"


class TestWorkItemOpsFacade:
    def test_create_via_facade(self, substrate):
        wi, evt = substrate.work_items.create(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "facade-test"},
        )
        assert isinstance(wi, WorkItem)
        assert isinstance(evt, Event)
        assert wi.work_item_type == "feature"
        assert wi.current_state == "new"

    def test_get_via_facade(self, substrate):
        wi, _ = substrate.work_items.create(
            "test_workflow", "bug", "actor-2",
            custom_fields={"severity": "major"},
        )
        found = substrate.work_items.get(wi.work_item_id)
        assert found is not None
        assert found.work_item_id == wi.work_item_id

    def test_query_via_facade(self, substrate):
        substrate.work_items.create(
            "test_workflow", "feature", "actor-3",
            custom_fields={"title": "query-test"},
        )
        page = substrate.work_items.query(
            workflow_name="test_workflow",
            work_item_types=["feature"],
            page_size=10,
        )
        assert len(page.items) > 0
        assert all(wi.work_item_type == "feature" for wi in page.items)

    def test_update_not_before_via_facade(self, substrate):
        wi, _ = substrate.work_items.create(
            "test_workflow", "feature", "actor-4",
            custom_fields={"title": "nb-test"},
        )
        future = datetime(2027, 1, 1, tzinfo=UTC)
        evt = substrate.work_items.update_not_before(
            wi.work_item_id, future, "actor-4",
        )
        assert isinstance(evt, Event)
        assert evt.transition == "not_before_set"


class TestEventOpsFacade:
    def test_append_via_facade(self, substrate):
        wi, _ = substrate.work_items.create(
            "test_workflow", "feature", "actor-5",
            custom_fields={"title": "evt-test"},
        )
        evt = substrate.events.append(
            wi.work_item_id, "actor-5",
            transition="note", payload={"msg": "hello"},
        )
        assert isinstance(evt, Event)
        assert evt.transition == "note"

    def test_read_via_facade(self, substrate):
        wi, _ = substrate.work_items.create(
            "test_workflow", "feature", "actor-6",
            custom_fields={"title": "read-test"},
        )
        substrate.events.append(
            wi.work_item_id, "actor-6",
            transition="log", payload={"k": "v"},
        )
        events = substrate.events.read(work_item_id=wi.work_item_id)
        assert len(events) >= 2

    def test_read_since_via_facade(self, substrate):
        wi, create_evt = substrate.work_items.create(
            "test_workflow", "feature", "actor-7",
            custom_fields={"title": "since-test"},
        )
        after = create_evt.event_seq
        substrate.events.append(
            wi.work_item_id, "actor-7",
            transition="log2", payload={"k": "v2"},
        )
        events = substrate.events.read_since(wi.work_item_id, after)
        assert len(events) >= 1


class TestClaimOpsFacade:
    def test_acquire_via_facade(self, substrate):
        wi, _ = substrate.work_items.create(
            "test_workflow", "feature", "actor-8",
            custom_fields={"title": "claim-test"},
        )
        claim = substrate.claims.acquire(wi.work_item_id, "actor-8")
        assert isinstance(claim, Claim)
        assert claim.actor_id == "actor-8"

    def test_heartbeat_via_facade(self, substrate):
        wi, _ = substrate.work_items.create(
            "test_workflow", "feature", "actor-9",
            custom_fields={"title": "hb-test"},
        )
        substrate.claims.acquire(wi.work_item_id, "actor-9")
        claim = substrate.claims.heartbeat(wi.work_item_id, "actor-9")
        assert isinstance(claim, Claim)

    def test_release_via_facade(self, substrate):
        wi, _ = substrate.work_items.create(
            "test_workflow", "feature", "actor-10",
            custom_fields={"title": "rel-test"},
        )
        substrate.claims.acquire(wi.work_item_id, "actor-10")
        substrate.claims.release(wi.work_item_id, "actor-10")
        found = substrate.work_items.get(wi.work_item_id)
        assert found.claimed_by is None

    def test_sweep_expired_via_facade(self, substrate):
        swept = substrate.claims.sweep_expired()
        assert isinstance(swept, int)


class TestLinkOpsFacade:
    def test_create_and_remove_via_facade(self, substrate):
        wi1, _ = substrate.work_items.create(
            "test_workflow", "feature", "actor-11",
            custom_fields={"title": "link-src"},
        )
        wi2, _ = substrate.work_items.create(
            "test_workflow", "feature", "actor-11",
            custom_fields={"title": "link-dst"},
        )
        link = substrate.links.create(
            wi1.work_item_id, wi2.work_item_id, "blocks", "actor-11",
        )
        assert isinstance(link, Link)
        assert link.link_type == "blocks"

        substrate.links.remove(
            wi1.work_item_id, wi2.work_item_id, "blocks", "actor-11",
        )


class TestBackwardCompatibility:
    def test_old_create_work_item(self, substrate):
        wi, _ = substrate.create_work_item(
            "test_workflow", "feature", "compat-actor",
            custom_fields={"title": "compat-test"},
        )
        assert isinstance(wi, WorkItem)

    def test_old_append_event(self, substrate):
        wi, _ = substrate.create_work_item(
            "test_workflow", "feature", "compat-actor",
            custom_fields={"title": "compat-evt"},
        )
        evt = substrate.append_event(
            wi.work_item_id, "compat-actor",
            transition="note", payload={"x": 1},
        )
        assert isinstance(evt, Event)

    def test_old_acquire_claim(self, substrate):
        wi, _ = substrate.create_work_item(
            "test_workflow", "feature", "compat-actor",
            custom_fields={"title": "compat-claim"},
        )
        claim = substrate.acquire_claim(wi.work_item_id, "compat-actor")
        assert isinstance(claim, Claim)

    def test_old_create_link(self, substrate):
        wi1, _ = substrate.create_work_item(
            "test_workflow", "feature", "compat-actor",
            custom_fields={"title": "compat-link1"},
        )
        wi2, _ = substrate.create_work_item(
            "test_workflow", "feature", "compat-actor",
            custom_fields={"title": "compat-link2"},
        )
        link = substrate.create_link(
            wi1.work_item_id, wi2.work_item_id, "blocks", "compat-actor",
        )
        assert isinstance(link, Link)

    def test_old_register_workflow(self, substrate):
        yaml_content = _read_workflow_yaml()
        result = substrate.register_workflow(yaml_content)
        assert result.name == "test_workflow"

    def test_old_query_work_items(self, substrate):
        page = substrate.query_work_items(
            workflow_name="test_workflow",
            page_size=5,
        )
        assert len(page.items) >= 0

    def test_old_read_events(self, substrate):
        wi, _ = substrate.create_work_item(
            "test_workflow", "feature", "compat-actor",
            custom_fields={"title": "compat-rev"},
        )
        events = substrate.read_events(work_item_id=wi.work_item_id)
        assert len(events) >= 1

    def test_facade_equals_old_api(self, substrate):
        wi, _create_evt = substrate.create_work_item(
            "test_workflow", "feature", "eq-actor",
            custom_fields={"title": "eq-test"},
        )
        evts_old = substrate.read_events(work_item_id=wi.work_item_id)
        evts_new = substrate.events.read(work_item_id=wi.work_item_id)
        assert len(evts_old) == len(evts_new)
        assert [e.event_id for e in evts_old] == [e.event_id for e in evts_new]

        found_old = substrate.get_work_item(wi.work_item_id)
        found_new = substrate.work_items.get(wi.work_item_id)
        assert found_old.work_item_id == found_new.work_item_id
