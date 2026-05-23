from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from substrate import Substrate
from substrate._errors import ErrorCode, SubstrateError
from substrate.testing import InMemorySubstrate

_KEY_PATH = str(Path(__file__).parent / "test_keys.json")
_WF = (Path(__file__).parent / "test_workflow.yaml").read_text()


@pytest.fixture
def sub(request) -> Substrate:
    from substrate.testing import drop_project_schema

    dsn = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
    project = f"test_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(dsn, project, hmac_key_path=_KEY_PATH)

    def teardown():
        sub.close()
        drop_project_schema(dsn, project)

    request.addfinalizer(teardown)
    return sub


@pytest.fixture
def imsub(request) -> InMemorySubstrate:
    return InMemorySubstrate(project="test", hmac_key_path=_KEY_PATH)


def _register_and_create(sub: Substrate) -> uuid.UUID:
    sub.register_workflow(_WF)
    sub.register_actor_role("actor_a", "agent")
    wi, _evt = sub.work_items.create(
        "test_workflow", "feature", "actor_a",
        custom_fields={"title": "test"},
        actor_metadata={"role": "agent"},
    )
    return wi.work_item_id


class TestPostgresAppendEventOnBehalfOf:
    def test_append_event_with_on_behalf_of(self, sub: Substrate) -> None:
        wid = _register_and_create(sub)
        evt = sub.append_event(
            wid, "actor_a",
            on_behalf_of={"principal_id": "alice"},
        )
        assert evt.on_behalf_of == {"principal_id": "alice"}

    def test_append_event_without_on_behalf_of_is_none(self, sub: Substrate) -> None:
        wid = _register_and_create(sub)
        evt = sub.append_event(wid, "actor_a")
        assert evt.on_behalf_of is None

    def test_append_event_round_trips_via_read(self, sub: Substrate) -> None:
        wid = _register_and_create(sub)
        evt = sub.append_event(
            wid, "actor_a",
            on_behalf_of={"principal_id": "alice", "scope": ["read"]},
        )
        evts = sub.read_events(work_item_id=wid)
        assert evts[-1].on_behalf_of == {"principal_id": "alice", "scope": ["read"]}


class TestPostgresTransitionOnBehalfOf:
    def test_transition_with_on_behalf_of(self, sub: Substrate) -> None:
        wid = _register_and_create(sub)
        evt = sub.transition(
            wid, "start", "actor_a",
            actor_metadata={"role": "agent"},
            on_behalf_of={"principal_id": "bob"},
        )
        assert evt.on_behalf_of == {"principal_id": "bob"}

    def test_transition_rejects_invalid_on_behalf_of(self, sub: Substrate) -> None:
        wid = _register_and_create(sub)
        with pytest.raises(SubstrateError) as exc:
            sub.transition(
                wid, "start", "actor_a",
                actor_metadata={"role": "agent"},
                on_behalf_of={"principal_id": ""},
            )
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT


class TestInMemorySubstrateOnBehalfOf:
    def test_append_event_with_on_behalf_of(self, imsub: InMemorySubstrate) -> None:
        imsub.register_workflow(_WF)
        wi, _evt = imsub.create_work_item(
            "test_workflow", "feature", "actor_a",
            custom_fields={"title": "test"},
            actor_metadata={"role": "agent"},
        )
        evt = imsub.append_event(
            wi.work_item_id, "actor_a",
            on_behalf_of={"principal_id": "alice"},
        )
        assert evt.on_behalf_of == {"principal_id": "alice"}

    def test_transition_with_on_behalf_of(self, imsub: InMemorySubstrate) -> None:
        imsub.register_workflow(_WF)
        wi, _evt = imsub.create_work_item(
            "test_workflow", "feature", "actor_a",
            custom_fields={"title": "test"},
            actor_metadata={"role": "agent"},
        )
        evt = imsub.transition(
            wi.work_item_id, "start", "actor_a",
            actor_metadata={"role": "agent"},
            on_behalf_of={"principal_id": "carol"},
        )
        assert evt.on_behalf_of == {"principal_id": "carol"}

    def test_reads_return_on_behalf_of(self, imsub: InMemorySubstrate) -> None:
        imsub.register_workflow(_WF)
        wi, _evt = imsub.create_work_item(
            "test_workflow", "feature", "actor_a",
            custom_fields={"title": "test"},
            actor_metadata={"role": "agent"},
        )
        imsub.append_event(
            wi.work_item_id, "actor_a",
            on_behalf_of={"principal_id": "alice"},
        )
        evts = imsub.read_events(work_item_id=wi.work_item_id)
        assert evts[-1].on_behalf_of == {"principal_id": "alice"}

    def test_replay_with_on_behalf_of_no_drift(self, imsub: InMemorySubstrate) -> None:
        imsub.register_workflow(_WF)
        wi, _evt = imsub.create_work_item(
            "test_workflow", "feature", "actor_a",
            custom_fields={"title": "test"},
            actor_metadata={"role": "agent"},
        )
        imsub.transition(
            wi.work_item_id, "start", "actor_a",
            actor_metadata={"role": "agent"},
            on_behalf_of={"principal_id": "alice"},
        )
        report = imsub.replay()
        assert report.replayed_drift == 0

    def test_replay_signature_still_verifies(self, imsub: InMemorySubstrate) -> None:
        imsub.register_workflow(_WF)
        wi, _evt = imsub.create_work_item(
            "test_workflow", "feature", "actor_a",
            custom_fields={"title": "test"},
            actor_metadata={"role": "agent"},
        )
        imsub.transition(
            wi.work_item_id, "start", "actor_a",
            actor_metadata={"role": "agent"},
            on_behalf_of={"principal_id": "alice"},
        )
        report = imsub.replay()
        assert report.replayed_ok == 1
