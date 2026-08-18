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


#: Canonical per TRUST-DOMAIN.md §2.1 — the v6 ingress refuses a bare legacy name.
WORKER = "agent:worker"
#: The second claimant the claim-stealing cases need.
OTHER = "agent:reviewer"

#: One accepted principal per execution kind, because `actor_kind` and the
#: principal's grammatical class are separate axes and this test exercises all
#: three kinds. A `system` actor is infrastructure, hence the `service:` id.
KIND_ACTORS = {
    "agent": "agent:worker",
    "human": "human:operator",
    "system": "service:hooks",
}


@pytest.fixture(scope="module")
def regista(tmp_path_factory):
    from regista import Regista
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project = f"test_prodready_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path_factory.mktemp("prodready_keys"))
    sub = Regista.create_project(DSN, project, keyset.path)
    # The epoch first: `register_workflow_file` emits the signed
    # `workflow_registered` event admission gate 1 requires, and there is no
    # epoch to append it to before `open_v6_epoch` returns.
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestActorKindValidation:
    def test_invalid_actor_kind_on_create(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id=WORKER,
                actor_kind="robot",
                custom_fields={"title": "bad kind"},
            )
        assert "actor_kind" in exc_info.value.message

    def test_invalid_actor_kind_on_append(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "AC kind"},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.append_event(
                work_item_id=wi.work_item_id,
                actor_id=WORKER,
                actor_kind="alien",
                transition="note",
            )
        assert "actor_kind" in exc_info.value.message

    def test_invalid_actor_kind_on_transition(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "AC trans kind"},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="start",
                actor_id=WORKER,
                actor_kind="robot",
                actor_metadata={"role": "agent"},
            )
        assert "actor_kind" in exc_info.value.message

    def test_invalid_actor_kind_on_create_link(self, regista):
        wi1, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "A"},
        )
        wi2, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="bug",
            actor_id=WORKER,
            custom_fields={"severity": "major"},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.create_link(
                from_work_item_id=wi1.work_item_id,
                to_work_item_id=wi2.work_item_id,
                link_type="fixes",
                actor_id=WORKER,
                actor_kind="robot",
            )
        assert "actor_kind" in exc_info.value.message

    def test_invalid_actor_kind_on_remove_link(self, regista):
        wi1, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "A"},
        )
        wi2, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="bug",
            actor_id=WORKER,
            custom_fields={"severity": "major"},
        )
        regista.create_link(
            from_work_item_id=wi1.work_item_id,
            to_work_item_id=wi2.work_item_id,
            link_type="fixes",
            actor_id=WORKER,
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.remove_link(
                from_work_item_id=wi1.work_item_id,
                to_work_item_id=wi2.work_item_id,
                link_type="fixes",
                actor_id=WORKER,
                actor_kind="robot",
            )
        assert "actor_kind" in exc_info.value.message

    def test_invalid_actor_kind_on_update_not_before(self, regista):
        from datetime import UTC, datetime, timedelta

        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "AC nb kind"},
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.update_not_before(
                work_item_id=wi.work_item_id,
                not_before=datetime.now(UTC) + timedelta(hours=1),
                actor_id=WORKER,
                actor_kind="robot",
            )
        assert "actor_kind" in exc_info.value.message

    def test_valid_actor_kinds_accepted(self, regista):
        for kind, actor in KIND_ACTORS.items():
            wi, _ = regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id=actor,
                actor_kind=kind,
                custom_fields={"title": f"kind {kind}"},
            )
            assert wi is not None

            events = regista.read_events(work_item_id=wi.work_item_id)
            created_events = [e for e in events if e.transition == "created"]
            assert len(created_events) >= 1
            assert created_events[0].actor_kind == kind


class TestTransitionEventIdCollision:
    def test_same_event_id_different_transition_rejected(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            actor_metadata={"role": "agent"},
            custom_fields={"title": "trans collision"},
        )

        eid = uuid.uuid4()
        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id=WORKER,
            actor_metadata={"role": "agent"},
            event_id=eid,
        )

        with pytest.raises(RegistaError) as exc_info:
            regista.append_event(
                work_item_id=wi.work_item_id,
                actor_id=WORKER,
                transition="custom_event_b",
                event_id=eid,
            )
        assert exc_info.value.code == ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD


class TestClaimStolenMetric:
    def test_stolen_claim_emits_event_and_metric(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "stolen metric"},
        )
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE claims SET expires_at = now() - interval '1 second' "
                "WHERE work_item_id = %s",
                [wi.work_item_id],
            )

        regista.acquire_claim(wi.work_item_id, OTHER, ttl_seconds=300)

        events = regista.read_events(work_item_id=wi.work_item_id)
        stolen_events = [e for e in events if e.transition == "claim_stolen"]
        assert len(stolen_events) >= 1
        assert stolen_events[-1].payload["prior_actor_id"] == WORKER
        assert stolen_events[-1].payload["new_actor_id"] == OTHER

    def test_same_actor_reacquire_does_not_count_as_stolen(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "reacquire not stolen"},
        )
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=300)
        regista.acquire_claim(wi.work_item_id, WORKER, ttl_seconds=600)

        events = regista.read_events(work_item_id=wi.work_item_id)
        stolen_events = [e for e in events if e.transition == "claim_stolen"]
        assert len(stolen_events) == 0
