from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from _helpers import DSN
from _v6_fixtures import make_v6_keyset, open_v6_epoch

from regista._errors import RegistaError
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


#: Canonical principal ids (TRUST-DOMAIN.md §2.1). The pre-epoch spellings were
#: "agent-1" / "agent-2", which `validate_v6_envelope` refuses at ingress — a bare
#: legacy name is exactly what criterion 19's inversion rejects, so they are
#: renamed rather than grandfathered.
ACTOR_1 = "agent:idem-one"
ACTOR_2 = "agent:idem-two"


@pytest.fixture(scope="module")
def regista(tmp_path_factory):
    from regista import Regista

    # One Ed25519 actor-role key per principal: the v6 writer requires
    # entry.principal_id == actor_id, so the shared HMAC test_keys.json is unusable.
    keyset = make_v6_keyset(
        tmp_path_factory.mktemp("idem_keys"), principals=(ACTOR_1, ACTOR_2)
    )
    project = f"test_idem_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, keyset.path)
    # Genesis, then a project-local acceptance per principal. register_workflow_file
    # then appends its signed workflow_registered event for real (admission gate 1
    # refuses a workflow_registry row), so this order is load-bearing.
    open_v6_epoch(sub, keyset, principals=(ACTOR_1, ACTOR_2))
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestAC24IdempotencyMismatch:
    def test_same_event_id_different_transition_rejected(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR_1,
            custom_fields={"title": "AC-24 mismatch"},
        )

        eid = uuid.uuid4()
        regista.append_event(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR_1,
            transition="custom_event_a",
            event_id=eid,
        )

        with pytest.raises(RegistaError, match="IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD"):
            regista.append_event(
                work_item_id=wi.work_item_id,
                actor_id=ACTOR_1,
                transition="custom_event_b",
                event_id=eid,
            )

    def test_same_event_id_different_actor_rejected(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR_1,
            custom_fields={"title": "AC-24 actor mismatch"},
        )

        eid = uuid.uuid4()
        regista.append_event(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR_1,
            transition="custom_event",
            event_id=eid,
        )

        with pytest.raises(RegistaError, match="IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD"):
            regista.append_event(
                work_item_id=wi.work_item_id,
                actor_id=ACTOR_2,
                transition="custom_event",
                event_id=eid,
            )

    def test_idempotent_retry_returns_original(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR_1,
            custom_fields={"title": "AC-24 happy retry"},
        )

        eid = uuid.uuid4()
        e1 = regista.append_event(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR_1,
            transition="custom_event",
            event_id=eid,
        )
        e2 = regista.append_event(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR_1,
            transition="custom_event",
            event_id=eid,
        )
        assert e1.event_id == e2.event_id
        assert e1.event_seq == e2.event_seq


class TestAC25ExpectedEventSeq:
    def test_expected_seq_mismatch_rejected(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR_1,
            custom_fields={"title": "AC-25"},
        )

        with pytest.raises(RegistaError, match="CONCURRENT_MODIFICATION"):
            regista.append_event(
                work_item_id=wi.work_item_id,
                actor_id=ACTOR_1,
                transition="custom_event",
                expected_event_seq=99,
            )

    def test_expected_seq_match_accepted(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR_1,
            custom_fields={"title": "AC-25 ok"},
        )

        evt = regista.append_event(
            work_item_id=wi.work_item_id,
            actor_id=ACTOR_1,
            transition="custom_event",
            expected_event_seq=2,
        )
        assert evt.event_seq == 2

    def test_expected_seq_on_transition(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ACTOR_1,
            actor_metadata={"role": "agent"},
            custom_fields={"title": "AC-25 transition"},
        )

        with pytest.raises(RegistaError, match="CONCURRENT_MODIFICATION"):
            regista.transition(
                work_item_id=wi.work_item_id,
                transition_name="start",
                actor_id=ACTOR_1,
                actor_metadata={"role": "agent"},
                expected_event_seq=99,
            )
