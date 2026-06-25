from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._testing import KeySet, raw_transaction, verify_event
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def regista():
    from regista import Regista

    project = f"test_sign_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestAC26JsonbDriftSurvival:
    def test_replay_survives_jsonb_payload_key_reorder(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-26 drift test"},
        )
        eid = uuid.uuid4()
        regista.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="custom_event",
            payload={"z": 1, "a": 2, "m": 3},
            event_id=eid,
        )

        events = regista.read_events(work_item_id=wi.work_item_id)
        assert len(events) == 2
        assert events[1].canonical_envelope is not None

        with raw_transaction(regista) as conn:
            conn.execute(
                "UPDATE events SET payload = '{\"a\": 2, \"m\": 3, \"z\": 1}'::jsonb "
                "WHERE event_id = %s",
                [eid],
            )

        report = regista.replay()
        assert report.halted == 0
        assert report.replayed_drift == 0

    def test_canonical_envelope_stored_on_append(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-26 envelope"},
        )

        events = regista.read_events(work_item_id=wi.work_item_id)
        for evt in events:
            assert evt.canonical_envelope is not None
            assert len(evt.canonical_envelope) > 0

    def test_replay_succeeds_after_events(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-26 replay"},
        )
        regista.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="custom_event",
            payload={"nested": {"key": "value"}},
        )

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_signature_verification_uses_stored_envelope(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-26 verify"},
        )

        events = regista.read_events(work_item_id=wi.work_item_id)
        evt = events[0]

        key_set = KeySet(KEY_PATH)
        key_entry = key_set.active_key()

        assert verify_event(
            event_id=evt.event_id,
            work_item_id=evt.work_item_id,
            actor_id=evt.actor_id,
            key_id=evt.key_id,
            event_seq=evt.event_seq,
            workflow_name=evt.workflow_name,
            workflow_version=evt.workflow_version,
            timestamp=evt.timestamp,
            transition=evt.transition,
            payload=evt.payload,
            signature=evt.signature,
            canonical_hash=evt.payload_canonical_hash,
            key=key_entry.secret,
            stored_envelope=evt.canonical_envelope,
        )

    def test_transition_event_signature_verifies_with_stored_envelope(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "transition verify"},
        )
        regista.register_actor_role("agent-1", "agent")
        regista.transition(
            work_item_id=wi.work_item_id,
            transition_name="start",
            actor_id="agent-1",
            actor_metadata={"role": "agent"},
        )

        events = regista.read_events(work_item_id=wi.work_item_id)
        transition_evt = events[1]
        assert transition_evt.transition == "start"
        assert transition_evt.canonical_envelope is not None
        assert transition_evt.entity_kind == "work_item"
        assert transition_evt.hash_alg == "sha-256"

        key_set = KeySet(KEY_PATH)
        key_entry = key_set.active_key()

        assert verify_event(
            event_id=transition_evt.event_id,
            work_item_id=transition_evt.work_item_id,
            actor_id=transition_evt.actor_id,
            key_id=transition_evt.key_id,
            event_seq=transition_evt.event_seq,
            workflow_name=transition_evt.workflow_name,
            workflow_version=transition_evt.workflow_version,
            timestamp=transition_evt.timestamp,
            transition=transition_evt.transition,
            payload=transition_evt.payload,
            signature=transition_evt.signature,
            canonical_hash=transition_evt.payload_canonical_hash,
            key=key_entry.secret,
            stored_envelope=transition_evt.canonical_envelope,
            entity_kind=transition_evt.entity_kind,
            hash_alg=transition_evt.hash_alg,
            prev_event_hash=transition_evt.prev_event_hash,
            prev_global_event_hash=transition_evt.prev_global_event_hash,
        )
