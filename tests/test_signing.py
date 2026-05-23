from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from substrate._testing import KeySet, raw_transaction, verify_event
from substrate.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def substrate():
    from substrate import Substrate

    project = f"test_sign_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestAC26JsonbDriftSurvival:
    def test_replay_survives_jsonb_payload_key_reorder(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-26 drift test"},
        )
        eid = uuid.uuid4()
        substrate.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="custom_event",
            payload={"z": 1, "a": 2, "m": 3},
            event_id=eid,
        )

        events = substrate.read_events(work_item_id=wi.work_item_id)
        assert len(events) == 2
        assert events[1].canonical_envelope is not None

        with raw_transaction(substrate) as conn:
            conn.execute(
                "UPDATE events SET payload = '{\"a\": 2, \"m\": 3, \"z\": 1}'::jsonb "
                "WHERE event_id = %s",
                [eid],
            )

        report = substrate.replay()
        assert report.halted == 0
        assert report.replayed_drift == 0

    def test_canonical_envelope_stored_on_append(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-26 envelope"},
        )

        events = substrate.read_events(work_item_id=wi.work_item_id)
        for evt in events:
            assert evt.canonical_envelope is not None
            assert len(evt.canonical_envelope) > 0

    def test_replay_succeeds_after_events(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-26 replay"},
        )
        substrate.append_event(
            work_item_id=wi.work_item_id,
            actor_id="agent-1",
            transition="custom_event",
            payload={"nested": {"key": "value"}},
        )

        report = substrate.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_signature_verification_uses_stored_envelope(self, substrate):
        wi, _ = substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "AC-26 verify"},
        )

        events = substrate.read_events(work_item_id=wi.work_item_id)
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
