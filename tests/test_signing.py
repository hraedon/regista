from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from regista._signing import (
    build_signing_envelope,
    build_signing_envelope_v2,
    build_signing_envelope_v3,
    build_signing_envelope_v4,
    classify_envelope_version,
)
from regista._signing_scheme import HMACSHA256Scheme
from regista._testing import KeySet, raw_transaction, sign_event, verify_event
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


class TestDowngradeEnvelopeFiltering:
    def test_verify_rejects_downgrade_when_stored_v4(self):
        key_set = KeySet(KEY_PATH)
        key_entry = key_set.active_key()
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime.now(UTC)
        payload = {"foo": "bar"}

        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            key=key_entry.secret,
        )

        assert classify_envelope_version(envelope) == 4
        assert verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=envelope,
        )

        tampered_envelope = build_signing_envelope_v4(
            event_id=event_id,
            entity_kind="work_item",
            entity_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            hash_alg="sha-256",
            transition="t",
            payload={"foo": "tampered"},
        )
        assert not verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload={"foo": "tampered"},
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=tampered_envelope,
        )

    def test_verify_all_candidates_when_no_stored_envelope(self):
        key_set = KeySet(KEY_PATH)
        key_entry = key_set.active_key()
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime.now(UTC)
        payload = {"foo": "bar"}
        scheme = HMACSHA256Scheme()

        legacy_envelope = build_signing_envelope(
            event_id, work_item_id, "actor-1", "t", payload, None,
        )
        legacy_signature, legacy_canonical_hash = scheme.sign(
            legacy_envelope, key_entry.secret,
        )

        assert verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            signature=legacy_signature,
            canonical_hash=legacy_canonical_hash,
            key=key_entry.secret,
            stored_envelope=None,
        )

    def test_verify_v4_event_does_not_match_v3_envelope(self):
        key_set = KeySet(KEY_PATH)
        key_entry = key_set.active_key()
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime.now(UTC)
        payload = {"foo": "bar"}
        prev_event_hash = b"\x00" * 32
        global_seq = 7
        prev_global_event_hash = b"\x11" * 32

        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            key=key_entry.secret,
            prev_event_hash=prev_event_hash,
            global_seq=global_seq,
            prev_global_event_hash=prev_global_event_hash,
        )

        assert classify_envelope_version(envelope) == 4

        v3_envelope = build_signing_envelope_v3(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            prev_event_hash=prev_event_hash,
            global_seq=global_seq,
            prev_global_event_hash=prev_global_event_hash,
        )
        assert classify_envelope_version(v3_envelope) == 3

        assert not verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=v3_envelope,
        )

    def test_classify_envelope_version_correct(self):
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime.now(UTC)
        prev_event_hash = b"\x00" * 32
        global_seq = 7
        prev_global_event_hash = b"\x11" * 32

        v1_envelope = build_signing_envelope(
            event_id, work_item_id, "actor-1", "t", {"x": 1}, None,
        )
        assert classify_envelope_version(v1_envelope) == 1

        v2_envelope = build_signing_envelope_v2(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id="k1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload={"x": 1},
        )
        assert classify_envelope_version(v2_envelope) == 2

        v3_envelope = build_signing_envelope_v3(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id="k1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload={"x": 1},
        )
        assert classify_envelope_version(v3_envelope) == 2

        v3_chain_envelope = build_signing_envelope_v3(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id="k1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload={"x": 1},
            prev_event_hash=prev_event_hash,
            global_seq=global_seq,
            prev_global_event_hash=prev_global_event_hash,
        )
        assert classify_envelope_version(v3_chain_envelope) == 3

        v4_envelope = build_signing_envelope_v4(
            event_id=event_id,
            entity_kind="work_item",
            entity_id=work_item_id,
            actor_id="actor-1",
            key_id="k1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            hash_alg="sha-256",
            transition="t",
            payload={"x": 1},
        )
        assert classify_envelope_version(v4_envelope) == 4

        v4_chain_envelope = build_signing_envelope_v4(
            event_id=event_id,
            entity_kind="work_item",
            entity_id=work_item_id,
            actor_id="actor-1",
            key_id="k1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            hash_alg="sha-256",
            transition="t",
            payload={"x": 1},
            prev_event_hash=prev_event_hash,
            global_seq=global_seq,
            prev_global_event_hash=prev_global_event_hash,
        )
        assert classify_envelope_version(v4_chain_envelope) == 4
