from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import psycopg.types.json
import pytest

from regista._signing import (
    build_signing_envelope_v3,
    build_signing_envelope_v4,
    classify_envelope_version,
    sign_event,
    verify_event,
)
from regista._types import Event

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

_SECRET = b"test-secret-key-32-bytes-long!!!"


def _load_key_set():
    from regista._keys import KeySet
    return KeySet(KEY_PATH)


class TestV4EnvelopeConstruction:
    def test_v4_envelope_contains_entity_fields(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        env = build_signing_envelope_v4(
            event_id=eid,
            entity_kind="work_item",
            entity_id=wid,
            actor_id="agent-1",
            key_id="key-1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=datetime.now(UTC),
            hash_alg="sha-256",
            transition="start",
            payload={"key": "val"},
        )
        obj = json.loads(env)
        assert obj["entity_kind"] == "work_item"
        assert obj["entity_id"] == str(wid)
        assert obj["hash_alg"] == "sha-256"
        assert "work_item_id" not in obj

    def test_v4_envelope_no_work_item_id(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        env = build_signing_envelope_v4(
            event_id=eid,
            entity_kind="work_item",
            entity_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=datetime.now(UTC),
            hash_alg="sha-256",
            transition=None,
            payload=None,
        )
        obj = json.loads(env)
        assert "work_item_id" not in obj

    def test_v4_envelope_includes_prev_event_hash(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        prev_hash = hashlib.sha256(b"prev").digest()
        env = build_signing_envelope_v4(
            event_id=eid,
            entity_kind="work_item",
            entity_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=2,
            workflow_name="wf",
            workflow_version=1,
            timestamp=datetime.now(UTC),
            hash_alg="sha-256",
            transition="start",
            payload=None,
            prev_event_hash=prev_hash,
        )
        obj = json.loads(env)
        assert obj["prev_event_hash"] == prev_hash.hex()


class TestClassifyEnvelopeVersion:
    def test_classify_v4(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        env = build_signing_envelope_v4(
            event_id=eid,
            entity_kind="work_item",
            entity_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=datetime.now(UTC),
            hash_alg="sha-256",
            transition="start",
            payload=None,
        )
        assert classify_envelope_version(env) == 4

    def test_classify_v4_with_prev_hash(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        prev_hash = hashlib.sha256(b"x").digest()
        env = build_signing_envelope_v4(
            event_id=eid,
            entity_kind="work_item",
            entity_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=2,
            workflow_name="wf",
            workflow_version=1,
            timestamp=datetime.now(UTC),
            hash_alg="sha-256",
            transition="start",
            payload=None,
            prev_event_hash=prev_hash,
        )
        assert classify_envelope_version(env) == 4

    def test_classify_v3_still_works(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        prev_hash = hashlib.sha256(b"x").digest()
        env = build_signing_envelope_v3(
            event_id=eid,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=2,
            workflow_name="wf",
            workflow_version=1,
            timestamp=datetime.now(UTC),
            transition="start",
            payload=None,
            prev_event_hash=prev_hash,
        )
        assert classify_envelope_version(env) == 3


class TestSignAndVerifyV4:
    def test_sign_event_produces_v4_envelope(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        now = datetime.now(UTC)
        _sig, _chash, env = sign_event(
            event_id=eid,
            work_item_id=wid,
            actor_id="agent-1",
            key_id="key-1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload={"a": 1},
            key=_SECRET,
        )
        assert classify_envelope_version(env) == 4

    def test_verify_v4_event(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        now = datetime.now(UTC)
        sig, chash, env = sign_event(
            event_id=eid,
            work_item_id=wid,
            actor_id="agent-1",
            key_id="key-1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload={"a": 1},
            key=_SECRET,
        )
        assert verify_event(
            event_id=eid,
            work_item_id=wid,
            actor_id="agent-1",
            key_id="key-1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload={"a": 1},
            signature=sig,
            canonical_hash=chash,
            key=_SECRET,
            stored_envelope=env,
        )

    def test_verify_v4_with_prev_hash(self):
        eid1 = uuid.uuid4()
        eid2 = uuid.uuid4()
        wid = uuid.uuid4()
        now1 = datetime.now(UTC)
        now2 = datetime.now(UTC)

        sig1, _chash1, env1 = sign_event(
            event_id=eid1,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now1,
            transition="start",
            payload=None,
            key=_SECRET,
        )

        prev_hash = hashlib.sha256(env1 + sig1).digest()

        sig2, chash2, env2 = sign_event(
            event_id=eid2,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=2,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now2,
            transition="next",
            payload=None,
            key=_SECRET,
            prev_event_hash=prev_hash,
        )

        assert verify_event(
            event_id=eid2,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=2,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now2,
            transition="next",
            payload=None,
            signature=sig2,
            canonical_hash=chash2,
            key=_SECRET,
            stored_envelope=env2,
            prev_event_hash=prev_hash,
        )

    def test_verify_rejects_tampered_v4(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        now = datetime.now(UTC)
        sig, chash, _env = sign_event(
            event_id=eid,
            work_item_id=wid,
            actor_id="agent-1",
            key_id="key-1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload={"a": 1},
            key=_SECRET,
        )
        assert not verify_event(
            event_id=eid,
            work_item_id=wid,
            actor_id="agent-1",
            key_id="key-1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload={"a": 2},
            signature=sig,
            canonical_hash=chash,
            key=_SECRET,
        )


class TestBackwardCompatVerification:
    def test_v3_event_verifies_with_v4_verify(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        now = datetime.now(UTC)
        prev_hash = hashlib.sha256(b"prev").digest()

        v3_env = build_signing_envelope_v3(
            event_id=eid,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=2,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload=None,
            prev_event_hash=prev_hash,
        )
        from regista._signing_scheme import HMACSHA256Scheme
        scheme = HMACSHA256Scheme()
        sig, chash = scheme.sign(v3_env, _SECRET)

        assert verify_event(
            event_id=eid,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=2,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload=None,
            signature=sig,
            canonical_hash=chash,
            key=_SECRET,
            stored_envelope=v3_env,
            prev_event_hash=prev_hash,
        )

    def test_v4_chained_event_rejects_v3_downgrade(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        now = datetime.now(UTC)
        prev_hash = hashlib.sha256(b"prev").digest()

        sig, chash, _env = sign_event(
            event_id=eid,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=2,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload=None,
            key=_SECRET,
            prev_event_hash=prev_hash,
        )

        assert verify_event(
            event_id=eid,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=2,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload=None,
            signature=sig,
            canonical_hash=chash,
            key=_SECRET,
            prev_event_hash=prev_hash,
        )

        assert not verify_event(
            event_id=eid,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=2,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload=None,
            signature=sig,
            canonical_hash=chash,
            key=_SECRET,
        )

    def test_v4_chained_event_rejects_bare_downgrade(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        now = datetime.now(UTC)
        prev_hash = hashlib.sha256(b"prev").digest()
        prev_global_hash = hashlib.sha256(b"global").digest()

        sig, chash, _env = sign_event(
            event_id=eid,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=2,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload=None,
            key=_SECRET,
            prev_event_hash=prev_hash,
            prev_global_event_hash=prev_global_hash,
        )

        assert not verify_event(
            event_id=eid,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=2,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload=None,
            signature=sig,
            canonical_hash=chash,
            key=_SECRET,
        )

    def test_v2_event_verifies_with_v4_verify(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        now = datetime.now(UTC)

        from regista._signing import build_signing_envelope_v2
        v2_env = build_signing_envelope_v2(
            event_id=eid,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload=None,
        )
        from regista._signing_scheme import HMACSHA256Scheme
        scheme = HMACSHA256Scheme()
        sig, chash = scheme.sign(v2_env, _SECRET)

        assert verify_event(
            event_id=eid,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload=None,
            signature=sig,
            canonical_hash=chash,
            key=_SECRET,
            stored_envelope=v2_env,
        )


class TestEventDataclass:
    def test_event_defaults_entity_kind_work_item(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        evt = Event(
            event_id=eid,
            work_item_id=wid,
            event_seq=1,
            actor_id="a",
            actor_kind="agent",
            actor_metadata=None,
            key_id="k",
            workflow_name="wf",
            workflow_version=1,
            timestamp=datetime.now(UTC),
            transition="start",
            payload=None,
            payload_canonical_hash=b"\x00" * 32,
            signature=b"\x00" * 32,
        )
        assert evt.entity_kind == "work_item"
        assert evt.entity_id == wid
        assert evt.hash_alg == "sha-256"

    def test_event_effective_entity_id(self):
        wid = uuid.uuid4()
        evt = Event(
            event_id=uuid.uuid4(),
            work_item_id=wid,
            event_seq=1,
            actor_id="a",
            actor_kind="agent",
            actor_metadata=None,
            key_id="k",
            workflow_name="wf",
            workflow_version=1,
            timestamp=datetime.now(UTC),
            transition="start",
            payload=None,
            payload_canonical_hash=b"\x00" * 32,
            signature=b"\x00" * 32,
        )
        assert evt.effective_entity_id == wid

    def test_event_to_dict_includes_entity_fields(self):
        wid = uuid.uuid4()
        evt = Event(
            event_id=uuid.uuid4(),
            work_item_id=wid,
            event_seq=1,
            actor_id="a",
            actor_kind="agent",
            actor_metadata=None,
            key_id="k",
            workflow_name="wf",
            workflow_version=1,
            timestamp=datetime.now(UTC),
            transition="start",
            payload=None,
            payload_canonical_hash=b"\x00" * 32,
            signature=b"\x00" * 32,
        )
        d = evt.to_dict()
        assert d["entity_kind"] == "work_item"
        assert d["entity_id"] == str(wid)
        assert d["hash_alg"] == "sha-256"

    def test_event_from_dict_roundtrip(self):
        wid = uuid.uuid4()
        evt = Event(
            event_id=uuid.uuid4(),
            work_item_id=wid,
            event_seq=1,
            actor_id="a",
            actor_kind="agent",
            actor_metadata=None,
            key_id="k",
            workflow_name="wf",
            workflow_version=1,
            timestamp=datetime.now(UTC),
            transition="start",
            payload=None,
            payload_canonical_hash=b"\x00" * 32,
            signature=b"\x00" * 32,
            entity_kind="work_item",
            entity_id=wid,
            hash_alg="sha-256",
        )
        d = evt.to_dict()
        evt2 = Event.from_dict(d)
        assert evt2.entity_kind == "work_item"
        assert evt2.entity_id == wid
        assert evt2.hash_alg == "sha-256"


@pytest.fixture
def regista():
    from regista import Regista
    from regista.testing import drop_project_schema

    project = f"test_p022_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestIntegrationEntityFields:
    def test_created_event_has_entity_columns(self, regista):
        wi, evt = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "entity test"},
        )
        assert evt.entity_kind == "work_item"
        assert evt.entity_id == wi.work_item_id
        assert evt.hash_alg == "sha-256"

    def test_transition_event_has_entity_columns(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "transition entity"},
        )
        evt = regista.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )
        assert evt.entity_kind == "work_item"
        assert evt.entity_id == wi.work_item_id
        assert evt.hash_alg == "sha-256"

    def test_read_events_returns_entity_fields(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "read entity"},
        )
        regista.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        assert len(events) >= 2
        for evt in events:
            assert evt.entity_kind == "work_item"
            assert evt.entity_id == wi.work_item_id
            assert evt.hash_alg == "sha-256"

    def test_replay_verifies_v4_events(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "replay v4"},
        )
        regista.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )
        regista.transition(
            wi.work_item_id, "submit_review", "agent-1",
            actor_metadata={"role": "agent"},
        )
        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_claim_events_have_entity_fields(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "claim entity"},
        )
        regista.acquire_claim(wi.work_item_id, "agent-1", ttl_seconds=300)
        events = regista.read_events(work_item_id=wi.work_item_id)
        claim_events = [e for e in events if e.transition == "claim_acquired"]
        assert len(claim_events) == 1
        assert claim_events[0].entity_kind == "work_item"
        assert claim_events[0].entity_id == wi.work_item_id

    def test_db_entity_columns_populated(self, regista):
        from regista._testing import raw_transaction

        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "db columns"},
        )
        with raw_transaction(regista) as conn:
            row = conn.execute(
                "SELECT entity_kind, entity_id, hash_alg, work_item_id "
                "FROM events WHERE work_item_id = %s LIMIT 1",
                [wi.work_item_id],
            ).fetchone()
        assert row["entity_kind"] == "work_item"
        assert row["entity_id"] == wi.work_item_id
        assert row["hash_alg"] == "sha-256"
        assert row["work_item_id"] == wi.work_item_id

    def test_unique_constraint_on_entity(self, regista):
        from regista._testing import raw_transaction

        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "unique test"},
        )
        with pytest.raises(Exception) as exc_info:
            with raw_transaction(regista) as conn:
                conn.execute(
                    "INSERT INTO events "
                    "(event_id, work_item_id, entity_kind, entity_id, hash_alg, "
                    "event_seq, actor_id, actor_kind, key_id, workflow_name, "
                    "workflow_version, timestamp, transition, payload, "
                    "payload_canonical_hash, signature, canonical_envelope) "
                    "VALUES (%s, %s, 'work_item', %s, 'sha-256', "
                    "1, 'dup', 'agent', 'k', 'wf', 1, now(), 'created', %s, %s, %s, %s)",
                    [
                        uuid.uuid4(), wi.work_item_id, wi.work_item_id,
                        psycopg.types.json.Jsonb({}),
                        b"\x00" * 32, b"\x00" * 32, b"\x00" * 32,
                    ],
                )
        assert "events_entity_event_seq_key" in str(exc_info.value).lower() or \
               "duplicate" in str(exc_info.value).lower()


class TestInMemoryEntityFields:
    def test_in_memory_event_has_entity_fields(self):
        from regista.testing import InMemoryRegista

        s = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)
        wi, evt = s.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "inmem entity"},
        )
        assert evt.entity_kind == "work_item"
        assert evt.entity_id == wi.work_item_id
        assert evt.hash_alg == "sha-256"

    def test_in_memory_replay_verifies_v4(self):
        from regista.testing import InMemoryRegista

        s = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)
        wi, _ = s.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "inmem replay v4"},
        )
        s.transition(
            wi.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )
        report = s.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0
