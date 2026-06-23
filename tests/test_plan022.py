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
from regista._types import Event, Link

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


class TestRegistryDrivenSchemeResolution:
    def test_unregistered_scheme_rejected_at_key_load(self, tmp_path):
        from regista._errors import RegistaError
        from regista._keys import KeySet

        kf = tmp_path / "keys.json"
        kf.write_text(json.dumps({
            "keys": [
                {"key_id": "k1", "secret": "c2VjcmV0", "status": "active",
                 "scheme": "ml-dsa-65"},
            ]
        }))
        with pytest.raises(RegistaError, match=r"unknown scheme.*ml-dsa-65"):
            KeySet(str(kf))

    def test_registered_scheme_accepted_at_key_load(self, tmp_path):
        from regista._keys import KeySet
        from regista._signing_scheme import register_scheme, unregister_scheme

        @register_scheme
        class MockScheme:
            scheme_id: str = "mock-test-scheme"

            def sign(self, envelope, key_material, hash_alg="sha-256"):
                import hashlib
                return (hashlib.sha256(envelope + key_material).digest(),
                        hashlib.sha256(envelope).digest())

            def verify(self, envelope, signature, envelope_hash, key_material,
                       hash_alg="sha-256"):
                import hashlib
                import hmac
                expected = hashlib.sha256(envelope + key_material).digest()
                return (hmac.compare_digest(expected, signature)
                        and hmac.compare_digest(
                            hashlib.sha256(envelope).digest(), envelope_hash))

        try:
            kf = tmp_path / "keys.json"
            kf.write_text(json.dumps({
                "keys": [
                    {"key_id": "k1", "secret": "c2VjcmV0", "status": "active",
                     "scheme": "mock-test-scheme"},
                ]
            }))
            ks = KeySet(str(kf))
            assert ks.active_scheme() == "mock-test-scheme"
        finally:
            unregister_scheme("mock-test-scheme")

    def test_available_schemes_lists_registered(self):
        from regista._signing_scheme import available_schemes

        schemes = available_schemes()
        assert "hmac-sha256" in schemes
        assert "ed25519" in schemes


class TestHashAlgAgility:
    def test_resolve_hash_function_sha256(self):
        from regista._signing_scheme import resolve_hash_function

        fn = resolve_hash_function("sha-256")
        assert fn(b"test").hexdigest() == hashlib.sha256(b"test").hexdigest()

    def test_resolve_hash_function_sha384(self):
        from regista._signing_scheme import resolve_hash_function

        fn = resolve_hash_function("sha-384")
        assert fn(b"test").hexdigest() == hashlib.sha384(b"test").hexdigest()

    def test_resolve_hash_function_unknown_raises(self):
        from regista._errors import RegistaError
        from regista._signing_scheme import resolve_hash_function

        with pytest.raises(RegistaError, match="Unknown hash algorithm"):
            resolve_hash_function("md5")

    def test_sign_with_sha384(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        now = datetime.now(UTC)

        sig, chash, env = sign_event(
            event_id=eid,
            work_item_id=wid,
            actor_id="a",
            key_id="k",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=now,
            transition="start",
            payload={"x": 1},
            key=_SECRET,
            hash_alg="sha-384",
        )
        obj = json.loads(env)
        assert obj["hash_alg"] == "sha-384"

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
            payload={"x": 1},
            signature=sig,
            canonical_hash=chash,
            key=_SECRET,
            stored_envelope=env,
            hash_alg="sha-384",
        )

    def test_sign_with_sha384_rejects_sha256_verification(self):
        eid = uuid.uuid4()
        wid = uuid.uuid4()
        now = datetime.now(UTC)

        sig, chash, env = sign_event(
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
            key=_SECRET,
            hash_alg="sha-384",
        )
        assert not verify_event(
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
            stored_envelope=env,
            hash_alg="sha-256",
        )


class TestHybridSchemeSeam:
    def test_hybrid_scheme_signs_and_verifies(self):
        import hashlib
        import hmac as _hmac

        from regista._signing_scheme import get_scheme, register_scheme, unregister_scheme

        @register_scheme
        class HybridHMACEd25519MockScheme:
            scheme_id: str = "hybrid-hmac-ed25519-mock"

            def sign(self, envelope, key_material, hash_alg="sha-256"):
                from regista._signing_scheme import resolve_hash_function
                hash_fn = resolve_hash_function(hash_alg)
                hmac_sig = _hmac.new(key_material, envelope, hash_fn).digest()
                mock_pqc_sig = hashlib.sha256(key_material + envelope).digest()
                composite = hmac_sig + mock_pqc_sig
                h = hash_fn(envelope).digest()
                return (composite, h)

            def verify(self, envelope, signature, envelope_hash, key_material,
                       hash_alg="sha-256"):
                from regista._signing_scheme import resolve_hash_function
                hash_fn = resolve_hash_function(hash_alg)
                if len(signature) != 64:
                    return False
                hmac_part = signature[:32]
                pqc_part = signature[32:]
                expected_hmac = _hmac.new(key_material, envelope, hash_fn).digest()
                expected_pqc = hashlib.sha256(key_material + envelope).digest()
                return (_hmac.compare_digest(expected_hmac, hmac_part)
                        and _hmac.compare_digest(expected_pqc, pqc_part)
                        and _hmac.compare_digest(
                            hash_fn(envelope).digest(), envelope_hash))

        try:
            scheme = get_scheme("hybrid-hmac-ed25519-mock")
            envelope = b"test envelope"
            key = b"test-key-material"
            sig, h = scheme.sign(envelope, key)
            assert len(sig) == 64
            assert scheme.verify(envelope, sig, h, key)
            assert not scheme.verify(envelope, b"\x00" * 64, h, key)
        finally:
            unregister_scheme("hybrid-hmac-ed25519-mock")

    def test_hybrid_scheme_through_sign_event(self):
        import hashlib
        import hmac as _hmac

        from regista._signing_scheme import get_scheme, register_scheme, unregister_scheme

        @register_scheme
        class HybridTestScheme:
            scheme_id: str = "hybrid-test-v2"

            def sign(self, envelope, key_material, hash_alg="sha-256"):
                from regista._signing_scheme import resolve_hash_function
                hash_fn = resolve_hash_function(hash_alg)
                leg1 = _hmac.new(key_material, envelope, hash_fn).digest()
                leg2 = hashlib.sha256(key_material + envelope).digest()
                return (leg1 + leg2, hash_fn(envelope).digest())

            def verify(self, envelope, signature, envelope_hash, key_material,
                       hash_alg="sha-256"):
                from regista._signing_scheme import resolve_hash_function
                hash_fn = resolve_hash_function(hash_alg)
                if len(signature) != 64:
                    return False
                leg1 = _hmac.new(key_material, envelope, hash_fn).digest()
                leg2 = hashlib.sha256(key_material + envelope).digest()
                return (_hmac.compare_digest(leg1, signature[:32])
                        and _hmac.compare_digest(leg2, signature[32:])
                        and _hmac.compare_digest(
                            hash_fn(envelope).digest(), envelope_hash))

        try:
            eid = uuid.uuid4()
            wid = uuid.uuid4()
            now = datetime.now(UTC)

            scheme = get_scheme("hybrid-test-v2")

            sig, chash, env = sign_event(
                event_id=eid,
                work_item_id=wid,
                actor_id="a",
                key_id="k",
                event_seq=1,
                workflow_name="wf",
                workflow_version=1,
                timestamp=now,
                transition="start",
                payload={"hybrid": True},
                key=_SECRET,
                scheme=scheme,
                hash_alg="sha-256",
            )
            assert len(sig) == 64

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
                payload={"hybrid": True},
                signature=sig,
                canonical_hash=chash,
                key=_SECRET,
                stored_envelope=env,
                scheme=scheme,
            )
        finally:
            unregister_scheme("hybrid-test-v2")


class TestSizeAudit:
    def test_signature_column_is_bytea(self, regista):
        from regista._testing import raw_transaction

        with raw_transaction(regista) as conn:
            row = conn.execute(
                "SELECT data_type FROM information_schema.columns "
                "WHERE table_name = 'events' AND column_name = 'signature'"
            ).fetchone()
        assert row is not None
        assert row["data_type"] == "bytea"

    def test_no_index_on_signature_column(self, regista):
        from regista._testing import raw_transaction

        with raw_transaction(regista) as conn:
            rows = conn.execute(
                "SELECT indexname FROM pg_indexes "
                "WHERE tablename = 'events'"
            ).fetchall()
        for row in rows:
            assert "signature" not in row["indexname"].lower(), (
                f"Index {row['indexname']} appears to be on signature column"
            )


class TestCrossProjectValueReferences:
    def test_cross_project_link_create(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "xproject source"},
        )
        target_id = uuid.uuid4()
        link = regista.create_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="other_project",
        )
        assert link.target_project == "other_project"
        assert link.target_entity_kind == "work_item"

        events = regista.read_events(work_item_id=wi.work_item_id)
        link_events = [e for e in events if e.transition == "link_created"]
        assert len(link_events) == 1
        payload = link_events[0].payload
        assert payload["target_project"] == "other_project"
        assert payload["target_entity_kind"] == "work_item"

    def test_cross_project_link_with_content_hash(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "content hash test"},
        )
        target_id = uuid.uuid4()
        link = regista.create_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="other_project",
            content_hash="sha256:abc123",
        )
        assert link.content_hash == "sha256:abc123"

        events = regista.read_events(work_item_id=wi.work_item_id)
        link_events = [e for e in events if e.transition == "link_created"]
        assert link_events[0].payload["content_hash"] == "sha256:abc123"

    def test_cross_project_link_with_target_entity_kind(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "entity kind test"},
        )
        target_id = uuid.uuid4()
        link = regista.create_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="other_project",
            target_entity_kind="note",
        )
        assert link.target_entity_kind == "note"

        events = regista.read_events(work_item_id=wi.work_item_id)
        link_events = [e for e in events if e.transition == "link_created"]
        assert link_events[0].payload["target_entity_kind"] == "note"

    def test_cross_project_link_rejects_undeclared_link_type(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "undeclared type test"},
        )
        target_id = uuid.uuid4()
        with pytest.raises(Exception) as exc_info:
            regista.create_link(
                wi.work_item_id, target_id, "nonexistent_type", "agent-1",
                target_project="other_project",
            )
        assert "LINK_TYPE_NOT_ALLOWED" in str(exc_info.value) or \
               "not declared" in str(exc_info.value)

    def test_cross_project_link_remove(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "xproject remove test"},
        )
        target_id = uuid.uuid4()
        regista.create_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="other_project",
        )
        regista.remove_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="other_project",
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        remove_events = [e for e in events if e.transition == "link_removed"]
        assert len(remove_events) == 1
        assert remove_events[0].payload.get("target_project") == "other_project"

    def test_cross_project_link_does_not_lookup_target(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "no lookup test"},
        )
        target_id = uuid.uuid4()
        link = regista.create_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="nonexistent_project",
        )
        assert link.target_project == "nonexistent_project"

    def test_cross_project_link_replay(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "replay xproject test"},
        )
        target_id = uuid.uuid4()
        regista.create_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="other_project",
            content_hash="sha256:test123",
        )
        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0

    def test_intra_project_link_still_works(self, regista):
        wi1, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "intra 1"},
        )
        wi2, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "intra 2"},
        )
        link = regista.create_link(
            wi1.work_item_id, wi2.work_item_id, "blocks", "agent-1",
        )
        assert link.target_project is None
        assert link.target_entity_kind is None

    def test_cross_project_link_target_not_needed_for_remove(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "remove no target"},
        )
        target_id = uuid.uuid4()
        regista.create_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="other_project",
        )
        with pytest.raises(Exception):
            regista.remove_link(
                wi.work_item_id, uuid.uuid4(), "blocks", "agent-1",
            )

    def test_multiple_cross_project_links_same_target_distinct(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "multi xproject"},
        )
        target_id = uuid.uuid4()
        regista.create_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="project_a",
        )
        regista.create_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="project_b",
        )
        regista.remove_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="project_a",
        )
        regista.remove_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="project_b",
        )

    def test_cross_project_remove_wrong_project_raises(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "wrong project remove"},
        )
        target_id = uuid.uuid4()
        regista.create_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="project_a",
        )
        with pytest.raises(Exception):
            regista.remove_link(
                wi.work_item_id, target_id, "blocks", "agent-1",
                target_project="project_b",
            )

    def test_empty_target_project_rejected(self, regista):
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "empty target_project"},
        )
        target_id = uuid.uuid4()
        with pytest.raises(Exception):
            regista.create_link(
                wi.work_item_id, target_id, "blocks", "agent-1",
                target_project="",
            )


class TestInMemoryCrossProjectValueReferences:
    def test_in_memory_cross_project_link_create(self):
        from regista.testing import InMemoryRegista

        s = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)
        wi, _ = s.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "inmem xproject"},
        )
        target_id = uuid.uuid4()
        link = s.create_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="other_project",
        )
        assert link.target_project == "other_project"

        events = s.read_events(work_item_id=wi.work_item_id)
        link_events = [e for e in events if e.transition == "link_created"]
        assert len(link_events) == 1
        assert link_events[0].payload["target_project"] == "other_project"

    def test_in_memory_cross_project_link_remove(self):
        from regista.testing import InMemoryRegista

        s = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)
        wi, _ = s.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "inmem remove"},
        )
        target_id = uuid.uuid4()
        s.create_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="other_project",
        )
        s.remove_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="other_project",
        )
        events = s.read_events(work_item_id=wi.work_item_id)
        remove_events = [e for e in events if e.transition == "link_removed"]
        assert len(remove_events) == 1
        assert remove_events[0].payload.get("target_project") == "other_project"

    def test_in_memory_cross_project_replay(self):
        from regista.testing import InMemoryRegista

        s = InMemoryRegista(project="test", hmac_key_path=KEY_PATH)
        s.register_workflow_file(WORKFLOW_PATH)
        wi, _ = s.create_work_item(
            "test_workflow", "feature", "agent-1",
            custom_fields={"title": "inmem replay xproject"},
        )
        target_id = uuid.uuid4()
        s.create_link(
            wi.work_item_id, target_id, "blocks", "agent-1",
            target_project="other_project",
            content_hash="sha256:abc",
        )
        report = s.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0


class TestLinkDataclassCrossProject:
    def test_link_to_dict_includes_cross_project_fields(self):
        link = Link(
            link_id=uuid.uuid4(),
            from_work_item_id=uuid.uuid4(),
            to_work_item_id=uuid.uuid4(),
            link_type="references",
            target_project="other_project",
            target_entity_kind="note",
            content_hash="sha256:xyz",
        )
        d = link.to_dict()
        assert d["target_project"] == "other_project"
        assert d["target_entity_kind"] == "note"
        assert d["content_hash"] == "sha256:xyz"

    def test_link_from_dict_roundtrip_cross_project(self):
        link = Link(
            link_id=uuid.uuid4(),
            from_work_item_id=uuid.uuid4(),
            to_work_item_id=uuid.uuid4(),
            link_type="references",
            target_project="other_project",
            target_entity_kind="note",
            content_hash="sha256:xyz",
        )
        d = link.to_dict()
        link2 = Link.from_dict(d)
        assert link2.target_project == "other_project"
        assert link2.target_entity_kind == "note"
        assert link2.content_hash == "sha256:xyz"

    def test_link_to_dict_omits_cross_project_when_none(self):
        link = Link(
            link_id=uuid.uuid4(),
            from_work_item_id=uuid.uuid4(),
            to_work_item_id=uuid.uuid4(),
            link_type="blocks",
        )
        d = link.to_dict()
        assert "target_project" not in d
        assert "target_entity_kind" not in d
        assert "content_hash" not in d
