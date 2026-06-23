from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._testing import KeySet

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")
MULTI_PRINCIPAL_KEY_PATH = str(TESTS_DIR / "test_keys_multi_principal.json")
ED_KEY_PATH = str(TESTS_DIR / "test_keys_ed25519.json")
HMAC_KEY_PATH = str(TESTS_DIR / "test_keys.json")

_HAS_NACL = True
try:
    import nacl.signing  # noqa: F401
except ImportError:
    _HAS_NACL = False

skip_no_nacl = pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")


def _write_keys(tmp_path, keys_data):
    p = tmp_path / "keys.json"
    p.write_text(json.dumps(keys_data))
    return str(p)


def _gen_ed25519_keypair_b64():
    import nacl.signing

    sk = nacl.signing.SigningKey.generate()
    pk = sk.verify_key
    return base64.b64encode(bytes(sk)).decode("ascii"), base64.b64encode(bytes(pk)).decode("ascii")


@skip_no_nacl
class TestPerPrincipalEd25519Signing:
    def test_two_principals_sign_with_different_keys(self):
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(project="test", hmac_key_path=MULTI_PRINCIPAL_KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)

        wi_alice, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="alice",
            custom_fields={"title": "alice's work"},
        )
        events_alice = sub.read_events(work_item_id=wi_alice.work_item_id)
        assert events_alice[-1].key_id == "ed-alice-001"
        assert events_alice[-1].scheme_id == "ed25519"

        wi_bob, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="bob",
            custom_fields={"title": "bob's work"},
        )
        events_bob = sub.read_events(work_item_id=wi_bob.work_item_id)
        assert events_bob[-1].key_id == "ed-bob-001"
        assert events_bob[-1].scheme_id == "ed25519"

        assert events_alice[-1].key_id != events_bob[-1].key_id

    def test_explicit_key_id_overrides_principal_resolution(self):
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(project="test", hmac_key_path=MULTI_PRINCIPAL_KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)

        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="alice",
            custom_fields={"title": "explicit key"},
        )
        evt = sub.append_event(
            wi.work_item_id, "bob", key_id="ed-bob-001",
            transition="note", payload={"text": "bob signing as bob"},
        )
        assert evt.key_id == "ed-bob-001"
        assert evt.actor_id == "bob"

    def test_postgres_per_principal_signing(self):
        from regista import Regista
        from regista.testing import drop_project_schema

        project = f"test_p3_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, MULTI_PRINCIPAL_KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        try:
            wi, _ = sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="alice",
                custom_fields={"title": "pg per-principal"},
            )
            events = sub.read_events(work_item_id=wi.work_item_id)
            assert events[-1].key_id == "ed-alice-001"
            assert events[-1].scheme_id == "ed25519"

            sub.transition(wi.work_item_id, "start", "bob", actor_metadata={"role": "agent"})
            events = sub.read_events(work_item_id=wi.work_item_id)
            start_evt = next(e for e in events if e.transition == "start")
            assert start_evt.key_id == "ed-bob-001"
            assert start_evt.scheme_id == "ed25519"
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_replay_verifies_per_principal_events(self):
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(project="test", hmac_key_path=MULTI_PRINCIPAL_KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)

        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="alice",
            custom_fields={"title": "replay test alice"},
        )
        wi_bob, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="bob",
            custom_fields={"title": "replay test bob"},
        )
        sub.transition(wi_bob.work_item_id, "start", "bob", actor_metadata={"role": "agent"})

        report = sub.replay()
        assert report.halted == 0, f"Replay halted: {report.entries}"


@skip_no_nacl
class TestIndependentVerification:
    def test_verify_with_exported_public_key_in_memory(self):
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(project="test", hmac_key_path=MULTI_PRINCIPAL_KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)

        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="alice",
            custom_fields={"title": "verify test"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        evt = events[-1]

        assert sub.verify_event_signature(evt) is True

        public_keys = sub.export_public_keys()
        alice_key = next(k for k in public_keys if k["principal_id"] == "alice")
        pub_bytes = base64.b64decode(alice_key["public_key"])

        assert sub.verify_event_signature(evt, public_key=pub_bytes) is True

        bob_key = next(k for k in public_keys if k["principal_id"] == "bob")
        bob_pub = base64.b64decode(bob_key["public_key"])
        assert sub.verify_event_signature(evt, public_key=bob_pub) is False

    def test_verify_with_exported_public_key_postgres(self):
        from regista import Regista
        from regista.testing import drop_project_schema

        project = f"test_p3v_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, MULTI_PRINCIPAL_KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        try:
            wi, _ = sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="alice",
                custom_fields={"title": "pg verify"},
            )
            events = sub.read_events(work_item_id=wi.work_item_id)
            evt = events[-1]

            assert sub.verify_event_signature(evt) is True

            public_keys = sub.export_public_keys()
            alice_key = next(k for k in public_keys if k["principal_id"] == "alice")
            pub_bytes = base64.b64decode(alice_key["public_key"])
            assert sub.verify_event_signature(evt, public_key=pub_bytes) is True
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_standalone_verify_without_keyset(self):
        from regista._signing import verify_event_with_public_key
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(project="test", hmac_key_path=MULTI_PRINCIPAL_KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)

        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="alice",
            custom_fields={"title": "standalone"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        evt = events[-1]

        public_keys = sub.export_public_keys()
        alice_key = next(k for k in public_keys if k["principal_id"] == "alice")
        pub_bytes = base64.b64decode(alice_key["public_key"])

        assert verify_event_with_public_key(evt, pub_bytes) is True

        bob_key = next(k for k in public_keys if k["principal_id"] == "bob")
        tampered = base64.b64decode(bob_key["public_key"])
        assert verify_event_with_public_key(evt, tampered) is False

    def test_export_public_keys_excludes_hmac(self, tmp_path):
        secret_b64, pub_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "hmac-001",
                    "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
                    "status": "active",
                    "scheme": "hmac-sha256",
                },
                {
                    "key_id": "ed-001",
                    "secret": secret_b64,
                    "public_key": pub_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                },
            ]
        })
        ks = KeySet(kf)
        exported = ks.export_public_keys()
        assert len(exported) == 1
        assert exported[0]["key_id"] == "ed-001"
        assert exported[0]["scheme"] == "ed25519"
        assert exported[0]["principal_id"] == "alice"
        assert "public_key" in exported[0]
        assert "secret" not in exported[0]

    def test_export_public_keys_includes_revoked(self, tmp_path):
        secret_b64, pub_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-revoked",
                    "secret": secret_b64,
                    "public_key": pub_b64,
                    "encoding": "base64",
                    "status": "revoked",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                    "revoked_at": "2026-01-01T00:00:00+00:00",
                },
            ]
        })
        ks = KeySet(kf)
        exported = ks.export_public_keys()
        assert len(exported) == 1
        assert exported[0]["status"] == "revoked"
        assert exported[0]["revoked_at"] == "2026-01-01T00:00:00+00:00"


    def test_verify_without_canonical_envelope_postgres(self):
        from regista import Regista
        from regista.testing import drop_project_schema

        project = f"test_p3ne_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, MULTI_PRINCIPAL_KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        try:
            wi, _ = sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="alice",
                custom_fields={"title": "no envelope test"},
            )
            sub.transition(
                wi.work_item_id, "start", "alice",
                actor_metadata={"role": "agent"},
            )

            events = sub.read_events(work_item_id=wi.work_item_id)
            evt = events[-1]

            from regista._types import Event as _Event

            evt_no_env = _Event(
                event_id=evt.event_id,
                work_item_id=evt.work_item_id,
                event_seq=evt.event_seq,
                actor_id=evt.actor_id,
                actor_kind=evt.actor_kind,
                actor_metadata=evt.actor_metadata,
                key_id=evt.key_id,
                workflow_name=evt.workflow_name,
                workflow_version=evt.workflow_version,
                timestamp=evt.timestamp,
                transition=evt.transition,
                payload=evt.payload,
                payload_canonical_hash=evt.payload_canonical_hash,
                signature=evt.signature,
                canonical_envelope=None,
                on_behalf_of=evt.on_behalf_of,
                scheme_id=evt.scheme_id,
                prev_event_hash=evt.prev_event_hash,
                global_seq=evt.global_seq,
                prev_global_event_hash=evt.prev_global_event_hash,
                entity_kind=evt.entity_kind,
                entity_id=evt.entity_id,
                hash_alg=evt.hash_alg,
            )

            public_keys = sub.export_public_keys()
            alice_key = next(k for k in public_keys if k["principal_id"] == "alice")
            pub_bytes = base64.b64decode(alice_key["public_key"])

            from regista._signing import verify_event_with_public_key

            assert verify_event_with_public_key(evt_no_env, pub_bytes) is True
        finally:
            sub.close()
            drop_project_schema(DSN, project)


@skip_no_nacl
class TestStrictAsymmetric:
    def test_rejects_hmac_fallback(self, tmp_path):
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "hmac-001",
                    "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
                    "status": "active",
                    "scheme": "hmac-sha256",
                },
            ]
        })
        ks = KeySet(kf, strict_asymmetric=True)
        with pytest.raises(RegistaError) as exc_info:
            ks.resolve_signing_key("unknown-actor")
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_rejects_ed25519_without_principal_binding(self, tmp_path):
        secret_b64, pub_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-001",
                    "secret": secret_b64,
                    "public_key": pub_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                },
            ]
        })
        ks = KeySet(kf, strict_asymmetric=True)
        with pytest.raises(RegistaError) as exc_info:
            ks.resolve_signing_key("alice")
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_rejects_ed25519_with_wrong_principal(self, tmp_path):
        secret_b64, pub_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-alice",
                    "secret": secret_b64,
                    "public_key": pub_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                },
            ]
        })
        ks = KeySet(kf, strict_asymmetric=True)
        with pytest.raises(RegistaError) as exc_info:
            ks.resolve_signing_key("bob")
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_accepts_matching_principal_ed25519(self, tmp_path):
        secret_b64, pub_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-alice",
                    "secret": secret_b64,
                    "public_key": pub_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                },
            ]
        })
        ks = KeySet(kf, strict_asymmetric=True)
        entry = ks.resolve_signing_key("alice")
        assert entry.key_id == "ed-alice"
        assert entry.scheme == "ed25519"

    def test_rejects_explicit_hmac_key_in_strict_mode(self, tmp_path):
        secret_b64, pub_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "hmac-001",
                    "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
                    "status": "active",
                    "scheme": "hmac-sha256",
                },
                {
                    "key_id": "ed-alice",
                    "secret": secret_b64,
                    "public_key": pub_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                },
            ]
        })
        ks = KeySet(kf, strict_asymmetric=True)
        with pytest.raises(RegistaError) as exc_info:
            ks.resolve_signing_key("alice", key_id="hmac-001")
        assert exc_info.value.code == ErrorCode.KEY_ROLE_NOT_PERMITTED
        assert "asymmetric" in str(exc_info.value).lower()

    def test_rejects_explicit_ed25519_wrong_principal(self, tmp_path):
        sk1_b64, pk1_b64 = _gen_ed25519_keypair_b64()
        sk2_b64, pk2_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-alice",
                    "secret": sk1_b64,
                    "public_key": pk1_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                },
                {
                    "key_id": "ed-bob",
                    "secret": sk2_b64,
                    "public_key": pk2_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                    "principal_id": "bob",
                },
            ]
        })
        ks = KeySet(kf, strict_asymmetric=True)
        with pytest.raises(RegistaError) as exc_info:
            ks.resolve_signing_key("alice", key_id="ed-bob")
        assert exc_info.value.code == ErrorCode.KEY_ROLE_NOT_PERMITTED

    def test_strict_asymmetric_end_to_end_in_memory(self):
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(
            project="test", hmac_key_path=MULTI_PRINCIPAL_KEY_PATH,
            strict_asymmetric=True,
        )
        sub.register_workflow_file(WORKFLOW_PATH)

        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="alice",
            custom_fields={"title": "strict mode"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        assert events[-1].key_id == "ed-alice-001"
        assert events[-1].scheme_id == "ed25519"

        sub.transition(wi.work_item_id, "start", "bob", actor_metadata={"role": "agent"})
        events = sub.read_events(work_item_id=wi.work_item_id)
        start_evt = next(e for e in events if e.transition == "start")
        assert start_evt.key_id == "ed-bob-001"

    def test_strict_asymmetric_rejects_unbound_actor_in_memory(self, tmp_path):
        from regista.testing import InMemoryRegista

        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "hmac-001",
                    "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
                    "status": "active",
                    "scheme": "hmac-sha256",
                },
            ]
        })
        sub = InMemoryRegista(
            project="test", hmac_key_path=kf,
            strict_asymmetric=True,
        )
        sub.register_workflow_file(WORKFLOW_PATH)
        with pytest.raises(RegistaError) as exc_info:
            sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="charlie",
                custom_fields={"title": "should fail"},
            )
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_strict_asymmetric_postgres(self):
        from regista import Regista
        from regista.testing import drop_project_schema

        project = f"test_p3s_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(
            DSN, project, MULTI_PRINCIPAL_KEY_PATH,
            strict_asymmetric=True,
        )
        sub.register_workflow_file(WORKFLOW_PATH)
        try:
            wi, _ = sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="alice",
                custom_fields={"title": "pg strict"},
            )
            events = sub.read_events(work_item_id=wi.work_item_id)
            assert events[-1].key_id == "ed-alice-001"
            assert events[-1].scheme_id == "ed25519"

            report = sub.replay()
            assert report.halted == 0
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_strict_asymmetric_disabled_by_default(self, tmp_path):
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "hmac-001",
                    "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
                    "status": "active",
                    "scheme": "hmac-sha256",
                },
            ]
        })
        ks = KeySet(kf)
        entry = ks.resolve_signing_key("any-actor")
        assert entry.scheme == "hmac-sha256"


@skip_no_nacl
class TestRevocation:
    def test_revoked_key_prevents_new_signing(self, tmp_path):
        sk_b64, pk_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-alice",
                    "secret": sk_b64,
                    "public_key": pk_b64,
                    "encoding": "base64",
                    "status": "revoked",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                    "revoked_at": "2026-01-01T00:00:00+00:00",
                },
            ]
        })
        ks = KeySet(kf)
        with pytest.raises(RegistaError) as exc_info:
            ks.resolve_signing_key("alice")
        assert exc_info.value.code == ErrorCode.REVOKED_KEY_ID

    def test_revoked_key_still_verifies_in_replay(self):
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(project="test", hmac_key_path=MULTI_PRINCIPAL_KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)

        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="alice",
            custom_fields={"title": "before revocation"},
        )

        report = sub.replay()
        assert report.halted == 0

        from regista._keys import KeySet as _KeySet

        key_entry = _KeySet(MULTI_PRINCIPAL_KEY_PATH).get_key("ed-alice-001")
        assert key_entry.status == "active"

        assert sub.verify_event_signature(
            sub.read_events(work_item_id=wi.work_item_id)[-1]
        ) is True

    def test_replay_continue_on_revoked(self):
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(project="test", hmac_key_path=MULTI_PRINCIPAL_KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)

        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="alice",
            custom_fields={"title": "continue on revoked"},
        )

        report = sub.replay(continue_on_revoked=True)
        assert report.halted == 0


@skip_no_nacl
class TestPostgresFullLifecycle:
    def test_full_lifecycle_strict_asymmetric(self):
        from regista import Regista
        from regista.testing import drop_project_schema

        project = f"test_p3l_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(
            DSN, project, MULTI_PRINCIPAL_KEY_PATH,
            strict_asymmetric=True,
        )
        sub.register_workflow_file(WORKFLOW_PATH)
        try:
            wi, _ = sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="alice",
                custom_fields={"title": "lifecycle"},
            )
            sub.transition(
                wi.work_item_id, "start", "alice",
                actor_metadata={"role": "agent"},
            )
            sub.transition(
                wi.work_item_id, "submit_review", "alice",
                actor_metadata={"role": "agent"},
            )

            events = sub.read_events(work_item_id=wi.work_item_id)
            assert all(e.scheme_id == "ed25519" for e in events)

            assert all(e.key_id == "ed-alice-001" for e in events)

            public_keys = sub.export_public_keys()
            assert len(public_keys) == 2
            alice_pub = next(k for k in public_keys if k["principal_id"] == "alice")
            pub_bytes = base64.b64decode(alice_pub["public_key"])

            for evt in events:
                assert sub.verify_event_signature(evt, public_key=pub_bytes) is True

            report = sub.replay()
            assert report.halted == 0
            assert report.replayed_drift == 0
        finally:
            sub.close()
            drop_project_schema(DSN, project)
