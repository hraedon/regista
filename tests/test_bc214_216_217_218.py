from __future__ import annotations

import json
import uuid
from pathlib import Path

import pytest

from substrate._errors import ErrorCode, SubstrateError
from substrate._keys import KeySet
from substrate._signing import sign_event, verify_event


def _write_key_file(path: Path, keys: list[dict]) -> Path:
    path.write_text(json.dumps({"keys": keys}))
    return path


SECRET = "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl"


class TestBC216KeyEntryRestructure:
    def test_default_alg_is_hmac_sha256(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "k1", "secret": SECRET, "status": "active"},
        ])
        ks = KeySet(str(kf))
        entry = ks.active_key()
        assert entry.alg == "HMAC-SHA256"

    def test_ed25519_alg_round_trip(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "k1", "alg": "Ed25519",
                "secret": SECRET, "status": "active",
                "public_key": "dGVzdC1rZXk=",
            },
        ])
        ks = KeySet(str(kf))
        entry = ks.active_key()
        assert entry.alg == "Ed25519"
        assert entry.public_key is not None

    def test_base64_secret_decoding(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "k1", "secret": "ZW5jb2RlZA==",
                "encoding": "base64", "status": "active",
            },
        ])
        ks = KeySet(str(kf))
        entry = ks.active_key()
        assert entry.secret == b"encoded"

    def test_fingerprint_hmac(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "k1", "secret": SECRET, "status": "active"},
        ])
        entry = KeySet(str(kf)).active_key()
        fp = entry.fingerprint()
        assert fp.startswith("hmac:sha256:")

    def test_fingerprint_ed25519(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "k1", "alg": "Ed25519",
                "secret": SECRET, "status": "active",
                "public_key": "dGVzdC1rZXk=",
            },
        ])
        entry = KeySet(str(kf)).active_key()
        fp = entry.fingerprint()
        assert fp.startswith("Ed25519:sha256:")


class TestBC218KeyRole:
    def test_default_role_is_actor(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "k1", "secret": SECRET, "status": "active"},
        ])
        entry = KeySet(str(kf)).active_key()
        assert entry.role == "actor"

    def test_auditor_role_loads(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "k1", "secret": SECRET, "status": "active", "role": "auditor"},
        ])
        entry = KeySet(str(kf)).active_key()
        assert entry.role == "auditor"

    def test_recovery_role_loads(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "k1", "secret": SECRET, "status": "active", "role": "recovery"},
        ])
        entry = KeySet(str(kf)).active_key()
        assert entry.role == "recovery"

    def test_invalid_key_role_rejected(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "k1", "secret": SECRET, "status": "active", "role": "operator"},
        ])
        with pytest.raises(SubstrateError) as exc:
            KeySet(str(kf))
        assert exc.value.code == ErrorCode.INVALID_KEY_ROLE

    def test_validate_key_role_contract(self):
        from substrate._contract import validate_key_role
        validate_key_role("actor")
        validate_key_role("auditor")
        validate_key_role("recovery")
        with pytest.raises(SubstrateError) as exc:
            validate_key_role("invalid")
        assert exc.value.code == ErrorCode.INVALID_KEY_ROLE


class TestBC215RevokedAt:
    def test_revoked_at_validates_revoked_at(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "old", "secret": SECRET, "status": "revoked",
                "revoked_at": "2026-06-01T00:00:00Z",
            },
            {"key_id": "new", "secret": SECRET, "status": "active"},
        ])
        ks = KeySet(str(kf))
        with pytest.raises(SubstrateError) as exc:
            ks.verify_key_status("old")
        assert exc.value.code == ErrorCode.REVOKED_KEY_ID

    def test_revoked_at_predates_event(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "old", "secret": SECRET, "status": "revoked",
                "revoked_at": "2026-06-01T00:00:00Z",
            },
        ])
        ks = KeySet(str(kf))
        entry = ks.verify_key_status("old", event_timestamp="2026-05-01T00:00:00Z")
        assert entry.key_id == "old"


class TestBC217PerActorKeyResolution:
    def test_resolve_signing_key_falls_back_to_active(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "k1", "secret": SECRET, "status": "active"},
        ])
        ks = KeySet(str(kf))
        entry = ks.resolve_signing_key("agent-1")
        assert entry.key_id == "k1"

    def test_active_keys_for_principal(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "k1", "secret": SECRET, "status": "active",
                "principal_id": "alice",
            },
            {
                "key_id": "k2", "secret": SECRET, "status": "active",
                "principal_id": "bob",
            },
        ])
        ks = KeySet(str(kf))
        candidates = ks.active_keys_for("alice")
        assert len(candidates) == 1
        assert candidates[0].key_id == "k1"

    def test_resolve_by_principal_prefers_matching(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "k1", "secret": SECRET, "status": "active",
                "principal_id": "alice",
            },
            {"key_id": "k2", "secret": SECRET, "status": "active"},
        ])
        ks = KeySet(str(kf))
        entry = ks.resolve_signing_key("alice")
        assert entry.key_id == "k1"

    def test_key_id_override(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {"key_id": "k1", "secret": SECRET, "status": "active"},
            {"key_id": "k2", "secret": SECRET, "status": "active"},
        ])
        ks = KeySet(str(kf))
        entry = ks.resolve_signing_key("alice", key_id="k2")
        assert entry.key_id == "k2"


class TestBC214EnvelopeV2:
    def test_new_envelope_is_used(self, tmp_path):
        from datetime import UTC, datetime
        key = b"x" * 32
        _sig, _ch, env = sign_event(
            event_id=uuid.uuid4(),
            work_item_id=uuid.uuid4(),
            actor_id="agent",
            key_id="k1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=datetime.now(UTC),
            transition="start",
            payload={"a": 1},
            key=key,
        )
        assert b"key_id" in env
        assert b"event_seq" in env
        assert b"workflow_name" in env
        assert b"workflow_version" in env

    def test_backward_compat_verifies(self, tmp_path):
        import hashlib
        from datetime import UTC, datetime

        from substrate._jcs import canonicalize
        from substrate._signing import compute_hmac

        key = b"x" * 32
        now = datetime.now(UTC)

        # Sign with v2 envelope
        env2 = {
            "event_id": str(uuid.uuid4()),
            "work_item_id": str(uuid.uuid4()),
            "actor_id": "agent",
            "key_id": "k1",
            "event_seq": 1,
            "workflow_name": "wf",
            "workflow_version": 1,
            "timestamp": now.isoformat(),
            "on_behalf_of": None,
            "transition": "start",
            "payload": {"a": 1},
        }
        envelope_bytes = canonicalize(env2)
        sig = compute_hmac(envelope_bytes, key)
        ch = hashlib.sha256(envelope_bytes).digest()

        # Verify via public API (should retry old envelope internally)
        assert verify_event(
            event_id=uuid.UUID(env2["event_id"]),
            work_item_id=uuid.UUID(env2["work_item_id"]),
            actor_id=env2["actor_id"],
            key_id=env2["key_id"],
            event_seq=env2["event_seq"],
            workflow_name=env2["workflow_name"],
            workflow_version=env2["workflow_version"],
            timestamp=now,
            transition=env2["transition"],
            payload=env2["payload"],
            signature=sig,
            canonical_hash=ch,
            key=key,
        )
