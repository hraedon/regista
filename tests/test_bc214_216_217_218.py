from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path

import pytest
from _v6_fixtures import make_v6_keyset, open_v6_epoch

from regista._errors import ErrorCode, RegistaError
from regista._keys import KeySet
from regista._signing import sign_event, verify_event
from regista._signing_scheme import Ed25519Scheme


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
        assert fp.startswith("hmac-sha256:sha256:")

    def test_fingerprint_ed25519(self, tmp_path):
        kf = _write_key_file(tmp_path / "keys.json", [
            {
                "key_id": "k1", "alg": "Ed25519",
                "secret": SECRET, "status": "active",
                "public_key": "dGVzdC1rZXk=",
                "scheme": "ed25519",
            },
        ])
        entry = KeySet(str(kf)).active_key()
        fp = entry.fingerprint()
        assert fp.startswith("ed25519:sha256:")


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
        with pytest.raises(RegistaError) as exc:
            KeySet(str(kf))
        assert exc.value.code == ErrorCode.INVALID_KEY_ROLE

    def test_validate_key_role_contract(self):
        from regista._contract import validate_key_role
        validate_key_role("actor")
        validate_key_role("auditor")
        validate_key_role("recovery")
        with pytest.raises(RegistaError) as exc:
            validate_key_role("invalid")
        assert exc.value.code == ErrorCode.INVALID_KEY_ROLE


class TestBC218KeyRolePolicy:
    def test_actor_can_sign_workflow_transition(self):
        from regista._contract import check_key_role_policy
        check_key_role_policy("actor", "start")

    def test_actor_can_sign_tool_call(self):
        from regista._contract import check_key_role_policy
        check_key_role_policy("actor", "tool_call")

    def test_actor_can_sign_none_transition(self):
        from regista._contract import check_key_role_policy
        check_key_role_policy("actor", None)

    def test_auditor_can_sign_auditor_attestation(self):
        from regista._contract import check_key_role_policy
        check_key_role_policy("auditor", "auditor_attestation")

    def test_auditor_cannot_sign_tool_call(self):
        from regista._contract import check_key_role_policy
        with pytest.raises(RegistaError) as exc:
            check_key_role_policy("auditor", "tool_call")
        assert exc.value.code == ErrorCode.KEY_ROLE_NOT_PERMITTED

    def test_auditor_cannot_sign_workflow_transition(self):
        from regista._contract import check_key_role_policy
        with pytest.raises(RegistaError) as exc:
            check_key_role_policy("auditor", "start")
        assert exc.value.code == ErrorCode.KEY_ROLE_NOT_PERMITTED

    def test_auditor_cannot_sign_key_rotation(self):
        from regista._contract import check_key_role_policy
        with pytest.raises(RegistaError) as exc:
            check_key_role_policy("auditor", "key_rotation")
        assert exc.value.code == ErrorCode.KEY_ROLE_NOT_PERMITTED

    def test_recovery_can_sign_key_rotation(self):
        from regista._contract import check_key_role_policy
        check_key_role_policy("recovery", "key_rotation")

    def test_recovery_cannot_sign_tool_call(self):
        from regista._contract import check_key_role_policy
        with pytest.raises(RegistaError) as exc:
            check_key_role_policy("recovery", "tool_call")
        assert exc.value.code == ErrorCode.KEY_ROLE_NOT_PERMITTED

    def test_actor_can_sign_key_rotation(self):
        from regista._contract import check_key_role_policy
        check_key_role_policy("actor", "key_rotation")


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
        with pytest.raises(RegistaError) as exc:
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
        from datetime import UTC, datetime

        from regista._jcs import canonicalize
        from regista._signing_scheme import HMACSHA256Scheme
        from regista._verification import EnvelopeVersion, VerificationPolicy

        legacy_policy = VerificationPolicy(
            accept_legacy_versions=frozenset(
                {EnvelopeVersion.V2, EnvelopeVersion.V3, EnvelopeVersion.V4}
            ),
        )

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
        sig, ch = HMACSHA256Scheme().sign(envelope_bytes, key)

        # WI-267: a v2 envelope is only accepted when the policy names v2.
        # There is no fallback and no implicit tolerance — accepting a legacy
        # envelope version is now an explicit, greppable decision
        # (CUTOVER-POLICY §3). The stored bytes must also be supplied: nothing
        # is rebuilt from the row.
        assert verify_event(
            stored_envelope=envelope_bytes,
            policy=legacy_policy,
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


class TestBC218KeyRolePolicyIntegration:
    WORKFLOW_YAML = """\
name: test_policy
version: 1
regista_version: "0.1.0"
states:
  - name: new
    initial: true
  - name: done
    terminal: true
transitions:
  - name: start
    from: new
    to: done
    allowed_roles: [agent]
roles:
  - name: agent
work_item_types:
  - name: task
    custom_fields:
      - name: title
        type: string
        required: true
"""

    #: The acting principals, canonical per ``TRUST-DOMAIN.md`` §2.1 — the bare
    #: ``agent1`` these replace is refused at the v6 ingress. ``WRITER`` always holds an
    #: ``actor`` key and creates the work item; the other two hold the non-actor roles
    #: under test, and the list passed to ``make_v6_keyset`` and ``open_v6_epoch`` must
    #: be identical or an unaccepted id is refused with ``KEY_BINDING_UNRESOLVED``.
    WRITER = "agent:worker"
    AUDITOR = "agent:auditor"
    RECOVERY = "agent:recovery"
    PRINCIPALS = (WRITER, AUDITOR, RECOVERY)

    def _v6_project(self, tmp_path, *, roles=None):
        """An in-memory project on a clean v6 epoch, with ``roles`` overriding.

        ``make_v6_keyset`` writes ``role: "actor"`` for every principal because that is
        what ``_v6_writer._writer_key`` requires. Rewriting one entry's role is how
        BC-218's key-role policy is still exercised in the clean epoch: the bootstrap
        key keeps ``actor`` so genesis and the standalone acceptances can be signed at
        all, and the *acting* principal's key carries the role under test. The single
        HMAC key the pre-epoch version of this test used is unusable here — a v6 event
        must be Ed25519 and must be signed by a key bound to ``actor.principal_id``.
        """
        from regista.testing import InMemoryRegista

        keyset = make_v6_keyset(tmp_path, principals=self.PRINCIPALS)
        entries = []
        for principal_id, key in keyset.keys.items():
            entries.append({
                "key_id": key.key_id,
                "scheme": "ed25519",
                "alg": "Ed25519",
                "secret": base64.b64encode(key.seed).decode("ascii"),
                "encoding": "base64",
                "public_key": key.public_key_b64,
                "principal_id": principal_id,
                "role": (roles or {}).get(principal_id, "actor"),
                "status": "active",
            })
        key_path = tmp_path / "roled_keys.json"
        key_path.write_text(json.dumps({"keys": entries}))

        sub = InMemoryRegista(project="test", hmac_key_path=str(key_path))
        # The clean v6 epoch before the registration: `register_workflow` emits the
        # signed `workflow_registered` event admission gate 1 requires, and there is no
        # epoch to append it to until `open_v6_epoch` returns.
        open_v6_epoch(sub, keyset, principals=self.PRINCIPALS)
        sub.register_workflow(self.WORKFLOW_YAML)
        return sub

    def test_actor_key_can_transition(self, tmp_path):
        sub = self._v6_project(tmp_path)
        wi, _ = sub.create_work_item(
            "test_policy", "task", self.WRITER, custom_fields={"title": "t"},
        )
        evt = sub.transition(
            wi.work_item_id, "start", self.WRITER,
            actor_metadata={"role": "agent"},
        )
        assert evt.transition == "start"
        sub.close()

    def test_auditor_key_blocked_from_workflow_transition(self, tmp_path):
        sub = self._v6_project(tmp_path, roles={self.AUDITOR: "auditor"})
        wi, _ = sub.create_work_item(
            "test_policy", "task", self.WRITER, custom_fields={"title": "t"},
        )
        with pytest.raises(RegistaError) as exc:
            sub.transition(
                wi.work_item_id, "start", self.AUDITOR,
                actor_metadata={"role": "agent"},
            )
        assert exc.value.code == ErrorCode.KEY_ROLE_NOT_PERMITTED
        sub.close()

    def test_auditor_key_blocked_from_append_event_transition(self, tmp_path):
        sub = self._v6_project(tmp_path, roles={self.AUDITOR: "auditor"})
        wi, _ = sub.create_work_item(
            "test_policy", "task", self.WRITER, custom_fields={"title": "t"},
        )
        with pytest.raises(RegistaError) as exc:
            sub.append_event(wi.work_item_id, self.AUDITOR, transition="tool_call")
        assert exc.value.code == ErrorCode.KEY_ROLE_NOT_PERMITTED
        sub.close()

    def test_recovery_key_blocked_from_workflow_transition(self, tmp_path):
        sub = self._v6_project(tmp_path, roles={self.RECOVERY: "recovery"})
        wi, _ = sub.create_work_item(
            "test_policy", "task", self.WRITER, custom_fields={"title": "t"},
        )
        with pytest.raises(RegistaError) as exc:
            sub.transition(
                wi.work_item_id, "start", self.RECOVERY,
                actor_metadata={"role": "agent"},
            )
        assert exc.value.code == ErrorCode.KEY_ROLE_NOT_PERMITTED
        sub.close()


class TestEd25519SchemeVerify:
    def test_verify_with_short_public_key_returns_false(self):
        import importlib.util

        if importlib.util.find_spec("nacl.signing") is None:
            pytest.skip("PyNaCl not installed")

        scheme = Ed25519Scheme()
        envelope = b"test envelope"
        signature = b"\x00" * 64
        assert scheme.verify(envelope, signature, b"\x00" * 32, b"\x01" * 16) is False
