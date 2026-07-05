from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path

import pytest

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from tests.conftest import DSN, WORKFLOW_PATH


def _generate_ed25519_keypair() -> tuple[bytes, bytes]:
    import nacl.signing
    sk = nacl.signing.SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def _make_ed25519_key_file(tmp_path: Path, principal_id: str) -> tuple[str, bytes, bytes, str]:
    sk, vk = _generate_ed25519_keypair()
    priv_path = tmp_path / f"{principal_id}_priv.key"
    priv_path.write_bytes(sk)
    try:
        priv_path.chmod(0o600)
    except OSError:
        pass
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({"keys": [
        {
            "key_id": "bootstrap-hmac",
            "secret": "dGVzdA==",
            "encoding": "base64",
            "status": "active",
        },
        {
            "key_id": f"ed25519-{principal_id}",
            "scheme": "ed25519",
            "principal_id": principal_id,
            "secret_ref": f"file:{priv_path}",
            "public_key": base64.b64encode(vk).decode("ascii"),
            "role": "actor",
            "status": "active",
        },
    ]}))
    return str(key_file), sk, vk, str(priv_path)


def _make_multi_ed25519_key_file(
    tmp_path: Path, principal_id: str,
) -> tuple[str, bytes, bytes, bytes, bytes]:
    sk1, vk1 = _generate_ed25519_keypair()
    sk2, vk2 = _generate_ed25519_keypair()
    priv1 = tmp_path / f"{principal_id}_priv1.key"
    priv2 = tmp_path / f"{principal_id}_priv2.key"
    priv1.write_bytes(sk1)
    priv2.write_bytes(sk2)
    try:
        priv1.chmod(0o600)
        priv2.chmod(0o600)
    except OSError:
        pass
    key_file = tmp_path / "keys.json"
    v2_key_id = f"ed25519-{principal_id}-v2"
    key_file.write_text(json.dumps({"keys": [
        {
            "key_id": "bootstrap-hmac",
            "secret": "dGVzdA==",
            "encoding": "base64",
            "status": "active",
        },
        {
            "key_id": f"ed25519-{principal_id}",
            "scheme": "ed25519",
            "principal_id": principal_id,
            "secret_ref": f"file:{priv1}",
            "public_key": base64.b64encode(vk1).decode("ascii"),
            "role": "actor",
            "status": "active",
        },
        {
            "key_id": v2_key_id,
            "scheme": "ed25519",
            "principal_id": principal_id,
            "secret_ref": f"file:{priv2}",
            "public_key": base64.b64encode(vk2).decode("ascii"),
            "role": "actor",
            "status": "active",
        },
    ]}))
    return str(key_file), sk1, vk1, sk2, vk2


@pytest.fixture
def principal_setup(tmp_path):
    project = f"signbind_{uuid.uuid4().hex[:8]}"
    principal_id = f"test_principal_{uuid.uuid4().hex[:8]}"
    from regista.testing import drop_project_schema

    key_path, sk, vk, _priv_path = _make_ed25519_key_file(tmp_path, principal_id)

    Regista.create_project(DSN, project, key_path)
    sub = Regista(DSN, project, key_path)
    try:
        sub.register_workflow_file(WORKFLOW_PATH)
        from regista._principal_keys import register_principal_key
        key_id = f"ed25519-{principal_id}"
        entry = register_principal_key(
            sub._mgr, principal_id, vk, "ed25519", key_id=key_id,
        )
        yield sub, principal_id, entry.key_id, sk, vk
    finally:
        sub.close()
        drop_project_schema(DSN, project)


@pytest.fixture
def multi_key_setup(tmp_path):
    project = f"signbind_{uuid.uuid4().hex[:8]}"
    principal_id = f"test_principal_{uuid.uuid4().hex[:8]}"
    from regista.testing import drop_project_schema

    key_path, sk1, vk1, sk2, vk2 = _make_multi_ed25519_key_file(tmp_path, principal_id)

    Regista.create_project(DSN, project, key_path)
    sub = Regista(DSN, project, key_path)
    try:
        sub.register_workflow_file(WORKFLOW_PATH)
        from regista._principal_keys import register_principal_key
        key_id = f"ed25519-{principal_id}"
        entry = register_principal_key(
            sub._mgr, principal_id, vk1, "ed25519", key_id=key_id,
        )
        yield sub, principal_id, entry.key_id, sk1, vk1, sk2, vk2
    finally:
        sub.close()
        drop_project_schema(DSN, project)


@pytest.fixture
def rotated_key_setup(tmp_path):
    project = f"signbind_{uuid.uuid4().hex[:8]}"
    principal_id = f"test_principal_{uuid.uuid4().hex[:8]}"
    from regista.testing import drop_project_schema

    sk1, vk1 = _generate_ed25519_keypair()
    sk2, vk2 = _generate_ed25519_keypair()
    priv1 = tmp_path / f"{principal_id}_priv1.key"
    priv2 = tmp_path / f"{principal_id}_priv2.key"
    priv1.write_bytes(sk1)
    priv2.write_bytes(sk2)
    try:
        priv1.chmod(0o600)
        priv2.chmod(0o600)
    except OSError:
        pass
    old_key_id = f"ed25519-{principal_id}"
    key_file = tmp_path / "keys.json"
    key_file.write_text(json.dumps({"keys": [
        {
            "key_id": "bootstrap-hmac",
            "secret": "dGVzdA==",
            "encoding": "base64",
            "status": "active",
        },
        {
            "key_id": old_key_id,
            "scheme": "ed25519",
            "principal_id": principal_id,
            "secret_ref": f"file:{priv1}",
            "public_key": base64.b64encode(vk1).decode("ascii"),
            "role": "actor",
            "status": "active",
        },
    ]}))

    Regista.create_project(DSN, project, str(key_file))
    sub = Regista(DSN, project, str(key_file))
    try:
        sub.register_workflow_file(WORKFLOW_PATH)
        from regista._principal_keys import register_principal_key
        register_principal_key(
            sub._mgr, principal_id, vk1, "ed25519", key_id=old_key_id,
        )
        import time
        # Stagger so the old event predates the rotation's valid_to.
        time.sleep(0.15)
        yield sub, principal_id, old_key_id, sk1, vk1, sk2, vk2
    finally:
        sub.close()
        drop_project_schema(DSN, project)


class TestVerifyEventPrincipalBinding:
    def test_matching_principal_verifies(self, principal_setup):
        sub, principal_id, _key_id, _sk, _vk = principal_setup

        wi, _evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=principal_id,
            custom_fields={"title": "test"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        assert len(events) > 0

        result = sub.verify_event_principal_binding(events[0])
        assert result["verified"] is True
        assert result["principal_id"] == principal_id
        assert result["error"] is None

    def test_unregistered_signer_fails(self, regista_instance):
        sub = regista_instance
        sub.register_workflow_file(WORKFLOW_PATH)
        wi, _evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="test-actor",
            custom_fields={"title": "test"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        assert len(events) > 0

        result = sub.verify_event_principal_binding(events[0])
        assert result["verified"] is False
        assert "unregistered" in (result["error"] or "").lower()

    def test_hmac_event_fails_scheme_mismatch(self, principal_setup):
        sub, _principal_id, _key_id, _sk, vk = principal_setup

        wi, _evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="hmac-actor",
            custom_fields={"title": "test"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        assert len(events) > 0
        assert events[0].scheme_id == "hmac-sha256"

        from regista._principal_keys import register_principal_key
        register_principal_key(sub._mgr, "hmac-actor", vk, "ed25519")

        result = sub.verify_event_principal_binding(events[0])
        assert result["verified"] is False
        assert "scheme" in (result["error"] or "").lower()


class TestPrincipalKeyOpsFacade:
    def test_verify_binding_via_facade(self, principal_setup):
        sub, principal_id, key_id, _sk, _vk = principal_setup
        result = sub.principals.verify_binding(principal_id, principal_id)
        assert result["principal_id"] == principal_id
        assert result["key_id"] == key_id

    def test_verify_binding_mismatch_raises(self, principal_setup):
        sub, principal_id, _key_id, _sk, _vk = principal_setup
        with pytest.raises(RegistaError) as exc_info:
            sub.principals.verify_binding(principal_id, "different-actor")
        assert exc_info.value.code == ErrorCode.ACTOR_SIGNER_MISMATCH


class TestKeySetSecretRef:
    def test_resolve_signing_key_by_principal_id(self, tmp_path):
        sk, vk = _generate_ed25519_keypair()
        priv_path = tmp_path / "test_priv.key"
        priv_path.write_bytes(sk)
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [
            {
                "key_id": "ed25519-principal",
                "scheme": "ed25519",
                "principal_id": "my-principal",
                "secret_ref": f"file:{priv_path}",
                "public_key": base64.b64encode(vk).decode("ascii"),
                "role": "actor",
                "status": "active",
            }
        ]}))
        from regista._keys import KeySet
        ks = KeySet(str(key_file))
        entry = ks.resolve_signing_key("my-principal")
        assert entry.scheme == "ed25519"
        assert entry.principal_id == "my-principal"
        assert entry.secret == sk
        assert entry.public_key == vk

    def test_secret_ref_env_provider(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MY_TEST_KEY", "env-secret-value")
        key_file = tmp_path / "keys.json"
        key_file.write_text(json.dumps({"keys": [
            {
                "key_id": "env-key",
                "scheme": "hmac-sha256",
                "secret_ref": "env:MY_TEST_KEY",
                "status": "active",
            }
        ]}))
        from regista._keys import KeySet
        ks = KeySet(str(key_file))
        entry = ks.get_key("env-key")
        assert entry.secret == b"env-secret-value"


class TestKeyRotationHistoricalVerification:
    def test_rotated_key_still_verifies_old_events(self, principal_setup):
        sub, principal_id, _key_id, _sk, _vk = principal_setup

        wi, _evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=principal_id,
            custom_fields={"title": "rotation-test"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        assert len(events) > 0
        old_event = events[0]

        result_before = sub.verify_event_principal_binding(old_event)
        assert result_before["verified"] is True

        from regista._principal_keys import rotate_principal_key
        _new_sk, new_vk = _generate_ed25519_keypair()
        rotate_principal_key(sub._mgr, principal_id, new_vk, "ed25519")

        result_after = sub.verify_event_principal_binding(old_event)
        assert result_after["verified"] is True
        assert result_after["key_id"] == _key_id


class TestPathTraversal:
    def test_provision_principal_rejects_path_traversal(self, tmp_path):
        from regista._provision import provision_principal
        project = f"prov_{uuid.uuid4().hex[:8]}"
        from regista.testing import drop_project_schema
        try:
            from regista._provision import provision as _prov
            _prov(DSN, [project])
            with pytest.raises(RegistaError) as exc_info:
                provision_principal(
                    DSN, project, "../../../etc/cron.d/evil",
                    hmac_key_path=str(tmp_path / "keys.json"),
                )
            assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT
        finally:
            drop_project_schema(DSN, project)
            import psycopg
            with psycopg.connect(DSN, autocommit=True) as conn:
                conn.execute(f'DROP ROLE IF EXISTS "regista_{project}"')


class TestReplayPrincipalBinding:
    """End-to-end tests: replay(verify_principal_binding=True) closes the
    non-repudiation loop — a forged actor with a valid key-set key is caught.
    """

    def test_valid_ed25519_event_passes(self, principal_setup):
        sub, principal_id, _key_id, _sk, _vk = principal_setup

        wi, _evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=principal_id,
            custom_fields={"title": "valid-ed25519"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        assert events[0].scheme_id == "ed25519"

        report = sub.replay(verify_principal_binding=True)
        baseline = sub.replay(verify_principal_binding=False)
        assert report.replayed_drift == 0
        assert report.halted == 0
        assert report.warnings == baseline.warnings

    def test_forged_hmac_event_caught(self, principal_setup):
        sub, _principal_id, _key_id, _sk, vk = principal_setup

        wi, _evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="hmac-forger",
            custom_fields={"title": "forged"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        assert events[0].scheme_id == "hmac-sha256"

        from regista._principal_keys import register_principal_key
        register_principal_key(sub._mgr, "hmac-forger", vk, "ed25519")

        baseline = sub.replay(verify_principal_binding=False)
        report = sub.replay(verify_principal_binding=True)
        assert report.replayed_drift == 0
        assert report.halted == 0
        assert report.warnings > baseline.warnings

    def test_forged_actor_with_victim_id_caught(self, principal_setup):
        """The headline attack: attacker has valid HMAC key, forges event
        with actor_id=victim (who has a registered Ed25519 key). The event
        passes key-set verification (valid HMAC) but principal binding
        catches the scheme mismatch."""
        sub, principal_id, _key_id, _sk, _vk = principal_setup

        hmac_only_key_file = {
            "keys": [
                {
                    "key_id": "bootstrap-hmac",
                    "secret": "dGVzdA==",
                    "encoding": "base64",
                    "status": "active",
                }
            ]
        }
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json.dump(hmac_only_key_file, f)
            hmac_key_path = f.name

        hmac_sub = Regista(DSN, sub.project, hmac_key_path)
        try:
            wi, _evt = hmac_sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id=principal_id,
                custom_fields={"title": "forged-actor-id"},
            )
            events = hmac_sub.read_events(work_item_id=wi.work_item_id)
            assert events[0].scheme_id == "hmac-sha256"
        finally:
            hmac_sub.close()

        baseline = sub.replay(verify_principal_binding=False)
        report = sub.replay(verify_principal_binding=True)
        assert report.replayed_drift == 0
        assert report.halted == 0
        assert report.warnings > baseline.warnings

        import os

        os.unlink(hmac_key_path)

    def test_no_principal_keys_backward_compat(self, principal_setup):
        sub, _principal_id, _key_id, _sk, _vk = principal_setup

        wi, _evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="unregistered-actor",
            custom_fields={"title": "no-principal"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        assert events[0].scheme_id == "hmac-sha256"

        baseline = sub.replay(verify_principal_binding=False)
        report = sub.replay(verify_principal_binding=True)
        assert report.replayed_drift == 0
        assert report.halted == 0
        assert report.warnings == baseline.warnings

    def test_revoked_principal_key_warning(self, principal_setup):
        sub, principal_id, key_id, _sk, _vk = principal_setup

        wi, _evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=principal_id,
            custom_fields={"title": "revoked-test"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        assert events[0].scheme_id == "ed25519"

        from regista._principal_keys import revoke_principal_key
        revoke_principal_key(sub._mgr, principal_id, key_id, reason="compromised")

        baseline = sub.replay(verify_principal_binding=False, continue_on_revoked=True)
        report = sub.replay(verify_principal_binding=True, continue_on_revoked=True)
        assert report.replayed_drift == 0
        assert report.halted == 0
        assert report.warnings > baseline.warnings

    def test_rotated_key_old_event_passes(self, principal_setup):
        sub, principal_id, _key_id, _sk, _vk = principal_setup

        wi, _evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=principal_id,
            custom_fields={"title": "rotation-replay"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        assert events[0].scheme_id == "ed25519"

        from regista._principal_keys import rotate_principal_key
        _new_sk, new_vk = _generate_ed25519_keypair()
        rotate_principal_key(sub._mgr, principal_id, new_vk, "ed25519")

        baseline = sub.replay(verify_principal_binding=False)
        report = sub.replay(verify_principal_binding=True)
        assert report.replayed_drift == 0
        assert report.halted == 0
        assert report.warnings == baseline.warnings

    def test_rotated_key_old_event_still_verifies(self, multi_key_setup):
        sub, principal_id, key_id, _sk1, _vk1, _sk2, vk2 = multi_key_setup

        from regista._principal_keys import register_principal_key
        v2_key_id = f"ed25519-{principal_id}-v2"
        register_principal_key(
            sub._mgr, principal_id, vk2, "ed25519", key_id=v2_key_id,
        )

        wi, _evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=principal_id,
            custom_fields={"title": "pre-rotation"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        old_event = events[0]
        assert old_event.key_id in (key_id, v2_key_id)

        from regista._principal_keys import rotate_principal_key
        rotate_principal_key(sub._mgr, principal_id, vk2, "ed25519")

        result = sub.verify_event_principal_binding(old_event)
        assert result["verified"] is True
        assert result["key_id"] == old_event.key_id

    def test_event_after_valid_to_rejected(self, multi_key_setup):
        import time

        sub, principal_id, key_id, _sk1, _vk1, _sk2, vk2 = multi_key_setup

        from regista._principal_keys import register_principal_key, rotate_principal_key
        v2_key_id = f"ed25519-{principal_id}-v2"
        register_principal_key(
            sub._mgr, principal_id, vk2, "ed25519", key_id=v2_key_id,
        )

        wi1, _evt1 = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=principal_id,
            custom_fields={"title": "old"},
        )
        old_event = sub.read_events(work_item_id=wi1.work_item_id)[0]
        signed_key_id = old_event.key_id
        assert signed_key_id in (key_id, v2_key_id)

        old_result = sub.verify_event_principal_binding(old_event)
        assert old_result["verified"] is True
        assert old_result["key_id"] == signed_key_id

        time.sleep(0.05)
        rotate_principal_key(sub._mgr, principal_id, vk2, "ed25519")
        # Rotate again so that the active key_id matches the v2 secret in the
        # key set and a new event can be signed successfully.
        time.sleep(0.05)
        rotate_principal_key(sub._mgr, principal_id, vk2, "ed25519")

        time.sleep(0.05)
        wi2, _evt2 = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=principal_id,
            custom_fields={"title": "new"},
        )
        new_event = sub.read_events(work_item_id=wi2.work_item_id)[0]
        assert new_event.key_id == v2_key_id
        new_result = sub.verify_event_principal_binding(new_event)
        assert new_result["verified"] is False
        assert new_result["error"] is not None
        assert "key-not-valid-at-time" in (new_result["error"] or "")


    def test_ed25519_key_id_mismatch_rejected(self, multi_key_setup):
        import time

        sub, principal_id, key_id, _sk1, _vk1, _sk2, vk2 = multi_key_setup

        from regista._principal_keys import register_principal_key, rotate_principal_key
        v2_key_id = f"ed25519-{principal_id}-v2"
        register_principal_key(
            sub._mgr, principal_id, vk2, "ed25519", key_id=v2_key_id,
        )

        # Rotate twice so the original key_id is no longer among non-revoked
        # keys while the event was signed with it.
        time.sleep(0.05)
        rotate_principal_key(sub._mgr, principal_id, vk2, "ed25519")
        time.sleep(0.05)
        _new_sk, new_vk = _generate_ed25519_keypair()
        rotate_principal_key(sub._mgr, principal_id, new_vk, "ed25519")

        wi, _evt = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=principal_id,
            custom_fields={"title": "mismatch"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        evt = events[0]
        assert evt.key_id in (key_id, v2_key_id)

        result = sub.verify_event_principal_binding(evt)
        assert result["verified"] is False
        assert result["error"] is not None
        assert any(
            fragment in (result["error"] or "")
            for fragment in ("key-id-mismatch", "key-not-valid-at-time")
        )

