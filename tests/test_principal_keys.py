from __future__ import annotations

import hashlib

import pytest

from regista._errors import RegistaError
from regista._principal_keys import (
    get_active_key,
    list_principal_keys,
    register_principal_key,
    revoke_principal_key,
    rotate_principal_key,
    verify_principal_binding,
)


def _generate_ed25519_keypair():
    try:
        import nacl.signing
        sk = nacl.signing.SigningKey.generate()
        return sk, sk.verify_key
    except ImportError:
        import os
        fake_priv = os.urandom(32)
        fake_pub = os.urandom(32)
        return fake_priv, fake_pub


@pytest.fixture
def principal_keys(regista_instance):
    return regista_instance


class TestRegisterPrincipalKey:
    def test_register_returns_entry(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry = register_principal_key(
            principal_keys._mgr,
            "alice@example.com",
            bytes(vk),
            "ed25519",
            registered_by="admin",
        )
        assert entry.principal_id == "alice@example.com"
        assert entry.scheme == "ed25519"
        assert entry.status == "active"
        assert entry.registered_by == "admin"
        assert entry.public_key == bytes(vk)
        assert entry.fingerprint.startswith("ed25519:sha256:")

    def test_register_idempotent_same_key_id(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry1 = register_principal_key(
            principal_keys._mgr,
            "bob@example.com",
            bytes(vk),
            "ed25519",
            key_id="key-001",
        )
        entry2 = register_principal_key(
            principal_keys._mgr,
            "bob@example.com",
            bytes(vk),
            "ed25519",
            key_id="key-001",
        )
        assert entry1.key_id == entry2.key_id
        assert entry2.status == "active"

    def test_register_new_key_supersedes_old(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        entry1 = register_principal_key(
            principal_keys._mgr,
            "carol@example.com",
            bytes(vk1),
            "ed25519",
        )
        assert entry1.status == "active"

        _sk2, vk2 = _generate_ed25519_keypair()
        entry2 = register_principal_key(
            principal_keys._mgr,
            "carol@example.com",
            bytes(vk2),
            "ed25519",
        )
        assert entry2.status == "active"

        old = get_active_key(principal_keys._mgr, "carol@example.com")
        assert old.key_id == entry2.key_id

        all_keys = list_principal_keys(principal_keys._mgr, "carol@example.com")
        statuses = {k.key_id: k.status for k in all_keys}
        assert statuses[entry1.key_id] == "superseded"
        assert statuses[entry2.key_id] == "active"

    def test_register_empty_principal_raises(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        with pytest.raises(RegistaError) as exc_info:
            register_principal_key(
                principal_keys._mgr,
                "",
                bytes(vk),
                "ed25519",
            )
        assert "INVALID_ARGUMENT" in str(exc_info.value)

    def test_register_empty_pubkey_raises(self, principal_keys):
        with pytest.raises(RegistaError) as exc_info:
            register_principal_key(
                principal_keys._mgr,
                "dave@example.com",
                b"",
                "ed25519",
            )
        assert "INVALID_ARGUMENT" in str(exc_info.value)


class TestListPrincipalKeys:
    def test_list_all(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        _sk2, vk2 = _generate_ed25519_keypair()
        register_principal_key(principal_keys._mgr, "p1", bytes(vk1), "ed25519")
        register_principal_key(principal_keys._mgr, "p2", bytes(vk2), "ed25519")
        all_keys = list_principal_keys(principal_keys._mgr)
        principals = {k.principal_id for k in all_keys}
        assert "p1" in principals
        assert "p2" in principals

    def test_list_by_principal(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        _sk2, vk2 = _generate_ed25519_keypair()
        register_principal_key(principal_keys._mgr, "p3", bytes(vk1), "ed25519")
        register_principal_key(principal_keys._mgr, "p4", bytes(vk2), "ed25519")
        keys = list_principal_keys(principal_keys._mgr, "p3")
        assert all(k.principal_id == "p3" for k in keys)

    def test_list_by_status(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        _sk2, vk2 = _generate_ed25519_keypair()
        entry1 = register_principal_key(principal_keys._mgr, "p5", bytes(vk1), "ed25519")
        entry2 = register_principal_key(principal_keys._mgr, "p5", bytes(vk2), "ed25519")
        active = list_principal_keys(principal_keys._mgr, "p5", status="active")
        superseded = list_principal_keys(principal_keys._mgr, "p5", status="superseded")
        assert len(active) == 1
        assert active[0].key_id == entry2.key_id
        assert len(superseded) == 1
        assert superseded[0].key_id == entry1.key_id


class TestGetActiveKey:
    def test_returns_active_key(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        register_principal_key(principal_keys._mgr, "p6", bytes(vk), "ed25519")
        active = get_active_key(principal_keys._mgr, "p6")
        assert active.principal_id == "p6"
        assert active.status == "active"

    def test_raises_when_no_active_key(self, principal_keys):
        from regista._errors import ErrorCode
        with pytest.raises(RegistaError) as exc_info:
            get_active_key(principal_keys._mgr, "nonexistent")
        assert exc_info.value.code == ErrorCode.UNREGISTERED_SIGNER


class TestRotatePrincipalKey:
    def test_rotation_supersedes_old(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        entry1 = register_principal_key(principal_keys._mgr, "p7", bytes(vk1), "ed25519")
        _sk2, vk2 = _generate_ed25519_keypair()
        entry2 = rotate_principal_key(
            principal_keys._mgr, "p7", bytes(vk2), "ed25519",
        )
        assert entry2.status == "active"
        assert entry2.key_id != entry1.key_id

        all_keys = list_principal_keys(principal_keys._mgr, "p7")
        old = next(k for k in all_keys if k.key_id == entry1.key_id)
        assert old.status == "superseded"
        assert old.valid_to is not None

    def test_rotation_keeps_old_key_for_history(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        register_principal_key(principal_keys._mgr, "p8", bytes(vk1), "ed25519")
        _sk2, vk2 = _generate_ed25519_keypair()
        rotate_principal_key(principal_keys._mgr, "p8", bytes(vk2), "ed25519")
        all_keys = list_principal_keys(principal_keys._mgr, "p8")
        assert len(all_keys) == 2


class TestRevokePrincipalKey:
    def test_revoke_sets_status(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry = register_principal_key(principal_keys._mgr, "p9", bytes(vk), "ed25519")
        revoked = revoke_principal_key(
            principal_keys._mgr, "p9", entry.key_id, reason="compromised",
        )
        assert revoked.status == "revoked"
        assert revoked.revoked_reason == "compromised"
        assert revoked.revoked_at is not None

    def test_revoke_idempotent(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry = register_principal_key(principal_keys._mgr, "p10", bytes(vk), "ed25519")
        revoke_principal_key(principal_keys._mgr, "p10", entry.key_id)
        revoked2 = revoke_principal_key(principal_keys._mgr, "p10", entry.key_id)
        assert revoked2.status == "revoked"

    def test_revoke_nonexistent_raises(self, principal_keys):
        from regista._errors import ErrorCode
        with pytest.raises(RegistaError) as exc_info:
            revoke_principal_key(principal_keys._mgr, "nonexistent", "fake-key-id")
        assert exc_info.value.code == ErrorCode.PRINCIPAL_KEY_NOT_FOUND


class TestVerifyPrincipalBinding:
    def test_matching_principal_succeeds(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        register_principal_key(principal_keys._mgr, "p11", bytes(vk), "ed25519")
        entry = verify_principal_binding(principal_keys._mgr, "p11", "p11")
        assert entry.status == "active"

    def test_mismatch_raises(self, principal_keys):
        from regista._errors import ErrorCode
        _sk, vk = _generate_ed25519_keypair()
        register_principal_key(principal_keys._mgr, "p12", bytes(vk), "ed25519")
        with pytest.raises(RegistaError) as exc_info:
            verify_principal_binding(principal_keys._mgr, "p12", "impostor")
        assert exc_info.value.code == ErrorCode.ACTOR_SIGNER_MISMATCH


class TestFingerprint:
    def test_fingerprint_matches_sha256(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        pub = bytes(vk)
        entry = register_principal_key(principal_keys._mgr, "p13", pub, "ed25519")
        expected = f"ed25519:sha256:{hashlib.sha256(pub).hexdigest()}"
        assert entry.fingerprint == expected


class TestToDict:
    def test_to_dict_shape(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry = register_principal_key(principal_keys._mgr, "p14", bytes(vk), "ed25519")
        d = entry.to_dict()
        assert d["principal_id"] == "p14"
        assert d["scheme"] == "ed25519"
        assert d["status"] == "active"
        assert "public_key" in d
        assert "fingerprint" in d
        assert "valid_from" in d
        assert "registered_by" in d
        assert "registered_at" in d


class TestFacadeAPI:
    def test_register_via_facade(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        result = principal_keys.principals.register(
            "p15", bytes(vk), "ed25519",
        )
        assert result["principal_id"] == "p15"
        assert result["status"] == "active"

    def test_list_via_facade(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        principal_keys.principals.register("p16", bytes(vk), "ed25519")
        result = principal_keys.principals.list()
        assert any(r["principal_id"] == "p16" for r in result)

    def test_rotate_via_facade(self, principal_keys):
        _sk1, vk1 = _generate_ed25519_keypair()
        principal_keys.principals.register("p17", bytes(vk1), "ed25519")
        _sk2, vk2 = _generate_ed25519_keypair()
        result = principal_keys.principals.rotate("p17", bytes(vk2), "ed25519")
        assert result["status"] == "active"

    def test_revoke_via_facade(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        entry = principal_keys.principals.register("p18", bytes(vk), "ed25519")
        result = principal_keys.principals.revoke("p18", entry["key_id"])
        assert result["status"] == "revoked"

    def test_verify_binding_via_facade(self, principal_keys):
        _sk, vk = _generate_ed25519_keypair()
        principal_keys.principals.register("p19", bytes(vk), "ed25519")
        result = principal_keys.principals.verify_binding("p19", "p19")
        assert result["status"] == "active"
