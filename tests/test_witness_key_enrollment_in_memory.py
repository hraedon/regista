from __future__ import annotations

import os
import uuid

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._in_memory import InMemoryRegista
from regista._witness import witness_principal_id

KEY_PATH = os.path.join(os.path.dirname(__file__), "test_keys.json")


def _make_sub() -> InMemoryRegista:
    return InMemoryRegista(hmac_key_path=KEY_PATH)


def _ed25519_keypair():
    try:
        import nacl.signing

        sk = nacl.signing.SigningKey.generate()
        return bytes(sk.verify_key)
    except ImportError:
        return b"\x01" * 32


class TestInMemoryEnrollOnRegister:
    def test_ed25519_witness_enrolled(self):
        sub = _make_sub()
        pub = _ed25519_keypair()
        wid = sub.register_witness(
            "https://example.com/witness",
            public_key=pub,
            key_scheme="ed25519",
        )
        entry = sub.enrolled_witness_key(wid)
        assert entry is not None
        assert entry["principal_id"] == witness_principal_id(wid)
        assert entry["scheme"] == "ed25519"
        assert entry["status"] == "active"
        assert entry["public_key"] == pub

    def test_hmac_witness_not_enrolled(self):
        sub = _make_sub()
        wid = sub.register_witness(
            "https://example.com/witness",
            key_scheme="hmac-sha256",
        )
        assert sub.enrolled_witness_key(wid) is None

    def test_enrolled_via_facade(self):
        sub = _make_sub()
        pub = _ed25519_keypair()
        wid = sub.register_witness(
            "https://example.com/witness",
            public_key=pub,
            key_scheme="ed25519",
        )
        entry = sub.witnesses.enrolled_key(wid)
        assert entry["public_key"] == pub


class TestInMemoryRotate:
    def test_rotate_supersedes_and_activates(self):
        sub = _make_sub()
        pub1 = _ed25519_keypair()
        wid = sub.register_witness(
            "https://example.com/witness",
            public_key=pub1,
            key_scheme="ed25519",
        )
        old = sub.enrolled_witness_key(wid)
        pub2 = _ed25519_keypair()
        new = sub.rotate_witness_key(wid, pub2)
        assert new["status"] == "active"
        assert new["key_id"] != old["key_id"]
        active = sub.enrolled_witness_key(wid)
        assert active["public_key"] == pub2

    def test_rotate_hmac_rejected(self):
        sub = _make_sub()
        wid = sub.register_witness(
            "https://example.com/witness",
            key_scheme="hmac-sha256",
        )
        with pytest.raises(RegistaError) as exc_info:
            sub.rotate_witness_key(wid, b"\x02" * 32)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rotate_nonexistent_raises(self):
        sub = _make_sub()
        with pytest.raises(RegistaError) as exc_info:
            sub.rotate_witness_key(uuid.uuid4(), b"\x02" * 32)
        assert exc_info.value.code == ErrorCode.WITNESS_NOT_FOUND


class TestInMemoryRevokeOnUnregister:
    def test_unregister_revokes_enrolled_key(self):
        sub = _make_sub()
        pub = _ed25519_keypair()
        wid = sub.register_witness(
            "https://example.com/witness",
            public_key=pub,
            key_scheme="ed25519",
        )
        sub.unregister_witness(wid)
        assert sub.enrolled_witness_key(wid) is None
        revoked = sub._enrolled_witness_keys[wid]
        assert revoked["status"] == "revoked"
        assert revoked["revoked_reason"] == "witness unregistered"

    def test_unregister_hmac_no_op_on_enrollment(self):
        sub = _make_sub()
        wid = sub.register_witness(
            "https://example.com/witness",
            key_scheme="hmac-sha256",
        )
        sub.unregister_witness(wid)
        assert wid not in sub._enrolled_witness_keys
