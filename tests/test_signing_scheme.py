from __future__ import annotations

import pytest

from substrate._errors import ErrorCode, SubstrateError
from substrate._signing_scheme import (
    Ed25519Scheme,
    HMACSHA256Scheme,
    available_schemes,
    get_scheme,
    register_scheme,
)


class TestHMACSHA256Scheme:
    def test_round_trip(self):
        scheme = HMACSHA256Scheme()
        envelope = b"test envelope"
        key = b"secret key"
        sig, h = scheme.sign(envelope, key)
        assert scheme.verify(envelope, sig, h, key) is True

    def test_tamper_signature(self):
        scheme = HMACSHA256Scheme()
        envelope = b"test envelope"
        key = b"secret key"
        sig, h = scheme.sign(envelope, key)
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0xFF
        assert scheme.verify(envelope, bytes(bad_sig), h, key) is False

    def test_tamper_envelope(self):
        scheme = HMACSHA256Scheme()
        envelope = b"test envelope"
        key = b"secret key"
        sig, h = scheme.sign(envelope, key)
        assert scheme.verify(b"bad envelope", sig, h, key) is False


class TestEd25519Scheme:
    def test_round_trip(self):
        pytest.importorskip("nacl.signing")
        import nacl.signing

        scheme = Ed25519Scheme()
        signing_key = nacl.signing.SigningKey.generate()
        envelope = b"test envelope"
        sig, h = scheme.sign(envelope, signing_key.encode())
        assert scheme.verify(envelope, sig, h, bytes(signing_key.verify_key)) is True

    def test_tamper_signature(self):
        pytest.importorskip("nacl.signing")
        import nacl.signing

        scheme = Ed25519Scheme()
        signing_key = nacl.signing.SigningKey.generate()
        envelope = b"test envelope"
        sig, h = scheme.sign(envelope, signing_key.encode())
        bad_sig = bytearray(sig)
        bad_sig[0] ^= 0xFF
        assert scheme.verify(envelope, bytes(bad_sig), h, bytes(signing_key.verify_key)) is False

    def test_tamper_envelope(self):
        pytest.importorskip("nacl.signing")
        import nacl.signing

        scheme = Ed25519Scheme()
        signing_key = nacl.signing.SigningKey.generate()
        envelope = b"test envelope"
        sig, h = scheme.sign(envelope, signing_key.encode())
        assert scheme.verify(b"bad envelope", sig, h, bytes(signing_key.verify_key)) is False


class TestRegistry:
    def test_available_schemes(self):
        schemes = available_schemes()
        assert "hmac-sha256" in schemes
        assert "ed25519" in schemes

    def test_get_scheme_known(self):
        assert get_scheme("hmac-sha256") is not None

    def test_get_scheme_unknown_raises(self):
        with pytest.raises(SubstrateError) as exc_info:
            get_scheme("unknown-scheme")
        assert exc_info.value.code == ErrorCode.SIGNING_SCHEME_NOT_FOUND

    def test_register_scheme(self):
        class MyScheme:
            scheme_id = "my-scheme"

            def sign(self, envelope, key):
                return (b"sig", b"hash")

            def verify(self, envelope, signature, envelope_hash, key_material):
                return True

        register_scheme(MyScheme)
        assert "my-scheme" in available_schemes()
        inst = get_scheme("my-scheme")
        assert inst.sign(b"", b"") == (b"sig", b"hash")
