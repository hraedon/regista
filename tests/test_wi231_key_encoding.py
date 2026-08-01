"""WI-231 — the encoding contract for encryption key material.

A 256-bit key stored in a text backend (Vault KV field, env var, literal)
necessarily arrives encoded. Before this contract, nothing decoded it: the
only working keys were strings whose UTF-8 bytes happened to number 32, and
the estate's correctly-provisioned 43-char base64url key was rejected at
first use with "requires a 32-byte key, got 43 bytes".

The contract under test (``decode_key_material``):

1. Exactly 32 bytes are the key itself — raw always wins.
2. Anything else must be ASCII text (whitespace-tolerant) decoding to exactly
   32 bytes as base64, base64url, or hex.
3. Everything else fails at LOAD time with KEY_LOAD_ERROR naming the
   accepted encodings.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from regista._encryption import (
    decode_key_material,
    decrypt_fields,
    encrypt_fields,
    verify_encrypted_integrity,
)
from regista._errors import ErrorCode, RegistaError

KEY = os.urandom(32)


class TestDecodeKeyMaterial:
    def test_raw_32_bytes_pass_through(self) -> None:
        assert decode_key_material(KEY) == KEY

    def test_base64url_unpadded_decodes(self) -> None:
        # The estate's actual shape: 43 chars of base64url, no padding.
        encoded = base64.urlsafe_b64encode(KEY).rstrip(b"=")
        assert len(encoded) == 43
        assert decode_key_material(encoded) == KEY

    def test_base64_standard_padded_decodes(self) -> None:
        encoded = base64.b64encode(KEY)
        assert len(encoded) == 44
        assert decode_key_material(encoded) == KEY

    def test_base64url_alphabet_is_distinguished(self) -> None:
        # Force '-' and '_' into the encoding so standard base64 rejects it.
        key = bytes([0xFB, 0xEF] * 16)
        encoded = base64.urlsafe_b64encode(key).rstrip(b"=")
        assert b"-" in encoded or b"_" in encoded
        assert decode_key_material(encoded) == key

    def test_trailing_newline_is_tolerated(self) -> None:
        # `openssl rand -base64 32 > keyfile` writes a trailing newline.
        encoded = base64.b64encode(KEY) + b"\n"
        assert decode_key_material(encoded) == KEY

    def test_hex_decodes(self) -> None:
        # `openssl rand -hex 32` is the other common provisioning idiom.
        assert decode_key_material(KEY.hex().encode("ascii")) == KEY

    def test_hex_with_newline_decodes(self) -> None:
        assert decode_key_material(KEY.hex().encode("ascii") + b"\n") == KEY

    def test_hex_is_never_misread_as_base64(self) -> None:
        # 64 hex chars are also valid base64 chars, but decode to 48 bytes —
        # the contract's non-collision property.
        assert decode_key_material(KEY.hex().encode("ascii")) == KEY

    def test_32_char_text_is_used_raw(self) -> None:
        # Backwards compatible: a 32-char passphrase's UTF-8 bytes ARE 32
        # bytes, so rule 1 applies. Documented, not silent.
        text = b"0123456789abcdef0123456789abcdef"
        assert decode_key_material(text) == text

    def test_wrong_size_base64_fails_at_load(self) -> None:
        encoded = base64.b64encode(os.urandom(16))
        with pytest.raises(RegistaError) as exc_info:
            decode_key_material(encoded, source="vault:kv/x/y/key")
        assert exc_info.value.code == ErrorCode.KEY_LOAD_ERROR
        assert "base64" in str(exc_info.value)
        assert "vault:kv/x/y/key" in str(exc_info.value)

    def test_undecodable_text_names_the_contract(self) -> None:
        with pytest.raises(RegistaError) as exc_info:
            decode_key_material(b"not!a@valid#key$material%here&now*")
        assert exc_info.value.code == ErrorCode.KEY_LOAD_ERROR
        msg = str(exc_info.value)
        assert "32 raw bytes" in msg
        assert "base64" in msg
        assert "hex" in msg

    def test_non_ascii_wrong_length_fails_at_load(self) -> None:
        with pytest.raises(RegistaError) as exc_info:
            decode_key_material(os.urandom(43))
        assert exc_info.value.code == ErrorCode.KEY_LOAD_ERROR
        assert "43 bytes" in str(exc_info.value)

    def test_empty_material_fails(self) -> None:
        with pytest.raises(RegistaError) as exc_info:
            decode_key_material(b"")
        assert exc_info.value.code == ErrorCode.KEY_LOAD_ERROR


class TestEncodedKeyEndToEnd:
    """The production paths honour the contract, not just the decoder."""

    @pytest.fixture
    def payload(self) -> dict[str, object]:
        return {"message_content": "the plaintext", "other": 1}

    def _roundtrip(self, key_ref: str, payload: dict[str, object]) -> None:
        encrypted = encrypt_fields(
            dict(payload), field_paths=["message_content"],
            key_ref=key_ref, key_id="k1",
        )
        assert encrypted["message_content"]["encrypted"] is True
        decrypted = decrypt_fields(encrypted, key_source=key_ref)
        assert decrypted == payload
        results = verify_encrypted_integrity(encrypted, key_source=key_ref)
        assert [r.status for r in results] == ["verified"]

    def test_base64url_file_ref_roundtrips(
        self, tmp_path: Path, payload: dict[str, object]
    ) -> None:
        key_file = tmp_path / "content.key"
        key_file.write_bytes(base64.urlsafe_b64encode(KEY).rstrip(b"=") + b"\n")
        self._roundtrip(f"file:{key_file}", payload)

    def test_raw_file_ref_still_roundtrips(
        self, tmp_path: Path, payload: dict[str, object]
    ) -> None:
        key_file = tmp_path / "content.key"
        key_file.write_bytes(KEY)
        self._roundtrip(f"file:{key_file}", payload)

    def test_hex_env_ref_roundtrips(
        self, monkeypatch: pytest.MonkeyPatch, payload: dict[str, object]
    ) -> None:
        monkeypatch.setenv("WI231_CONTENT_KEY", KEY.hex())
        self._roundtrip("env:WI231_CONTENT_KEY", payload)

    def test_encrypt_with_bad_key_fails_at_load_naming_ref(
        self, tmp_path: Path, payload: dict[str, object]
    ) -> None:
        key_file = tmp_path / "content.key"
        key_file.write_bytes(base64.b64encode(os.urandom(16)))
        with pytest.raises(RegistaError) as exc_info:
            encrypt_fields(
                payload, field_paths=["message_content"],
                key_ref=f"file:{key_file}", key_id="k1",
            )
        assert exc_info.value.code == ErrorCode.KEY_LOAD_ERROR
        assert str(key_file) in str(exc_info.value)

    def test_callable_resolver_output_is_decoded(
        self, payload: dict[str, object]
    ) -> None:
        encoded = base64.urlsafe_b64encode(KEY).rstrip(b"=")
        key_file_free_resolver = lambda key_id: encoded  # noqa: E731
        encrypted = encrypt_fields(
            dict(payload), field_paths=["message_content"],
            key_ref=f"literal:{encoded.decode('ascii')}", key_id="k1",
        )
        decrypted = decrypt_fields(encrypted, key_source=key_file_free_resolver)
        assert decrypted == payload

    def test_callable_resolver_bad_material_names_key_id(self) -> None:
        encrypted = encrypt_fields(
            {"message_content": "x"}, field_paths=["message_content"],
            key_ref=f"literal:{base64.b64encode(KEY).decode('ascii')}",
            key_id="cairn-content-001",
        )
        with pytest.raises(RegistaError) as exc_info:
            decrypt_fields(encrypted, key_source=lambda kid: b"short")
        assert exc_info.value.code == ErrorCode.KEY_LOAD_ERROR
        assert "cairn-content-001" in str(exc_info.value)
