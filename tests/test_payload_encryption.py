from __future__ import annotations

import base64
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from regista._encryption import (
    AES256GCMScheme,
    EncryptedBlob,
    FieldVerificationResult,
    available_encryption_schemes,
    decrypt_fields,
    encrypt_fields,
    get_encryption_scheme,
    is_encrypted_field,
    is_encrypted_payload,
    register_encryption_scheme,
    status_label,
    strip_encrypted_fields,
    unregister_encryption_scheme,
    verify_encrypted_integrity,
)
from regista._errors import ErrorCode, RegistaError
from regista._signing import sign_event, verify_event


def _make_key_ref(tmp_path: Path) -> str:
    key = os.urandom(32)
    key_file = tmp_path / "enc_key.bin"
    key_file.write_bytes(key)
    return f"file:{key_file}"


class TestEncryptionSchemeRegistry:
    def test_aes256gcm_registered(self) -> None:
        assert "aes-256-gcm" in available_encryption_schemes()

    def test_get_scheme_returns_instance(self) -> None:
        scheme = get_encryption_scheme("aes-256-gcm")
        assert scheme.scheme_id == "aes-256-gcm"

    def test_unknown_scheme_raises(self) -> None:
        with pytest.raises(RegistaError) as exc_info:
            get_encryption_scheme("nonexistent-scheme")
        assert exc_info.value.code == ErrorCode.ENCRYPTION_SCHEME_NOT_FOUND

    def test_register_and_unregister_custom_scheme(self) -> None:
        class DummyScheme:
            scheme_id: str = "dummy-enc"

            def encrypt(self, plaintext: bytes, key: bytes) -> EncryptedBlob:
                return EncryptedBlob(ciphertext=plaintext, nonce=b"\x00" * 12)

            def decrypt(self, blob: EncryptedBlob, key: bytes) -> bytes:
                return blob.ciphertext

        register_encryption_scheme(DummyScheme)
        assert "dummy-enc" in available_encryption_schemes()
        scheme = get_encryption_scheme("dummy-enc")
        assert scheme.scheme_id == "dummy-enc"
        unregister_encryption_scheme("dummy-enc")
        assert "dummy-enc" not in available_encryption_schemes()

    def test_overwrite_warns(self) -> None:
        class DummyV1:
            scheme_id: str = "test-overwrite"

            def encrypt(self, plaintext: bytes, key: bytes) -> EncryptedBlob:
                return EncryptedBlob(ciphertext=b"", nonce=b"")

            def decrypt(self, blob: EncryptedBlob, key: bytes) -> bytes:
                return b""

        class DummyV2:
            scheme_id: str = "test-overwrite"

            def encrypt(self, plaintext: bytes, key: bytes) -> EncryptedBlob:
                return EncryptedBlob(ciphertext=b"", nonce=b"")

            def decrypt(self, blob: EncryptedBlob, key: bytes) -> bytes:
                return b""

        register_encryption_scheme(DummyV1)
        register_encryption_scheme(DummyV2)
        assert get_encryption_scheme("test-overwrite").__class__.__name__ == "DummyV2"
        unregister_encryption_scheme("test-overwrite")


class TestAES256GCMScheme:
    def test_encrypt_decrypt_roundtrip(self) -> None:
        scheme = AES256GCMScheme()
        key = os.urandom(32)
        plaintext = b"secret content for encryption"
        blob = scheme.encrypt(plaintext, key)
        decrypted = scheme.decrypt(blob, key)
        assert decrypted == plaintext

    def test_encrypt_produces_different_nonces(self) -> None:
        scheme = AES256GCMScheme()
        key = os.urandom(32)
        plaintext = b"same plaintext"
        blob1 = scheme.encrypt(plaintext, key)
        blob2 = scheme.encrypt(plaintext, key)
        assert blob1.nonce != blob2.nonce
        assert blob1.ciphertext != blob2.ciphertext

    def test_decrypt_with_wrong_key_fails(self) -> None:
        scheme = AES256GCMScheme()
        key = os.urandom(32)
        wrong_key = os.urandom(32)
        plaintext = b"secret content"
        blob = scheme.encrypt(plaintext, key)
        with pytest.raises(RegistaError) as exc_info:
            scheme.decrypt(blob, wrong_key)
        assert exc_info.value.code == ErrorCode.DECRYPTION_FAILED

    def test_decrypt_tampered_ciphertext_fails(self) -> None:
        scheme = AES256GCMScheme()
        key = os.urandom(32)
        plaintext = b"secret content"
        blob = scheme.encrypt(plaintext, key)
        tampered = EncryptedBlob(
            ciphertext=b"\x00" + blob.ciphertext[1:],
            nonce=blob.nonce,
        )
        with pytest.raises(RegistaError) as exc_info:
            scheme.decrypt(tampered, key)
        assert exc_info.value.code == ErrorCode.DECRYPTION_FAILED

    def test_decrypt_tampered_nonce_fails(self) -> None:
        scheme = AES256GCMScheme()
        key = os.urandom(32)
        plaintext = b"secret content"
        blob = scheme.encrypt(plaintext, key)
        tampered = EncryptedBlob(
            ciphertext=blob.ciphertext,
            nonce=b"\x00" * 12,
        )
        with pytest.raises(RegistaError) as exc_info:
            scheme.decrypt(tampered, key)
        assert exc_info.value.code == ErrorCode.DECRYPTION_FAILED

    def test_wrong_key_length_raises(self) -> None:
        scheme = AES256GCMScheme()
        with pytest.raises(RegistaError) as exc_info:
            scheme.encrypt(b"data", os.urandom(16))
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_nonce_is_12_bytes(self) -> None:
        scheme = AES256GCMScheme()
        key = os.urandom(32)
        blob = scheme.encrypt(b"data", key)
        assert len(blob.nonce) == 12


class TestEncryptFields:
    def test_encrypt_single_field(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "sensitive data", "meta": "public"}
        result = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        assert result["meta"] == "public"
        assert is_encrypted_field(result["content"])
        assert result["content"]["alg"] == "aes-256-gcm"
        assert result["content"]["key_id"] == "enc-001"
        assert "nonce" in result["content"]
        assert "ciphertext" in result["content"]
        assert "digest" in result["content"]

    def test_encrypt_multiple_fields(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {
            "content": "secret1",
            "transcript": "secret2",
            "meta": "public",
        }
        result = encrypt_fields(payload, ["content", "transcript"], key_ref, "enc-001")
        assert is_encrypted_field(result["content"])
        assert is_encrypted_field(result["transcript"])
        assert result["meta"] == "public"

    def test_encrypt_dict_value(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": {"text": "secret", "line": 42}}
        result = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        assert is_encrypted_field(result["content"])

    def test_encrypt_list_value(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"messages": ["msg1", "msg2"]}
        result = encrypt_fields(payload, ["messages"], key_ref, "enc-001")
        assert is_encrypted_field(result["messages"])

    def test_encrypt_nonexistent_field_skips(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "data"}
        result = encrypt_fields(payload, ["nonexistent"], key_ref, "enc-001")
        assert result == payload

    def test_encrypt_already_encrypted_field_skips(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "data"}
        first = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        second = encrypt_fields(first, ["content"], key_ref, "enc-001")
        assert second["content"] == first["content"]

    def test_encrypt_does_not_mutate_original(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "sensitive", "meta": "public"}
        original = dict(payload)
        encrypt_fields(payload, ["content"], key_ref, "enc-001")
        assert payload == original

    def test_encrypt_with_custom_scheme_id(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "data"}
        result = encrypt_fields(
            payload, ["content"], key_ref, "enc-001", scheme_id="aes-256-gcm"
        )
        assert result["content"]["alg"] == "aes-256-gcm"

    def test_digest_is_sha256_of_plaintext(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "hello world"}
        result = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        import json as _json

        plaintext_bytes = _json.dumps(
            "hello world", sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        expected_digest = f"sha256:{hashlib.sha256(plaintext_bytes).hexdigest()}"
        assert result["content"]["digest"] == expected_digest

    def test_digest_stored_outside_ciphertext(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "secret"}
        result = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        ciphertext = base64.b64decode(result["content"]["ciphertext"])
        digest_str = result["content"]["digest"]
        assert digest_str.encode("ascii") not in ciphertext


class TestDecryptFields:
    def test_decrypt_roundtrip(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {
            "content": "sensitive data",
            "meta": "public",
            "nested": {"key": "value"},
        }
        encrypted = encrypt_fields(payload, ["content", "nested"], key_ref, "enc-001")
        decrypted = decrypt_fields(encrypted, key_ref)
        assert decrypted["content"] == "sensitive data"
        assert decrypted["nested"] == {"key": "value"}
        assert decrypted["meta"] == "public"

    def test_decrypt_with_wrong_key_fails(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        wrong_key_file = tmp_path / "wrong_key.bin"
        wrong_key_file.write_bytes(os.urandom(32))
        wrong_ref = f"file:{wrong_key_file}"

        payload = {"content": "secret"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        with pytest.raises(RegistaError) as exc_info:
            decrypt_fields(encrypted, wrong_ref)
        assert exc_info.value.code == ErrorCode.DECRYPTION_FAILED

    def test_decrypt_unencrypted_field_passes_through(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "plaintext", "meta": "public"}
        result = decrypt_fields(payload, key_ref)
        assert result == payload

    def test_decrypt_none_payload(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        assert decrypt_fields({}, key_ref) == {}

    def test_decrypt_with_key_resolver(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        key_bytes = Path(key_ref.removeprefix("file:")).read_bytes()

        def resolver(key_id: str) -> bytes:
            assert key_id == "enc-001"
            return key_bytes

        payload = {"content": "secret"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        decrypted = decrypt_fields(encrypted, resolver)
        assert decrypted["content"] == "secret"

    def test_decrypt_preserves_unencrypted_fields(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {
            "encrypted_field": "secret",
            "plain_field": "public",
            "another_plain": 42,
        }
        encrypted = encrypt_fields(payload, ["encrypted_field"], key_ref, "enc-001")
        decrypted = decrypt_fields(encrypted, key_ref)
        assert decrypted["encrypted_field"] == "secret"
        assert decrypted["plain_field"] == "public"
        assert decrypted["another_plain"] == 42

    def test_decrypt_does_not_mutate_original(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "secret"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        original = dict(encrypted)
        decrypt_fields(encrypted, key_ref)
        assert encrypted == original


class TestIsEncrypted:
    def test_is_encrypted_field_true(self) -> None:
        field = {
            "encrypted": True,
            "alg": "aes-256-gcm",
            "key_id": "enc-001",
            "nonce": "abc",
            "ciphertext": "def",
            "digest": "sha256:xyz",
        }
        assert is_encrypted_field(field)

    def test_is_encrypted_field_false_for_plain(self) -> None:
        assert not is_encrypted_field("just a string")
        assert not is_encrypted_field({"key": "value"})
        assert not is_encrypted_field(42)

    def test_is_encrypted_field_false_for_missing_fields(self) -> None:
        assert not is_encrypted_field({"encrypted": True})
        assert not is_encrypted_field({"encrypted": True, "alg": "aes-256-gcm"})

    def test_is_encrypted_field_false_for_encrypted_false(self) -> None:
        field = {"encrypted": False, "ciphertext": "abc", "nonce": "def", "alg": "x"}
        assert not is_encrypted_field(field)

    def test_is_encrypted_payload_true(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "secret", "meta": "public"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        assert is_encrypted_payload(encrypted)

    def test_is_encrypted_payload_false(self) -> None:
        assert not is_encrypted_payload({"content": "plain"})
        assert not is_encrypted_payload(None)
        assert not is_encrypted_payload({})


class TestVerifyEncryptedIntegrity:
    def test_verify_with_key_succeeds(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "secret data", "meta": "public"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        results = verify_encrypted_integrity(encrypted, key_ref)
        assert len(results) == 1
        assert results[0].field == "content"
        assert results[0].status == "verified"
        assert results[0].key_id == "enc-001"
        assert results[0].alg == "aes-256-gcm"

    def test_verify_without_key_reports_not_decrypted(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "secret data"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        results = verify_encrypted_integrity(encrypted, key_source=None)
        assert len(results) == 1
        assert results[0].status == "not_decrypted"
        assert "no content key" in results[0].detail.lower()

    def test_verify_with_wrong_key_reports_decryption_error(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        wrong_key_file = tmp_path / "wrong.bin"
        wrong_key_file.write_bytes(os.urandom(32))
        wrong_ref = f"file:{wrong_key_file}"

        payload = {"content": "secret"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        results = verify_encrypted_integrity(encrypted, wrong_ref)
        assert len(results) == 1
        assert results[0].status == "decryption_error"

    def test_verify_digest_mismatch(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "secret"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        encrypted["content"]["digest"] = (
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        )
        results = verify_encrypted_integrity(encrypted, key_ref)
        assert len(results) == 1
        assert results[0].status == "digest_mismatch"

    def test_verify_mixed_encrypted_and_plain(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "secret", "meta": "public"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        results = verify_encrypted_integrity(encrypted, key_ref)
        assert len(results) == 1
        assert results[0].field == "content"

    def test_verify_no_encrypted_fields_returns_empty(self) -> None:
        payload = {"content": "plain", "meta": "public"}
        results = verify_encrypted_integrity(payload, key_source=None)
        assert results == []

    def test_verify_with_key_resolver(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        key_bytes = Path(key_ref.removeprefix("file:")).read_bytes()

        def resolver(key_id: str) -> bytes:
            return key_bytes

        payload = {"content": "secret"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        results = verify_encrypted_integrity(encrypted, resolver)
        assert results[0].status == "verified"

    def test_field_verification_result_to_dict(self) -> None:
        r = FieldVerificationResult(
            field="content",
            status="verified",
            detail="ok",
            key_id="enc-001",
            alg="aes-256-gcm",
        )
        d = r.to_dict()
        assert d["field"] == "content"
        assert d["status"] == "verified"
        assert d["key_id"] == "enc-001"
        assert d["alg"] == "aes-256-gcm"


class TestStatusLabel:
    def test_verified(self) -> None:
        assert "OK" in status_label("verified")

    def test_not_decrypted(self) -> None:
        assert "WARN" in status_label("not_decrypted")

    def test_digest_mismatch(self) -> None:
        assert "FAIL" in status_label("digest_mismatch")

    def test_decryption_error(self) -> None:
        assert "ERROR" in status_label("decryption_error")

    def test_unknown_raises_assert_never(self) -> None:
        with pytest.raises(AssertionError):
            status_label("unknown")  # type: ignore[arg-type]


class TestStripEncryptedFields:
    def test_strip_removes_ciphertext_and_nonce(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "secret", "meta": "public"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        stripped = strip_encrypted_fields(encrypted)
        assert "ciphertext" not in stripped["content"]
        assert "nonce" not in stripped["content"]
        assert stripped["content"]["encrypted"] is True
        assert stripped["content"]["alg"] == "aes-256-gcm"
        assert stripped["content"]["key_id"] == "enc-001"
        assert "digest" in stripped["content"]
        assert stripped["meta"] == "public"

    def test_strip_none_returns_none(self) -> None:
        assert strip_encrypted_fields(None) is None

    def test_strip_unencrypted_unchanged(self) -> None:
        payload = {"content": "plain", "meta": "public"}
        result = strip_encrypted_fields(payload)
        assert result == payload


class TestBackwardCompatibility:
    def test_unencrypted_payload_reads_as_is(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "plaintext", "meta": "public"}
        assert not is_encrypted_payload(payload)
        decrypted = decrypt_fields(payload, key_ref)
        assert decrypted == payload

    def test_old_event_still_verifies(self, tmp_path: Path) -> None:
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        payload = {"content": "plaintext content", "meta": "public"}
        key = b"test-hmac-key-for-signing!!"
        ts = datetime.now(UTC)
        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id="key-001",
            event_seq=1,
            workflow_name="test-wf",
            workflow_version=1,
            timestamp=ts,
            transition="created",
            payload=payload,
            key=key,
        )
        assert verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id="key-001",
            event_seq=1,
            workflow_name="test-wf",
            workflow_version=1,
            timestamp=ts,
            transition="created",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key,
            stored_envelope=envelope,
        )

    def test_encrypted_event_verifies_with_ciphertext_payload(
        self, tmp_path: Path
    ) -> None:
        key_ref = _make_key_ref(tmp_path)
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        plaintext_payload = {"content": "secret transcript", "meta": "public"}
        encrypted_payload = encrypt_fields(
            plaintext_payload, ["content"], key_ref, "enc-001"
        )
        key = b"test-hmac-key-for-signing!!"
        ts = datetime.now(UTC)
        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id="key-001",
            event_seq=1,
            workflow_name="test-wf",
            workflow_version=1,
            timestamp=ts,
            transition="created",
            payload=encrypted_payload,
            key=key,
        )
        assert verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id="key-001",
            event_seq=1,
            workflow_name="test-wf",
            workflow_version=1,
            timestamp=ts,
            transition="created",
            payload=encrypted_payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key,
            stored_envelope=envelope,
        )

    def test_encrypted_event_fails_verification_if_payload_tampered(
        self, tmp_path: Path
    ) -> None:
        key_ref = _make_key_ref(tmp_path)
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        plaintext_payload = {"content": "secret transcript"}
        encrypted_payload = encrypt_fields(
            plaintext_payload, ["content"], key_ref, "enc-001"
        )
        key = b"test-hmac-key-for-signing!!"
        ts = datetime.now(UTC)
        signature, canonical_hash, _envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id="key-001",
            event_seq=1,
            workflow_name="test-wf",
            workflow_version=1,
            timestamp=ts,
            transition="created",
            payload=encrypted_payload,
            key=key,
        )
        tampered_payload = dict(encrypted_payload)
        tampered_payload["content"] = dict(encrypted_payload["content"])
        tampered_payload["content"]["ciphertext"] = base64.b64encode(
            b"tampered"
        ).decode("ascii")
        assert not verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id="key-001",
            event_seq=1,
            workflow_name="test-wf",
            workflow_version=1,
            timestamp=ts,
            transition="created",
            payload=tampered_payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key,
        )


class TestKeyCustodyViaSecretBackend:
    def test_encrypt_with_env_ref(self, monkeypatch: pytest.MonkeyPatch) -> None:
        key = b"0123456789abcdef0123456789abcdef"
        monkeypatch.setenv("TEST_ENC_KEY", key.decode("ascii"))
        ref = "env:TEST_ENC_KEY"
        payload = {"content": "secret"}
        encrypted = encrypt_fields(payload, ["content"], ref, "enc-001")
        assert is_encrypted_field(encrypted["content"])

    def test_encrypt_with_literal_ref(self) -> None:
        key = b"0123456789abcdef0123456789abcdef"
        ref = f"literal:{key.decode('ascii')}"
        payload = {"content": "secret"}
        encrypted = encrypt_fields(payload, ["content"], ref, "enc-001")
        assert is_encrypted_field(encrypted["content"])

    def test_encrypt_with_file_ref(self, tmp_path: Path) -> None:
        key = os.urandom(32)
        key_file = tmp_path / "enc_key.bin"
        key_file.write_bytes(key)
        ref = f"file:{key_file}"
        payload = {"content": "secret"}
        encrypted = encrypt_fields(payload, ["content"], ref, "enc-001")
        decrypted = decrypt_fields(encrypted, ref)
        assert decrypted["content"] == "secret"

    def test_decrypt_with_key_resolver_multi_key(self, tmp_path: Path) -> None:
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        kf1 = tmp_path / "k1.bin"
        kf2 = tmp_path / "k2.bin"
        kf1.write_bytes(key1)
        kf2.write_bytes(key2)
        ref1 = f"file:{kf1}"
        ref2 = f"file:{kf2}"

        payload = {"field_a": "secret1", "field_b": "secret2"}
        enc_a = encrypt_fields(payload, ["field_a"], ref1, "key-a")
        enc_both = encrypt_fields(enc_a, ["field_b"], ref2, "key-b")

        key_map = {"key-a": ref1, "key-b": ref2}

        from regista._secrets import resolve as resolve_secret

        def resolver(key_id: str) -> bytes:
            return resolve_secret(key_map[key_id])

        decrypted = decrypt_fields(enc_both, resolver)
        assert decrypted["field_a"] == "secret1"
        assert decrypted["field_b"] == "secret2"


class TestEncryptedFieldStructure:
    def test_structure_has_all_required_fields(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "secret"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        field = encrypted["content"]
        assert field["encrypted"] is True
        assert field["alg"] == "aes-256-gcm"
        assert field["key_id"] == "enc-001"
        assert isinstance(field["nonce"], str)
        assert isinstance(field["ciphertext"], str)
        assert field["digest"].startswith("sha256:")

    def test_base64_decodable(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "secret"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        nonce = base64.b64decode(encrypted["content"]["nonce"])
        ciphertext = base64.b64decode(encrypted["content"]["ciphertext"])
        assert len(nonce) == 12
        assert len(ciphertext) > 0

    def test_digest_outside_encrypted_subtree(self, tmp_path: Path) -> None:
        key_ref = _make_key_ref(tmp_path)
        payload = {"content": "the quick brown fox"}
        encrypted = encrypt_fields(payload, ["content"], key_ref, "enc-001")
        ciphertext = base64.b64decode(encrypted["content"]["ciphertext"])
        plaintext_json = json.dumps(
            "the quick brown fox", sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        assert plaintext_json not in ciphertext
        assert b"the quick brown fox" not in ciphertext


class TestVersionInfoIntegration:
    def test_versions_includes_encryption_schemes(self) -> None:
        from regista._version_info import versions

        info = versions()
        assert "aes-256-gcm" in info.available_encryption_schemes
        d = info.to_dict()
        assert "available_encryption_schemes" in d
        assert "aes-256-gcm" in d["available_encryption_schemes"]
