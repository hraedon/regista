from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol, assert_never, runtime_checkable

from ._errors import ErrorCode, RegistaError

KeyResolver = Callable[[str], bytes]

_DIGEST_ALG = "sha256"
_ENCRYPTED_MARKER = "encrypted"
_ALG_FIELD = "alg"
_KEY_ID_FIELD = "key_id"
_NONCE_FIELD = "nonce"
_CIPHERTEXT_FIELD = "ciphertext"
_DIGEST_FIELD = "digest"


@dataclass(frozen=True)
class EncryptedBlob:
    ciphertext: bytes
    nonce: bytes


@runtime_checkable
class EncryptionScheme(Protocol):
    scheme_id: str

    def encrypt(self, plaintext: bytes, key: bytes) -> EncryptedBlob: ...

    def decrypt(self, blob: EncryptedBlob, key: bytes) -> bytes: ...


_enc_registry: dict[str, type[EncryptionScheme]] = {}


def register_encryption_scheme(cls: type[EncryptionScheme]) -> type[EncryptionScheme]:
    existing = _enc_registry.get(cls.scheme_id)
    if existing is not None and existing is not cls:
        import structlog

        structlog.get_logger().warning(
            "encryption.scheme_overwritten",
            scheme_id=cls.scheme_id,
            old=existing.__name__,
            new=cls.__name__,
        )
    _enc_registry[cls.scheme_id] = cls
    return cls


def unregister_encryption_scheme(scheme_id: str) -> None:
    _enc_registry.pop(scheme_id, None)


def get_encryption_scheme(scheme_id: str) -> EncryptionScheme:
    cls = _enc_registry.get(scheme_id)
    if cls is None:
        raise RegistaError(
            ErrorCode.ENCRYPTION_SCHEME_NOT_FOUND,
            f"Unknown encryption scheme: {scheme_id!r}. "
            f"Available: {available_encryption_schemes()}",
        )
    return cls()


def available_encryption_schemes() -> list[str]:
    return sorted(_enc_registry.keys())


@register_encryption_scheme
class AES256GCMScheme:
    scheme_id: str = "aes-256-gcm"

    def encrypt(self, plaintext: bytes, key: bytes) -> EncryptedBlob:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as e:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                "Encryption scheme 'aes-256-gcm' requires the 'cryptography' "
                "package: pip install regista[encryption]",
            ) from e
        _validate_key_length(key)
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return EncryptedBlob(ciphertext=ciphertext, nonce=nonce)

    def decrypt(self, blob: EncryptedBlob, key: bytes) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as e:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                "Encryption scheme 'aes-256-gcm' requires the 'cryptography' "
                "package: pip install regista[encryption]",
            ) from e
        _validate_key_length(key)
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(blob.nonce, blob.ciphertext, None)
        except Exception as e:
            raise RegistaError(
                ErrorCode.DECRYPTION_FAILED,
                f"Decryption failed: {type(e).__name__}: {e}",
            ) from e


def _validate_key_length(key: bytes) -> None:
    if len(key) != 32:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"AES-256-GCM requires a 32-byte key, got {len(key)} bytes",
        )


def _serialize_value(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_digest(plaintext: bytes) -> str:
    return f"{_DIGEST_ALG}:{hashlib.sha256(plaintext).hexdigest()}"


def _encode_b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _decode_b64(s: str) -> bytes:
    return base64.b64decode(s)


def is_encrypted_field(value: object) -> bool:
    return (
        isinstance(value, dict)
        and value.get(_ENCRYPTED_MARKER) is True
        and _CIPHERTEXT_FIELD in value
        and _NONCE_FIELD in value
        and _ALG_FIELD in value
    )


def is_encrypted_payload(payload: dict[str, Any] | None) -> bool:
    if payload is None:
        return False
    return any(is_encrypted_field(v) for v in payload.values())


def encrypt_fields(
    payload: dict[str, Any],
    field_paths: list[str],
    key_ref: str,
    key_id: str,
    scheme_id: str = "aes-256-gcm",
) -> dict[str, Any]:
    from ._secrets import resolve as _resolve_secret

    key = _resolve_secret(key_ref)
    scheme = get_encryption_scheme(scheme_id)
    result = dict(payload)
    for path in field_paths:
        if path not in result:
            continue
        value = result[path]
        if is_encrypted_field(value):
            continue
        plaintext = _serialize_value(value)
        blob = scheme.encrypt(plaintext, key)
        digest = _compute_digest(plaintext)
        result[path] = {
            _ENCRYPTED_MARKER: True,
            _ALG_FIELD: scheme_id,
            _KEY_ID_FIELD: key_id,
            _NONCE_FIELD: _encode_b64(blob.nonce),
            _CIPHERTEXT_FIELD: _encode_b64(blob.ciphertext),
            _DIGEST_FIELD: digest,
        }
    return result


def decrypt_fields(
    payload: dict[str, Any],
    key_source: str | KeyResolver,
) -> dict[str, Any]:
    def _resolve_key(key_id: str) -> bytes:
        if isinstance(key_source, str):
            from ._secrets import resolve as _resolve_secret

            return _resolve_secret(key_source)
        return key_source(key_id)

    result = dict(payload)
    for k, v in result.items():
        if not is_encrypted_field(v):
            continue
        alg = v[_ALG_FIELD]
        scheme = get_encryption_scheme(alg)
        nonce = _decode_b64(v[_NONCE_FIELD])
        ciphertext = _decode_b64(v[_CIPHERTEXT_FIELD])
        blob = EncryptedBlob(ciphertext=ciphertext, nonce=nonce)
        field_key_id = v.get(_KEY_ID_FIELD, "")
        key = _resolve_key(field_key_id)
        plaintext = scheme.decrypt(blob, key)
        result[k] = json.loads(plaintext.decode("utf-8"))
    return result


VerificationStatus = Literal[
    "verified",
    "not_decrypted",
    "digest_mismatch",
    "decryption_error",
]


@dataclass(frozen=True)
class FieldVerificationResult:
    field: str
    status: VerificationStatus
    detail: str
    key_id: str | None = None
    alg: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "field": self.field,
            "status": self.status,
            "detail": self.detail,
            "key_id": self.key_id,
            "alg": self.alg,
        }


def status_label(status: VerificationStatus) -> str:
    if status == "verified":
        return "OK"
    elif status == "not_decrypted":
        return "WARN: content not decrypted (no key)"
    elif status == "digest_mismatch":
        return "FAIL: content digest mismatch"
    elif status == "decryption_error":
        return "ERROR: decryption failed"
    else:
        assert_never(status)


def verify_encrypted_integrity(
    payload: dict[str, Any],
    key_source: str | KeyResolver | None = None,
) -> list[FieldVerificationResult]:
    results: list[FieldVerificationResult] = []
    for k, v in payload.items():
        if not is_encrypted_field(v):
            continue
        alg = v[_ALG_FIELD]
        field_key_id = v.get(_KEY_ID_FIELD)
        if key_source is None:
            results.append(FieldVerificationResult(
                field=k,
                status="not_decrypted",
                detail="no content key provided; integrity claim is "
                       "authenticated by signature but plaintext is not verifiable",
                key_id=field_key_id,
                alg=alg,
            ))
            continue
        try:
            decrypted = decrypt_fields({k: v}, key_source)
            plaintext = _serialize_value(decrypted[k])
            stored_digest = v.get(_DIGEST_FIELD, "")
            computed_digest = _compute_digest(plaintext)
            if stored_digest == computed_digest:
                results.append(FieldVerificationResult(
                    field=k,
                    status="verified",
                    detail="decrypted; digest matches",
                    key_id=field_key_id,
                    alg=alg,
                ))
            else:
                results.append(FieldVerificationResult(
                    field=k,
                    status="digest_mismatch",
                    detail=f"expected {stored_digest}, got {computed_digest}",
                    key_id=field_key_id,
                    alg=alg,
                ))
        except RegistaError as e:
            results.append(FieldVerificationResult(
                field=k,
                status="decryption_error",
                detail=str(e),
                key_id=field_key_id,
                alg=alg,
            ))
    return results


def strip_encrypted_fields(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if payload is None:
        return None
    result = dict(payload)
    for k, v in list(result.items()):
        if is_encrypted_field(v):
            result[k] = {
                _ENCRYPTED_MARKER: True,
                _ALG_FIELD: v.get(_ALG_FIELD, "unknown"),
                _KEY_ID_FIELD: v.get(_KEY_ID_FIELD, ""),
                _DIGEST_FIELD: v.get(_DIGEST_FIELD, ""),
            }
    return result
