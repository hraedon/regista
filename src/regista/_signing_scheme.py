from __future__ import annotations

import hashlib
import hmac as _hmac
from typing import Protocol, runtime_checkable


@runtime_checkable
class SigningScheme(Protocol):
    scheme_id: str

    def sign(self, envelope: bytes, key_material: bytes) -> tuple[bytes, bytes]:
        """Returns (signature, envelope_hash)."""
        ...

    def verify(
        self,
        envelope: bytes,
        signature: bytes,
        envelope_hash: bytes,
        key_material: bytes,
    ) -> bool: ...


_registry: dict[str, type] = {}


def register_scheme(cls: type) -> type:
    _registry[cls.scheme_id] = cls
    return cls


def get_scheme(scheme_id: str) -> SigningScheme:
    cls = _registry.get(scheme_id)
    if cls is None:
        from ._errors import ErrorCode, RegistaError

        raise RegistaError(
            ErrorCode.SIGNING_SCHEME_NOT_FOUND,
            f"Unknown signing scheme: {scheme_id!r}",
        )
    return cls()


def available_schemes() -> list[str]:
    return sorted(_registry.keys())


@register_scheme
class HMACSHA256Scheme:
    scheme_id: str = "hmac-sha256"

    def sign(self, envelope: bytes, key_material: bytes) -> tuple[bytes, bytes]:
        sig = _hmac.new(key_material, envelope, hashlib.sha256).digest()
        h = hashlib.sha256(envelope).digest()
        return (sig, h)

    def verify(
        self,
        envelope: bytes,
        signature: bytes,
        envelope_hash: bytes,
        key_material: bytes,
    ) -> bool:
        expected = _hmac.new(key_material, envelope, hashlib.sha256).digest()
        return _hmac.compare_digest(expected, signature) and _hmac.compare_digest(
            hashlib.sha256(envelope).digest(), envelope_hash
        )


@register_scheme
class Ed25519Scheme:
    scheme_id: str = "ed25519"

    def sign(self, envelope: bytes, key_material: bytes) -> tuple[bytes, bytes]:
        try:
            import nacl.signing
        except ImportError as e:
            from ._errors import ErrorCode, RegistaError

            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                "Scheme 'ed25519' requires PyNaCl: pip install regista[ed25519]",
            ) from e
        signing_key = nacl.signing.SigningKey(key_material)
        sig = signing_key.sign(envelope).signature
        h = hashlib.sha256(envelope).digest()
        return (sig, h)

    def verify(
        self,
        envelope: bytes,
        signature: bytes,
        envelope_hash: bytes,
        key_material: bytes,
    ) -> bool:
        try:
            import nacl.signing
        except ImportError as e:
            from ._errors import ErrorCode, RegistaError

            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                "Scheme 'ed25519' requires PyNaCl: pip install regista[ed25519]",
            ) from e
        verify_key = nacl.signing.VerifyKey(key_material)
        try:
            verify_key.verify(envelope, signature)
        except nacl.exceptions.BadSignatureError:
            return False
        except (ValueError, TypeError):
            return False
        except Exception:
            import structlog
            structlog.get_logger().error(
                "signing.ed25519_verify_unexpected_error",
                exc_info=True,
            )
            return False
        return _hmac.compare_digest(hashlib.sha256(envelope).digest(), envelope_hash)
