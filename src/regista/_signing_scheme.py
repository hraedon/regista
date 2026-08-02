from __future__ import annotations

import hashlib
import hmac as _hmac
from collections.abc import Callable
from typing import Protocol, runtime_checkable

_HASH_ALGORITHMS: dict[str, Callable[[bytes], hashlib._Hash]] = {
    "sha-256": hashlib.sha256,
    "sha-384": hashlib.sha384,
    "sha-512": hashlib.sha512,
    "sha3-256": hashlib.sha3_256,
    "sha3-384": hashlib.sha3_384,
    "sha3-512": hashlib.sha3_512,
}


def resolve_hash_function(hash_alg: str) -> Callable[[bytes], hashlib._Hash]:
    fn = _HASH_ALGORITHMS.get(hash_alg)
    if fn is None:
        from ._errors import ErrorCode, RegistaError

        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Unknown hash algorithm {hash_alg!r}; "
            f"expected one of {sorted(_HASH_ALGORITHMS)}",
        )
    return fn


@runtime_checkable
class SigningScheme(Protocol):
    scheme_id: str
    is_asymmetric: bool

    def sign(
        self, envelope: bytes, key_material: bytes, hash_alg: str = "sha-256"
    ) -> tuple[bytes, bytes]:
        """Returns (signature, envelope_hash)."""
        ...

    def verify(
        self,
        envelope: bytes,
        signature: bytes,
        envelope_hash: bytes,
        key_material: bytes,
        hash_alg: str = "sha-256",
    ) -> bool: ...


_registry: dict[str, type[SigningScheme]] = {}


def register_scheme(cls: type[SigningScheme]) -> type[SigningScheme]:
    existing = _registry.get(cls.scheme_id)
    if existing is not None and existing is not cls:
        import structlog

        structlog.get_logger().warning(
            "signing.scheme_overwritten",
            scheme_id=cls.scheme_id,
            old=existing.__name__,
            new=cls.__name__,
        )
    _registry[cls.scheme_id] = cls
    return cls


def unregister_scheme(scheme_id: str) -> None:
    _registry.pop(scheme_id, None)


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


def asymmetric_scheme_ids() -> frozenset[str]:
    """Derive the set of asymmetric scheme ids from the live registry."""
    return frozenset(
        sid for sid, cls in _registry.items()
        if getattr(cls, "is_asymmetric", False)
    )


@register_scheme
class HMACSHA256Scheme:
    scheme_id: str = "hmac-sha256"
    is_asymmetric: bool = False

    def sign(
        self, envelope: bytes, key_material: bytes, hash_alg: str = "sha-256"
    ) -> tuple[bytes, bytes]:
        hash_fn = resolve_hash_function(hash_alg)
        sig = _hmac.new(key_material, envelope, hash_fn).digest()  # type: ignore[arg-type]
        h = hash_fn(envelope).digest()
        return (sig, h)

    def verify(
        self,
        envelope: bytes,
        signature: bytes,
        envelope_hash: bytes,
        key_material: bytes,
        hash_alg: str = "sha-256",
    ) -> bool:
        hash_fn = resolve_hash_function(hash_alg)
        expected = _hmac.new(key_material, envelope, hash_fn).digest()  # type: ignore[arg-type]
        return _hmac.compare_digest(expected, signature) and _hmac.compare_digest(
            hash_fn(envelope).digest(), envelope_hash
        )


@register_scheme
class Ed25519Scheme:
    scheme_id: str = "ed25519"
    is_asymmetric: bool = True

    def sign(
        self, envelope: bytes, key_material: bytes, hash_alg: str = "sha-256"
    ) -> tuple[bytes, bytes]:
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
        hash_fn = resolve_hash_function(hash_alg)
        h = hash_fn(envelope).digest()
        return (sig, h)

    def verify(
        self,
        envelope: bytes,
        signature: bytes,
        envelope_hash: bytes,
        key_material: bytes,
        hash_alg: str = "sha-256",
    ) -> bool:
        try:
            import nacl.signing
        except ImportError as e:
            from ._errors import ErrorCode, RegistaError

            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                "Scheme 'ed25519' requires PyNaCl: pip install regista[ed25519]",
            ) from e
        try:
            verify_key = nacl.signing.VerifyKey(key_material)
        except (ValueError, TypeError):
            return False
        except Exception:
            import structlog
            structlog.get_logger().error(
                "signing.ed25519_verify_unexpected_error",
                exc_info=True,
            )
            return False
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
        hash_fn = resolve_hash_function(hash_alg)
        return _hmac.compare_digest(hash_fn(envelope).digest(), envelope_hash)
