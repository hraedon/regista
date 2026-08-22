"""Client-side key custody and signing helper.

This module provides the out-of-process signer that Plan 031 §5 requires:
it generates Ed25519 keypairs, custodies private keys (file mode for
development; DPAPI/AKV later), and signs possession and effective-use
challenges without ever exposing private material to the caller.

The signer is deliberately a library *and* CLI target (Plan 031 §4: CLI and
library call the same core).  A web process never imports this module; it
receives only public keys, proofs, and receipts.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Final

from ._custody import (
    CustodyResult,
    store_private_key,
)
from ._secrets import resolve as resolve_secret
from .principal_lifecycle import (
    EffectiveChallenge,
    EffectiveReceipt,
    EffectiveReceiptStatus,
    PossessionChallenge,
    PossessionProof,
    ProofFormat,
)

CLIENT_TYPE: Final[str] = "regista-client-signer"
CLIENT_VERSION: Final[str] = "1.0.0"


@dataclass(frozen=True)
class SignerIdentity:
    """Public identity of a custodied signing key."""

    principal_id: str
    public_key: bytes
    fingerprint: str
    scheme: str
    custody_mode: str
    secret_ref: str

    def to_dict(self) -> dict[str, str]:
        return {
            "principal_id": self.principal_id,
            "public_key": base64.b64encode(self.public_key).decode("ascii"),
            "fingerprint": self.fingerprint,
            "scheme": self.scheme,
            "custody_mode": self.custody_mode,
            "secret_ref": self.secret_ref,
        }


class ClientSigner:
    """Custody a private key and sign lifecycle challenges.

    The signer never returns private key material.  It exposes only:

    - :meth:`generate` — create and custody a new keypair, return public identity.
    - :meth:`sign_possession` — sign a possession challenge, return a proof.
    - :meth:`sign_effective` — sign an effective-use challenge, return a receipt.
    - :meth:`load` — load an existing custodied key by secret ref.
    """

    def __init__(self, *, private_key: bytes, identity: SignerIdentity) -> None:
        self._private_key = private_key
        self._identity = identity

    @property
    def identity(self) -> SignerIdentity:
        return self._identity

    @property
    def public_key(self) -> bytes:
        return self._identity.public_key

    @classmethod
    def generate(
        cls,
        principal_id: str,
        *,
        backend: str | None = None,
        project: str | None = None,
        private_key_dir: str | None = None,
        scheme: str = "ed25519",
    ) -> ClientSigner:
        """Generate a new Ed25519 keypair and custody the private key.

        Returns a signer holding the private key in custody.  The public
        identity is safe to share; the private key never leaves this object.
        """
        if scheme != "ed25519":
            raise ValueError(f"Unsupported scheme: {scheme!r}; only 'ed25519' is supported")

        result: CustodyResult = store_private_key(
            backend=backend,
            principal_id=principal_id,
            project=project,
            private_key_dir=private_key_dir,
        )
        identity = SignerIdentity(
            principal_id=principal_id,
            public_key=result.public_key,
            fingerprint=_fingerprint(result.public_key, scheme),
            scheme=scheme,
            custody_mode=result.backend,
            secret_ref=result.secret_ref,
        )
        private_key = _load_private_key(
            result.secret_ref,
            encoding=result.encoding,
        )
        return cls(private_key=private_key, identity=identity)

    @classmethod
    def load(
        cls,
        principal_id: str,
        secret_ref: str,
        *,
        scheme: str = "ed25519",
        custody_mode: str | None = None,
        encoding: str | None = None,
    ) -> ClientSigner:
        """Load an existing custodied private key by its secret reference.

        The public key is derived from the private key; the caller supplies
        the principal_id for identity binding.

        If ``encoding`` is not supplied it is inferred from the secret ref
        prefix: vault/azure refs are base64-encoded, file/windows are raw.
        """
        if encoding is None:
            encoding = _encoding_from_ref(secret_ref)
        private_key = _load_private_key(secret_ref, encoding=encoding)
        public_key = _derive_public_key(private_key)
        resolved_custody = custody_mode or _custody_from_ref(secret_ref)
        identity = SignerIdentity(
            principal_id=principal_id,
            public_key=public_key,
            fingerprint=_fingerprint(public_key, scheme),
            scheme=scheme,
            custody_mode=resolved_custody,
            secret_ref=secret_ref,
        )
        return cls(private_key=private_key, identity=identity)

    def sign_possession(self, challenge: PossessionChallenge) -> PossessionProof:
        """Sign a possession challenge and return the proof.

        The challenge's ``signing_bytes()`` are signed with the custodied
        private key.  The proof binds the challenge ID, operation ID, and
        operation digest so a proof for one operation cannot authorize another.

        Raises ``ValueError`` if the challenge does not match this signer's
        identity (principal, fingerprint, scheme) — fail-closed defense
        against confused-deputy attacks.
        """
        if challenge.principal_id != self._identity.principal_id:
            raise ValueError(
                f"Challenge principal_id {challenge.principal_id!r} does not "
                f"match signer principal {self._identity.principal_id!r}"
            )
        if challenge.fingerprint != self._identity.fingerprint:
            raise ValueError(
                f"Challenge fingerprint {challenge.fingerprint!r} does not "
                f"match signer fingerprint {self._identity.fingerprint!r}"
            )
        if challenge.scheme != self._identity.scheme:
            raise ValueError(
                f"Challenge scheme {challenge.scheme!r} does not "
                f"match signer scheme {self._identity.scheme!r}"
            )
        envelope = challenge.signing_bytes()
        signature = _sign_ed25519(self._private_key, envelope)
        return PossessionProof(
            format=ProofFormat.SIGNATURE_V1,
            challenge_id=challenge.challenge_id,
            operation_id=challenge.operation_id,
            operation_digest=challenge.operation_digest,
            signature=signature,
        )

    def sign_rotation_authorization(self, authorization_bytes: bytes) -> bytes:
        """Sign the server-provided dual-rotation authorization bytes.

        The server constructs and returns the exact domain-separated bytes from
        the prepared operation.  The outgoing key's custody helper signs those
        bytes without exposing its private material; the resulting detached
        signature is submitted to the server before commit.
        """
        if not authorization_bytes:
            raise ValueError("rotation authorization bytes must not be empty")
        return _sign_ed25519(self._private_key, authorization_bytes)

    def sign_effective(
        self,
        challenge: EffectiveChallenge,
        *,
        status: EffectiveReceiptStatus = EffectiveReceiptStatus.EFFECTIVE,
    ) -> EffectiveReceipt:
        """Sign an effective-use challenge and produce a receipt.

        The signature covers the full receipt envelope (the challenge plus
        client_type/version, status, and observed_at), not just the challenge,
        so no receipt field can be tampered with without invalidating it.
        Without a valid receipt the operation stays ``committed_not_effective``.

        Raises ``ValueError`` if the challenge does not match this signer's
        identity.
        """
        if challenge.principal_id != self._identity.principal_id:
            raise ValueError(
                f"Challenge principal_id {challenge.principal_id!r} does not "
                f"match signer principal {self._identity.principal_id!r}"
            )
        if challenge.fingerprint != self._identity.fingerprint:
            raise ValueError(
                f"Challenge fingerprint {challenge.fingerprint!r} does not "
                f"match signer fingerprint {self._identity.fingerprint!r}"
            )
        if challenge.scheme != self._identity.scheme:
            raise ValueError(
                f"Challenge scheme {challenge.scheme!r} does not "
                f"match signer scheme {self._identity.scheme!r}"
            )
        unsigned = EffectiveReceipt(
            operation_id=challenge.operation_id,
            operation_digest=challenge.operation_digest,
            project=challenge.project,
            principal_id=self._identity.principal_id,
            fingerprint=self._identity.fingerprint,
            client_type=CLIENT_TYPE,
            client_version=CLIENT_VERSION,
            status=status,
            observed_at=datetime.now(UTC),
            challenge_id=challenge.challenge_id,
            signature=None,
        )
        envelope = unsigned.signing_bytes(challenge)
        signature = _sign_ed25519(self._private_key, envelope)
        return replace(unsigned, signature=signature)

    def destroy(self) -> None:
        """Drop this process's reference to the private key.

        This does not remove the custodied key from the backend; use the
        backend's delete mechanism for that.  It prevents accidental reuse
        of the key material within this process.  Note that Python cannot
        guarantee the original bytes are scrubbed from memory (they are
        immutable and may persist until GC); the signer is a short-lived
        CLI, so process exit is the real hygiene boundary.
        """
        self._private_key = b""


def _load_private_key(secret_ref: str, *, encoding: str | None = None) -> bytes:
    """Resolve the private key bytes from a secret reference.

    If ``encoding`` is ``"base64"`` the resolved bytes are base64-decoded
    first (vault/azure store base64-encoded material).
    """
    raw = resolve_secret(secret_ref)
    if encoding == "base64":
        try:
            raw = base64.b64decode(raw)
        except Exception as e:
            raise ValueError(f"Secret at {secret_ref!r} is not valid base64: {e}") from e
    if len(raw) != 32:
        raise ValueError(f"Expected 32-byte Ed25519 private key, got {len(raw)} bytes")
    return raw


def _derive_public_key(private_key: bytes) -> bytes:
    """Derive the Ed25519 public key from a private key."""
    try:
        import nacl.signing
    except ImportError as e:
        raise ValueError("Ed25519 requires PyNaCl: pip install regista[ed25519]") from e
    signing_key = nacl.signing.SigningKey(private_key)
    return bytes(signing_key.verify_key)


def _sign_ed25519(private_key: bytes, message: bytes) -> bytes:
    """Sign a message with an Ed25519 private key."""
    try:
        import nacl.signing
    except ImportError as e:
        raise ValueError("Ed25519 requires PyNaCl: pip install regista[ed25519]") from e
    signing_key = nacl.signing.SigningKey(private_key)
    return signing_key.sign(message).signature


def _fingerprint(public_key: bytes, scheme: str) -> str:
    """Compute the key fingerprint."""
    return f"{scheme}:sha256:{hashlib.sha256(public_key).hexdigest()}"


def _custody_from_ref(secret_ref: str) -> str:
    """Infer custody mode from a secret reference prefix.

    Raises ``ValueError`` for unrecognized prefixes — fail closed rather
    than silently mislabeling an unknown backend.
    """
    if secret_ref.startswith("file:"):
        return "file"
    if secret_ref.startswith("vault:"):
        return "remote_organizational"
    if secret_ref.startswith("azure:"):
        return "remote_organizational"
    if secret_ref.startswith("windows:"):
        return "windows_local"
    raise ValueError(
        f"Cannot infer custody mode from secret ref {secret_ref!r}; pass custody_mode explicitly"
    )


def _encoding_from_ref(secret_ref: str) -> str | None:
    """Infer the encoding used by the backend from the secret ref prefix.

    vault/azure store base64-encoded material; file/windows store raw bytes.
    """
    if secret_ref.startswith("vault:") or secret_ref.startswith("azure:"):
        return "base64"
    return None


__all__ = [
    "CLIENT_TYPE",
    "CLIENT_VERSION",
    "ClientSigner",
    "SignerIdentity",
]
