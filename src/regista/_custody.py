from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._errors import ErrorCode, RegistaError
from ._secrets import store as _store_secret

_DEFAULT_BACKEND = "file"
_KNOWN_BASE64_BACKENDS = frozenset({"vault", "azure"})
_READ_ONLY_BACKENDS = frozenset({"env", "literal"})


@dataclass(frozen=True)
class CustodyResult:
    public_key: bytes
    secret_ref: str
    encoding: str | None
    backend: str


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    try:
        import nacl.signing
    except ImportError as e:
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            "Ed25519 key generation requires PyNaCl: pip install regista[ed25519]",
        ) from e
    signing_key = nacl.signing.SigningKey.generate()
    private_key = bytes(signing_key)
    public_key = bytes(signing_key.verify_key)
    return private_key, public_key


def resolve_backend(explicit: str | None) -> str:
    if explicit:
        return explicit
    from ._config import resolve as resolve_config

    cfg = resolve_config()
    return cfg.secret_backend or _DEFAULT_BACKEND


def _sanitize_azure_name(project: str, principal_id: str) -> str:
    import hashlib

    raw = f"regista-{project}-{principal_id}"
    cleaned = re.sub(r"[^a-zA-Z0-9-]", "-", raw)
    if len(cleaned) <= 127:
        return cleaned
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    head = cleaned[: 127 - len(digest) - 1]
    return f"{head}-{digest}"


def build_ref(
    backend: str,
    principal_id: str,
    *,
    project: str | None = None,
    private_key_dir: str | None = None,
) -> str:
    if backend == "file":
        if private_key_dir:
            key_dir = Path(private_key_dir)
        else:
            key_dir = Path.cwd() / "principals"
        return f"file:{key_dir / f'{principal_id}_ed25519.key'}"
    if backend == "windows":
        return f"windows:{principal_id}"
    if backend == "vault":
        safe = re.sub(r"[^a-zA-Z0-9._-]", "-", principal_id)
        proj = project or "default"
        return f"vault:secret/regista/{proj}/principals/{safe}/private_key"
    if backend == "azure":
        return f"azure:{_sanitize_azure_name(project or 'default', principal_id)}"
    from ._secrets import _PROVIDERS

    if backend in _PROVIDERS:
        return f"{backend}:{principal_id}"
    raise RegistaError(
        ErrorCode.INVALID_ARGUMENT,
        f"Unknown secret backend: {backend!r}. "
        f"Writable backends: file/windows/vault/azure, or 'operator' "
        f"for operator-writes custody.",
    )


def operator_ref_template(
    principal_id: str,
    *,
    project: str | None = None,
) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "-", principal_id)
    proj = project or "<project>"
    return f"vault:secret/regista/{proj}/principals/{safe}/private_key"


def store_private_key(
    *,
    backend: str | None,
    principal_id: str,
    project: str | None = None,
    private_key_dir: str | None = None,
) -> CustodyResult:
    resolved = resolve_backend(backend)

    if resolved == "operator":
        ref_tmpl = operator_ref_template(principal_id, project=project)
        raise RegistaError(
            ErrorCode.SECRET_WRITE_EXTERNAL,
            f"Secret backend 'operator' is read-only: regista cannot custody "
            f"a generated private key. Generate an Ed25519 keypair "
            f"out-of-band, populate the ref {ref_tmpl!r} in your secret "
            f"backend, then register the public key via "
            f"`regista principal register`.",
            detail={
                "ref_template": ref_tmpl,
                "backend": "operator",
                "principal_id": principal_id,
            },
        )

    if resolved in _READ_ONLY_BACKENDS:
        raise RegistaError(
            ErrorCode.SECRET_WRITE_UNSUPPORTED,
            f"Secret backend {resolved!r} cannot custody a generated key "
            f"(read-only by nature); use a writable backend "
            f"(file/windows/vault/azure) or 'operator' for operator-writes.",
        )

    ref = build_ref(
        resolved,
        principal_id,
        project=project,
        private_key_dir=private_key_dir,
    )
    private_key, public_key = generate_ed25519_keypair()
    secret_ref = _store_secret(ref, private_key)
    encoding: str | None = "base64" if resolved in _KNOWN_BASE64_BACKENDS else None
    return CustodyResult(
        public_key=public_key,
        secret_ref=secret_ref,
        encoding=encoding,
        backend=resolved,
    )


def custody_summary(result: CustodyResult) -> dict[str, Any]:
    return {
        "backend": result.backend,
        "secret_ref": result.secret_ref,
        "encoding": result.encoding,
    }
