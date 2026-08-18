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

#: POSIX ``NAME_MAX`` — 255 bytes on every filesystem regista targets (ext4, xfs, btrfs,
#: APFS) and also the per-component limit on NTFS. Deliberately a constant rather than a
#: runtime ``os.pathconf`` lookup: the custody directory may not exist yet when a ref is
#: built, and a ref that depends on the host's filesystem would not be reproducible.
_MAX_FILENAME_BYTES = 255
#: ``_secrets.FileProvider.store`` writes ``<name>.tmp`` and then renames onto ``<name>``,
#: so the temporary name — not the final one — is what the kernel must accept. Reserving
#: those bytes here is why a name this module approves can actually be created.
_FILENAME_SUFFIX_RESERVE = len(".tmp")


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


def _contained_key_path(key_dir: Path, principal_id: str) -> Path:
    """A file-backend key path for ``principal_id`` that is always inside ``key_dir``.

    **Security-relevant, added with P2.3 (WI-294).** Before the enrolment inversion,
    ``_provision._validate_principal_id`` accepted only the ASCII
    alphanumeric-dot-hyphen-underscore class, so a principal id could not contain a path
    separator and ``key_dir / f"{principal_id}_ed25519.key"`` was safe by accident.
    ``TRUST-DOMAIN.md`` §2.1's subject class legitimately includes ``/`` —
    ``service:idp:tenant-a/svc-7`` is a stated legal example — so a *grammatically
    canonical* id such as ``agent:a/../../../etc/cron.d/evil`` now reaches here and would
    otherwise write outside the custody directory.

    Resolution rule, in order:

    1. if ``<principal_id>_ed25519.key`` is a single path component that stays inside
       ``key_dir`` **and the kernel can actually create it**, use it — every ``secret_ref``
       ever written by an older release keeps resolving, because every legacy principal id
       is a bare name and therefore path-safe;
    2. otherwise fall back to ``<backend_name>_ed25519.key``, the §2.2 derived name, which
       is ``rp-`` plus 32 hex characters plus the suffix — 47 bytes, path-safe and
       length-safe by construction.

    The length half of condition 1 exists because ``service:`` + a 247-character subject is
    a *legal* canonical id (§2.1's maximum) whose direct filename is 267 bytes, over
    ``NAME_MAX``. Without it, ``FileProvider.store``'s ``os.open`` raises a bare
    ``OSError(ENAMETOOLONG)`` that propagates untyped through ``provision_principal`` and
    ``enroll_principal`` — an always-strict boundary answering with an unhandled OS
    exception instead of a ``RegistaError``. Routing to the derived name makes the same
    input simply *work*, which is better than either crashing or refusing.

    **No existing secret can be orphaned by the length condition.** The budget is exactly
    the one ``FileProvider`` has always been bound by (``NAME_MAX`` minus the ``.tmp``
    reserve), so an id that now routes to the derived name is precisely an id whose direct
    write would have failed with ``ENAMETOOLONG`` before this change — it has no
    ``test_the_length_cutover_matches_what_was_ever_writable`` pins that
    equivalence.
    pins that equivalence.

    Two filename conventions is a cost, and it is the smaller cost: refusing case 2 would
    make a legal canonical identity un-enrollable on the file backend, and rewriting case 1
    would invalidate existing refs. The derived form stays auditable by hand through
    ``regista principal resolve-backend-name``, which §2.2 requires for exactly this reason.
    WI-297 tracks moving *every* backend to the derived name as a deliberate custody
    migration; this is a forward-compatible step toward it, not a competing scheme.
    """
    base = key_dir.resolve(strict=False)

    def _inside(candidate: Path) -> bool:
        resolved = candidate.resolve(strict=False)
        return resolved.parent == base and resolved.name == candidate.name

    direct = key_dir / f"{principal_id}_ed25519.key"
    if (
        "/" not in principal_id
        and "\\" not in principal_id
        and len(direct.name.encode("utf-8")) + _FILENAME_SUFFIX_RESERVE
        <= _MAX_FILENAME_BYTES
        and _inside(direct)
    ):
        return direct

    from ._principals import backend_name

    derived = key_dir / f"{backend_name(principal_id)}_ed25519.key"
    if not _inside(derived):  # pragma: no cover - the derived name is rp-<32 hex>
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Refusing to custody a private key outside {str(base)!r} for principal_id "
            f"{principal_id!r}",
            detail={
                "reason": "custody_path_escape",
                "principal_id": principal_id,
                "key_dir": str(base),
            },
        )
    return derived


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
        return f"file:{_contained_key_path(key_dir, principal_id)}"
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
