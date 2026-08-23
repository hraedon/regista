from __future__ import annotations

import hashlib
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


#: A project name that may be used *verbatim* as a backend name segment. This is
#: deliberately **stricter than** Azure Key Vault's own secret-name class
#: (``[A-Za-z0-9-]``, 1-127): it is lowercase-only, and capped at 63 rather than 127.
#:
#: *Lowercase-only* because Key Vault secret names are **case-insensitive**, so
#: ``[A-Za-z0-9-]`` is not an injective alphabet for them — ``MyProj`` and ``myproj`` are one
#: name at the service. Anything carrying an uppercase character therefore takes the derived
#: branch rather than being folded into a neighbour's secret.
#:
#: *63* because it makes the whole name fit by construction —
#: ``len("regista-") + 63 + len("-") + 35 == 107`` against Key Vault's 127 — which is what
#: removes the truncation branch entirely. It is also the upstream project cap
#: (``_connection._SCHEMA_RE``, a Postgres schema name). Note that the upstream grammar
#: permits ``_`` and Key Vault does not, so ordinary project names like ``my_proj`` land on
#: the derived branch below.
_VERBATIM_PROJECT_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
#: The shape :func:`_project_segment` derives. The verbatim branch refuses this shape so the
#: two branches have **disjoint ranges**: a project literally named ``px-<32 hex>`` can never
#: alias the derived segment of some other project. Matched case-insensitively because Key
#: Vault folds case: without ``IGNORECASE`` a project named ``px-<UPPERCASE 32 hex>`` would
#: be refused by the lowercase-only class above but, were that class ever widened, could
#: case-fold onto a real derived segment. Belt and braces on the boundary that matters.
_DERIVED_PROJECT_RE = re.compile(r"px-[0-9a-f]{32}", re.IGNORECASE)
#: Domain separation, as for ``_principals.BACKEND_NAME_DOMAIN``. A project segment and a
#: principal segment must never be derivable from each other.
_PROJECT_NAME_DOMAIN = b"regista.custody.project-name.v1\x00"


def _project_segment(project: str) -> str:
    """A backend-safe, injective rendering of ``project`` for a custody name.

    The project stays in the name on purpose (WI-297 review): a Key Vault may be shared
    across projects, so a principal-only name would let two projects' keys collide on one
    secret. Verbatim when it is already safe — §2.2 keeps derived names auditable by hand,
    and an opaque project segment has no lookup verb to recover it — otherwise a
    domain-separated digest, which is the only representation for a project name Key Vault
    cannot spell.

    **Injective under case folding**, which is the equivalence that matters because Key
    Vault secret names are case-insensitive; plain injectivity would not be enough. Taking
    the branches in turn:

    * *within verbatim* — the map is the identity on strings that are already lowercase, so
      two distinct verbatim inputs are two distinct lowercase strings, and casefolding fixes
      each of them. Distinct inputs, case-fold-distinct outputs.
    * *within derived* — outputs are ``px-`` plus lowercase hex, already case-folded, so
      case-fold-collision reduces to a SHA-256 collision on a domain-separated input.
    * *across the branches* — every derived output case-folds to ``px-<32 lowercase hex>``,
      and the verbatim branch refuses exactly that shape (case-insensitively). Disjoint
      ranges, so no verbatim project can land on any project's derived segment.

    The lowercase-only class is what makes the first bullet true, and it is why an uppercase
    project takes the derived branch: ``MyProj`` derives, ``myproj`` stays verbatim, and the
    two cannot fold together. A project spelled ``px-<UPPERCASE 32 hex>`` is caught twice —
    by the lowercase class and by the case-insensitive shape refusal — and derives.
    """
    if _VERBATIM_PROJECT_RE.fullmatch(project) and not _DERIVED_PROJECT_RE.fullmatch(
        project
    ):
        return project
    digest = hashlib.sha256(_PROJECT_NAME_DOMAIN + project.encode("utf-8")).digest()[:16]
    return f"px-{digest.hex()}"


def _derived_custody_name(project: str, principal_id: str) -> str:
    """The §2.2 backend-safe custody name: ``regista-<project>-<backend_name>``.

    The layout is unambiguous by construction rather than by convention. ``backend_name``
    is a **fixed-width trailing token** (``"rp-"`` plus exactly 32 lowercase hex, 35
    characters), so the name parses right-to-left: the last 35 characters are always the
    principal segment and everything between ``regista-`` and it is always the project
    segment. Two distinct canonical principal ids therefore never map to one name — the
    trailing token differs and no project segment, of any length, can absorb the difference.

    That survives case folding, which Key Vault applies to secret names. Every character
    this function emits outside the project segment is already lowercase, so if two names
    case-fold together their trailing 35 characters are equal outright and the principals
    are the same; the remaining middles must then case-fold together, which
    :func:`_project_segment` rules out for distinct projects.
    """
    from ._principals import backend_name

    return f"regista-{_project_segment(project)}-{backend_name(principal_id)}"


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

    WI-297 moved the *other* writable backends (azure/windows/vault) onto the derived name
    and deliberately left this branch alone: those backends had no path-safety problem to
    solve, only a §2.2 one, whereas here condition 1 is what keeps every legacy file-backend
    ref resolving. The dual convention is therefore the settled state, not a way station.
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
        # This value is superseded in practice — `_secrets.WindowsProvider.store` ignores
        # the ref it is handed and returns `windows:<DPAPI blob>` as the ref, because a
        # `windows:` ref *carries* the secret rather than addressing a store entry. It is
        # still derived here: the credential store forbids `:`, and §2.2 is a rule about
        # every name regista produces, not only the ones something later reads.
        return f"windows:{_derived_custody_name(project or 'default', principal_id)}"
    if backend == "vault":
        # Vault paths accept far more than Key Vault does, but §2.2's collision-resistance
        # rule is backend-agnostic: the old `[^a-zA-Z0-9._-]` -> `-` substitution collided
        # (`human:it-admin` and `human-it:admin` shared a path). The path structure is
        # unchanged so the tree stays browsable.
        from ._principals import backend_name

        proj = project or "default"
        return (
            f"vault:secret/regista/{proj}/principals/"
            f"{backend_name(principal_id)}/private_key"
        )
    if backend == "azure":
        return f"azure:{_derived_custody_name(project or 'default', principal_id)}"
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
    from ._principals import backend_name

    proj = project or "<project>"
    return (
        f"vault:secret/regista/{proj}/principals/"
        f"{backend_name(principal_id)}/private_key"
    )


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
