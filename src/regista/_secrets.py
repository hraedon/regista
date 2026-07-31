from __future__ import annotations

import os
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import structlog

from ._errors import ErrorCode, RegistaError

_log = structlog.get_logger(__name__)


def _open_exclusive(path: Path) -> tuple[int, Path]:
    flags = os.O_CREAT | os.O_WRONLY | os.O_EXCL | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(str(path), flags, 0o600), path
    except FileExistsError:
        suffix = f".{uuid.uuid4().hex[:8]}.tmp"
        alt = path.with_name(path.name + suffix)
        return os.open(str(alt), flags, 0o600), alt


def _ensure_secure_dir(path: Path) -> None:
    if path.exists():
        return
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.chmod(0o700)
    except OSError:
        pass


class DeleteOutcome(Enum):
    """What actually happened to the custodied material.

    Three states, not a bool, because the backends genuinely differ. For
    ``file``/``vault``/``azure`` the reference *points at* stored material and
    deleting it removes something. For ``windows``/``literal`` the reference
    *contains* the material — a DPAPI blob or the value itself — so there is
    nothing server-side to remove and discarding the reference is the whole
    act. Reporting that as ``DELETED`` would tell an operator their key is
    gone when in fact every copy of the reference still holds it.
    """

    DELETED = "deleted"
    ALREADY_ABSENT = "already_absent"
    INLINE_REF = "inline_ref"


@runtime_checkable
class SecretProvider(Protocol):
    name: str

    def resolve(self, ref: str) -> bytes: ...

    def store(self, ref: str, data: bytes) -> str: ...

    def delete(self, ref: str) -> DeleteOutcome: ...


class FileProvider:
    name: str = "file"

    def resolve(self, ref: str) -> bytes:
        path = Path(ref)
        if not path.is_file():
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                f"file: path does not exist or is not a file: {ref}",
            )
        return path.read_bytes()

    def store(self, ref: str, data: bytes) -> str:
        path = Path(ref)
        _ensure_secure_dir(path.parent)
        tmp = path.with_name(path.name + ".tmp")
        fd, tmp = _open_exclusive(tmp)
        try:
            remaining = memoryview(data)
            while remaining:
                n = os.write(fd, remaining)
                remaining = remaining[n:]
        finally:
            os.close(fd)
        os.replace(str(tmp), str(path))
        return f"file:{path}"

    def delete(self, ref: str) -> DeleteOutcome:
        path = Path(ref)
        try:
            path.unlink()
        except FileNotFoundError:
            return DeleteOutcome.ALREADY_ABSENT
        except OSError as e:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                f"file: could not remove {ref}: {e!s}",
            ) from e
        return DeleteOutcome.DELETED


class EnvProvider:
    name: str = "env"

    def resolve(self, ref: str) -> bytes:
        val = os.environ.get(ref)
        if val is None:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                f"env: variable not set: {ref}",
            )
        return val.encode("utf-8")

    def store(self, ref: str, data: bytes) -> str:
        raise RegistaError(
            ErrorCode.SECRET_WRITE_UNSUPPORTED,
            f"env: cannot custody a generated secret into a read-only "
            f"environment variable {ref!r}; use a writable backend "
            f"(file/windows/vault/azure)",
        )

    def delete(self, ref: str) -> DeleteOutcome:
        # Clearing os.environ would only affect this process, leaving the
        # variable set everywhere it actually matters — a deletion that
        # reports success and removes nothing.
        raise RegistaError(
            ErrorCode.SECRET_WRITE_UNSUPPORTED,
            f"env: cannot delete environment variable {ref!r} from here; "
            f"unset it wherever it is defined",
        )


class LiteralProvider:
    name: str = "literal"

    def resolve(self, ref: str) -> bytes:
        return ref.encode("utf-8")

    def store(self, ref: str, data: bytes) -> str:
        raise RegistaError(
            ErrorCode.SECRET_WRITE_UNSUPPORTED,
            "literal: cannot custody a generated secret into a literal value; "
            "use a writable backend (file/windows/vault/azure)",
        )

    def delete(self, ref: str) -> DeleteOutcome:
        # The value *is* the reference. Nothing is stored anywhere to remove;
        # the caller discarding the reference is the deletion.
        return DeleteOutcome.INLINE_REF


_PROVIDERS: dict[str, SecretProvider] = {}


def register_provider(provider: SecretProvider) -> SecretProvider:
    _PROVIDERS[provider.name] = provider
    return provider


def unregister_provider(name: str) -> None:
    _PROVIDERS.pop(name, None)


def available_providers() -> list[str]:
    return sorted(_PROVIDERS.keys())


register_provider(FileProvider())
register_provider(EnvProvider())
register_provider(LiteralProvider())

_KNOWN_PROVIDER_NAMES = frozenset(
    {"file", "env", "literal", "vault", "azure", "windows"}
)


def known_providers() -> list[str]:
    """Return every canonical provider name, installed or not.

    Unlike :func:`available_providers`, this does not imply that an optional
    SDK is installed or that the current platform supports the provider.
    """
    return sorted(_KNOWN_PROVIDER_NAMES)


def is_provider_available(name: str) -> bool:
    """Whether ``name`` has an implementation registered in this process."""
    return name in _PROVIDERS


def reference_provider(ref: str, *, require_explicit: bool = False) -> str:
    """Validate ``ref`` and return its canonical provider name without resolving it.

    ``require_explicit`` is intended for security-sensitive brokers: it refuses
    bare paths and values, and it refuses unknown schemes instead of inheriting
    the resolver's backwards-compatible literal fallback.
    """
    if not isinstance(ref, str) or not ref:
        raise RegistaError(ErrorCode.INVALID_ARGUMENT, "Empty secret reference")
    if require_explicit:
        if ":" not in ref:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "Secret reference requires an explicit provider prefix",
            )
        prefix, _, value = ref.partition(":")
        if prefix not in _KNOWN_PROVIDER_NAMES:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"Unknown secret provider: {prefix!r}",
            )
        if not value:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"Secret reference for provider {prefix!r} is empty",
            )
        return prefix
    provider, _ = _detect_prefix(ref)
    return provider


def _detect_prefix(ref: str) -> tuple[str, str]:
    if ":" not in ref:
        return "file", ref
    prefix, _, rest = ref.partition(":")
    if prefix in _PROVIDERS:
        return prefix, rest
    if prefix in _KNOWN_PROVIDER_NAMES:
        return prefix, rest
    if ref.startswith("/") or ref.startswith("~") or ref.startswith("."):
        return "file", ref
    if os.path.isabs(ref):
        return "file", ref
    return "literal", ref


def resolve(ref: str) -> bytes:
    if not ref:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "Empty secret reference",
        )
    provider_name, value = _detect_prefix(ref)
    provider = _PROVIDERS.get(provider_name)
    if provider is None:
        raise RegistaError(
            ErrorCode.SECRET_RESOLVE_FAILED,
            f"Unknown secret provider: {provider_name!r}. "
            f"Available: {available_providers()}",
        )
    return provider.resolve(value)


def resolve_str(ref: str) -> str:
    raw = resolve(ref)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as e:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Secret from {ref!r} is not valid UTF-8",
        ) from e


def store(ref: str, data: bytes) -> str:
    if not ref:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "Empty secret reference",
        )
    provider_name, value = _detect_prefix(ref)
    provider = _PROVIDERS.get(provider_name)
    if provider is None:
        raise RegistaError(
            ErrorCode.SECRET_RESOLVE_FAILED,
            f"Unknown secret provider: {provider_name!r}. "
            f"Available: {available_providers()}",
        )
    return provider.store(value, data)


def delete(ref: str) -> DeleteOutcome:
    """Remove custodied material behind ``ref``.

    Idempotent: an already-absent secret returns ``ALREADY_ABSENT`` rather
    than raising, so a re-run of an offboarding is safe. Backends whose
    reference *contains* the secret return ``INLINE_REF`` — see
    :class:`DeleteOutcome`.
    """
    if not ref:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "Empty secret reference",
        )
    provider_name, value = _detect_prefix(ref)
    provider = _PROVIDERS.get(provider_name)
    if provider is None:
        raise RegistaError(
            ErrorCode.SECRET_RESOLVE_FAILED,
            f"Unknown secret provider: {provider_name!r}. "
            f"Available: {available_providers()}",
        )
    deleter = getattr(provider, "delete", None)
    if deleter is None:
        # A third-party provider registered before `delete` existed.
        raise RegistaError(
            ErrorCode.SECRET_WRITE_UNSUPPORTED,
            f"{provider_name}: provider does not implement delete",
        )
    return deleter(value)


def supports_write(name: str) -> bool:
    provider = _PROVIDERS.get(name)
    if provider is None:
        return False
    try:
        return provider.store is not None
    except AttributeError:
        return False


def supports_delete(name: str) -> bool:
    provider = _PROVIDERS.get(name)
    if provider is None:
        return False
    return getattr(provider, "delete", None) is not None


# ---------------------------------------------------------------------------
# Vault
#
# Two auth methods, and which one is in use is never implicit (WI-228).
#
#   AppRole  — production. RoleID + SecretID, the SecretID normally read from a
#              *file* because that is where response-wrapped delivery lands it
#              (agent-suite docs/secrets-vault.md §5). No VAULT_TOKEN needs to
#              exist anywhere in the process environment, which is what §6
#              requires of a production host.
#   token    — dev only. A static VAULT_TOKEN, kept so `vault server -dev`
#              walkthroughs still work.
#
# Three properties the qualification found missing and that this module now
# guarantees:
#
#   1. The resolver reports which method it used (:func:`vault_auth_status`,
#      `regista secrets --auth-status`, `regista doctor`'s `custody:vault_auth`
#      row, and a `vault_authenticated` log line). A host cannot silently sit
#      on the weaker method.
#   2. AppRole material that is configured but unusable fails closed with an
#      actionable message. It never falls back to VAULT_TOKEN — a silent
#      downgrade to the dev method is exactly the posture confusion this is
#      meant to prevent.
#   3. A login yields a *lease*. Long-running processes (dossier, agent-waked)
#      re-authenticate before the lease expires, and again if a 403 turns out to
#      be a dead token rather than a policy denial, so they do not wedge an hour
#      after start.
# ---------------------------------------------------------------------------

# Re-authenticate this many seconds before the lease actually runs out, so an
# in-flight read never races the expiry. Clamped to half the lease for the very
# short TTLs used in tests.
_VAULT_REAUTH_MARGIN_SECONDS = 60.0
_VAULT_APPROLE_DEFAULT_MOUNT = "approle"

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _split_vault_ref(ref: str) -> tuple[str, str, str]:
    """``kv/agent-suite/hosts/h/regista/hmac_key`` -> (mount, path, field).

    The field is the **last** path segment. There is no ``#field`` form: against
    a real mount it parses to a different, neighbouring secret rather than
    failing, so it is rejected by the four-segment minimum instead.
    """
    parts = ref.split("/")
    if len(parts) < 4:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"vault: ref must be mount/path/key, got {ref!r}",
        )
    return parts[0], "/".join(parts[1:-1]), parts[-1]


@dataclass(frozen=True)
class _VaultAuthShape:
    """What the environment *declares*, decided without reading any secret.

    Deliberately separate from :class:`_VaultAuthPlan`: reporting the configured
    auth method (doctor, ``--auth-status``) must not require pulling SecretID
    material into memory, so this inspects names and file metadata only.
    """

    method: str | None
    role_id_source: str | None = None
    secret_id_source: str | None = None
    token_source: str | None = None
    role_id_file: str | None = None
    secret_id_file: str | None = None
    approle_mount: str = _VAULT_APPROLE_DEFAULT_MOUNT
    response_wrapped: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "configured_method": self.method,
            "configured_error": self.error,
            "role_id_source": self.role_id_source,
            "secret_id_source": self.secret_id_source,
            "token_source": self.token_source,
            "approle_mount": self.approle_mount if self.method == "approle" else None,
            "secret_id_response_wrapped": self.response_wrapped,
        }


@dataclass(frozen=True)
class _VaultAuthPlan:
    """Resolved credential material for one login. Never reported anywhere."""

    shape: _VaultAuthShape
    role_id: str | None = None
    secret_id: str | None = None
    token: str | None = None


def _vault_file_value(path: str, *, var: str) -> str:
    """Read a credential file, mapping every failure to an actionable error.

    The path is named in errors (it is not secret); the contents never are.
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            f"vault: {var} names {path!r}, which does not exist. Deliver the "
            f"credential to that path — response-wrapped delivery unwraps into "
            f"it — or unset {var}.",
        ) from e
    except IsADirectoryError as e:
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            f"vault: {var} names {path!r}, which is a directory, not a file.",
        ) from e
    except OSError as e:
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            f"vault: cannot read {var} file {path!r}: {e.strerror or type(e).__name__}. "
            f"The service user needs read access (mode 0400/0600, owned by it).",
        ) from e
    except UnicodeDecodeError as e:
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            f"vault: {var} file {path!r} is not valid UTF-8 text.",
        ) from e
    value = raw.strip()
    if not value:
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            f"vault: {var} file {path!r} is empty. An empty credential file is "
            f"usually a delivery that failed silently — re-deliver it.",
        )
    return value


def _vault_auth_shape(env: dict[str, str] | Any) -> _VaultAuthShape:
    """Classify the declared auth method without reading credential material.

    Any AppRole variable being set means the operator asked for AppRole. From
    that point ``VAULT_TOKEN`` is not consulted: falling back to it would turn a
    broken production posture into a working dev one without saying so.
    """
    role_id_env = env.get("VAULT_ROLE_ID") or None
    role_id_file = env.get("VAULT_ROLE_ID_FILE") or None
    secret_id_env = env.get("VAULT_SECRET_ID") or None
    secret_id_file = env.get("VAULT_SECRET_ID_FILE") or None
    mount = env.get("VAULT_APPROLE_MOUNT_POINT") or _VAULT_APPROLE_DEFAULT_MOUNT
    wrapped = str(env.get("VAULT_SECRET_ID_RESPONSE_WRAPPED") or "").strip().lower() in _TRUTHY
    token = env.get("VAULT_TOKEN") or None

    declared_approle = any((role_id_env, role_id_file, secret_id_env, secret_id_file))
    if not declared_approle:
        if token:
            return _VaultAuthShape(method="token", token_source="env:VAULT_TOKEN")
        return _VaultAuthShape(
            method=None,
            error=(
                "vault: no credentials configured. Set VAULT_ROLE_ID and "
                "VAULT_SECRET_ID_FILE for AppRole (the production posture — "
                "agent-suite docs/secrets-vault.md §6), or VAULT_TOKEN for a dev "
                "Vault."
            ),
        )

    # The file is preferred over the inline variable: it is the channel
    # response-wrapped delivery actually writes to, and it keeps the SecretID
    # out of /proc/<pid>/environ.
    if role_id_file:
        role_source = "file:VAULT_ROLE_ID_FILE"
    elif role_id_env:
        role_source = "env:VAULT_ROLE_ID"
    else:
        role_source = None
    if secret_id_file:
        secret_source = "file:VAULT_SECRET_ID_FILE"
    elif secret_id_env:
        secret_source = "env:VAULT_SECRET_ID"
    else:
        secret_source = None
    if wrapped and secret_source == "file:VAULT_SECRET_ID_FILE":
        secret_source += " (response-wrapped)"

    base = _VaultAuthShape(
        method="approle",
        role_id_source=role_source,
        secret_id_source=secret_source,
        role_id_file=role_id_file,
        secret_id_file=secret_id_file,
        approle_mount=mount,
        response_wrapped=wrapped,
    )

    if role_source is None:
        return _replace_shape(
            base,
            error=(
                f"vault: an AppRole SecretID is configured ({secret_source}) but no "
                f"RoleID. Set VAULT_ROLE_ID, or VAULT_ROLE_ID_FILE to a file holding "
                f"it. Refusing to fall back to VAULT_TOKEN — that would silently "
                f"downgrade this host to the dev auth method."
            ),
        )
    if secret_source is None:
        return _replace_shape(
            base,
            error=(
                f"vault: an AppRole RoleID is configured ({role_source}) but no "
                f"SecretID. Set VAULT_SECRET_ID_FILE to the file the SecretID is "
                f"delivered into (recommended; add "
                f"VAULT_SECRET_ID_RESPONSE_WRAPPED=1 if that file holds a "
                f"response-wrapping token), or VAULT_SECRET_ID for an inline value. "
                f"Refusing to fall back to VAULT_TOKEN — that would silently "
                f"downgrade this host to the dev auth method."
            ),
        )
    if wrapped and not secret_id_file:
        return _replace_shape(
            base,
            error=(
                "vault: VAULT_SECRET_ID_RESPONSE_WRAPPED is set but "
                "VAULT_SECRET_ID_FILE is not. A response-wrapping token is "
                "delivered as a file; unset the flag or name the file."
            ),
        )
    return base


def _replace_shape(shape: _VaultAuthShape, *, error: str) -> _VaultAuthShape:
    """``shape`` with ``method`` cleared and ``error`` set (fail closed)."""
    return _VaultAuthShape(
        method=None,
        role_id_source=shape.role_id_source,
        secret_id_source=shape.secret_id_source,
        token_source=shape.token_source,
        role_id_file=shape.role_id_file,
        secret_id_file=shape.secret_id_file,
        approle_mount=shape.approle_mount,
        response_wrapped=shape.response_wrapped,
        error=error,
    )


def try_register_vault() -> None:
    try:
        import hvac  # type: ignore[import-untyped]  # noqa: F401
    except ImportError:
        return
    register_provider(VaultProvider())


class VaultProvider:
    """KV v2 provider with AppRole and static-token auth.

    ``client_factory`` and ``environ`` exist so the auth state machine — method
    selection, fail-closed refusals, lease-driven re-login, 403 disambiguation —
    is testable without a Vault. Production callers construct it with neither.
    """

    name: str = "vault"

    def __init__(
        self,
        *,
        client_factory: Any = None,
        environ: dict[str, str] | None = None,
    ) -> None:
        self._client: Any = None
        self._client_factory = client_factory
        self._environ = environ
        self._lock = threading.RLock()
        self._auth_method: str | None = None
        self._shape: _VaultAuthShape | None = None
        self._deadline: float | None = None
        self._lease_duration: int | None = None
        self._renewable: bool | None = None
        self._logins = 0
        # A response-wrapping token is single-use, so the unwrapped SecretID is
        # kept for the process lifetime: otherwise the first re-login after a
        # lease expiry would have nothing left to log in with.
        self._unwrapped_secret_id: str | None = None

    # -- environment / hvac -------------------------------------------------

    def _env(self) -> Any:
        return os.environ if self._environ is None else self._environ

    def _hvac(self) -> Any:
        import hvac  # type: ignore[import-untyped]

        return hvac

    def _new_client(self, url: str) -> Any:
        if self._client_factory is not None:
            return self._client_factory(url)
        return self._hvac().Client(url=url)

    # -- auth ---------------------------------------------------------------

    def _plan(self, env: Any) -> _VaultAuthPlan:
        shape = _vault_auth_shape(env)
        if shape.error is not None:
            # Carry the (secret-free) auth shape as structured detail: a caller
            # deciding what to fix should not have to parse the message, which
            # the CLI contract explicitly says is not API surface.
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                shape.error,
                detail={
                    "auth": shape.to_dict(),
                    "remediation": (
                        "AppRole (production): set VAULT_ROLE_ID and "
                        "VAULT_SECRET_ID_FILE. Static token (dev only): set "
                        "VAULT_TOKEN. See agent-suite docs/secrets-vault.md §5-§6."
                    ),
                },
            )
        if shape.method == "token":
            return _VaultAuthPlan(shape=shape, token=env.get("VAULT_TOKEN"))

        if shape.role_id_file:
            role_id = _vault_file_value(shape.role_id_file, var="VAULT_ROLE_ID_FILE")
        else:
            role_id = env.get("VAULT_ROLE_ID")

        if self._unwrapped_secret_id is not None:
            secret_id = self._unwrapped_secret_id
        elif shape.secret_id_file:
            secret_id = _vault_file_value(shape.secret_id_file, var="VAULT_SECRET_ID_FILE")
            if shape.response_wrapped:
                secret_id = self._unwrap_secret_id(secret_id, env)
                self._unwrapped_secret_id = secret_id
        else:
            secret_id = env.get("VAULT_SECRET_ID")
        return _VaultAuthPlan(shape=shape, role_id=role_id, secret_id=secret_id)

    def _unwrap_secret_id(self, wrapping_token: str, env: Any) -> str:
        """Exchange a response-wrapping token for the SecretID it wraps.

        This is the delivery flow of docs/secrets-vault.md §5: only a
        short-lived, single-use wrapping token crosses onto the host, and the
        host unwraps it itself.
        """
        url = env.get("VAULT_ADDR")
        client = self._new_client(url)
        client.token = wrapping_token
        try:
            resp = client.sys.unwrap()
        except Exception as e:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                f"vault: could not unwrap the response-wrapped SecretID from "
                f"{self._shape_secret_file()!r} ({type(e).__name__}). A wrapping "
                f"token is single-use and short-lived — if it has already been "
                f"unwrapped or has expired, issue a new one and re-deliver.",
            ) from e
        secret_id = ((resp or {}).get("data") or {}).get("secret_id")
        if not secret_id:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                "vault: the response-wrapped payload carried no 'secret_id' "
                "field. Wrap the output of "
                "'vault write -wrap-ttl=<ttl> -f auth/<mount>/role/<role>/secret-id'.",
            )
        return str(secret_id)

    def _shape_secret_file(self) -> str:
        env = self._env()
        return str(env.get("VAULT_SECRET_ID_FILE") or "")

    def _authenticate(self) -> None:
        """Log in and record the method plus its lease. Caller holds the lock."""
        env = self._env()
        url = env.get("VAULT_ADDR")
        if not url:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                "vault: VAULT_ADDR not set",
            )
        plan = self._plan(env)
        shape = plan.shape
        client = self._new_client(url)

        lease: int | None = None
        renewable: bool | None = None
        if shape.method == "approle":
            try:
                resp = client.auth.approle.login(
                    role_id=plan.role_id,
                    secret_id=plan.secret_id,
                    mount_point=shape.approle_mount,
                )
            except Exception as e:
                raise RegistaError(
                    ErrorCode.KEY_LOAD_ERROR,
                    f"vault: AppRole login failed at auth/{shape.approle_mount} "
                    f"({type(e).__name__}). RoleID came from {shape.role_id_source} "
                    f"and the SecretID from {shape.secret_id_source}. A rejected "
                    f"login almost always means the SecretID expired or ran out of "
                    f"uses — issue a new one and re-deliver it; or the RoleID does "
                    f"not match a role at that mount (set "
                    f"VAULT_APPROLE_MOUNT_POINT if it is not 'approle').",
                    detail={
                        "auth": shape.to_dict(),
                        "exception_type": type(e).__name__,
                        "remediation": (
                            f"vault write -f -wrap-ttl=300 "
                            f"auth/{shape.approle_mount}/role/<role>/secret-id, then "
                            f"deliver the wrapping token into "
                            f"{shape.secret_id_file or 'VAULT_SECRET_ID_FILE'} with "
                            f"VAULT_SECRET_ID_RESPONSE_WRAPPED=1"
                        ),
                    },
                ) from e
            auth = (resp or {}).get("auth") or {}
            raw_lease = auth.get("lease_duration")
            lease = int(raw_lease) if isinstance(raw_lease, (int, float)) else None
            renewable = bool(auth.get("renewable"))
            token = auth.get("client_token")
            if token:
                # hvac sets this itself, but a client_factory double may not.
                client.token = token
        else:
            client.token = plan.token
            lease, renewable = self._token_self_lease(client)

        try:
            authenticated = bool(client.is_authenticated())
        except Exception as e:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                f"vault: could not reach {url} to verify authentication "
                f"({type(e).__name__}).",
            ) from e
        if not authenticated:
            if shape.method == "approle":
                detail = (
                    f"vault: AppRole login at auth/{shape.approle_mount} returned a "
                    f"token that does not authenticate. Check the role's token_ttl "
                    f"and that the token is not already expired."
                )
            else:
                detail = (
                    "vault: VAULT_TOKEN did not authenticate — it is expired, "
                    "revoked, or for a different Vault. For a production host use "
                    "AppRole (VAULT_ROLE_ID + VAULT_SECRET_ID_FILE) instead."
                )
            raise RegistaError(ErrorCode.KEY_LOAD_ERROR, detail)

        self._client = client
        self._auth_method = shape.method
        self._shape = shape
        self._lease_duration = lease
        self._renewable = renewable
        self._deadline = None if not lease or lease <= 0 else time.monotonic() + lease
        self._logins += 1
        _log.info(
            "vault_authenticated",
            auth_method=shape.method,
            role_id_source=shape.role_id_source,
            secret_id_source=shape.secret_id_source,
            approle_mount=shape.approle_mount if shape.method == "approle" else None,
            lease_duration_seconds=lease,
            renewable=renewable,
            logins=self._logins,
        )

    def _token_self_lease(self, client: Any) -> tuple[int | None, bool | None]:
        """Best-effort TTL for a static token; a root token simply has none."""
        try:
            resp = client.auth.token.lookup_self()
        except Exception:
            return None, None
        data = (resp or {}).get("data") or {}
        raw = data.get("ttl")
        ttl = int(raw) if isinstance(raw, (int, float)) else None
        return (ttl if ttl else None), bool(data.get("renewable"))

    def _margin(self) -> float:
        if not self._lease_duration or self._lease_duration <= 0:
            return _VAULT_REAUTH_MARGIN_SECONDS
        return min(_VAULT_REAUTH_MARGIN_SECONDS, self._lease_duration / 2)

    @property
    def _reauthenticatable(self) -> bool:
        """Whether this provider can mint a fresh token on its own.

        True for AppRole (it holds RoleID + SecretID). False for a static
        VAULT_TOKEN — there is nothing to log in with, so an expiry is reported
        rather than papered over.
        """
        return self._auth_method == "approle"

    def _lease_expiring(self) -> bool:
        return self._deadline is not None and time.monotonic() >= self._deadline - self._margin()

    def _get_client(self) -> Any:
        with self._lock:
            if self._client is None:
                self._authenticate()
            elif self._lease_expiring() and self._reauthenticatable:
                # The reason dossier and agent-waked used to wedge an hour after
                # start: the client was cached for the process lifetime while
                # the token behind it had a lease.
                _log.info(
                    "vault_reauthenticating",
                    reason="lease_expiring",
                    auth_method=self._auth_method,
                )
                self._authenticate()
            return self._client

    # -- error mapping ------------------------------------------------------

    def _exc(self, name: str) -> Any:
        return getattr(self._hvac().exceptions, name, None)

    def _is_forbidden(self, e: BaseException) -> bool:
        forbidden = self._exc("Forbidden")
        return forbidden is not None and isinstance(e, forbidden)

    def _token_alive(self) -> bool:
        client = self._client
        if client is None:
            return False
        try:
            return bool(client.is_authenticated())
        except Exception:
            return False

    def _map_error(self, e: BaseException, mount: str, path: str) -> RegistaError:
        """Map an hvac failure to a RegistaError. Contract §4: no tracebacks.

        Exception *text* is never interpolated — only its type — so a backend
        message can never smuggle secret material into the error envelope
        (contract §3, redaction).
        """
        where = f"{mount}/{path}"
        if self._is_forbidden(e):
            method = self._auth_method or "unknown"
            return RegistaError(
                ErrorCode.SECRET_RESOLVE_FAILED,
                f"vault: permission denied reading {where} (HTTP 403). The "
                f"{method} credential authenticated, so this is its policy, not "
                f"its identity: grant read on {mount}/data/{path} (and "
                f"{mount}/metadata/{path}) to the role's policy, or point the ref "
                f"at a path the policy already covers.",
                detail={
                    "auth_method": method,
                    "mount": mount,
                    "path": path,
                    "required_capabilities": [
                        f"read on {mount}/data/{path}",
                        f"read on {mount}/metadata/{path}",
                    ],
                    "token_valid": True,
                },
            )
        invalid_path = self._exc("InvalidPath")
        if invalid_path is not None and isinstance(e, invalid_path):
            return RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                f"vault: no secret at {where} — the path does not exist, is not a "
                f"KV v2 mount, or its latest version is deleted. Note the ref "
                f"shape is mount/path/field with the field LAST.",
                detail={"vault_absent": True},
            )
        for name, code in (
            ("VaultDown", ErrorCode.SECRET_RESOLVE_FAILED),
            ("Unauthorized", ErrorCode.KEY_LOAD_ERROR),
            ("InternalServerError", ErrorCode.SECRET_RESOLVE_FAILED),
        ):
            exc_type = self._exc(name)
            if exc_type is not None and isinstance(e, exc_type):
                return RegistaError(
                    code,
                    f"vault: {where} could not be read — {name}. "
                    f"auth_method={self._auth_method or 'unknown'}.",
                )
        return RegistaError(
            ErrorCode.SECRET_RESOLVE_FAILED,
            f"vault: read of {where} failed ({type(e).__name__}). "
            f"auth_method={self._auth_method or 'unknown'}.",
        )

    def _call(self, op: str, mount: str, path: str, fn: Any) -> Any:
        """Run one Vault call, re-authenticating once if the token is dead.

        A 403 from Vault is ambiguous: it is both "your policy forbids this" and
        "your token is no longer valid". They are told apart by asking whether
        the token still validates — so a genuine policy denial is reported
        immediately instead of triggering a login loop, and an expired lease is
        recovered from instead of being reported as a permissions problem.
        """
        client = self._get_client()
        try:
            return fn(client)
        except RegistaError:
            raise
        except Exception as e:
            if self._is_forbidden(e) and self._reauthenticatable and not self._token_alive():
                _log.info(
                    "vault_reauthenticating",
                    reason="token_rejected",
                    auth_method=self._auth_method,
                    operation=op,
                )
                with self._lock:
                    self._authenticate()
                    client = self._client
                try:
                    return fn(client)
                except RegistaError:
                    raise
                except Exception as retry_exc:
                    raise self._map_error(retry_exc, mount, path) from retry_exc
            raise self._map_error(e, mount, path) from e

    # -- SecretProvider -----------------------------------------------------

    def _read_secret(
        self, mount: str, path: str, *, absent_ok: bool = False
    ) -> dict[str, Any] | None:
        """Read the KV v2 data map at ``mount/path``.

        ``absent_ok`` returns ``None`` for a path that genuinely does not exist,
        which is what makes ``delete`` idempotent. It deliberately does **not**
        widen to other failures: a 403 answered with "already absent" would tell
        an operator their key was gone when nothing was ever looked at.
        """
        try:
            resp = self._call(
                "read",
                mount,
                path,
                lambda c: c.secrets.kv.v2.read_secret_version(
                    path=path, mount_point=mount, raise_on_deleted_version=True
                ),
            )
        except RegistaError as e:
            if absent_ok and isinstance(e.detail, dict) and e.detail.get("vault_absent"):
                return None
            raise
        data = ((resp or {}).get("data") or {}).get("data")
        if not isinstance(data, dict):
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                f"vault: {mount}/{path} returned no secret data.",
            )
        return data

    def resolve(self, ref: str) -> bytes:
        mount, path, key_name = _split_vault_ref(ref)
        data = self._read_secret(mount, path) or {}
        if key_name not in data:
            raise RegistaError(
                ErrorCode.KEY_LOAD_ERROR,
                f"vault: key {key_name!r} not found at {mount}/{path}",
            )
        val = data[key_name]
        if isinstance(val, bytes):
            return val
        return str(val).encode("utf-8")

    def store(self, ref: str, data: bytes) -> str:
        import base64

        mount, path, key_name = _split_vault_ref(ref)
        encoded = base64.b64encode(data).decode("ascii")
        self._call(
            "write",
            mount,
            path,
            lambda c: c.secrets.kv.v2.create_or_update_secret(
                path=path, mount_point=mount, secret={key_name: encoded}
            ),
        )
        return f"vault:{ref}"

    def delete(self, ref: str) -> DeleteOutcome:
        mount, path, key_name = _split_vault_ref(ref)
        # Only a genuinely absent path is "already absent" — every other failure
        # (a 403 above all) propagates. The old code answered `except Exception:
        # return ALREADY_ABSENT`, which reported a permission denial as a
        # successful deletion.
        existing = self._read_secret(mount, path, absent_ok=True)
        if existing is None:
            return DeleteOutcome.ALREADY_ABSENT
        data = dict(existing)
        if key_name not in data:
            return DeleteOutcome.ALREADY_ABSENT
        del data[key_name]
        if data:
            # Other keys share this path — rewrite without ours rather
            # than destroying secrets that are not ours to remove.
            self._call(
                "write",
                mount,
                path,
                lambda c: c.secrets.kv.v2.create_or_update_secret(
                    path=path, mount_point=mount, secret=data
                ),
            )
        else:
            # Destroy every version: a soft delete leaves the material
            # recoverable, which is not what an offboarding is asking for.
            self._call(
                "destroy",
                mount,
                path,
                lambda c: c.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=path, mount_point=mount
                ),
            )
        return DeleteOutcome.DELETED

    # -- reporting ----------------------------------------------------------

    def auth_status(self, *, probe: bool = False) -> dict[str, Any]:
        """Report the auth method, never the credentials.

        ``configured_*`` comes from the environment alone. ``active_*`` is
        populated once a login has actually happened; ``probe=True`` forces one
        so a caller can distinguish "declared AppRole" from "AppRole works".
        """
        shape = _vault_auth_shape(self._env())
        status: dict[str, Any] = {
            "provider_available": True,
            "vault_addr_set": bool(self._env().get("VAULT_ADDR")),
        }
        status.update(shape.to_dict())
        if probe:
            try:
                self._get_client()
            except RegistaError as e:
                status["probe_ok"] = False
                status["probe_error"] = e.message
            else:
                status["probe_ok"] = True
                status["probe_error"] = None
        expires_in: float | None = None
        if self._deadline is not None:
            expires_in = round(max(0.0, self._deadline - time.monotonic()), 1)
        status.update(
            {
                "active_method": self._auth_method,
                "authenticated": self._client is not None,
                "lease_duration_seconds": self._lease_duration,
                "expires_in_seconds": expires_in,
                "renewable": self._renewable,
                "reauthenticatable": self._reauthenticatable,
                "logins": self._logins,
            }
        )
        return status


def vault_auth_status(*, probe: bool = False) -> dict[str, Any]:
    """Which Vault auth method this process is using, and its lease.

    Answers WI-228's "a host cannot silently be on the weaker method". Contains
    no credential values — only where each one came from. Safe to print, log and
    put in a doctor report.
    """
    provider = _PROVIDERS.get("vault")
    if provider is None:
        return {
            "provider_available": False,
            "vault_addr_set": bool(os.environ.get("VAULT_ADDR")),
            "configured_method": None,
            "configured_error": (
                "vault: provider not registered in this process — 'hvac' is not "
                "importable here. Each component resolves vault: refs in its own "
                "environment, so install the vault extra for this component."
            ),
            "active_method": None,
            "authenticated": False,
        }
    status = getattr(provider, "auth_status", None)
    if status is None:  # pragma: no cover - third-party provider
        return {
            "provider_available": True,
            "configured_method": None,
            "configured_error": "vault: registered provider does not report its auth method",
            "active_method": None,
            "authenticated": False,
        }
    return dict(status(probe=probe))


def try_register_azure() -> None:
    try:
        from azure.identity import DefaultAzureCredential  # type: ignore[import-untyped]
        from azure.keyvault.secrets import SecretClient  # type: ignore[import-untyped]
    except ImportError:
        return

    class AzureProvider:
        name: str = "azure"

        def __init__(self) -> None:
            self._client: Any = None

        def _get_client(self) -> Any:
            if self._client is not None:
                return self._client
            vault_name = os.environ.get("AZURE_KEY_VAULT_NAME")
            if not vault_name:
                raise RegistaError(
                    ErrorCode.KEY_LOAD_ERROR,
                    "azure: AZURE_KEY_VAULT_NAME not set",
                )
            vault_url = f"https://{vault_name}.vault.azure.net"
            credential = DefaultAzureCredential()
            self._client = SecretClient(vault_url=vault_url, credential=credential)
            return self._client

        def resolve(self, ref: str) -> bytes:
            client = self._get_client()
            secret = client.get_secret(ref)
            return secret.value.encode("utf-8")

        def store(self, ref: str, data: bytes) -> str:
            import base64

            client = self._get_client()
            encoded = base64.b64encode(data).decode("ascii")
            client.set_secret(ref, encoded)
            return f"azure:{ref}"

        def delete(self, ref: str) -> DeleteOutcome:
            from azure.core.exceptions import (  # type: ignore[import-untyped]
                ResourceNotFoundError,
            )

            client = self._get_client()
            try:
                poller = client.begin_delete_secret(ref)
            except ResourceNotFoundError:
                return DeleteOutcome.ALREADY_ABSENT
            # Block until the delete lands; the caller is about to report the
            # key gone, so returning while it is still in flight would make
            # that report a guess.
            poller.wait()
            try:
                # On a soft-delete-enabled vault the secret is recoverable
                # until purged, which is not "gone". Purge when we are allowed
                # to; report honestly when we are not.
                client.purge_deleted_secret(ref)
            except Exception:
                raise RegistaError(
                    ErrorCode.SECRET_WRITE_UNSUPPORTED,
                    f"azure: {ref!r} was deleted but could not be purged — it "
                    f"stays recoverable until the soft-delete window expires "
                    f"or an operator with purge rights removes it",
                ) from None
            return DeleteOutcome.DELETED

    register_provider(AzureProvider())


try_register_vault()
try_register_azure()


def try_register_windows() -> None:
    if sys.platform != "win32":
        return

    class WindowsProvider:
        name: str = "windows"

        def resolve(self, ref: str) -> bytes:
            import base64

            try:
                encrypted = base64.b64decode(ref)
            except Exception as e:
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    f"windows: ref is not valid base64: {e!s}",
                ) from e

            try:
                return _dpapi_unprotect_ctypes(encrypted)
            except RegistaError:
                return _dpapi_unprotect_dotnet(encrypted)

        def store(self, ref: str, data: bytes) -> str:
            blob = protect_windows_secret(data)
            return f"windows:{blob}"

        def delete(self, ref: str) -> DeleteOutcome:
            # A `windows:` ref carries the DPAPI blob itself — there is no
            # credential-store entry behind it. Every copy of the reference is
            # a copy of the secret, so removing the reference is the deletion.
            return DeleteOutcome.INLINE_REF

    register_provider(WindowsProvider())


_win_dpapi_cache: dict[str, Any] | None = None
_win_dpapi_lock = threading.Lock()


def _win_dpapi_bindings() -> dict[str, Any]:
    global _win_dpapi_cache
    if _win_dpapi_cache is not None:
        return _win_dpapi_cache

    with _win_dpapi_lock:
        if _win_dpapi_cache is not None:
            return _win_dpapi_cache

    import ctypes
    import ctypes.wintypes

    class _DataBlob(ctypes.Structure):
        _fields_ = [
            ("cbData", ctypes.wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt32.CryptProtectData.restype = ctypes.wintypes.BOOL
    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    crypt32.CryptUnprotectData.restype = ctypes.wintypes.BOOL
    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    _win_dpapi_cache = {
        "ctypes": ctypes,
        "crypt32": crypt32,
        "kernel32": kernel32,
        "data_blob": _DataBlob,
        "cryptprotect_local_machine": 0x1,
    }
    return _win_dpapi_cache


def _dpapi_unprotect_ctypes(encrypted: bytes) -> bytes:
    b = _win_dpapi_bindings()
    ctypes_mod = b["ctypes"]

    in_blob = b["data_blob"]()
    in_buf = ctypes_mod.create_string_buffer(encrypted, len(encrypted))
    in_blob.cbData = len(encrypted)
    in_blob.pbData = ctypes_mod.cast(in_buf, ctypes_mod.POINTER(ctypes_mod.c_char))

    out_blob = b["data_blob"]()
    ok = b["crypt32"].CryptUnprotectData(
        ctypes_mod.byref(in_blob), None, None, None, None,
        b["cryptprotect_local_machine"],
        ctypes_mod.byref(out_blob),
    )
    if not ok:
        err = ctypes_mod.get_last_error()
        raise RegistaError(
            ErrorCode.SECRET_RESOLVE_FAILED,
            f"windows: CryptUnprotectData failed (Win32 error {err})",
        )
    try:
        return ctypes_mod.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        b["kernel32"].LocalFree(out_blob.pbData)


def _dpapi_protect_ctypes(data: bytes) -> bytes:
    b = _win_dpapi_bindings()
    ctypes_mod = b["ctypes"]

    in_blob = b["data_blob"]()
    in_buf = ctypes_mod.create_string_buffer(data, len(data))
    in_blob.cbData = len(data)
    in_blob.pbData = ctypes_mod.cast(in_buf, ctypes_mod.POINTER(ctypes_mod.c_char))

    out_blob = b["data_blob"]()
    ok = b["crypt32"].CryptProtectData(
        ctypes_mod.byref(in_blob), None, None, None, None,
        b["cryptprotect_local_machine"],
        ctypes_mod.byref(out_blob),
    )
    if not ok:
        err = ctypes_mod.get_last_error()
        raise RegistaError(
            ErrorCode.SECRET_RESOLVE_FAILED,
            f"windows: CryptProtectData failed (Win32 error {err})",
        )
    try:
        return ctypes_mod.string_at(out_blob.pbData, out_blob.cbData)
    finally:
        b["kernel32"].LocalFree(out_blob.pbData)


def _dpapi_unprotect_dotnet(encrypted: bytes) -> bytes:
    import base64
    import subprocess

    b64_input = base64.b64encode(encrypted).decode("ascii")
    ps_script = (
        "Add-Type -AssemblyName System.Security;"
        f"$b=[Convert]::FromBase64String('{b64_input}');"
        "$d=[System.Security.Cryptography.ProtectedData]::Unprotect("
        "$b,$null,[System.Security.Cryptography.DataProtectionScope]::LocalMachine);"
        "[Convert]::ToBase64String($d)"
    )
    result = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", ps_script],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise RegistaError(
            ErrorCode.SECRET_RESOLVE_FAILED,
            "windows: DPAPI unprotect via .NET failed",
        )
    return base64.b64decode(result.stdout.strip())


def _dpapi_protect_dotnet(data: bytes) -> bytes:
    import base64
    import subprocess

    b64_input = base64.b64encode(data).decode("ascii")
    ps_script = (
        "Add-Type -AssemblyName System.Security;"
        f"$b=[Convert]::FromBase64String('{b64_input}');"
        "$e=[System.Security.Cryptography.ProtectedData]::Protect("
        "$b,$null,[System.Security.Cryptography.DataProtectionScope]::LocalMachine);"
        "[Convert]::ToBase64String($e)"
    )
    result = subprocess.run(
        ["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", ps_script],
        capture_output=True, text=True, timeout=15,
    )
    if result.returncode != 0:
        raise RegistaError(
            ErrorCode.SECRET_RESOLVE_FAILED,
            "windows: DPAPI protect via .NET failed",
        )
    return base64.b64decode(result.stdout.strip())


def protect_windows_secret(data: bytes) -> str:
    if sys.platform != "win32":
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "windows: DPAPI protection is only available on win32",
        )

    import base64

    try:
        encrypted = _dpapi_protect_ctypes(data)
    except RegistaError:
        encrypted = _dpapi_protect_dotnet(data)
    return base64.b64encode(encrypted).decode("ascii")


try_register_windows()
