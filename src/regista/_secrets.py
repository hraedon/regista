from __future__ import annotations

import os
import sys
import threading
import uuid
from enum import Enum
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ._errors import ErrorCode, RegistaError


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


def try_register_vault() -> None:
    try:
        import hvac  # type: ignore[import-untyped]
    except ImportError:
        return

    class VaultProvider:
        name: str = "vault"

        def __init__(self) -> None:
            self._client: Any = None

        def _get_client(self) -> Any:
            if self._client is not None:
                return self._client
            url = os.environ.get("VAULT_ADDR")
            if not url:
                raise RegistaError(
                    ErrorCode.KEY_LOAD_ERROR,
                    "vault: VAULT_ADDR not set",
                )
            self._client = hvac.Client(url=url)
            token = os.environ.get("VAULT_TOKEN")
            if token:
                self._client.token = token
            if not self._client.is_authenticated():
                raise RegistaError(
                    ErrorCode.KEY_LOAD_ERROR,
                    "vault: authentication failed",
                )
            return self._client

        def resolve(self, ref: str) -> bytes:
            client = self._get_client()
            parts = ref.split("/")
            if len(parts) < 4:
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    f"vault: ref must be mount/path/key, got {ref!r}",
                )
            mount = parts[0]
            key_name = parts[-1]
            path = "/".join(parts[1:-1])
            resp = client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=mount,
            )
            data = resp["data"]["data"]
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

            client = self._get_client()
            parts = ref.split("/")
            if len(parts) < 4:
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    f"vault: ref must be mount/path/key, got {ref!r}",
                )
            mount = parts[0]
            key_name = parts[-1]
            path = "/".join(parts[1:-1])
            encoded = base64.b64encode(data).decode("ascii")
            client.secrets.kv.v2.create_or_update_secret(
                path=path,
                mount_point=mount,
                secret={key_name: encoded},
            )
            return f"vault:{ref}"

        def delete(self, ref: str) -> DeleteOutcome:
            client = self._get_client()
            parts = ref.split("/")
            if len(parts) < 4:
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    f"vault: ref must be mount/path/key, got {ref!r}",
                )
            mount = parts[0]
            key_name = parts[-1]
            path = "/".join(parts[1:-1])
            try:
                resp = client.secrets.kv.v2.read_secret_version(
                    path=path, mount_point=mount
                )
            except Exception:
                return DeleteOutcome.ALREADY_ABSENT
            data = dict(resp["data"]["data"])
            if key_name not in data:
                return DeleteOutcome.ALREADY_ABSENT
            del data[key_name]
            if data:
                # Other keys share this path — rewrite without ours rather
                # than destroying secrets that are not ours to remove.
                client.secrets.kv.v2.create_or_update_secret(
                    path=path, mount_point=mount, secret=data
                )
            else:
                # Destroy every version: a soft delete leaves the material
                # recoverable, which is not what an offboarding is asking for.
                client.secrets.kv.v2.delete_metadata_and_all_versions(
                    path=path, mount_point=mount
                )
            return DeleteOutcome.DELETED

    register_provider(VaultProvider())


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
