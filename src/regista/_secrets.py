from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from ._errors import ErrorCode, RegistaError


@runtime_checkable
class SecretProvider(Protocol):
    name: str

    def resolve(self, ref: str) -> bytes: ...


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


class LiteralProvider:
    name: str = "literal"

    def resolve(self, ref: str) -> bytes:
        return ref.encode("utf-8")


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


def _detect_prefix(ref: str) -> tuple[str, str]:
    if ":" not in ref:
        return "file", ref
    prefix, _, rest = ref.partition(":")
    if prefix in _PROVIDERS:
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
            ErrorCode.SIGNING_SCHEME_NOT_FOUND,
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

    register_provider(AzureProvider())


try_register_vault()
try_register_azure()
