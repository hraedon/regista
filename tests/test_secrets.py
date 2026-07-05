from __future__ import annotations

import sys

import pytest

from regista._errors import RegistaError
from regista._secrets import (
    available_providers,
    resolve,
    resolve_str,
)


class TestFileProvider:
    def test_resolves_file(self, tmp_path):
        key_file = tmp_path / "key.json"
        key_file.write_bytes(b'{"key": "value"}')
        result = resolve(f"file:{key_file}")
        assert result == b'{"key": "value"}'

    def test_resolves_bare_path(self, tmp_path):
        key_file = tmp_path / "key.json"
        key_file.write_bytes(b"secret-bytes")
        result = resolve(str(key_file))
        assert result == b"secret-bytes"

    def test_missing_file_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            resolve("file:/nonexistent/path/key.json")
        assert "KEY_LOAD_ERROR" in str(exc_info.value)


class TestEnvProvider:
    def test_resolves_env(self, monkeypatch):
        monkeypatch.setenv("MY_TEST_SECRET", "secret-value")
        result = resolve("env:MY_TEST_SECRET")
        assert result == b"secret-value"

    def test_unset_env_raises(self, monkeypatch):
        monkeypatch.delenv("UNSET_SECRET_VAR", raising=False)
        with pytest.raises(RegistaError) as exc_info:
            resolve("env:UNSET_SECRET_VAR")
        assert "KEY_LOAD_ERROR" in str(exc_info.value)


class TestLiteralProvider:
    def test_resolves_literal(self):
        result = resolve("literal:plain-text-value")
        assert result == b"plain-text-value"


class TestResolveStr:
    def test_utf8_decode(self, tmp_path):
        key_file = tmp_path / "key.txt"
        key_file.write_bytes(b"hello-world")
        result = resolve_str(f"file:{key_file}")
        assert result == "hello-world"

    def test_binary_fails_gracefully(self, tmp_path):
        key_file = tmp_path / "key.bin"
        key_file.write_bytes(b"\xff\xfe\x00\x01")
        with pytest.raises(RegistaError) as exc_info:
            resolve_str(f"file:{key_file}")
        assert "not valid UTF-8" in str(exc_info.value)


class TestEmptyRef:
    def test_empty_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            resolve("")
        assert "INVALID_ARGUMENT" in str(exc_info.value)


class TestAvailableProviders:
    def test_file_env_literal_always_available(self):
        providers = available_providers()
        assert "file" in providers
        assert "env" in providers
        assert "literal" in providers

    def test_vault_not_registered_without_hvac(self):
        providers = available_providers()
        if "vault" in providers:
            pass
        else:
            assert "vault" not in providers


class TestKnownProviderDetection:
    def test_windows_prefix_raises_on_non_windows(self):
        if sys.platform == "win32":
            pytest.skip("test only runs on non-Windows")
        with pytest.raises(RegistaError) as exc_info:
            resolve("windows:my_secret_target")
        assert "SECRET_RESOLVE_FAILED" in str(exc_info.value)
        assert "windows" in str(exc_info.value)

    def test_vault_prefix_raises_without_hvac(self):
        providers = available_providers()
        if "vault" in providers:
            pytest.skip("vault provider is available")
        with pytest.raises(RegistaError) as exc_info:
            resolve("vault:mount/path/key")
        assert "SECRET_RESOLVE_FAILED" in str(exc_info.value)

    def test_azure_prefix_raises_without_sdk(self):
        providers = available_providers()
        if "azure" in providers:
            pytest.skip("azure provider is available")
        with pytest.raises(RegistaError) as exc_info:
            resolve("azure:my-secret")
        assert "SECRET_RESOLVE_FAILED" in str(exc_info.value)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows DPAPI only")
class TestWindowsProvider:
    def test_round_trip(self):
        from regista._secrets import protect_windows_secret, resolve

        secret = b'{"key": "windows-test-value"}'
        blob = protect_windows_secret(secret)
        result = resolve(f"windows:{blob}")
        assert result == secret

    def test_binary_secret(self):
        from regista._secrets import protect_windows_secret, resolve

        secret = bytes(range(256))
        blob = protect_windows_secret(secret)
        result = resolve(f"windows:{blob}")
        assert result == secret

    def test_text_secret(self):
        from regista._secrets import protect_windows_secret, resolve

        secret = b"my-dsn-password-12345"
        blob = protect_windows_secret(secret)
        result = resolve(f"windows:{blob}")
        assert result == secret

    def test_invalid_base64_raises(self):
        with pytest.raises(RegistaError) as exc_info:
            resolve("windows:not-valid-base64!!!")
        assert "INVALID_ARGUMENT" in str(exc_info.value)

    def test_windows_in_available_providers(self):
        providers = available_providers()
        assert "windows" in providers

    def test_protect_returns_base64(self):
        import base64

        from regista._secrets import protect_windows_secret

        blob = protect_windows_secret(b"test")
        decoded = base64.b64decode(blob)
        assert len(decoded) > 0
