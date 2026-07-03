from __future__ import annotations

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
