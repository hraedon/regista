from __future__ import annotations

import pytest

from regista._config import (
    SuiteConfig,
    _parse_env_file,
    resolve,
    resolve_or_raise,
)


class TestParseEnvFile:
    def test_simple_key_value(self, tmp_path):
        f = tmp_path / "suite.env"
        f.write_text("REGISTA_DSN=postgresql://localhost/db\n")
        result = _parse_env_file(f)
        assert result == {"REGISTA_DSN": "postgresql://localhost/db"}

    def test_comments_and_blanks(self, tmp_path):
        f = tmp_path / "suite.env"
        f.write_text(
            "# comment\n"
            "\n"
            "REGISTA_DSN=value\n"
            "  # indented comment\n"
            "REGISTA_KEY_PATH=/path\n"
        )
        result = _parse_env_file(f)
        assert result == {"REGISTA_DSN": "value", "REGISTA_KEY_PATH": "/path"}

    def test_quoted_values(self, tmp_path):
        f = tmp_path / "suite.env"
        f.write_text(
            'REGISTA_DSN="postgresql://host/db"\n'
            "REGISTA_KEY_PATH='/path/to/key'\n"
        )
        result = _parse_env_file(f)
        assert result["REGISTA_DSN"] == "postgresql://host/db"
        assert result["REGISTA_KEY_PATH"] == "/path/to/key"

    def test_nonexistent_file(self, tmp_path):
        result = _parse_env_file(tmp_path / "nonexistent.env")
        assert result == {}


class TestResolve:
    def test_env_takes_precedence_over_files(self, tmp_path):
        user_file = tmp_path / "user.env"
        user_file.write_text("REGISTA_DSN=from_file\n")
        sys_file = tmp_path / "sys.env"

        cfg = resolve(
            env={"REGISTA_DSN": "from_env"},
            user_config=user_file,
            system_config=sys_file,
        )
        assert cfg.dsn == "from_env"
        assert cfg.source["REGISTA_DSN"] == "env"

    def test_user_file_takes_precedence_over_system(self, tmp_path):
        user_file = tmp_path / "user.env"
        user_file.write_text("REGISTA_DSN=from_user\n")
        sys_file = tmp_path / "sys.env"
        sys_file.write_text("REGISTA_DSN=from_system\n")

        cfg = resolve(
            env={},
            user_config=user_file,
            system_config=sys_file,
        )
        assert cfg.dsn == "from_user"
        assert "user" in cfg.source["REGISTA_DSN"]

    def test_system_file_as_fallback(self, tmp_path):
        user_file = tmp_path / "user.env"
        sys_file = tmp_path / "sys.env"
        sys_file.write_text("REGISTA_DSN=from_system\n")

        cfg = resolve(
            env={},
            user_config=user_file,
            system_config=sys_file,
        )
        assert cfg.dsn == "from_system"

    def test_deprecated_alias_resolves(self, tmp_path):
        cfg = resolve(
            env={"REGISTA_HMAC_KEY_PATH": "/path/to/key"},
            user_config=tmp_path / "nonexistent.env",
            system_config=tmp_path / "nonexistent2.env",
        )
        assert cfg.key_path == "/path/to/key"
        assert "env:REGISTA_HMAC_KEY_PATH" in cfg.source.get("REGISTA_KEY_PATH", "")

    def test_canonical_overrides_alias(self, tmp_path):
        cfg = resolve(
            env={
                "REGISTA_KEY_PATH": "/canonical",
                "REGISTA_HMAC_KEY_PATH": "/alias",
            },
            user_config=tmp_path / "nonexistent.env",
            system_config=tmp_path / "nonexistent2.env",
        )
        assert cfg.key_path == "/canonical"

    def test_require_ssl_parsing(self, tmp_path):
        cfg = resolve(
            env={"REGISTA_REQUIRE_SSL": "true"},
            user_config=tmp_path / "nonexistent.env",
            system_config=tmp_path / "nonexistent2.env",
        )
        assert cfg.require_ssl is True

        cfg2 = resolve(
            env={"REGISTA_REQUIRE_SSL": "0"},
            user_config=tmp_path / "nonexistent.env",
            system_config=tmp_path / "nonexistent2.env",
        )
        assert cfg2.require_ssl is False

    def test_all_unset_returns_none(self, tmp_path):
        cfg = resolve(
            env={},
            user_config=tmp_path / "nonexistent.env",
            system_config=tmp_path / "nonexistent2.env",
        )
        assert cfg.dsn is None
        assert cfg.key_path is None
        assert cfg.require_ssl is False
        assert cfg.project is None

    def test_user_file_alias_falls_through_to_system(self, tmp_path):
        user_file = tmp_path / "user.env"
        user_file.write_text("REGISTA_HMAC_KEY_PATH=/from_user_alias\n")
        sys_file = tmp_path / "sys.env"
        sys_file.write_text("REGISTA_DSN=from_sys\n")

        cfg = resolve(
            env={},
            user_config=user_file,
            system_config=sys_file,
        )
        assert cfg.key_path == "/from_user_alias"
        assert cfg.dsn == "from_sys"

    def test_to_dict(self, tmp_path):
        cfg = SuiteConfig(
            dsn="postgresql://localhost/db",
            key_path="/key",
            require_ssl=True,
            project="test",
        )
        d = cfg.to_dict()
        assert d["dsn"] == "postgresql://localhost/db"
        assert d["require_ssl"] is True
        assert d["project"] == "test"


class TestResolveOrRaise:
    def test_raises_on_missing_dsn(self, tmp_path):
        with pytest.raises(Exception) as exc_info:
            resolve_or_raise(
                env={"REGISTA_KEY_PATH": "/key"},
                user_config=tmp_path / "nonexistent.env",
                system_config=tmp_path / "nonexistent2.env",
            )
        assert "REGISTA_DSN" in str(exc_info.value)

    def test_raises_on_missing_key_path(self, tmp_path):
        with pytest.raises(Exception) as exc_info:
            resolve_or_raise(
                env={"REGISTA_DSN": "postgresql://localhost/db"},
                user_config=tmp_path / "nonexistent.env",
                system_config=tmp_path / "nonexistent2.env",
            )
        assert "REGISTA_KEY_PATH" in str(exc_info.value)

    def test_succeeds_with_all_required(self, tmp_path):
        cfg = resolve_or_raise(
            env={
                "REGISTA_DSN": "postgresql://localhost/db",
                "REGISTA_KEY_PATH": "/key",
            },
            user_config=tmp_path / "nonexistent.env",
            system_config=tmp_path / "nonexistent2.env",
        )
        assert cfg.dsn == "postgresql://localhost/db"
        assert cfg.key_path == "/key"
