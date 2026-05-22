from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from substrate._keys import KeySet

KEY_PATH = str(Path(__file__).parent / "test_keys.json")


def _write_temp_keys(keys: list[dict]) -> str:
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False,
    )
    json.dump({"keys": keys}, f)
    f.close()
    return f.name


class TestEnvVarOverridesFile:
    def test_env_var_value_used_over_file(self) -> None:
        path = _write_temp_keys([
            {"key_id": "key-2024-01", "secret": "file_secret", "status": "active"},
        ])
        env = {"SUBSTRATE_HMAC_KEY_KEY_2024_01": "env_secret_value"}
        with patch.dict("os.environ", env, clear=False):
            ks = KeySet(path)
        entry = ks.get_key("key-2024-01")
        assert entry.secret == b"env_secret_value"


class TestFileUsedWhenNoEnvVar:
    def test_file_value_used_when_no_env(self) -> None:
        path = _write_temp_keys([
            {"key_id": "key-2024-01", "secret": "file_secret", "status": "active"},
        ])
        with patch.dict("os.environ", {}, clear=True):
            ks = KeySet(path)
        entry = ks.get_key("key-2024-01")
        assert entry.secret == b"file_secret"


class TestMixedEnvAndFile:
    def test_some_keys_from_env_some_from_file(self) -> None:
        path = _write_temp_keys([
            {"key_id": "key-alpha", "secret": "alpha_file", "status": "active"},
            {"key_id": "key-beta", "secret": "beta_file", "status": "deprecated"},
        ])
        env = {"SUBSTRATE_HMAC_KEY_KEY_ALPHA": "alpha_env"}
        with patch.dict("os.environ", env, clear=False):
            ks = KeySet(path)
        assert ks.get_key("key-alpha").secret == b"alpha_env"
        assert ks.get_key("key-beta").secret == b"beta_file"


class TestKeySourceLogging:
    def test_key_sources_distinguishes_env_vs_file(self) -> None:
        path = _write_temp_keys([
            {"key_id": "k-a", "secret": "sa", "status": "active"},
            {"key_id": "k-b", "secret": "sb", "status": "deprecated"},
        ])
        env = {"SUBSTRATE_HMAC_KEY_K_A": "env_sa"}
        sources: dict[str, str] = {}

        def capture_keys_loaded(event, **kwargs):
            if event == "keys_loaded":
                passed_sources = kwargs.get("key_sources")
                if passed_sources is not None:
                    sources.update(passed_sources)

        with patch.dict("os.environ", env, clear=False):
            with patch("substrate._keys.log.info", side_effect=capture_keys_loaded):
                KeySet(path)

        assert sources == {"k-a": "env", "k-b": "file"}


class TestCustomEnvPrefix:
    def test_custom_prefix_respected(self) -> None:
        path = _write_temp_keys([
            {"key_id": "my-key", "secret": "file_val", "status": "active"},
        ])
        env = {"CUSTOM_PREFIX_MY_KEY": "env_val"}
        with patch.dict("os.environ", env, clear=False):
            ks = KeySet(path, env_prefix="CUSTOM_PREFIX_")
        assert ks.get_key("my-key").secret == b"env_val"
