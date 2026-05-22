from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from substrate._errors import ErrorCode, SubstrateError
from substrate._keys import KeySet

KEY_PATH = str(Path(__file__).parent / "test_keys.json")


def _write_temp_keys(keys: list[dict]) -> str:
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    )
    json.dump({"keys": keys}, f)
    f.close()
    return f.name


class TestKeySetLoadBaseline:
    def test_loads_standard_keys(self) -> None:
        ks = KeySet(KEY_PATH)
        assert ks.key_count == 1
        assert ks.active_key().key_id == "test-key-001"


class TestKeySetUnknownStatus:
    def test_raises_on_unknown_status(self) -> None:
        path = _write_temp_keys([
            {"key_id": "k1", "secret": "c2VjcmV0", "status": "unknown_value"}
        ])
        with pytest.raises(SubstrateError) as exc_info:
            KeySet(path)
        assert exc_info.value.code == ErrorCode.KEY_LOAD_ERROR
        assert "k1" in exc_info.value.message
        assert "unknown_value" in exc_info.value.message


class TestKeySetExpectedCount:
    def test_raises_on_count_mismatch(self) -> None:
        path = _write_temp_keys([
            {"key_id": "k1", "secret": "c2VjcmV0", "status": "active"}
        ])
        with pytest.raises(SubstrateError) as exc_info:
            KeySet(path, expected_key_count=5)
        assert exc_info.value.code == ErrorCode.KEY_LOAD_ERROR
        assert "5" in exc_info.value.message
        assert "1" in exc_info.value.message

    def test_default_none_does_not_raise(self) -> None:
        ks = KeySet(KEY_PATH, expected_key_count=None)
        assert ks.key_count == 1

    def test_matching_count_does_not_raise(self) -> None:
        ks = KeySet(KEY_PATH, expected_key_count=1)
        assert ks.key_count == 1
