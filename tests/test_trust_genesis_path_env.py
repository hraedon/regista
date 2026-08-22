from __future__ import annotations

from regista._trust_genesis_file import (
    TRUST_GENESIS_PATH_ENV,
    trust_genesis_path_from_env,
)


def test_canonical_trust_genesis_path_is_resolved(monkeypatch) -> None:
    monkeypatch.setenv(TRUST_GENESIS_PATH_ENV, "/canonical/genesis.json")

    assert trust_genesis_path_from_env() == "/canonical/genesis.json"


def test_missing_trust_genesis_path_is_unconfigured(monkeypatch) -> None:
    monkeypatch.delenv(TRUST_GENESIS_PATH_ENV, raising=False)

    assert trust_genesis_path_from_env() is None
