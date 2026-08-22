"""Tests for the public, read-only trust-log verification seam."""

from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest

import regista
from regista import ErrorCode, Regista, RegistaError, TrustLogVerificationReport


class _Connection:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def execute(self, statement: str) -> None:
        self.statements.append(statement)


class _Manager:
    def __init__(self) -> None:
        self.connection = _Connection()

    @contextmanager
    def transaction(self):
        yield self.connection


def _handle(*, genesis: dict[str, Any] | None) -> tuple[Regista, _Manager]:
    manager = _Manager()
    handle = object.__new__(Regista)
    handle._mgr = manager
    handle._trust_genesis_document = genesis
    return handle, manager


def test_verify_trust_log_is_public_read_only_and_typed(monkeypatch) -> None:
    handle, manager = _handle(genesis={"type": "regista.trust-genesis"})
    called: dict[str, Any] = {}

    def fake_verify(conn: Any, document: dict[str, Any]) -> Any:
        called["connection"] = conn
        called["document"] = document
        return SimpleNamespace(
            verified=(object(), object()),
            event_count=3,
            state=SimpleNamespace(
                identity=SimpleNamespace(trust_domain_id="domain-1"),
                genesis_event_hash="sha256:genesis",
            ),
        )

    monkeypatch.setattr(regista._trust_log_writer, "verify_trust_log_chain", fake_verify)

    report = handle.verify_trust_log()

    assert isinstance(report, TrustLogVerificationReport)
    assert report.to_dict() == {
        "verified": True,
        "event_count": 3,
        "trust_domain_id": "domain-1",
        "genesis_event_hash": "sha256:genesis",
    }
    assert called == {
        "connection": manager.connection,
        "document": {"type": "regista.trust-genesis"},
    }
    assert manager.connection.statements == ["SET TRANSACTION READ ONLY"]
    assert not hasattr(report, "connection")
    assert not hasattr(report, "manager")


def test_verify_trust_log_fails_closed_without_pinned_genesis() -> None:
    handle, manager = _handle(genesis=None)

    with pytest.raises(RegistaError) as exc_info:
        handle.verify_trust_log()

    assert exc_info.value.code is ErrorCode.TRUST_GENESIS_SCHEMA_INVALID
    assert exc_info.value.detail["reason"] == "pinned_genesis_missing"
    assert manager.connection.statements == []
