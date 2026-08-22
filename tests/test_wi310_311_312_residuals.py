from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from regista._action_delegation import action_delegation_revocation_authorized
from regista._errors import ErrorCode, RegistaError
from regista._transition import _verified_prior_delegation_principals
from regista._v6_referents import store_referents


def _revocation_material(transition: str) -> tuple[Any, Any, Any]:
    project = "00000000-0000-0000-0000-000000000001"
    revoker = "service:revoker"
    key_id = "pk_revoker"
    acceptance = {
        "principal_id": revoker,
        "project_instance_id": project,
        "key_id": key_id,
        "scopes": {"may_accept_keys": True},
    }
    payload = (
        acceptance
        if transition == "principal_key_accepted"
        else {"bootstrap_key_acceptance": acceptance}
    )
    binding = SimpleNamespace(
        transition=transition,
        project_instance_id=project,
        payload=payload,
    )
    event = SimpleNamespace(
        actor_principal_id=revoker,
        envelope={
            "project_instance_id": project,
            "signing": {
                "key_binding_event_hash": "sha256:" + "11" * 32,
                "key_id": key_id,
            },
        },
    )
    credential = SimpleNamespace(issuer_principal_id="service:issuer")
    referents = SimpleNamespace(resolve_referent=lambda _event_hash: binding)
    return event, credential, referents


def test_standalone_acceptance_cannot_authorize_delegation_revocation() -> None:
    event, credential, referents = _revocation_material("principal_key_accepted")

    assert not action_delegation_revocation_authorized(event, credential, referents)


@pytest.mark.parametrize(
    "transition", ["project_initialized", "project_cryptographic_epoch_started"]
)
def test_bootstrap_acceptance_can_authorize_delegation_revocation(
    transition: str,
) -> None:
    event, credential, referents = _revocation_material(transition)

    assert action_delegation_revocation_authorized(event, credential, referents)


def test_credential_issuer_can_revoke_without_a_binding_referent() -> None:
    event, credential, _referents = _revocation_material("principal_key_accepted")
    credential.issuer_principal_id = event.actor_principal_id
    referents = SimpleNamespace(
        resolve_referent=lambda _event_hash: pytest.fail("issuer path must return first")
    )

    assert action_delegation_revocation_authorized(event, credential, referents)


class _Result:
    def __init__(self, row: dict[str, Any] | None = None) -> None:
        self._row = row

    def fetchone(self) -> dict[str, Any] | None:
        return self._row

    def fetchall(self) -> list[dict[str, Any]]:
        return []


class _StoreConnection:
    provides_transactional_isolation = True
    cursor = None

    def __init__(self, *, archive_present: bool) -> None:
        self.archive_present = archive_present
        self.queries: list[str] = []

    def execute(self, statement: Any, _params: Any = None) -> _Result:
        rendered = str(statement)
        self.queries.append(rendered)
        if "to_regclass" in rendered:
            return _Result(
                {"relation": "events_archive" if self.archive_present else None}
            )
        if "events_archive" in rendered and not self.archive_present:
            raise AssertionError("events_archive must not be queried when it is absent")
        return _Result()


def test_store_referents_does_not_require_events_archive() -> None:
    conn = _StoreConnection(archive_present=False)
    referents = store_referents(conn)

    assert referents.resolve_referent("sha256:" + "22" * 32) is None
    assert any("to_regclass" in query for query in conn.queries)
    assert all("UNION ALL" not in query for query in conn.queries)


def test_store_referents_includes_events_archive_when_present() -> None:
    conn = _StoreConnection(archive_present=True)
    referents = store_referents(conn)

    assert referents.resolve_referent("sha256:" + "22" * 32) is None
    assert sum("to_regclass" in query for query in conn.queries) == 1
    assert any("UNION ALL" in query for query in conn.queries)


@pytest.mark.parametrize("canonical_envelope", [None, b"not-json"])
def test_prior_delegation_envelope_corruption_fails_closed(
    canonical_envelope: bytes | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("regista._transition._v6_epoch_open", lambda _conn: True)
    event = SimpleNamespace(
        canonical_envelope=canonical_envelope,
        actor_id="agent:author",
        on_behalf_of=None,
    )

    with pytest.raises(RegistaError) as exc_info:
        _verified_prior_delegation_principals(
            SimpleNamespace(),
            (event,),
            include_event=lambda _event: True,
            material=SimpleNamespace(),
        )

    assert exc_info.value.code is ErrorCode.ACTION_DELEGATION_INVALID
    assert "envelope" in exc_info.value.message


@pytest.mark.parametrize("canonical_envelope", [None, b"legacy-envelope"])
def test_legacy_prior_envelope_is_not_reinterpreted_as_v6_corruption(
    canonical_envelope: bytes | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("regista._transition._v6_epoch_open", lambda _conn: False)
    event = SimpleNamespace(
        canonical_envelope=canonical_envelope,
        actor_id="agent:legacy-author",
        on_behalf_of=None,
    )

    principals = _verified_prior_delegation_principals(
        SimpleNamespace(),
        (event,),
        include_event=lambda _event: True,
        material=SimpleNamespace(),
    )

    assert principals == frozenset()


def test_valid_direct_v6_prior_event_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("regista._transition._v6_epoch_open", lambda _conn: True)
    monkeypatch.setattr(
        "regista._verification.parse_v6_envelope_strict",
        lambda _envelope: {"authorization": {"mode": "direct"}},
    )
    event = SimpleNamespace(
        canonical_envelope=b"valid-v6-envelope",
        actor_id="agent:author",
        on_behalf_of=None,
    )

    principals = _verified_prior_delegation_principals(
        SimpleNamespace(),
        (event,),
        include_event=lambda _event: True,
        material=SimpleNamespace(),
    )

    assert principals == frozenset()
