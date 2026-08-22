from __future__ import annotations

import json
import uuid

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._v6_writer import append_v6_event
from regista._verification import parse_v6_envelope_strict
from regista.testing import (
    InMemoryRegista,
    make_v6_keyset,
    open_v6_epoch,
    set_v6_producer_env,
    v6_producer,
)


def test_installed_public_fixture_opens_a_scoped_note_epoch(tmp_path, monkeypatch) -> None:
    for variable in (
        "REGISTA_PRODUCER_HARNESS",
        "REGISTA_PRODUCER_HARNESS_VERSION",
        "REGISTA_PRODUCER_MODEL",
        "REGISTA_PRODUCER_MODEL_LINEAGE",
    ):
        monkeypatch.delenv(variable, raising=False)

    keyset = make_v6_keyset(
        tmp_path,
        principals=("agent:writer", "agent:not-accepted"),
    )
    entries = json.loads((tmp_path / "v6_keys.json").read_text(encoding="utf-8"))["keys"]
    assert {entry["principal_id"] for entry in entries} == {
        "service:regista-genesis",
        "agent:writer",
        "agent:not-accepted",
    }
    assert all(
        entry["scheme"] == "ed25519" and entry["role"] == "actor" and entry["status"] == "active"
        for entry in entries
    )
    instance = InMemoryRegista(project="public-v6-testing", hmac_key_path=keyset.path)
    try:
        genesis = open_v6_epoch(
            instance,
            keyset,
            principals=("agent:writer",),
            entity_kinds=("note",),
        )
        assert genesis.principal_id == "service:regista-genesis"
        assert set_v6_producer_env() == v6_producer()
        assert keyset.path == str(tmp_path / "v6_keys.json")

        with instance._mgr.transaction() as conn:
            note = append_v6_event(
                conn,
                instance._keys,
                entity_kind="note",
                entity_id=uuid.uuid4(),
                transition="created",
                actor_id="agent:writer",
                actor_kind="agent",
                producer=v6_producer(),
                payload={"text": "fixture"},
            )
        assert note.principal_id == "agent:writer"

        with pytest.raises(RegistaError) as refused:
            with instance._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    instance._keys,
                    entity_kind="note",
                    entity_id=uuid.uuid4(),
                    transition="created",
                    actor_id="agent:not-accepted",
                    actor_kind="agent",
                    producer=v6_producer(),
                )
        assert refused.value.code is ErrorCode.KEY_BINDING_UNRESOLVED

        accepted = next(
            event
            for event in instance._store.all_events()
            if event.transition == "principal_key_accepted"
            and event.payload["principal_id"] == "agent:writer"
        )
        envelope = parse_v6_envelope_strict(bytes(accepted.canonical_envelope))
        assert envelope["payload"]["scopes"]["entity_kinds"] == ["note"]
    finally:
        instance.close()
