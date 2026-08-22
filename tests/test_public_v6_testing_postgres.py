from __future__ import annotations

import uuid

from _helpers import DSN

from regista import Regista
from regista._provision import provision
from regista._v6_writer import append_v6_event
from regista.testing import make_v6_keyset, open_v6_epoch, v6_producer


def test_installed_public_fixture_opens_a_scoped_postgres_epoch(tmp_path) -> None:
    from regista.testing import drop_project_schema

    project = "public_v6_" + uuid.uuid4().hex[:12]
    keyset = make_v6_keyset(tmp_path, principals=("agent:writer", "agent:not-accepted"))
    provision(DSN, [project])
    instance = Regista(DSN, project, keyset.path)
    try:
        genesis = open_v6_epoch(instance, keyset, principals=("agent:writer",))
        assert genesis.principal_id == "service:regista-genesis"
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
            )
        assert note.principal_id == "agent:writer"
    finally:
        instance.close()
        drop_project_schema(DSN, project)
