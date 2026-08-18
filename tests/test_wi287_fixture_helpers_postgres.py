"""The WI-287 fixture-migration helpers, proven backend-agnostic on Postgres.

``tests/test_wi287_inmem_parity.py::TestMigrationHarness`` exercises
``_v6_fixtures.open_v6_epoch`` / ``register_test_workflow`` against
``InMemoryRegista``, and must stay database-free so the in-memory parity suite
runs on a machine with no Postgres. But the helpers' whole value is that the
epoch-blocked fixture migration can call *one* set of them for both backends, and
"it should work on Postgres too" is a claim, not evidence. This module is the
evidence, and it lives in its own file precisely so the in-memory suite keeps its
no-database property.

Deliberately thin: it asserts only that the helpers do on Postgres what they do in
memory. Every semantic assertion about the writer already lives in
``tests/test_p17_v6_writer.py``, and restating any of it here would be the
duplication the conformance split exists to avoid.
"""

from __future__ import annotations

import uuid

import pytest
from _helpers import DSN
from _v6_fixtures import (
    ACTOR_PRINCIPALS,
    make_v6_keyset,
    open_v6_epoch,
    register_test_workflow,
    v6_producer,
)

from regista import Regista
from regista._errors import ErrorCode, RegistaError
from regista._provision import provision
from regista._v6_writer import append_v6_event

_DEFINITION = {
    "states": ["open", "closed"],
    "initial_state": "open",
    "transitions": [{"name": "close", "from": "open", "to": "closed"}],
}


@pytest.fixture
def keyset(tmp_path):
    return make_v6_keyset(tmp_path)


@pytest.fixture
def project(keyset):
    from regista._testing import drop_project_schema

    name = f"wi287h_{uuid.uuid4().hex[:12]}"
    provision(DSN, [name])
    instance = Regista(DSN, name, keyset.path)
    try:
        yield instance
    finally:
        # WI-243's leak guard fails the whole session on a surviving schema, so
        # teardown is part of the fixture contract rather than politeness.
        instance.close()
        drop_project_schema(DSN, name)


def _kind(principal_id: str) -> str:
    return "agent" if principal_id.startswith("agent:") else "human"


def test_open_v6_epoch_makes_every_actor_principal_appendable(project, keyset) -> None:
    """The same one-call ceremony works on Postgres, principal for principal.

    Asserted by actually appending as each one: both ``resolve_key_binding_anchor``
    and admission gate 2 must be satisfied per principal, and a helper that wrote
    acceptances with wrong scopes would survive a mere count assertion.
    """

    open_v6_epoch(project, keyset)
    for principal_id in ACTOR_PRINCIPALS:
        with project._mgr.transaction() as conn:
            appended = append_v6_event(
                conn,
                project._keys,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="created",
                actor_id=principal_id,
                actor_kind=_kind(principal_id),
                producer=v6_producer(),
            )
        assert appended.principal_id == principal_id
        assert appended.key_id == keyset.key_for(principal_id).key_id


def test_register_test_workflow_satisfies_admission_gate_1(project, keyset) -> None:
    """Gate 1 refuses until the signed registration exists — on Postgres too.

    The refusal is asserted before the positive half so the second assertion
    cannot pass by accident.
    """

    open_v6_epoch(project, keyset)
    with pytest.raises(RegistaError) as exc:
        with project._mgr.transaction() as conn:
            append_v6_event(
                conn,
                project._keys,
                entity_kind="work_item",
                entity_id=uuid.uuid4(),
                transition="close",
                actor_id="agent:worker",
                actor_kind="agent",
                producer=v6_producer(),
                workflow_name="wf",
                workflow_version=1,
            )
    assert exc.value.code is ErrorCode.WORKFLOW_REGISTRATION_UNRESOLVED

    registered = register_test_workflow(project, "wf", 1, _DEFINITION)
    with project._mgr.transaction() as conn:
        appended = append_v6_event(
            conn,
            project._keys,
            entity_kind="work_item",
            entity_id=uuid.uuid4(),
            transition="close",
            actor_id="agent:worker",
            actor_kind="agent",
            producer=v6_producer(),
            workflow_name="wf",
            workflow_version=1,
        )
    assert appended.workflow is not None
    assert appended.workflow.registration_event_hash == registered.event_hash_text
