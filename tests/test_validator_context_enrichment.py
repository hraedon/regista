"""Plan 020 + Plan 021 — ValidatorContext enrichment.

Migrated (WI-305 A) to a genuine v6 epoch: canonical actor principals with accepted
keys, `open_v6_epoch`, and the signed workflow registration emitted by
``register_workflow``. ``on_behalf_of`` principals are delegation data, not signers,
so they need no key of their own.

Verifies that sync transition validators receive the acting actor's
``actor_kind``, the work-item's pre-transition event history, and the acting
actor's ``on_behalf_of`` delegation chain on both the InMemory and Postgres
backends, that non-validator transitions are unaffected, and that
``ValidatorContext`` serialization round-trips the new fields while tolerating
their absence (forward-compat with pre-Plan-020/021 payloads).
"""
from __future__ import annotations

import uuid

import pytest
from _helpers import DSN

from regista._types import ValidatorContext
from regista.testing import InMemoryRegista, drop_project_schema
from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

#: Every signer actor in this file, each with an accepted key in the v6 epoch.
CTX_PRINCIPALS = (
    "human:creator",
    "human:preparer",
    "human:finisher",
    "human:c",
    "human:p",
    "human:f",
    "human:author",
    "human:author-1",
    "agent:worker",
    "agent:prep-1",
    "agent:reviewer-1",
)

WORKFLOW = """\
name: ctx_enrich_test
version: 1
regista_version: "0.4.0"

states:
  - name: new
    initial: true
  - name: ready
  - name: done
    terminal: true

transitions:
  - name: prepare
    from: new
    to: ready
  - name: finish
    from: ready
    to: done
    validator: record_ctx

roles: []

work_item_types:
  - name: task
    custom_fields: []

link_types: []

attempt_threshold: 99
"""


def _make_recorder() -> tuple[list[ValidatorContext], object]:
    recorded: list[ValidatorContext] = []

    def handler(ctx: ValidatorContext) -> None:
        recorded.append(ctx)

    return recorded, handler


def _setup_ready(sub, *, creator="human:creator", preparer="human:preparer"):
    wi, _ = sub.create_work_item(
        workflow_name="ctx_enrich_test",
        work_item_type="task",
        actor_id=creator,
        actor_kind="agent",
    )
    sub.transition(
        wi.work_item_id, "prepare", preparer,
        actor_kind="agent",
    )
    return wi


@pytest.fixture
def mem_sub(tmp_path) -> InMemoryRegista:
    keyset = make_v6_keyset(tmp_path, principals=CTX_PRINCIPALS)
    s = InMemoryRegista(project="test_ctx020", hmac_key_path=keyset.path)
    open_v6_epoch(s, keyset, principals=CTX_PRINCIPALS)
    s.register_workflow(WORKFLOW)
    yield s
    s.close()


@pytest.fixture(scope="module")
def pg_sub(tmp_path_factory):
    from regista import Regista

    keyset = make_v6_keyset(
        tmp_path_factory.mktemp("ctx_pg_keys"), principals=CTX_PRINCIPALS
    )
    project = f"test_ctx020_{uuid.uuid4().hex[:8]}"
    s = Regista.create_project(DSN, project, keyset.path)
    open_v6_epoch(s, keyset, principals=CTX_PRINCIPALS)
    s.register_workflow(WORKFLOW)
    yield s
    s.close()
    drop_project_schema(DSN, project)


class TestActorKindInMemory:
    @pytest.mark.parametrize("kind", ["human", "agent", "system"])
    def test_recorded_actor_kind(self, mem_sub, kind):
        recorded, handler = _make_recorder()
        mem_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(mem_sub)
        mem_sub.transition(
            wi.work_item_id, "finish", "human:finisher",
            actor_kind=kind,
        )
        assert len(recorded) == 1
        assert recorded[0].actor_kind == kind


class TestPriorEventsInMemory:
    def test_prior_events_match_history(self, mem_sub):
        recorded, handler = _make_recorder()
        mem_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(mem_sub, creator="human:creator", preparer="human:preparer")
        mem_sub.transition(
            wi.work_item_id, "finish", "human:finisher",
            actor_kind="agent",
        )
        assert len(recorded) == 1
        ctx = recorded[0]
        prior = ctx.prior_events
        assert len(prior) == 2
        seqs = [e.event_seq for e in prior]
        assert seqs == sorted(seqs)
        assert seqs == [1, 2]
        assert prior[0].transition == "created"
        assert prior[0].actor_id == "human:creator"
        assert prior[1].transition == "prepare"
        assert prior[1].actor_id == "human:preparer"
        assert ctx.actor_id == "human:finisher"


class TestNoValidatorUnaffectedInMemory:
    def test_non_validator_transition_skips_handler(self, mem_sub):
        recorded, handler = _make_recorder()
        mem_sub.register_validator("record_ctx", handler)
        wi, _ = mem_sub.create_work_item(
            workflow_name="ctx_enrich_test",
            work_item_type="task",
            actor_id="agent:worker",
            actor_kind="agent",
        )
        evt = mem_sub.transition(
            wi.work_item_id, "prepare", "agent:worker",
            actor_kind="agent",
        )
        assert evt.transition == "prepare"
        assert len(recorded) == 0
        refreshed = mem_sub.get_work_item(wi.work_item_id)
        assert refreshed is not None
        assert refreshed.current_state == "ready"


class TestSerializationRoundTrip:
    def test_on_behalf_of_round_trip_with_none(self, mem_sub):
        recorded, handler = _make_recorder()
        mem_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(mem_sub)
        mem_sub.transition(
            wi.work_item_id, "finish", "human:finisher",
            actor_kind="human",
        )
        ctx = recorded[0]
        d = ctx.to_dict()
        assert "on_behalf_of" not in d
        rt = ValidatorContext.from_dict(d)
        assert rt.on_behalf_of is None
        assert rt == ctx


class TestFromDictTolerance:
    def test_missing_new_fields_decode_to_defaults(self):
        base = {
            "work_item_id": str(uuid.uuid4()),
            "workflow_name": "test",
            "workflow_version": 1,
            "work_item_type": "task",
            "current_state": "new",
            "new_state": "done",
            "transition_name": "finish",
            "custom_fields": {},
            "actor_id": "agent:worker",
        }
        ctx = ValidatorContext.from_dict(base)
        assert ctx.actor_kind == "agent"
        assert ctx.prior_events == ()
        assert ctx.on_behalf_of is None


class TestPostgresActorKind:
    def test_recorded_actor_kind(self, pg_sub):
        recorded, handler = _make_recorder()
        pg_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(pg_sub)
        pg_sub.transition(
            wi.work_item_id, "finish", "human:finisher",
            actor_kind="human",
        )
        assert len(recorded) == 1
        assert recorded[0].actor_kind == "human"


class TestPostgresPriorEvents:
    def test_prior_events_match_history(self, pg_sub):
        recorded, handler = _make_recorder()
        pg_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(pg_sub, creator="human:creator", preparer="human:preparer")
        pg_sub.transition(
            wi.work_item_id, "finish", "human:finisher",
            actor_kind="agent",
        )
        assert len(recorded) == 1
        ctx = recorded[0]
        prior = ctx.prior_events
        assert len(prior) == 2
        seqs = [e.event_seq for e in prior]
        assert seqs == sorted(seqs)
        assert seqs == [1, 2]
        assert prior[0].transition == "created"
        assert prior[0].actor_id == "human:creator"
        assert prior[1].transition == "prepare"
        assert prior[1].actor_id == "human:preparer"




class TestOnBehalfOfNoneDefaultInMemory:
    def test_on_behalf_of_defaults_to_none(self, mem_sub):
        recorded, handler = _make_recorder()
        mem_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(mem_sub)
        mem_sub.transition(
            wi.work_item_id, "finish", "human:finisher",
            actor_kind="agent",
        )
        assert len(recorded) == 1
        assert recorded[0].on_behalf_of is None




class TestPostgresOnBehalfOfNoneDefault:
    def test_on_behalf_of_defaults_to_none(self, pg_sub):
        recorded, handler = _make_recorder()
        pg_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(pg_sub)
        pg_sub.transition(
            wi.work_item_id, "finish", "human:finisher",
            actor_kind="agent",
        )
        assert len(recorded) == 1
        assert recorded[0].on_behalf_of is None




def _grow_history(sub, work_item_id, *, count, actor="human:author"):
    for i in range(count):
        sub.append_event(
            work_item_id, actor,
            actor_kind="agent",
            transition="note",
            payload={"i": i},
        )


class TestPriorEventsCapInMemory:
    def test_capped_to_most_recent(self, mem_sub, monkeypatch):
        monkeypatch.setattr(
            "regista._in_memory_transition.VALIDATOR_HISTORY_LIMIT", 3,
        )
        recorded, handler = _make_recorder()
        mem_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(mem_sub)
        _grow_history(mem_sub, wi.work_item_id, count=4)
        mem_sub.transition(wi.work_item_id, "finish", "human:f", actor_kind="human")
        ctx = recorded[0]
        assert len(ctx.prior_events) == 3
        seqs = [e.event_seq for e in ctx.prior_events]
        assert seqs == sorted(seqs)
        assert seqs == [4, 5, 6]


class TestPriorEventsCapPostgres:
    def test_capped_to_most_recent(self, pg_sub, monkeypatch):
        monkeypatch.setattr(
            "regista._transition.VALIDATOR_HISTORY_LIMIT", 3,
        )
        recorded, handler = _make_recorder()
        pg_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(pg_sub)
        _grow_history(pg_sub, wi.work_item_id, count=4)
        pg_sub.transition(wi.work_item_id, "finish", "human:f", actor_kind="human")
        ctx = recorded[0]
        assert len(ctx.prior_events) == 3
        seqs = [e.event_seq for e in ctx.prior_events]
        assert seqs == sorted(seqs)
        assert seqs == [4, 5, 6]
