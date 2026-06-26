"""Plan 020 + Plan 021 — ValidatorContext enrichment.

Verifies that sync transition validators receive the acting actor's
``actor_kind``, the work-item's pre-transition event history, and the acting
actor's ``on_behalf_of`` delegation chain on both the InMemory and Postgres
backends, that non-validator transitions are unaffected, and that
``ValidatorContext`` serialization round-trips the new fields while tolerating
their absence (forward-compat with pre-Plan-020/021 payloads).
"""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._types import ValidatorContext
from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")

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


def _setup_ready(sub, *, creator="creator-1", preparer="preparer-1"):
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


def _event_comparable(e) -> tuple:
    return (e.event_seq, e.actor_id, e.actor_kind, e.transition, e.on_behalf_of)


@pytest.fixture
def mem_sub() -> InMemoryRegista:
    s = InMemoryRegista(project="test_ctx020", hmac_key_path=KEY_PATH)
    s.register_workflow(WORKFLOW)
    yield s
    s.close()


@pytest.fixture(scope="module")
def pg_sub():
    from regista import Regista

    project = f"test_ctx020_{uuid.uuid4().hex[:8]}"
    s = Regista.create_project(DSN, project, hmac_key_path=KEY_PATH)
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
            wi.work_item_id, "finish", "finisher-1",
            actor_kind=kind,
        )
        assert len(recorded) == 1
        assert recorded[0].actor_kind == kind


class TestPriorEventsInMemory:
    def test_prior_events_match_history(self, mem_sub):
        recorded, handler = _make_recorder()
        mem_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(mem_sub, creator="creator-1", preparer="preparer-1")
        mem_sub.transition(
            wi.work_item_id, "finish", "finisher-1",
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
        assert prior[0].actor_id == "creator-1"
        assert prior[1].transition == "prepare"
        assert prior[1].actor_id == "preparer-1"
        assert ctx.actor_id == "finisher-1"


class TestNoValidatorUnaffectedInMemory:
    def test_non_validator_transition_skips_handler(self, mem_sub):
        recorded, handler = _make_recorder()
        mem_sub.register_validator("record_ctx", handler)
        wi, _ = mem_sub.create_work_item(
            workflow_name="ctx_enrich_test",
            work_item_type="task",
            actor_id="agent-1",
            actor_kind="agent",
        )
        evt = mem_sub.transition(
            wi.work_item_id, "prepare", "agent-1",
            actor_kind="agent",
        )
        assert evt.transition == "prepare"
        assert len(recorded) == 0
        refreshed = mem_sub.get_work_item(wi.work_item_id)
        assert refreshed is not None
        assert refreshed.current_state == "ready"


class TestSerializationRoundTrip:
    def test_round_trip_preserves_new_fields(self, mem_sub):
        recorded, handler = _make_recorder()
        mem_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(mem_sub)
        mem_sub.transition(
            wi.work_item_id, "finish", "finisher-1",
            actor_kind="human",
            on_behalf_of={"principal_id": "human:roundtrip-1"},
        )
        ctx = recorded[0]
        rt = ValidatorContext.from_dict(ctx.to_dict())
        assert rt == ctx
        assert rt.actor_kind == "human"
        assert rt.prior_events == ctx.prior_events
        assert rt.on_behalf_of == {"principal_id": "human:roundtrip-1"}

    def test_on_behalf_of_round_trip_with_none(self, mem_sub):
        recorded, handler = _make_recorder()
        mem_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(mem_sub)
        mem_sub.transition(
            wi.work_item_id, "finish", "finisher-1",
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
            "actor_id": "agent-1",
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
            wi.work_item_id, "finish", "finisher-1",
            actor_kind="human",
        )
        assert len(recorded) == 1
        assert recorded[0].actor_kind == "human"


class TestPostgresPriorEvents:
    def test_prior_events_match_history(self, pg_sub):
        recorded, handler = _make_recorder()
        pg_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(pg_sub, creator="creator-1", preparer="preparer-1")
        pg_sub.transition(
            wi.work_item_id, "finish", "finisher-1",
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
        assert prior[0].actor_id == "creator-1"
        assert prior[1].transition == "prepare"
        assert prior[1].actor_id == "preparer-1"


class TestOnBehalfOfInMemory:
    def test_recorded_on_behalf_of(self, mem_sub):
        recorded, handler = _make_recorder()
        mem_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(mem_sub)
        mem_sub.transition(
            wi.work_item_id, "finish", "finisher-1",
            actor_kind="agent",
            on_behalf_of={"principal_id": "human:reviewer-boss"},
        )
        assert len(recorded) == 1
        assert recorded[0].on_behalf_of == {"principal_id": "human:reviewer-boss"}


class TestOnBehalfOfNoneDefaultInMemory:
    def test_on_behalf_of_defaults_to_none(self, mem_sub):
        recorded, handler = _make_recorder()
        mem_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(mem_sub)
        mem_sub.transition(
            wi.work_item_id, "finish", "finisher-1",
            actor_kind="agent",
        )
        assert len(recorded) == 1
        assert recorded[0].on_behalf_of is None


class TestPostgresOnBehalfOf:
    def test_recorded_on_behalf_of(self, pg_sub):
        recorded, handler = _make_recorder()
        pg_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(pg_sub)
        pg_sub.transition(
            wi.work_item_id, "finish", "finisher-1",
            actor_kind="agent",
            on_behalf_of={"principal_id": "human:reviewer-boss"},
        )
        assert len(recorded) == 1
        assert recorded[0].on_behalf_of == {"principal_id": "human:reviewer-boss"}


class TestPostgresOnBehalfOfNoneDefault:
    def test_on_behalf_of_defaults_to_none(self, pg_sub):
        recorded, handler = _make_recorder()
        pg_sub.register_validator("record_ctx", handler)
        wi = _setup_ready(pg_sub)
        pg_sub.transition(
            wi.work_item_id, "finish", "finisher-1",
            actor_kind="agent",
        )
        assert len(recorded) == 1
        assert recorded[0].on_behalf_of is None


class TestConformanceAcrossBackends:
    def test_actor_kind_prior_events_on_behalf_of_equal(self, mem_sub, pg_sub):
        recorded_mem, handler_mem = _make_recorder()
        mem_sub.register_validator("record_ctx", handler_mem)
        wi_mem = _setup_ready(mem_sub, creator="c", preparer="p")
        mem_sub.transition(
            wi_mem.work_item_id, "finish", "f",
            actor_kind="human",
            on_behalf_of={"principal_id": "human:principal-1"},
        )

        recorded_pg, handler_pg = _make_recorder()
        pg_sub.register_validator("record_ctx", handler_pg)
        wi_pg = _setup_ready(pg_sub, creator="c", preparer="p")
        pg_sub.transition(
            wi_pg.work_item_id, "finish", "f",
            actor_kind="human",
            on_behalf_of={"principal_id": "human:principal-1"},
        )

        ctx_mem = recorded_mem[0]
        ctx_pg = recorded_pg[0]
        assert ctx_mem.actor_kind == ctx_pg.actor_kind
        assert ctx_mem.on_behalf_of == ctx_pg.on_behalf_of
        assert (
            [_event_comparable(e) for e in ctx_mem.prior_events]
            == [_event_comparable(e) for e in ctx_pg.prior_events]
        )


def _grow_history(sub, work_item_id, *, count, actor="author-1"):
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
        mem_sub.transition(wi.work_item_id, "finish", "f", actor_kind="human")
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
        pg_sub.transition(wi.work_item_id, "finish", "f", actor_kind="human")
        ctx = recorded[0]
        assert len(ctx.prior_events) == 3
        seqs = [e.event_seq for e in ctx.prior_events]
        assert seqs == sorted(seqs)
        assert seqs == [4, 5, 6]


def _make_self_review_validator():
    def handler(ctx: ValidatorContext) -> None:
        if ctx.on_behalf_of is None:
            return
        principal = ctx.on_behalf_of.get("principal_id")
        if principal is None:
            return
        authors = {e.actor_id for e in ctx.prior_events}
        if principal in authors:
            raise ValueError("self-review via delegation")

    return handler


class TestDelegationSelfReviewScenario:
    def test_rejects_when_principal_is_author(self, mem_sub):
        mem_sub.register_validator("record_ctx", _make_self_review_validator())
        wi = _setup_ready(mem_sub, creator="human:author-1", preparer="agent:prep-1")
        with pytest.raises(RegistaError) as exc_info:
            mem_sub.transition(
                wi.work_item_id, "finish", "agent:reviewer-1",
                actor_kind="agent",
                on_behalf_of={"principal_id": "human:author-1"},
            )
        assert exc_info.value.code == ErrorCode.VALIDATOR_FAILED
        assert isinstance(exc_info.value.__cause__, ValueError)
        assert "self-review via delegation" in str(exc_info.value.__cause__)

    def test_accepts_when_principal_is_not_author(self, mem_sub):
        mem_sub.register_validator("record_ctx", _make_self_review_validator())
        wi = _setup_ready(mem_sub, creator="human:author-1", preparer="agent:prep-1")
        mem_sub.transition(
            wi.work_item_id, "finish", "agent:reviewer-1",
            actor_kind="agent",
            on_behalf_of={"principal_id": "human:someone-else"},
        )
        refreshed = mem_sub.get_work_item(wi.work_item_id)
        assert refreshed is not None
        assert refreshed.current_state == "done"


class TestDelegationSelfReviewScenarioPostgres:
    def test_rejects_when_principal_is_author(self, pg_sub):
        pg_sub.register_validator("record_ctx", _make_self_review_validator())
        wi = _setup_ready(pg_sub, creator="human:author-1", preparer="agent:prep-1")
        with pytest.raises(RegistaError) as exc_info:
            pg_sub.transition(
                wi.work_item_id, "finish", "agent:reviewer-1",
                actor_kind="agent",
                on_behalf_of={"principal_id": "human:author-1"},
            )
        assert exc_info.value.code == ErrorCode.VALIDATOR_FAILED
        assert isinstance(exc_info.value.__cause__, ValueError)
        assert "self-review via delegation" in str(exc_info.value.__cause__)

    def test_accepts_when_principal_is_not_author(self, pg_sub):
        pg_sub.register_validator("record_ctx", _make_self_review_validator())
        wi = _setup_ready(pg_sub, creator="human:author-1", preparer="agent:prep-1")
        pg_sub.transition(
            wi.work_item_id, "finish", "agent:reviewer-1",
            actor_kind="agent",
            on_behalf_of={"principal_id": "human:someone-else"},
        )
        refreshed = pg_sub.get_work_item(wi.work_item_id)
        assert refreshed is not None
        assert refreshed.current_state == "done"


class TestValidatorCannotMutateOnBehalfOfInMemory:
    def test_event_records_original_not_mutated_chain(self, mem_sub):
        def mutating_handler(ctx: ValidatorContext) -> None:
            assert ctx.on_behalf_of is not None
            ctx.on_behalf_of["principal_id"] = "human:attacker"

        mem_sub.register_validator("record_ctx", mutating_handler)
        wi = _setup_ready(mem_sub)
        evt = mem_sub.transition(
            wi.work_item_id, "finish", "agent:reviewer-1",
            actor_kind="agent",
            on_behalf_of={"principal_id": "human:original-principal"},
        )
        assert evt.on_behalf_of == {"principal_id": "human:original-principal"}


class TestValidatorCannotMutateOnBehalfOfPostgres:
    def test_event_records_original_not_mutated_chain(self, pg_sub):
        def mutating_handler(ctx: ValidatorContext) -> None:
            assert ctx.on_behalf_of is not None
            ctx.on_behalf_of["principal_id"] = "human:attacker"

        pg_sub.register_validator("record_ctx", mutating_handler)
        wi = _setup_ready(pg_sub)
        evt = pg_sub.transition(
            wi.work_item_id, "finish", "agent:reviewer-1",
            actor_kind="agent",
            on_behalf_of={"principal_id": "human:original-principal"},
        )
        assert evt.on_behalf_of == {"principal_id": "human:original-principal"}
