from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path

import pytest
from _helpers import DSN, KEY_PATH
from _v6_fixtures import make_v6_keyset, open_v6_epoch
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from regista._errors import RegistaError
from regista.testing import InMemoryRegista, drop_project_schema

TESTS_DIR = Path(__file__).parent
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")
WORKFLOW_YAML = Path(WORKFLOW_PATH).read_text()

VALID_TYPES = ["feature", "bug"]
VALID_TRANSITIONS = {
    "new": [("start", "agent")],
    "in_progress": [("submit_review", "agent")],
    "review": [("approve", "reviewer"), ("reject", "reviewer")],
    "done": [],
}
ACTOR_IDS = ["agent-1", "agent-2", "reviewer-1"]
ROLES = ["agent", "reviewer"]
ACTOR_ROLE_MAP = {"agent-1": "agent", "agent-2": "agent", "reviewer-1": "reviewer"}

#: Canonical principal ids (TRUST-DOMAIN.md §2.1) for the three nodes that run on a
#: **clean v6 epoch**. A second list rather than a rename of ``ACTOR_IDS`` on
#: purpose: the other three nodes in this class were never epoch-blocked — they
#: compare *error codes* across backends over deliberately-invalid input and pass
#: pre-genesis today. Renaming the shared list would drag them onto the v6 route as
#: a side effect of migrating their neighbours, and their recorded behaviour is not
#: this change's to alter.
V6_AGENT_1 = "agent:worker"
V6_AGENT_2 = "agent:reviewer"
V6_REVIEWER = "human:reviewer"
V6_ACTOR_IDS = [V6_AGENT_1, V6_AGENT_2, V6_REVIEWER]


@st.composite
def operation(draw, seen_event_ids=None):
    reuse_id = draw(st.booleans())
    if reuse_id and seen_event_ids and len(seen_event_ids) > 0:
        prior_eid = draw(st.sampled_from(seen_event_ids))
    else:
        prior_eid = None
    kind = draw(
        st.sampled_from(
            [
                "create",
                "claim",
                "transition",
                "release",
                "sweep",
                "heartbeat",
                "append_event",
            ]
        )
    )
    if kind == "create":
        return {
            "op": "create",
            "work_item_type": draw(st.sampled_from(VALID_TYPES)),
            "actor_id": draw(st.sampled_from(ACTOR_IDS)),
            "title": draw(st.text(min_size=1, max_size=20)),
            "reuse_eid": prior_eid,
        }
    if kind == "claim":
        return {
            "op": "claim",
            "idx": draw(st.integers(min_value=0, max_value=5)),
            "actor_id": draw(st.sampled_from(ACTOR_IDS)),
            "ttl": draw(st.integers(min_value=60, max_value=600)),
            "reuse_eid": prior_eid,
        }
    if kind == "transition":
        return {
            "op": "transition",
            "idx": draw(st.integers(min_value=0, max_value=5)),
            "actor_id": draw(st.sampled_from(ACTOR_IDS)),
            "reuse_eid": prior_eid,
        }
    if kind == "release":
        return {
            "op": "release",
            "idx": draw(st.integers(min_value=0, max_value=5)),
            "actor_id": draw(st.sampled_from(ACTOR_IDS)),
            "reuse_eid": prior_eid,
        }
    if kind == "sweep":
        return {"op": "sweep"}
    if kind == "heartbeat":
        return {
            "op": "heartbeat",
            "idx": draw(st.integers(min_value=0, max_value=5)),
            "actor_id": draw(st.sampled_from(ACTOR_IDS)),
            "ttl": draw(st.integers(min_value=60, max_value=600)),
        }
    if kind == "append_event":
        return {
            "op": "append_event",
            "idx": draw(st.integers(min_value=0, max_value=5)),
            "actor_id": draw(st.sampled_from(ACTOR_IDS)),
            "transition": draw(st.none() | st.text(min_size=1, max_size=10)),
            "reuse_eid": prior_eid,
        }
    return {"op": "sweep"}


def _draw_operation(data, seen_event_ids):
    reuse_id = data.draw(st.booleans())
    if reuse_id and seen_event_ids:
        prior_eid = data.draw(st.sampled_from(seen_event_ids))
    else:
        prior_eid = None
    eid = prior_eid or uuid.uuid4()
    kind = data.draw(
        st.sampled_from(
            [
                "create",
                "claim",
                "transition",
                "release",
                "sweep",
                "heartbeat",
                "append_event",
            ]
        )
    )
    if kind == "create":
        return {
            "op": "create",
            "work_item_type": data.draw(st.sampled_from(VALID_TYPES)),
            "actor_id": data.draw(st.sampled_from(ACTOR_IDS)),
            "title": data.draw(st.text(min_size=1, max_size=20)),
            "event_id": eid,
        }
    if kind == "claim":
        return {
            "op": "claim",
            "idx": data.draw(st.integers(min_value=0, max_value=5)),
            "actor_id": data.draw(st.sampled_from(ACTOR_IDS)),
            "ttl": data.draw(st.integers(min_value=60, max_value=600)),
            "event_id": eid,
        }
    if kind == "transition":
        return {
            "op": "transition",
            "idx": data.draw(st.integers(min_value=0, max_value=5)),
            "actor_id": data.draw(st.sampled_from(ACTOR_IDS)),
            "event_id": eid,
        }
    if kind == "release":
        return {
            "op": "release",
            "idx": data.draw(st.integers(min_value=0, max_value=5)),
            "actor_id": data.draw(st.sampled_from(ACTOR_IDS)),
            "event_id": eid,
        }
    if kind == "sweep":
        return {"op": "sweep"}
    if kind == "heartbeat":
        return {
            "op": "heartbeat",
            "idx": data.draw(st.integers(min_value=0, max_value=5)),
            "actor_id": data.draw(st.sampled_from(ACTOR_IDS)),
            "ttl": data.draw(st.integers(min_value=60, max_value=600)),
        }
    if kind == "append_event":
        return {
            "op": "append_event",
            "idx": data.draw(st.integers(min_value=0, max_value=5)),
            "actor_id": data.draw(st.sampled_from(ACTOR_IDS)),
            "transition": data.draw(st.none() | st.text(min_size=1, max_size=10)),
            "event_id": eid,
        }
    return {"op": "sweep"}


@st.composite
def adversarial_operation(draw):
    """Operations designed to trigger input-validation errors."""
    kind = draw(
        st.sampled_from(
            [
                "create_bad_event_id",
                "create_bad_actor_kind",
                "create_bad_not_before",
                "claim_bad_ttl",
            ]
        )
    )
    if kind == "create_bad_event_id":
        raw = uuid.uuid4()
        non_v4 = uuid.UUID(bytes=raw.bytes[:-1] + bytes([raw.bytes[-1] & 0x3F]))
        return {
            "op": "create",
            "work_item_type": draw(st.sampled_from(VALID_TYPES)),
            "actor_id": draw(st.sampled_from(ACTOR_IDS)),
            "title": draw(st.text(min_size=1, max_size=20)),
            "event_id": non_v4,
        }
    if kind == "create_bad_actor_kind":
        return {
            "op": "create",
            "work_item_type": draw(st.sampled_from(VALID_TYPES)),
            "actor_id": draw(st.sampled_from(ACTOR_IDS)),
            "title": draw(st.text(min_size=1, max_size=20)),
            "actor_kind": "bot",
        }
    if kind == "create_bad_not_before":
        return {
            "op": "create",
            "work_item_type": draw(st.sampled_from(VALID_TYPES)),
            "actor_id": draw(st.sampled_from(ACTOR_IDS)),
            "title": draw(st.text(min_size=1, max_size=20)),
            "not_before": draw(st.datetimes(min_value=datetime(2100, 1, 1))),
        }
    if kind == "claim_bad_ttl":
        return {
            "op": "claim",
            "idx": draw(st.integers(min_value=0, max_value=5)),
            "actor_id": draw(st.sampled_from(ACTOR_IDS)),
            "ttl": draw(st.integers(min_value=-100, max_value=0)),
        }
    return {"op": "sweep"}


def _exec_op(backend, op, work_items, event_id_pool=None):
    if event_id_pool is None:
        event_id_pool = []
    if op["op"] == "create":
        role = ACTOR_ROLE_MAP.get(op["actor_id"], "agent")
        actor_metadata = {"role": role}
        if op["work_item_type"] == "feature":
            custom_fields = {"title": op["title"]}
        elif op["work_item_type"] == "bug":
            custom_fields = {"severity": "minor"}
        else:
            custom_fields = {}
        eid = op.get("event_id") or uuid.uuid4()
        try:
            wi, _evt = backend.create_work_item(
                workflow_name="test_workflow",
                work_item_type=op["work_item_type"],
                actor_id=op["actor_id"],
                actor_metadata=actor_metadata,
                custom_fields=custom_fields,
                event_id=eid,
            )
            event_id_pool.append(eid)
            work_items.append(wi)
            return ("ok", "created", str(wi.work_item_id))
        except RegistaError as e:
            return ("err", e.code)

    idx = op.get("idx", 0)
    if idx >= len(work_items):
        return ("noop", "no_target")
    wi = work_items[idx]
    wi_id = wi.work_item_id

    if op["op"] == "claim":
        eid = op.get("event_id") or uuid.uuid4()
        try:
            claim = backend.acquire_claim(
                wi_id, op["actor_id"], ttl_seconds=op["ttl"], event_id=eid
            )
            event_id_pool.append(eid)
            refreshed = backend.get_work_item(wi_id)
            if refreshed:
                work_items[idx] = refreshed
            return ("ok", "claimed", str(claim.attempt_number))
        except RegistaError as e:
            return ("err", e.code)

    if op["op"] == "heartbeat":
        try:
            claim = backend.heartbeat_claim(
                wi_id, op["actor_id"], ttl_seconds=op["ttl"]
            )
            return ("ok", "heartbeat", str(claim.attempt_number))
        except RegistaError as e:
            return ("err", e.code)

    if op["op"] == "release":
        eid = op.get("event_id") or uuid.uuid4()
        try:
            backend.release_claim(wi_id, op["actor_id"], event_id=eid)
            event_id_pool.append(eid)
            refreshed = backend.get_work_item(wi_id)
            if refreshed:
                work_items[idx] = refreshed
            return ("ok", "released")
        except RegistaError as e:
            return ("err", e.code)

    if op["op"] == "sweep":
        try:
            count = backend.sweep_expired_claims()
            return ("ok", "swept", count)
        except RegistaError as e:
            return ("err", e.code)

    if op["op"] == "transition":
        current_state = wi.current_state
        valid = VALID_TRANSITIONS.get(current_state, [])
        role = ACTOR_ROLE_MAP.get(op["actor_id"], "agent")
        matching = [(t, r) for t, r in valid if r == role]
        if not matching:
            if valid:
                t_name, t_role = valid[0]
            else:
                return ("noop", "terminal")
        else:
            t_name, t_role = matching[0]
        eid = op.get("event_id") or uuid.uuid4()
        try:
            backend.transition(
                wi_id,
                t_name,
                op["actor_id"],
                actor_metadata={"role": t_role},
                event_id=eid,
            )
            event_id_pool.append(eid)
            refreshed = backend.get_work_item(wi_id)
            if refreshed:
                work_items[idx] = refreshed
            return ("ok", "transitioned", t_name)
        except RegistaError as e:
            return ("err", e.code)

    if op["op"] == "append_event":
        eid = op.get("event_id") or uuid.uuid4()
        try:
            backend.append_event(
                wi_id,
                op["actor_id"],
                transition=op.get("transition"),
                event_id=eid,
            )
            event_id_pool.append(eid)
            return ("ok", "appended")
        except RegistaError as e:
            return ("err", e.code)

    return ("noop", "unknown")


def _compare_state(real_items, mem_items):
    assert len(real_items) == len(mem_items), (
        f"Work item count mismatch: real={len(real_items)} mem={len(mem_items)}"
    )
    for i, (r, m) in enumerate(zip(real_items, mem_items)):
        assert r.current_state == m.current_state, (
            f"[{i}] State mismatch: real={r.current_state} mem={m.current_state}"
        )
        assert r.custom_fields == m.custom_fields, (
            f"[{i}] Fields mismatch: real={r.custom_fields} mem={m.custom_fields}"
        )
        assert r.needs_review == m.needs_review, (
            f"[{i}] needs_review mismatch: real={r.needs_review} mem={m.needs_review}"
        )
        assert r.attempt_number == m.attempt_number, (
            f"[{i}] attempt_number mismatch: "
            f"real={r.attempt_number} mem={m.attempt_number}"
        )
        assert r.last_event_seq == m.last_event_seq, (
            f"[{i}] last_event_seq mismatch: "
            f"real={r.last_event_seq} mem={m.last_event_seq}"
        )
        assert r.claimed_by == m.claimed_by, (
            f"[{i}] claimed_by mismatch: real={r.claimed_by} mem={m.claimed_by}"
        )
        assert r.not_before == m.not_before, (
            f"[{i}] not_before mismatch: real={r.not_before} mem={m.not_before}"
        )
        assert r.workflow_version == m.workflow_version
        assert r.work_item_type == m.work_item_type


def _exec_op_adversarial(backend, op, work_items):
    if op["op"] == "create":
        role = ACTOR_ROLE_MAP.get(op["actor_id"], "agent")
        actor_metadata = {"role": role}
        if op["work_item_type"] == "feature":
            custom_fields = {"title": op["title"]}
        elif op["work_item_type"] == "bug":
            custom_fields = {"severity": "minor"}
        else:
            custom_fields = {}
        kwargs = {
            "workflow_name": "test_workflow",
            "work_item_type": op["work_item_type"],
            "actor_id": op["actor_id"],
            "actor_metadata": actor_metadata,
            "custom_fields": custom_fields,
        }
        if "event_id" in op:
            kwargs["event_id"] = op["event_id"]
        if "actor_kind" in op:
            kwargs["actor_kind"] = op["actor_kind"]
        if "not_before" in op:
            kwargs["not_before"] = op["not_before"]
        try:
            wi, _evt = backend.create_work_item(**kwargs)
            work_items.append(wi)
            return ("ok", "created", str(wi.work_item_id))
        except RegistaError as e:
            return ("err", e.code)

    idx = op.get("idx", 0)
    if idx >= len(work_items):
        return ("noop", "no_target")
    wi = work_items[idx]
    wi_id = wi.work_item_id

    if op["op"] == "claim":
        try:
            claim = backend.acquire_claim(
                wi_id, op["actor_id"], ttl_seconds=op["ttl"]
            )
            refreshed = backend.get_work_item(wi_id)
            if refreshed:
                work_items[idx] = refreshed
            return ("ok", "claimed", str(claim.attempt_number))
        except RegistaError as e:
            return ("err", e.code)

    return ("noop", "unknown")


@pytest.fixture(scope="module")
def v6_keyset(tmp_path_factory):
    """One Ed25519 keyset for every hypothesis example in this module.

    **Module-scoped deliberately**: hypothesis refuses a function-scoped fixture
    under ``@given`` (``function_scoped_fixture`` health check), and one keyset can
    serve any number of projects — a key file is not project-local, only the
    ``principal_key_accepted`` events are, and ``open_v6_epoch`` writes fresh ones
    into each project it opens.
    """
    return make_v6_keyset(tmp_path_factory.mktemp("prop_keys"), principals=V6_ACTOR_IDS)


def _v6_pair(keyset, project):
    """A Postgres/in-memory pair, both on a clean v6 epoch, workflow registered.

    Both sides get an epoch, not just Postgres. A migrated Postgres project beside a
    legacy in-memory one would compare two backends running *different* writers —
    and since the system actor these nodes exercise (auto-escalation) resolves per
    epoch, that mismatch is exactly the divergence this file exists to catch.
    """
    from regista import Regista

    real = Regista.create_project(DSN, project, keyset.path)
    open_v6_epoch(real, keyset, principals=V6_ACTOR_IDS)
    real.register_workflow(WORKFLOW_YAML)

    mem = InMemoryRegista(project="test", hmac_key_path=keyset.path)
    open_v6_epoch(mem, keyset, principals=V6_ACTOR_IDS)
    mem.register_workflow(WORKFLOW_YAML)
    return real, mem


@pytest.mark.slow
class TestPropertyBasedConformance:
    @settings(
        max_examples=150,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(data=st.data())
    def test_random_sequences_equivalent(self, data):
        from regista import Regista

        n_ops = data.draw(st.integers(min_value=0, max_value=30))

        project = f"prop_{uuid.uuid4().hex[:8]}"
        real = Regista.create_project(DSN, project, KEY_PATH)
        real.register_workflow(WORKFLOW_YAML)
        mem = InMemoryRegista(project="test")
        mem.register_workflow(WORKFLOW_YAML)

        real_items = []
        mem_items = []
        real_eids = []
        mem_eids = []

        try:
            for _ in range(n_ops):
                op = _draw_operation(data, real_eids)
                real_result = _exec_op(real, op, real_items, real_eids)
                mem_result = _exec_op(mem, op, mem_items, mem_eids)
                assert real_result[0] == mem_result[0], (
                    f"Op {op['op']} diverged: real={real_result} mem={mem_result}"
                )
                if real_result[0] == "err":
                    assert real_result[1] == mem_result[1], (
                        f"Error code diverged for {op['op']}: "
                        f"real={real_result[1]} mem={mem_result[1]}"
                    )

            if real_items and mem_items:
                _compare_state(real_items, mem_items)
        finally:
            real.close()
            drop_project_schema(DSN, project)

    @settings(
        max_examples=50,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(
        claim_ops=st.lists(
            st.fixed_dictionaries(
                {
                    "op": st.just("claim"),
                    "actor_id": st.sampled_from(V6_ACTOR_IDS),
                    "ttl": st.integers(min_value=60, max_value=600),
                }
            ),
            max_size=10,
        )
    )
    def test_claim_contention_sequence(self, claim_ops, v6_keyset):
        project = f"prop_claim_{uuid.uuid4().hex[:8]}"
        real, mem = _v6_pair(v6_keyset, project)

        try:
            real_wi, _ = real.create_work_item(
                "test_workflow", "feature", V6_AGENT_1,
                actor_metadata={"role": "agent"},
                custom_fields={"title": "test"},
            )
            mem_wi, _ = mem.create_work_item(
                "test_workflow", "feature", V6_AGENT_1,
                actor_metadata={"role": "agent"},
                custom_fields={"title": "test"},
            )

            for op in claim_ops:
                real_r = _safe_claim(real, real_wi.work_item_id, op["actor_id"], op["ttl"])
                mem_r = _safe_claim(mem, mem_wi.work_item_id, op["actor_id"], op["ttl"])
                assert real_r[0] == mem_r[0], (
                    f"Claim diverged: real={real_r} mem={mem_r}"
                )
                if real_r[0] == "ok":
                    assert real_r[1].attempt_number == mem_r[1].attempt_number

            real_refreshed = real.get_work_item(real_wi.work_item_id)
            mem_refreshed = mem.get_work_item(mem_wi.work_item_id)
            assert real_refreshed.attempt_number == mem_refreshed.attempt_number
            assert real_refreshed.needs_review == mem_refreshed.needs_review
        finally:
            real.close()
            drop_project_schema(DSN, project)

    @settings(max_examples=50, deadline=None)
    @given(
        n_claims=st.integers(min_value=1, max_value=5),
    )
    def test_escalation_equivalence(self, n_claims, v6_keyset):
        project = f"prop_esc_{uuid.uuid4().hex[:8]}"
        real, mem = _v6_pair(v6_keyset, project)

        try:
            real_wi, _ = real.create_work_item(
                "test_workflow", "feature", V6_AGENT_1,
                actor_metadata={"role": "agent"},
                custom_fields={"title": "test"},
            )
            mem_wi, _ = mem.create_work_item(
                "test_workflow", "feature", V6_AGENT_1,
                actor_metadata={"role": "agent"},
                custom_fields={"title": "test"},
            )

            actors = [V6_AGENT_1, V6_AGENT_2]
            for i in range(n_claims):
                actor = actors[i % len(actors)]
                _safe_claim(real, real_wi.work_item_id, actor, 1)
                _safe_claim(mem, mem_wi.work_item_id, actor, 1)
                _safe_release(real, real_wi.work_item_id, actor)
                _safe_release(mem, mem_wi.work_item_id, actor)

            real_r = real.get_work_item(real_wi.work_item_id)
            mem_r = mem.get_work_item(mem_wi.work_item_id)
            assert real_r.attempt_number == mem_r.attempt_number
            assert real_r.needs_review == mem_r.needs_review
        finally:
            real.close()
            drop_project_schema(DSN, project)

    @settings(max_examples=50, deadline=None)
    @given(data=st.data())
    def test_transition_sequence_equivalence(self, data, v6_keyset):
        project = f"prop_trans_{uuid.uuid4().hex[:8]}"
        real, mem = _v6_pair(v6_keyset, project)

        try:
            real_wi, _ = real.create_work_item(
                "test_workflow", "feature", V6_AGENT_1,
                actor_metadata={"role": "agent"},
                custom_fields={"title": "test"},
            )
            mem_wi, _ = mem.create_work_item(
                "test_workflow", "feature", V6_AGENT_1,
                actor_metadata={"role": "agent"},
                custom_fields={"title": "test"},
            )

            transitions = [
                ("start", "agent"),
                ("submit_review", "agent"),
                ("approve", "reviewer"),
            ]
            for t_name, t_role in transitions:
                actor = V6_AGENT_1 if t_role == "agent" else V6_REVIEWER
                real_evt = real.transition(
                    real_wi.work_item_id, t_name, actor,
                    actor_metadata={"role": t_role},
                )
                mem_evt = mem.transition(
                    mem_wi.work_item_id, t_name, actor,
                    actor_metadata={"role": t_role},
                )
                assert real_evt.transition == mem_evt.transition

            real_r = real.get_work_item(real_wi.work_item_id)
            mem_r = mem.get_work_item(mem_wi.work_item_id)
            assert real_r.current_state == mem_r.current_state
            assert real_r.workflow_version == mem_r.workflow_version
        finally:
            real.close()
            drop_project_schema(DSN, project)

    @settings(max_examples=30, deadline=None)
    @given(data=st.data())
    def test_replay_equivalence(self, data):
        from regista import Regista

        n_ops = data.draw(st.integers(min_value=0, max_value=20))

        project = f"prop_replay_{uuid.uuid4().hex[:8]}"
        real = Regista.create_project(DSN, project, KEY_PATH)
        real.register_workflow(WORKFLOW_YAML)
        mem = InMemoryRegista(project="test")
        mem.register_workflow(WORKFLOW_YAML)

        real_items = []
        mem_items = []
        real_eids = []
        mem_eids = []

        try:
            for _ in range(n_ops):
                op = _draw_operation(data, real_eids)
                _exec_op(real, op, real_items, real_eids)
                _exec_op(mem, op, mem_items, mem_eids)

            if real_items:
                real_report = real.replay()
                mem_report = mem.replay()
                assert real_report.replayed_drift == mem_report.replayed_drift, (
                    f"Drift mismatch: real={real_report.replayed_drift} "
                    f"mem={mem_report.replayed_drift}"
                )
        finally:
            real.close()
            drop_project_schema(DSN, project)

    @settings(
        max_examples=100,
        deadline=None,
        suppress_health_check=[HealthCheck.too_slow],
    )
    @given(ops=st.lists(adversarial_operation(), max_size=20))
    def test_adversarial_error_code_equivalence(self, ops):
        """Both backends must reject invalid inputs with the same error code."""
        from regista import Regista

        project = f"prop_adv_{uuid.uuid4().hex[:8]}"
        real = Regista.create_project(DSN, project, KEY_PATH)
        real.register_workflow(WORKFLOW_YAML)
        mem = InMemoryRegista(project="test")
        mem.register_workflow(WORKFLOW_YAML)

        real_items = []
        mem_items = []

        try:
            for op in ops:
                real_result = _exec_op_adversarial(real, op, real_items)
                mem_result = _exec_op_adversarial(mem, op, mem_items)
                if real_result[0] == "err" and mem_result[0] == "err":
                    assert real_result[1] == mem_result[1], (
                        f"Adversarial op {op['op']} diverged: "
                        f"real={real_result[1]} mem={mem_result[1]}"
                    )
        finally:
            real.close()
            drop_project_schema(DSN, project)


def _safe_claim(backend, wi_id, actor_id, ttl):
    try:
        claim = backend.acquire_claim(wi_id, actor_id, ttl_seconds=ttl)
        return ("ok", claim)
    except RegistaError as e:
        return ("err", e.code)


def _safe_release(backend, wi_id, actor_id):
    try:
        backend.release_claim(wi_id, actor_id)
    except RegistaError:
        pass
