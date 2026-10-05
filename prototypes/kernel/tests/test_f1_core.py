from __future__ import annotations

import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import replace
from typing import Any

import psycopg
import pytest
from kernel import (
    ClaimContestedError,
    DatabaseOperationError,
    IdempotencyConflictError,
    InvalidFieldError,
    InvalidWorkflowError,
    Kernel,
    LeaseExpiredError,
    LeaseNotHeldError,
    ReservedPayloadKeyError,
    StaleAttemptError,
    TransitionRefusedError,
    Workflow,
    WorkItem,
)
from psycopg.sql import SQL, Identifier


def create(k: Kernel, **fields: Any) -> WorkItem:
    return k.create_work_item(workflow="review", type="task", actor_id="worker", fields=fields)


def expire(dsn: str, schema: str, item: WorkItem) -> None:
    # Relative to the only authoritative clock, no calendar dates or sleeps.
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            SQL(
                "UPDATE {}.claims SET expires_at = clock_timestamp() - interval '1 second' "
                "WHERE work_item_id = %s"
            ).format(Identifier(schema)),
            (item.id,),
        )


def test_create_and_get(registered: Kernel) -> None:
    item = create(registered, title="test")
    assert isinstance(item.id, uuid.UUID)
    assert registered.get(item.id) == item
    assert item.state == "new" and item.type == "task" and item.last_event_seq == 0
    (event,) = registered.history(item.id)
    assert event.transition is None and event.payload["created"]["fields"] == item.fields


@pytest.mark.parametrize("case", ["workflow", "type"])
def test_create_refusals(registered: Kernel, case: str) -> None:
    before = registered.health()
    with pytest.raises(InvalidWorkflowError):
        registered.create_work_item(
            workflow="missing" if case == "workflow" else "review",
            type="missing" if case == "type" else "task",
            actor_id="w",
        )
    after = registered.health()
    assert (after["events"], after["work_items"]) == (before["events"], before["work_items"])


def test_workflow_idempotent(registered: Kernel, workflow: Workflow) -> None:
    assert registered.register_workflow(workflow) == 1
    assert registered.register_workflow(registered.get_workflow("review")) == 1
    assert len(registered.list_workflows()) == 1


def test_workflow_version_conflict(registered: Kernel, workflow: Workflow) -> None:
    with pytest.raises(InvalidWorkflowError, match="immutable"):
        registered.register_workflow(replace(workflow, version=1, required_fields={}))
    assert registered.get_workflow("review").required_fields == workflow.required_fields
    assert len(registered.list_workflows()) == 1


def test_version_pinning(registered: Kernel, workflow: Workflow) -> None:
    old = create(registered)
    v2 = replace(workflow, transitions={**workflow.transitions, "shortcut": (("new",), "done")})
    assert registered.register_workflow(v2) == 2
    new = create(registered)
    explicit = registered.create_work_item(
        workflow="review", workflow_version=1, type="task", actor_id="w"
    )
    for item in (old, explicit):
        with pytest.raises(TransitionRefusedError):
            registered.transition(item.id, transition="shortcut", actor_id="w")
        assert registered.get(item.id) == item
        assert registered.transition(item.id, transition="start", actor_id="w").state == "doing"
    assert new.workflow_version == 2
    assert registered.transition(new.id, transition="shortcut", actor_id="w").state == "done"


@pytest.mark.parametrize("case", ["unknown", "wrong_state", "role", "terminal", "required", "null"])
def test_transition_refusals(registered: Kernel, workflow: Workflow, case: str) -> None:
    if case == "terminal":
        registered.register_workflow(replace(workflow, terminal=("doing", "done", "rejected")))
    item = create(registered)
    if case in ("role", "terminal", "required", "null"):
        registered.transition(item.id, transition="start", actor_id="w")
    if case == "role":
        registered.transition(item.id, transition="submit", actor_id="w", fields={"note": "ready"})
    before = registered.get(item.id), registered.history(item.id)
    verb = {
        "unknown": "typo",
        "wrong_state": "edit",
        "role": "approve",
        "terminal": "edit",
        "required": "submit",
        "null": "submit",
    }[case]
    error = InvalidFieldError if case in ("required", "null") else TransitionRefusedError
    with pytest.raises(error):
        registered.transition(
            item.id,
            transition=verb,
            actor_id="w",
            role="worker",
            fields={"note": None} if case == "null" else {},
        )
    assert (registered.get(item.id), registered.history(item.id)) == before


def test_full_repair_handoff(registered: Kernel) -> None:
    item = create(registered, title="repair")
    for verb, role, fields in [
        ("start", None, {}),
        ("submit", None, {"note": "first"}),
        ("reject", "reviewer", {}),
        ("start", None, {}),
        ("submit", None, {"note": "fixed"}),
        ("approve", "reviewer", {}),
    ]:
        registered.transition(item.id, transition=verb, actor_id="person", role=role, fields=fields)
    assert registered.get(item.id).state == "done"
    assert registered.replay(item.id) == ("done", {"title": "repair", "note": "fixed"}, [])


def test_claim_acquire_release(registered: Kernel) -> None:
    item = create(registered)
    claim = registered.claim(item.id, actor_id="w")
    assert claim.actor_id == "w" and claim.attempt == 1 and claim.live
    assert registered.lease(item.id) == claim
    registered.release(item.id, actor_id="w", attempt=claim.attempt)
    assert registered.lease(item.id) is None


@pytest.mark.parametrize("actor", ["w", "other"])
def test_claim_contested(registered: Kernel, actor: str) -> None:
    item = create(registered)
    held = registered.claim(item.id, actor_id="w")
    with pytest.raises(ClaimContestedError):
        registered.claim(item.id, actor_id=actor)
    assert registered.lease(item.id) == held


def test_heartbeat_extension(registered: Kernel) -> None:
    item = create(registered)
    held = registered.claim(item.id, actor_id="w", ttl_seconds=60)
    for _ in range(5):
        extended = registered.heartbeat(
            item.id, actor_id="w", attempt=held.attempt, ttl_seconds=120
        )
        assert extended.expires_at > held.expires_at and extended.attempt == held.attempt
        held = extended
    assert len(registered.history(item.id)) == 1  # no heartbeat event storm


@pytest.mark.parametrize("case", ["actor", "attempt", "takeover", "expired"])
def test_heartbeat_refusals(registered: Kernel, dsn: str, schema: str, case: str) -> None:
    item = create(registered)
    held = registered.claim(item.id, actor_id="w")
    if case in ("takeover", "expired"):
        expire(dsn, schema, item)
    if case == "takeover":
        registered.claim(item.id, actor_id="next")
    before = registered.lease(item.id)
    error = {
        "actor": LeaseNotHeldError, "expired": LeaseExpiredError,
        "attempt": StaleAttemptError, "takeover": StaleAttemptError,
    }[case]
    with pytest.raises(error) as refusal:
        registered.heartbeat(
            item.id,
            actor_id="other" if case == "actor" else "w",
            attempt=held.attempt + (case == "attempt"),
            ttl_seconds=120,
        )
    assert type(refusal.value) is error
    assert registered.lease(item.id) == before


@pytest.mark.parametrize(
    "case", ["missing", "wrong", "actor", "expired", "swept", "released", "takeover"]
)
def test_transition_fencing(registered: Kernel, dsn: str, schema: str, case: str) -> None:
    item = create(registered)
    held = registered.claim(item.id, actor_id="w")
    if case in ("expired", "swept", "takeover"):
        expire(dsn, schema, item)
    if case == "swept":
        assert registered.expire_leases(item.id) == 1
    if case == "released":
        registered.release(item.id, actor_id="w", attempt=held.attempt)
    if case == "takeover":
        assert registered.claim(item.id, actor_id="next").attempt > held.attempt
    before = registered.get(item.id), registered.history(item.id), registered.lease(item.id)
    error = {
        "actor": LeaseNotHeldError, "released": LeaseNotHeldError, "swept": LeaseNotHeldError,
        "expired": LeaseExpiredError, "missing": StaleAttemptError,
        "wrong": StaleAttemptError, "takeover": StaleAttemptError,
    }[case]
    with pytest.raises(error) as refusal:
        registered.transition(
            item.id,
            transition="start",
            actor_id="other" if case == "actor" else "w",
            attempt=None if case == "missing" else held.attempt + (case == "wrong"),
            fields={"result": "stale"},
        )
    assert type(refusal.value) is error
    assert (
        registered.get(item.id),
        registered.history(item.id),
        registered.lease(item.id),
    ) == before


def test_attempt_monotonic(registered: Kernel, dsn: str, schema: str) -> None:
    item = create(registered)
    issued = []
    for _ in range(4):
        held = registered.claim(item.id, actor_id="w")
        issued.append(held.attempt)
        expire(dsn, schema, item)
    registered.expire_leases()
    held = registered.claim(item.id, actor_id="w")
    issued.append(held.attempt)
    registered.release(item.id, actor_id="w", attempt=issued[0])
    registered.release(item.id, actor_id="other", attempt=held.attempt)
    assert registered.lease(item.id) == held
    assert issued == [1, 2, 3, 4, 5]
    assert (
        registered.transition(item.id, transition="start", actor_id="w", attempt=5).state == "doing"
    )


def test_sweep_scoped_and_live_safe(registered: Kernel, dsn: str, schema: str) -> None:
    a, b, live = [create(registered) for _ in range(3)]
    for item in (a, b, live):
        registered.claim(item.id, actor_id="w")
    expire(dsn, schema, a)
    expire(dsn, schema, b)
    assert registered.expire_leases(a.id) == 1
    assert registered.lease(a.id) is None and registered.lease(b.id) is not None
    assert registered.expire_leases() == 1
    assert registered.lease(live.id) is not None
    assert registered.expire_leases() == 0


@pytest.mark.parametrize(
    "change", ["actor", "transition", "fields", "payload", "unset", "item", "actor_kind", "role",
               "expected_seq"]
)
def test_idempotency_conflict(registered: Kernel, change: str) -> None:
    item = create(registered)
    request: dict[str, Any] = {
        "transition": "start",
        "actor_id": "w",
        "fields": {"x": 1},
        "payload": {"note": "a"},
        "idempotency_key": "operation",
        "expected_seq": 0,
    }
    original = registered.transition(item.id, **request)
    if change == "item":
        target = create(registered).id
    else:
        target = item.id
        key, value = {
            "actor": ("actor_id", "other"),
            "transition": ("transition", "edit"),
            "fields": ("fields", {"x": 2}),
            "payload": ("payload", {"note": "b"}),
            "unset": ("unset_fields", ("obsolete",)),
            "actor_kind": ("actor_kind", "human"),
            "role": ("role", "reviewer"),
            "expected_seq": ("expected_seq", 99),
        }[change]
        request[key] = value
    before = registered.get(target), registered.history(target)
    with pytest.raises(IdempotencyConflictError):
        registered.transition(target, **request)
    assert (registered.get(target), registered.history(target)) == before
    assert registered.get(item.id) == original


def test_idempotency_original_result(registered: Kernel) -> None:
    item = create(registered, obsolete=1)
    req: dict[str, Any] = {
        "transition": "start",
        "actor_id": "w",
        "fields": {"x": 1},
        "unset_fields": ("obsolete",),
        "idempotency_key": "retry",
    }
    original = registered.transition(item.id, **req)
    registered.transition(item.id, transition="edit", actor_id="w", fields={"x": 2})
    assert registered.transition(item.id, **req) == original
    assert registered.get(item.id).fields == {"x": 2}
    assert len(registered.history(item.id)) == 3


@pytest.mark.parametrize("key", ["from", "to", "fields", "unset", "created"])
def test_reserved_payload_refusal(registered: Kernel, key: str) -> None:
    item = create(registered)
    with pytest.raises(ReservedPayloadKeyError):
        registered.transition(item.id, transition="start", actor_id="w", payload={key: "forged"})
    assert registered.get(item.id) == item and len(registered.history(item.id)) == 1


@pytest.mark.parametrize("phase", ["create", "transition"])
def test_event_projection_atomicity(registered: Kernel, dsn: str, schema: str, phase: str) -> None:
    item = create(registered)
    # A database-side fault AFTER the first effect. No mocking kernel internals.
    table = "events" if phase == "create" else "work_items_current"
    operation = "INSERT" if phase == "create" else "UPDATE"
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            SQL(
                "CREATE FUNCTION {}.fail_write() RETURNS trigger LANGUAGE plpgsql AS "
                "$$ BEGIN RAISE EXCEPTION 'F1 injected failure'; END $$"
            ).format(Identifier(schema))
        )
        conn.execute(
            SQL(
                "CREATE TRIGGER fail_write BEFORE {} ON {}.{} "
                "FOR EACH ROW EXECUTE FUNCTION {}.fail_write()"
            ).format(SQL(operation), Identifier(schema), Identifier(table), Identifier(schema))
        )
    before = registered.get(item.id), registered.history(item.id), registered.health()["work_items"]
    with pytest.raises(DatabaseOperationError):
        if phase == "create":
            create(registered, title="must roll back")
        else:
            registered.transition(
                item.id, transition="start", actor_id="w", idempotency_key="atomic"
            )
    assert (
        registered.get(item.id),
        registered.history(item.id),
        registered.health()["work_items"],
    ) == before
    with psycopg.connect(dsn, autocommit=True) as conn:
        row = conn.execute(
            SQL("SELECT count(*) FROM {}.idempotency_keys").format(Identifier(schema))
        ).fetchone()
        assert row == (0,)


def test_concurrent_gap_free(registered: Kernel) -> None:
    item = create(registered)
    registered.transition(item.id, transition="start", actor_id="w")
    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(
            pool.map(
                lambda i: registered.transition(item.id, transition="edit", actor_id=f"w{i}"),
                range(20),
            )
        )
    assert sorted(r.last_event_seq for r in results) == list(range(2, 22))
    assert [e.seq for e in registered.history(item.id)] == list(range(22))
    assert registered.replay(item.id)[2] == []


def test_concurrent_claim_one_winner(registered: Kernel) -> None:
    item = create(registered)

    def contender(i: int) -> int | None:
        try:
            return registered.claim(item.id, actor_id=f"w{i}").attempt
        except ClaimContestedError:
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(contender, range(8)))
    assert [r for r in results if r is not None] == [1]


@pytest.mark.parametrize("expected", [0, 1, 99])
def test_expected_sequence(registered: Kernel, expected: int) -> None:
    from kernel import SequenceConflictError

    item = create(registered)
    if expected == 0:
        result = registered.transition(item.id, transition="start", actor_id="w", expected_seq=0)
        assert result.last_event_seq == 1
    else:
        before = registered.get(item.id), registered.history(item.id)
        with pytest.raises(SequenceConflictError):
            registered.transition(item.id, transition="start", actor_id="w", expected_seq=expected)
        assert (registered.get(item.id), registered.history(item.id)) == before


def test_expected_sequence_stale_lower(registered: Kernel) -> None:
    from kernel import SequenceConflictError

    item = create(registered)
    registered.transition(item.id, transition="start", actor_id="w")
    for _ in range(4):
        registered.transition(item.id, transition="edit", actor_id="w")
    before = registered.get(item.id), registered.history(item.id)
    assert before[0].last_event_seq == 5
    with pytest.raises(SequenceConflictError, match="expected sequence 3, current is 5"):
        registered.transition(item.id, transition="edit", actor_id="reviewer", expected_seq=3)
    assert (registered.get(item.id), registered.history(item.id)) == before


@pytest.mark.parametrize("case", ["missing", "actor", "expired", "released", "takeover"])
def test_fencing_precedes_sequence(
    registered: Kernel, dsn: str, schema: str, case: str,
) -> None:
    item = create(registered)
    held = registered.claim(item.id, actor_id="w")
    if case in ("expired", "takeover"):
        expire(dsn, schema, item)
    if case == "takeover":
        registered.claim(item.id, actor_id="next")
    if case == "released":
        registered.release(item.id, actor_id="w", attempt=held.attempt)
    error = {
        "missing": StaleAttemptError, "actor": LeaseNotHeldError,
        "expired": LeaseExpiredError, "released": LeaseNotHeldError,
        "takeover": StaleAttemptError,
    }[case]
    before = registered.get(item.id), registered.history(item.id), registered.lease(item.id)
    with pytest.raises(error) as refusal:
        registered.transition(
            item.id, transition="start", actor_id="other" if case == "actor" else "w",
            attempt=None if case == "missing" else held.attempt, expected_seq=99,
        )
    assert type(refusal.value) is error
    assert (
        registered.get(item.id), registered.history(item.id), registered.lease(item.id)
    ) == before


def test_retry_precedes_fencing_and_sequence(registered: Kernel) -> None:
    item = create(registered)
    held = registered.claim(item.id, actor_id="w")
    request: dict[str, Any] = dict(
        transition="start", actor_id="w", attempt=held.attempt,
        expected_seq=0, idempotency_key="reviewed-retry",
    )
    original = registered.transition(item.id, **request)
    registered.release(item.id, actor_id="w", attempt=held.attempt)
    registered.transition(item.id, transition="edit", actor_id="other")
    before = registered.get(item.id), registered.history(item.id), registered.lease(item.id)
    assert registered.transition(item.id, **request) == original
    assert (
        registered.get(item.id), registered.history(item.id), registered.lease(item.id)
    ) == before


def wait_for_item_lock(
    admin: psycopg.Connection[Any], application: str, futures: list[Future[Any]], count: int,
) -> bool:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        admin.execute("SELECT pg_stat_clear_snapshot()")
        row = admin.execute(
            "SELECT count(*) FROM pg_stat_activity WHERE application_name=%s "
            "AND wait_event_type='Lock' AND query LIKE 'SELECT %%FROM work_items_current%%'",
            (application,),
        ).fetchone()
        if row and row[0] == count:
            return True
        if any(f.done() for f in futures):
            return False
        time.sleep(0.01)
    return False


def test_idempotency_recheck_under_item_lock(registered: Kernel, dsn: str, schema: str) -> None:
    item = create(registered)
    application = "f1_retry_" + uuid.uuid4().hex
    params: dict[str, Any] = psycopg.conninfo.conninfo_to_dict(dsn)
    racing = Kernel.connect(
        psycopg.conninfo.make_conninfo(**{**params, "application_name": application}),
        schema=schema, pool_min_size=2, pool_max_size=2,
    )
    try:
        with psycopg.connect(dsn) as admin, ThreadPoolExecutor(max_workers=2) as pool:
            admin.execute(
                SQL("SELECT * FROM {}.work_items_current WHERE work_item_id=%s FOR UPDATE")
                .format(Identifier(schema)), (item.id,),
            )
            futures = [pool.submit(
                racing.transition, item.id, transition="start", actor_id="w",
                idempotency_key="in-lock-retry",
            ) for _ in range(2)]
            try:
                reached = wait_for_item_lock(admin, application, futures, 2)
            finally:
                admin.commit()
            assert reached, "both retries must finish the fast lookup before the item lock opens"
            results = [future.result(timeout=10) for future in futures]
        assert results[0] == results[1]
        assert registered.get(item.id) == results[0]
        assert len(registered.history(item.id)) == 2
    finally:
        racing.close()


def test_heartbeat_serializes_before_expiry_check(
    registered: Kernel, dsn: str, schema: str,
) -> None:
    item = create(registered)
    held = registered.claim(item.id, actor_id="w", ttl_seconds=120)
    application = "f1_heartbeat_" + uuid.uuid4().hex
    params: dict[str, Any] = psycopg.conninfo.conninfo_to_dict(dsn)
    racing = Kernel.connect(
        psycopg.conninfo.make_conninfo(**{**params, "application_name": application}),
        schema=schema,
    )
    try:
        with psycopg.connect(dsn) as admin, ThreadPoolExecutor(max_workers=1) as pool:
            admin.execute(
                SQL("SELECT * FROM {}.work_items_current WHERE work_item_id=%s FOR UPDATE")
                .format(Identifier(schema)), (item.id,),
            )
            future = pool.submit(
                racing.heartbeat, item.id, actor_id="w", attempt=held.attempt, ttl_seconds=300,
            )
            try:
                reached = wait_for_item_lock(admin, application, [future], 1)
                admin.execute(
                    SQL("UPDATE {}.claims SET expires_at=clock_timestamp()-interval '1 second' "
                        "WHERE work_item_id=%s").format(Identifier(schema)), (item.id,),
                )
            finally:
                admin.commit()
            assert reached, "heartbeat must wait on the canonical item lock while its lease is live"
            with pytest.raises(LeaseExpiredError) as refusal:
                future.result(timeout=10)
            assert type(refusal.value) is LeaseExpiredError
        lease = registered.lease(item.id)
        assert lease and not lease.live and lease.attempt == held.attempt
        assert registered.get(item.id) == item and len(registered.history(item.id)) == 1
    finally:
        racing.close()


def test_sustained_pool_operations(registered: Kernel, caplog: pytest.LogCaptureFixture) -> None:
    item = create(registered)
    registered.transition(item.id, transition="start", actor_id="w")
    for _ in range(40):
        registered.transition(item.id, transition="edit", actor_id="w")
    assert registered.get(item.id).last_event_seq == 41
    assert not any("error resetting connection" in r.message for r in caplog.records)
    assert registered.replay(item.id)[2] == []


def test_lease_is_retained_until_explicit_release(registered: Kernel) -> None:
    item = create(registered)
    claim = registered.claim(item.id, actor_id="w")
    registered.transition(item.id, transition="start", actor_id="w", attempt=claim.attempt)
    assert registered.lease(item.id) == claim
    registered.release(item.id, actor_id="w", attempt=claim.attempt)
    assert registered.lease(item.id) is None


def test_transition_is_the_only_public_event_writer(registered: Kernel) -> None:
    assert not hasattr(registered, "append_event")
    item = create(registered)
    registered.transition(item.id, transition="start", actor_id="w")
    assert registered.history(item.id)[-1].transition == "start"


@pytest.mark.parametrize("same_item", [True, False])
def test_concurrent_idempotency(registered: Kernel, same_item: bool) -> None:
    a, b = create(registered), create(registered)

    def write(i: int) -> WorkItem | None:
        try:
            target = a if same_item or i == 0 else b
            return registered.transition(
                target.id, transition="start", actor_id="w", idempotency_key="racing-key"
            )
        except IdempotencyConflictError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(write, range(2)))
    if same_item:
        assert results[0] == results[1] and results[0] is not None
        assert len(registered.history(a.id)) == 2
    else:
        assert sum(r is not None for r in results) == 1
        assert sorted(len(registered.history(i.id)) for i in (a, b)) == [1, 2]


def test_concurrent_workflow_registration(kernel: Kernel, workflow: Workflow) -> None:
    with ThreadPoolExecutor(max_workers=8) as pool:
        versions = list(pool.map(lambda _: kernel.register_workflow(workflow), range(8)))
    assert versions == [1] * 8 and len(kernel.list_workflows()) == 1


@pytest.mark.parametrize("operation", ["claim", "heartbeat"])
@pytest.mark.parametrize("ttl", [0.0, -1.0, float("nan"), float("inf"), float("-inf")])
def test_invalid_lease_ttl(registered: Kernel, operation: str, ttl: float) -> None:
    item = create(registered)
    if operation == "heartbeat":
        registered.claim(item.id, actor_id="w")
    before = registered.lease(item.id)
    with pytest.raises(InvalidFieldError):
        if operation == "claim":
            registered.claim(item.id, actor_id="w", ttl_seconds=ttl)
        else:
            registered.heartbeat(item.id, actor_id="w", attempt=1, ttl_seconds=ttl)
    assert registered.lease(item.id) == before
    assert len(registered.history(item.id)) == 1
