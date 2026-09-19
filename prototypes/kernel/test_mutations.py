"""Mutation checks — prove the scenario's assertions can actually fail.

A green scenario that cannot go red manufactures confidence in the next
reviewer. Each case here breaks one guarantee and asserts the kernel notices,
and every refusal is PAIRED with the legitimate call that must still succeed —
otherwise "it refused" is indistinguishable from "it refuses everything".

Two rules these checks follow deliberately:

  * Expiry is tested with genuinely short leases and real waits, never by
    backdating expires_at in SQL. Backdating is faster and stops testing the
    public API: it cannot tell a correct expiry predicate from one evaluated
    against the wrong clock.
  * Deliberate database surgery (editing payloads, deleting events) goes through
    its own connection, never through the kernel's. Reaching into the kernel's
    connection would also silently paper over transaction-hygiene defects.

Run:  python test_mutations.py "postgresql://..."
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import fields as dataclass_fields
from dataclasses import replace
from datetime import datetime
from typing import Any, Literal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import psycopg
import yaml
from kernel import (
    REPLAY_COVERS,
    REPLAY_DOES_NOT_COVER,
    WORKFLOW_DOCUMENT_REMOVED_KEYS,
    WORKFLOW_DOCUMENT_VERSION,
    ClaimContestedError,
    IdempotencyConflictError,
    InvalidFieldError,
    InvalidQueryError,
    InvalidWorkflowError,
    Kernel,
    KernelError,
    LeaseExpiredError,
    LeaseNotHeldError,
    ReservedPayloadKeyError,
    StaleAttemptError,
    TransitionRefusedError,
    UnsupportedSchemaError,
    Workflow,
    load_workflow,
    load_workflow_document,
    validate_workflow_document,
    workflow_schema,
)
from psycopg.types.json import Jsonb

HERE = os.path.dirname(os.path.abspath(__file__))

# Real leases, real waits. Short enough to keep the suite quick, with enough
# margin over the wait that a loaded machine does not make them flaky.
SHORT_TTL = 1.0
EXPIRY_WAIT = 1.4
LOOP_TTL = 0.6
LOOP_WAIT = 0.9

WF = Workflow(
    # No version=: the registry assigns it. Asserting one here would be a claim
    # about the registry's state that this definition has no way to know.
    name="t",
    states=("open", "doing", "review", "done"), initial="open",
    transitions={"start": (("open",), "doing"), "submit": (("doing",), "review"),
                 # A self-loop: a transition that changes fields but not state.
                 # Truncating its event moves neither the state nor the chain,
                 # which is exactly the case replay used to miss.
                 "annotate": (("doing",), "doing"),
                 "accept": (("review",), "done")},
    roles={"accept": ("reviewer",)},
    role_names=("reviewer",),
    required_fields={"submit": ("note",)},
    terminal=("done",),
    types=("x", "y"),
)

#: A second workflow for the link-aware query, because the point that has to be
#: provable is that a TERMINAL state is not satisfaction -- and "t" has only one
#: terminal state, which happens to be the successful one.
WF_DEP = Workflow(
    name="dep",
    states=("open", "doing", "done", "rejected"), initial="open",
    transitions={"start": (("open",), "doing"), "finish": (("doing",), "done"),
                 "reject": (("doing",), "rejected")},
    terminal=("done", "rejected"),
    types=("x", "y"),
)

#: A second version of WF: one more state, and a transition that reaches it.
#: The added transition is not decoration -- validate() refuses a state nothing
#: enters, because a state an item can never hold is a state every report about
#: it is answering about nothing.
WF_V2 = replace(
    WF,
    states=(*WF.states, "parked"),
    transitions={**WF.transitions, "park": (("doing",), "parked")},
)

#: Every public name on Kernel, so that ADDING one fails the bounded-query check
#: until someone classifies it. A coverage list that is never itself checked is
#: how a query ships unbounded while a green check says every query is bounded.
KERNEL_PUBLIC_SURFACE = frozenset({
    "connect", "close", "initialize",
    "register_workflow", "get_workflow", "list_workflows", "health",
    "create_work_item", "get",
    "claim", "heartbeat", "lease", "release", "expire_leases",
    "transition", "link", "links_from",
    "list_items", "available", "owned", "in_states", "blocked",
    "history", "replay",
})

#: Workflow's fields and methods. Pinned for the same reason as the Kernel
#: surface: a new field is a decision (is it hashed? is it in the document? does
#: validate() check it?) and this check is what forces the decision to be made
#: rather than defaulted.
WORKFLOW_PUBLIC_SURFACE = frozenset({
    "name", "states", "initial", "transitions", "version", "roles",
    "required_fields", "terminal", "types", "role_names",
    "validate", "as_json", "from_json", "as_document", "from_document",
})

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, fn: Callable[[], None]) -> None:
    try:
        fn()
        PASS.append(name)
        print(f"  \033[32m✓\033[0m {name}")
    except AssertionError as e:
        FAIL.append(name)
        print(f"  \033[31m✗ {name}: {e}\033[0m")


def expect(exc: type[BaseException], fn: Callable[[], object], what: str) -> BaseException:
    """Assert fn() refuses with exc, and hand the exception back for inspection."""
    try:
        fn()
    except exc as caught:
        return caught
    except Exception as other:
        raise AssertionError(
            f"{what}: raised {type(other).__name__} not {exc.__name__}: {other}"
        ) from None
    raise AssertionError(f"{what}: NOTHING was raised — the check is vacuous")


def expect_exactly(
    exc: type[BaseException], fn: Callable[[], object], what: str
) -> BaseException:
    """As expect(), but the refusal must be exactly this class, not a subclass.

    The three lease conditions all subclass StaleAttemptError so old callers
    keep working; that makes it possible to 'pass' a check by raising the wrong
    one, so the checks that distinguish them assert the exact type.
    """
    caught = expect(exc, fn, what)
    if type(caught) is not exc:
        raise AssertionError(
            f"{what}: raised {type(caught).__name__}, but this case must be "
            f"distinguishable as {exc.__name__}: {caught}"
        )
    return caught


def fresh(dsn: str, schema: str) -> Kernel:
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        c.execute(f'CREATE SCHEMA "{schema}"')
    k = Kernel.connect(dsn, schema=schema)
    k.initialize(os.path.join(HERE, "schema.sql"))
    k.register_workflow(WF)
    return k


def surgery(dsn: str, schema: str, sql: str, params: tuple[Any, ...]) -> None:
    """Deliberate tampering, on its own connection. See the module docstring."""
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute(f'SET search_path TO "{schema}"')
        c.execute(sql, params)


def scalar(dsn: str, schema: str, sql: str, params: tuple[Any, ...] = ()) -> Any:
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute(f'SET search_path TO "{schema}"')
        row = c.execute(sql, params).fetchone()
    if row is None:
        raise AssertionError(f"expected one row from {sql!r}, got none")
    return row[0]


def named(dsn: str, app_name: str) -> str:
    """The same DSN, tagged so pg_stat_activity can pick this session out."""
    sep = "&" if "?" in dsn else "?"
    return f"{dsn}{sep}application_name={app_name}"


def open_transactions(dsn: str, app_name: str) -> int:
    return int(scalar(
        dsn, "public",
        "SELECT count(*) FROM pg_stat_activity WHERE application_name = %s "
        "AND state = 'idle in transaction'",
        (app_name,),
    ))


def main(dsn: str) -> int:
    print("\n\033[1mFencing\033[0m")

    def fencing_bites() -> None:
        k = fresh(dsn, "m1")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        c1 = k.claim(it.id, actor_id="w1", ttl_seconds=SHORT_TTL)
        # control: the CURRENT attempt, from the holder, is accepted
        k.transition(it.id, transition="start", actor_id="w1", attempt=c1.attempt)
        # a real short lease and a real wait -- not SQL backdating
        time.sleep(EXPIRY_WAIT)
        k.expire_leases()
        c2 = k.claim(it.id, actor_id="w2", ttl_seconds=300)
        assert c2.attempt != c1.attempt, "takeover reissued the same fencing token"
        expect_exactly(StaleAttemptError,
                       lambda: k.transition(it.id, transition="submit", actor_id="w1",
                                            attempt=c1.attempt, fields={"note": "stale"}),
                       "stale attempt after a takeover")
        # control: the replacement holder can still write
        k.transition(it.id, transition="submit", actor_id="w2", attempt=c2.attempt,
                     fields={"note": "legitimate"})
        assert k.get(it.id).state == "review", "the takeover holder's write did not land"
        k.close()
    check("a stale attempt is refused, and the current one is not", fencing_bites)

    def attempt_required() -> None:
        k = fresh(dsn, "m2")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        c = k.claim(it.id, actor_id="w1", ttl_seconds=300)
        expect(StaleAttemptError,
               lambda: k.transition(it.id, transition="start", actor_id="w2"),
               "omitted attempt under a live lease")
        k.transition(it.id, transition="start", actor_id="w1", attempt=c.attempt)  # control
        k.close()
    check("omitting attempt under a live lease is refused", attempt_required)

    def attempt_monotonic() -> None:
        k = fresh(dsn, "m3")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        seen = set()
        for i in range(4):
            c = k.claim(it.id, actor_id=f"w{i}", ttl_seconds=LOOP_TTL)
            assert c.attempt not in seen, f"attempt {c.attempt} was reissued"
            seen.add(c.attempt)
            time.sleep(LOOP_WAIT)
            k.expire_leases()
        assert seen == {1, 2, 3, 4}, f"attempts not monotonic: {sorted(seen)}"
        k.close()
    check("attempt numbers are monotonic across takeovers", attempt_monotonic)

    print("\n\033[1mLease ownership (WI-367)\033[0m")

    def expired_lease_cannot_write() -> None:
        """DEFECT 1. An expired lease used to fence nothing at all: a worker that
        merely slept past its TTL could still commit, before any takeover."""
        k = fresh(dsn, "m14")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        c = k.claim(it.id, actor_id="w1", ttl_seconds=SHORT_TTL)
        # control: while the lease is live, this exact call succeeds
        k.transition(it.id, transition="start", actor_id="w1", attempt=c.attempt)
        time.sleep(EXPIRY_WAIT)
        err = expect_exactly(
            LeaseExpiredError,
            lambda: k.transition(it.id, transition="annotate", actor_id="w1",
                                 attempt=c.attempt, fields={"late": True}),
            "a write on a lease that expired underneath its holder",
        )
        assert "expired" in str(err), f"the refusal does not say the lease expired: {err}"
        assert "took over" not in str(err), (
            f"an expiry with no takeover must not be reported as a takeover: {err}"
        )
        assert k.get(it.id).fields.get("late") is None, "the refused write left an effect"
        # control: the same call succeeds once the lease is resolved by a takeover
        c2 = k.claim(it.id, actor_id="w1", ttl_seconds=300)
        k.transition(it.id, transition="annotate", actor_id="w1", attempt=c2.attempt,
                     fields={"late": True})
        assert k.get(it.id).fields["late"] is True, "the legitimate retry did not land"
        k.close()
    check("an expired lease cannot write, and a fresh one can", expired_lease_cannot_write)

    def expiry_distinguished_from_takeover() -> None:
        """DEFECT 1, second half. 'your lease expired' and 'someone took over'
        need different responses, so they must be different refusals."""
        k = fresh(dsn, "m15")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        c = k.claim(it.id, actor_id="w1", ttl_seconds=SHORT_TTL)
        time.sleep(EXPIRY_WAIT)
        expired = expect_exactly(
            LeaseExpiredError,
            lambda: k.transition(it.id, transition="start", actor_id="w1",
                                 attempt=c.attempt),
            "expired, nobody has taken over",
        )
        k.expire_leases()
        k.claim(it.id, actor_id="w2", ttl_seconds=300)
        taken = expect_exactly(
            StaleAttemptError,
            lambda: k.transition(it.id, transition="start", actor_id="w1",
                                 attempt=c.attempt),
            "expired AND taken over",
        )
        assert str(expired) != str(taken), "both conditions produced the same message"
        assert "took over" in str(taken), f"a takeover is not named as one: {taken}"
        k.close()
    check("expiry and takeover are different refusals", expiry_distinguished_from_takeover)

    def unclaimed_writes_still_work() -> None:
        """DEFECT 1, third half. Plan 032 requires a person to act without first
        taking a lease. No lease row is NOT the same case as a dead lease row."""
        k = fresh(dsn, "m16")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        # control: an item that was never claimed accepts a write with no attempt
        k.transition(it.id, transition="start", actor_id="erin", actor_kind="human")
        assert k.get(it.id).state == "doing", "an unclaimed write was lost"
        # ...but claiming to hold a lease that does not exist is refused
        expect_exactly(
            LeaseNotHeldError,
            lambda: k.transition(it.id, transition="annotate", actor_id="erin", attempt=1),
            "an attempt supplied for an item with no lease",
        )
        # and after a release, the same thing holds
        c = k.claim(it.id, actor_id="w1", ttl_seconds=300)
        k.release(it.id, actor_id="w1", attempt=c.attempt)
        expect_exactly(
            LeaseNotHeldError,
            lambda: k.transition(it.id, transition="annotate", actor_id="w1",
                                 attempt=c.attempt),
            "an attempt supplied after the lease was released",
        )
        k.transition(it.id, transition="annotate", actor_id="w1")  # control
        k.close()
    check("an unclaimed item accepts an attempt-less write and refuses a fake attempt",
          unclaimed_writes_still_work)

    def expired_lease_blocks_unclaimed_write() -> None:
        """DEFECT 1, the decided edge. An EXPIRED lease refuses even a write that
        carries no attempt: the previous holder's fate is unresolved, and
        resolving it is one call."""
        k = fresh(dsn, "m17")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.claim(it.id, actor_id="w1", ttl_seconds=SHORT_TTL)
        time.sleep(EXPIRY_WAIT)
        err = expect_exactly(
            LeaseExpiredError,
            lambda: k.transition(it.id, transition="start", actor_id="erin",
                                 actor_kind="human"),
            "an attempt-less write over an unswept dead lease",
        )
        assert "expire_leases()" in str(err), (
            f"the refusal must say how to resolve it, got: {err}"
        )
        swept = k.expire_leases()
        assert swept == 1, f"expire_leases() swept {swept}, expected 1"
        # control: the identical call now succeeds
        k.transition(it.id, transition="start", actor_id="erin", actor_kind="human")
        assert k.get(it.id).state == "doing", "the write after the sweep did not land"
        k.close()
    check("an unswept dead lease blocks writes, and sweeping unblocks them",
          expired_lease_blocks_unclaimed_write)

    def holder_is_checked() -> None:
        """DEFECT 3. The fencing token alone was enough: any actor presenting the
        live holder's attempt number could write as though it held the lease."""
        k = fresh(dsn, "m18")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        c = k.claim(it.id, actor_id="w1", ttl_seconds=300)
        err = expect_exactly(
            LeaseNotHeldError,
            lambda: k.transition(it.id, transition="start", actor_id="not-w1",
                                 attempt=c.attempt),
            "a correct attempt attributed to someone who is not the holder",
        )
        assert "w1" in str(err) and "not-w1" in str(err), (
            f"the refusal names neither the holder nor the caller: {err}"
        )
        assert k.get(it.id).state == "open", "the refused write left an effect"
        # control: the holder, with the same attempt, succeeds
        k.transition(it.id, transition="start", actor_id="w1", attempt=c.attempt)
        assert k.get(it.id).state == "doing", "the holder's write did not land"
        k.close()
    check("a write attributed to a non-holder is refused; the holder's is not",
          holder_is_checked)

    def heartbeat_cannot_resurrect() -> None:
        """DEFECT 2. heartbeat() matched actor and attempt but not liveness, so a
        worker that slept past expiry revived its own lease and could race a
        legitimate takeover."""
        k = fresh(dsn, "m19")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        c = k.claim(it.id, actor_id="w1", ttl_seconds=SHORT_TTL)
        # control: a live lease heartbeats, and the item stays owned
        renewed = k.heartbeat(it.id, actor_id="w1", attempt=c.attempt, ttl_seconds=SHORT_TTL)
        assert renewed.expires_at > c.expires_at, "heartbeat did not extend a live lease"
        assert len(k.owned("w1")) == 1, "a heartbeaten lease is not reported as owned"
        expect_exactly(LeaseNotHeldError,
                       lambda: k.heartbeat(it.id, actor_id="not-w1", attempt=c.attempt),
                       "a non-holder heartbeating someone else's live lease")
        time.sleep(EXPIRY_WAIT)
        expect_exactly(LeaseExpiredError,
                       lambda: k.heartbeat(it.id, actor_id="w1", attempt=c.attempt,
                                           ttl_seconds=300),
                       "heartbeat against a lease that has expired")
        # the failed heartbeat must not have extended anything
        assert len(k.available(states=("open",))) == 1, (
            "the item is still held after its lease died — heartbeat revived it"
        )
        assert len(k.owned("w1")) == 0, "a dead lease is still reported as owned"
        k.close()
    check("heartbeat renews a live lease and refuses a dead one", heartbeat_cannot_resurrect)

    print("\n\033[1mOne clock (WI-368)\033[0m")

    def liveness_is_decided_at_serialization() -> None:
        """DEFECT 6, the subtle half. now() is frozen at transaction start, so a
        liveness test taken after blocking on a row lock was evaluated against
        the clock as it was BEFORE the wait. This check holds the row lock from
        another session until the lease dies underneath the waiting writer.

        It isolates the clock defect from the expiry defect: the writer's
        transaction begins while the lease is still live, so an expiry check
        using now() would see a live lease and let the write through.
        """
        app = f"kernel-lockwait-{uuid.uuid4().hex[:8]}"
        k = fresh(named(dsn, app), "m20")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        c = k.claim(it.id, actor_id="w1", ttl_seconds=SHORT_TTL)

        blocker = psycopg.connect(dsn)
        blocker.execute('SET search_path TO "m20"')
        blocker.execute(
            "SELECT 1 FROM work_items_current WHERE work_item_id = %s FOR UPDATE", (it.id,)
        )

        outcome: dict[str, BaseException | None] = {}

        def writer() -> None:
            try:
                k.transition(it.id, transition="start", actor_id="w1", attempt=c.attempt)
                outcome["r"] = None
            except BaseException as e:  # the outcome IS the measurement
                outcome["r"] = e

        th = threading.Thread(target=writer)
        th.start()
        try:
            # Prove this check's own premise: the writer's transaction must have
            # started BEFORE the lease expired, or it proves nothing about now().
            started = _wait_until_blocked(dsn, app)
            assert started < c.expires_at, (
                f"the writer's transaction began at {started.isoformat()}, after the lease "
                f"expired at {c.expires_at.isoformat()} — this check would pass for the "
                "wrong reason"
            )
            time.sleep(EXPIRY_WAIT)
            assert scalar(dsn, "m20", "SELECT clock_timestamp() > %s", (c.expires_at,)), (
                "the lease had not expired yet; the wait is too short"
            )
        finally:
            blocker.commit()
            blocker.close()
            th.join(30)

        got = outcome.get("r")
        assert got is not None, (
            "the write committed against a lease that expired while it waited for the row "
            "lock — liveness is being decided at transaction start, not at serialization"
        )
        assert type(got) is LeaseExpiredError, f"unexpected refusal: {type(got).__name__}: {got}"
        k.close()
    check("lease liveness is decided at the serialization point, not transaction start",
          liveness_is_decided_at_serialization)

    def lock_wait_control() -> None:
        """The control for the check above: the same lock-wait harness, with a
        lease that is still live when the lock is released, must SUCCEED. Without
        this, 'the write was refused' could just mean the harness always fails."""
        app = f"kernel-lockok-{uuid.uuid4().hex[:8]}"
        k = fresh(named(dsn, app), "m21")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        c = k.claim(it.id, actor_id="w1", ttl_seconds=60)

        blocker = psycopg.connect(dsn)
        blocker.execute('SET search_path TO "m21"')
        blocker.execute(
            "SELECT 1 FROM work_items_current WHERE work_item_id = %s FOR UPDATE", (it.id,)
        )
        outcome: dict[str, BaseException | None] = {}

        def writer() -> None:
            try:
                k.transition(it.id, transition="start", actor_id="w1", attempt=c.attempt)
                outcome["r"] = None
            except BaseException as e:  # the outcome IS the measurement
                outcome["r"] = e

        th = threading.Thread(target=writer)
        th.start()
        try:
            _wait_until_blocked(dsn, app)
            time.sleep(EXPIRY_WAIT)
        finally:
            blocker.commit()
            blocker.close()
            th.join(30)
        assert outcome.get("r") is None, f"a still-live lease was refused: {outcome.get('r')}"
        assert k.get(it.id).state == "doing", "the blocked write did not land after the wait"
        k.close()
    check("the same lock-wait harness lets a still-live lease through", lock_wait_control)

    def timestamps_come_from_the_database() -> None:
        """DEFECT 6, the plain half. occurred_at used to be stamped by the writing
        process while every expiry predicate used the database clock.

        Limit, stated rather than implied: on a host whose clock agrees with the
        database this cannot detect a process-stamped timestamp by its value.
        What it does pin down is that ONE database-generated instant is used for
        the event and the projection row it updates — two stamps taken
        separately, from either clock, would differ."""
        k = fresh(dsn, "m22")
        before = scalar(dsn, "m22", "SELECT clock_timestamp()")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.transition(it.id, transition="start", actor_id="a")
        after = scalar(dsn, "m22", "SELECT clock_timestamp()")

        last_event_at = scalar(
            dsn, "m22", "SELECT last_event_at FROM work_items_current WHERE work_item_id = %s",
            (it.id,),
        )
        events = k.history(it.id)
        assert events[-1].occurred_at == last_event_at, (
            f"the event says {events[-1].occurred_at.isoformat()} and the projection says "
            f"{last_event_at.isoformat()}: they are not the same database instant"
        )
        for e in events:
            assert before <= e.occurred_at <= after, (
                f"event {e.seq} is stamped {e.occurred_at.isoformat()}, outside the database "
                f"clock window [{before.isoformat()}, {after.isoformat()}]"
            )
        created_at = scalar(
            dsn, "m22", "SELECT created_at FROM work_items_current WHERE work_item_id = %s",
            (it.id,),
        )
        assert events[0].occurred_at >= created_at, (
            "the creation event predates the row it created"
        )
        k.close()
    check("event and projection timestamps are one database-generated instant",
          timestamps_come_from_the_database)

    print("\n\033[1mTransaction hygiene (WI-368)\033[0m")

    def reads_close_their_transaction() -> None:
        """DEFECT 7. get(), get_workflow() and links_from() left the transaction
        open, pinning a snapshot (and, on the old predicates, the clock)."""
        app = f"kernel-reads-{uuid.uuid4().hex[:8]}"
        # First prove the probe can SEE an open transaction, or its zero means
        # nothing. This is the control for the measurement itself.
        canary = psycopg.connect(named(dsn, app))
        canary.execute("SELECT 1")
        assert open_transactions(dsn, app) == 1, (
            "the probe cannot see a known-open transaction — it would report zero "
            "whatever the kernel did"
        )
        canary.rollback()
        canary.close()

        k = fresh(named(dsn, app), "m23")
        a = k.create_work_item(workflow="t", type="x", actor_id="a", fields={"n": 1})
        b = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.link(a.id, b.id, "blocks")
        reads: list[tuple[str, Callable[[], object]]] = [
            ("get", lambda: k.get(a.id)),
            ("get_workflow", lambda: k.get_workflow("t")),
            ("links_from", lambda: k.links_from(a.id)),
            ("history", lambda: k.history(a.id)),
            ("available", lambda: k.available()),
            ("owned", lambda: k.owned("w1")),
            ("in_states", lambda: k.in_states(("open",))),
            ("list_items", lambda: k.list_items()),
            ("blocked", lambda: k.blocked(link_type="blocks", direction="incoming",
                                          satisfied_states=("done",))),
            ("lease", lambda: k.lease(a.id)),
            ("list_workflows", k.list_workflows),
            ("health", k.health),
            ("replay", lambda: k.replay(a.id)),
        ]
        for label, call in reads:
            call()
            assert open_transactions(dsn, app) == 0, (
                f"{label}() left its transaction open"
            )
        # A REFUSED read has to close it too, and several of these refuse only
        # after they have already executed a statement -- resolving a cursor,
        # checking a state name. A refusal that leaks the transaction pins the
        # snapshot exactly as a successful one would.
        refusals: list[tuple[str, Callable[[], object]]] = [
            ("list_items(limit=0)", lambda: k.list_items(limit=0)),
            ("list_items(after=<missing>)", lambda: k.list_items(after=uuid.uuid4())),
            ("in_states(())", lambda: k.in_states(())),
            ("blocked(<misspelled state>)",
             lambda: k.blocked(link_type="blocks", direction="incoming",
                               satisfied_states=("nope",))),
            ("lease(<missing>)", lambda: k.lease(uuid.uuid4())),
        ]
        for label, call in refusals:
            try:
                call()
            except KernelError:
                pass
            else:
                raise AssertionError(f"{label} did not refuse — this case is vacuous")
            assert open_transactions(dsn, app) == 0, (
                f"{label} left its transaction open after refusing"
            )
        k.close()
    check("every read path closes its transaction", reads_close_their_transaction)

    def search_path_survives_a_refusal() -> None:
        """Not on the reported list, found while fixing DEFECT 7: connect() ran
        SET search_path and never committed it. A SET is undone by a rollback, so
        the first refusal silently dropped the session back to the default
        search_path while looking fine."""
        k = fresh(dsn, "m24")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        expect(TransitionRefusedError,
               lambda: k.transition(it.id, transition="nope", actor_id="a"),
               "a refusal that rolls the transaction back")
        # control: the session must still be pointed at m24, not at public
        assert k.get(it.id).state == "open", "the kernel lost its schema after a rollback"
        assert k.health()["work_items"] == 1, "health() is reading a different schema"
        k.close()
    check("a rollback does not reset the session's search_path",
          search_path_survives_a_refusal)

    print("\n\033[1mWorkflow validation\033[0m")

    def bad_transition() -> None:
        k = fresh(dsn, "m4")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        expect(TransitionRefusedError,
               lambda: k.transition(it.id, transition="accept", actor_id="a", role="reviewer"),
               "transition from the wrong state")
        expect(TransitionRefusedError,
               lambda: k.transition(it.id, transition="nope", actor_id="a"),
               "unknown transition")
        k.transition(it.id, transition="start", actor_id="a")  # control
        k.close()
    check("wrong-state and unknown transitions are refused", bad_transition)

    def role_gate() -> None:
        k = fresh(dsn, "m5")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.transition(it.id, transition="start", actor_id="a")
        k.transition(it.id, transition="submit", actor_id="a", fields={"note": "n"})
        expect(TransitionRefusedError,
               lambda: k.transition(it.id, transition="accept", actor_id="a", role="worker"),
               "disallowed role")
        expect(TransitionRefusedError,
               lambda: k.transition(it.id, transition="accept", actor_id="a"),
               "absent role where one is required")
        k.transition(it.id, transition="accept", actor_id="a", role="reviewer")  # control
        k.close()
    check("role gating refuses, and the allowed role still passes", role_gate)

    def required_field() -> None:
        k = fresh(dsn, "m6")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.transition(it.id, transition="start", actor_id="a")
        expect(InvalidFieldError,
               lambda: k.transition(it.id, transition="submit", actor_id="a"),
               "missing required field")
        k.transition(it.id, transition="submit", actor_id="a", fields={"note": "n"})  # control
        k.close()
    check("a missing required field refuses, supplying it passes", required_field)

    def terminal() -> None:
        k = fresh(dsn, "m7")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.transition(it.id, transition="start", actor_id="a")
        k.transition(it.id, transition="submit", actor_id="a", fields={"note": "n"})
        k.transition(it.id, transition="accept", actor_id="a", role="reviewer")
        expect(TransitionRefusedError,
               lambda: k.transition(it.id, transition="start", actor_id="a"),
               "transition out of a terminal state")
        k.close()
    check("a terminal state refuses everything after it", terminal)

    print("\n\033[1mField types\033[0m")

    def field_type_contract() -> None:
        """A datetime used to raise a raw TypeError out of psycopg on the write
        path while _canonical() stringified the same value on the hash path."""
        k = fresh(dsn, "m25")
        # control: the full supported type set survives create -> transition -> replay
        rich: dict[str, Any] = {
            "s": "text", "i": 7, "f": 1.5, "b": True, "n": None,
            "list": [1, "two", None, {"deep": [True]}],
            "obj": {"k": "v", "nested": {"x": 0.25}},
        }
        it = k.create_work_item(workflow="t", type="x", actor_id="a", fields=rich)
        assert k.get(it.id).fields == rich, "a supported field did not round-trip"
        for bad, why in [
            ({"when": datetime(2026, 1, 1)}, "datetime"),
            ({"id": uuid.uuid4()}, "uuid"),
            ({"nan": float("nan")}, "NaN"),
            ({"inf": float("inf")}, "infinity"),
            ({"t": (1, 2)}, "tuple"),
            ({"s": {1, 2}}, "set"),
            ({"nested": {"deeper": [datetime(2026, 1, 1)]}}, "datetime nested in a list"),
            ({"keys": {1: "x"}}, "a non-string object key"),
        ]:
            err = expect(InvalidFieldError,
                         lambda bad=bad: k.transition(  # type: ignore[misc]
                             it.id, transition="start", actor_id="a", fields=bad),
                         f"{why} in a custom field")
            assert "fields." in str(err), f"the refusal does not name the field path: {err}"
        # the same contract applies to the event payload
        expect(InvalidFieldError,
               lambda: k.transition(it.id, transition="start", actor_id="a",
                                    payload={"at": datetime(2026, 1, 1)}),
               "a datetime in the event payload")
        # control: the legitimate version of that very call still works
        k.transition(it.id, transition="start", actor_id="a",
                     payload={"at": "2026-01-01T00:00:00+00:00"},
                     fields={"when": "2026-01-01"})
        _, fields, drift = k.replay(it.id)
        assert not drift, f"the round-trip produced drift: {drift}"
        assert fields == {**rich, "when": "2026-01-01"}, f"replay lost a field: {fields}"
        k.close()
    check("unsupported field types refuse; the JSON type set round-trips", field_type_contract)

    def reserved_payload_keys() -> None:
        """DEFECT 4. payload={"fields": ...} used to overwrite the reducer's own
        record, so the projection and replay disagreed silently."""
        k = fresh(dsn, "m26")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.transition(it.id, transition="start", actor_id="a")
        for key in ("from", "to", "fields", "unset", "created"):
            err = expect_exactly(
                ReservedPayloadKeyError,
                lambda key=key: k.transition(  # type: ignore[misc]
                    it.id, transition="annotate", actor_id="a",
                    fields={"amount": 2}, payload={key: "hijack"}),
                f"a caller payload setting the reserved key {key!r}",
            )
            assert key in str(err), f"the refusal does not name the key: {err}"
        assert k.get(it.id).fields.get("amount") is None, "a refused payload left an effect"
        # control: a payload key the reducer does not own is recorded verbatim
        k.transition(it.id, transition="annotate", actor_id="a", fields={"amount": 2},
                     payload={"comment": "checked by hand"})
        last = k.history(it.id)[-1]
        assert last.payload["comment"] == "checked by hand", "the caller payload was dropped"
        assert last.payload["fields"] == {"amount": 2}, "the reducer's record was displaced"
        _, fields, drift = k.replay(it.id)
        assert not drift, f"a legitimate payload produced drift: {drift}"
        assert fields["amount"] == k.get(it.id).fields["amount"], "replay and projection differ"
        k.close()
    check("reserved payload keys refuse; other payload keys are kept", reserved_payload_keys)

    print("\n\033[1mIdempotency\033[0m")

    def idem() -> None:
        k = fresh(dsn, "m8")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.transition(it.id, transition="start", actor_id="a", idempotency_key="K1")
        k.transition(it.id, transition="start", actor_id="a", idempotency_key="K1")  # replay
        assert k.get(it.id).last_event_seq == 1, "identical retry duplicated an effect"
        expect(IdempotencyConflictError,
               lambda: k.transition(it.id, transition="submit", actor_id="a",
                                    fields={"note": "n"}, idempotency_key="K1"),
               "reusing a key for a different request")
        assert k.get(it.id).state == "doing", "a refused conflict left a partial effect"
        k.transition(it.id, transition="submit", actor_id="a", fields={"note": "n"},
                     idempotency_key="K2")  # control
        k.close()
    check("identical retry is a no-op; conflicting reuse refuses with no partial effect", idem)

    print("\n\033[1mReplay / chain\033[0m")

    def chain_detects_tamper() -> None:
        k = fresh(dsn, "m9")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.transition(it.id, transition="start", actor_id="a")
        _, _, drift = k.replay(it.id)
        assert not drift, f"clean history reported drift: {drift}"      # control
        surgery(dsn, "m9",                                              # mutate a payload
                "UPDATE events SET payload = %s WHERE work_item_id = %s AND event_seq = 1",
                (Jsonb({"from": "open", "to": "done"}), it.id))
        _, _, drift = k.replay(it.id)
        assert drift, "an edited payload produced NO drift — the chain check is vacuous"
        k.close()
    check("an edited event payload is detected on replay", chain_detects_tamper)

    def chain_detects_deletion() -> None:
        k = fresh(dsn, "m10")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.transition(it.id, transition="start", actor_id="a")
        k.transition(it.id, transition="submit", actor_id="a", fields={"note": "n"})
        _, _, drift = k.replay(it.id)
        assert not drift, f"clean history reported drift: {drift}"      # control
        surgery(dsn, "m10",
                "DELETE FROM events WHERE work_item_id = %s AND event_seq = 1", (it.id,))
        _, _, drift = k.replay(it.id)
        assert drift, "a deleted middle event produced NO drift"
        k.close()
    check("a removed middle event is detected on replay", chain_detects_deletion)

    def replay_detects_truncation() -> None:
        """DEFECT 5b. Deleting the LAST event of a transition that changed fields
        but not state moved neither the state nor the chain, so drift was []."""
        k = fresh(dsn, "m27")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.transition(it.id, transition="start", actor_id="a")
        k.transition(it.id, transition="annotate", actor_id="a", fields={"amount": 2})
        state, fields, drift = k.replay(it.id)
        assert not drift, f"clean history reported drift: {drift}"      # control
        assert state == "doing" and fields == {"amount": 2}, f"bad baseline: {state} {fields}"
        surgery(dsn, "m27",
                "DELETE FROM events WHERE work_item_id = %s AND event_seq = 2", (it.id,))
        state, fields, drift = k.replay(it.id)
        assert drift, (
            "the final event was deleted and replay reported NO drift — the state and the "
            "chain both still reconcile, which is exactly why state alone is not enough"
        )
        assert any("last_event_seq" in d for d in drift), (
            f"truncation was noticed, but not as truncation: {drift}"
        )
        k.close()
    check("a truncated final event is detected on replay", replay_detects_truncation)

    def replay_detects_field_drift() -> None:
        """DEFECT 5a. Replay compared only state, so a projection whose fields
        disagreed with the history was reported as clean."""
        k = fresh(dsn, "m28")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.transition(it.id, transition="start", actor_id="a", fields={"amount": 2})
        _, _, drift = k.replay(it.id)
        assert not drift, f"clean history reported drift: {drift}"      # control
        surgery(dsn, "m28",
                "UPDATE work_items_current SET custom_fields = %s WHERE work_item_id = %s",
                (Jsonb({"amount": 999}), it.id))
        state, _, drift = k.replay(it.id)
        assert state == k.get(it.id).state, "this check must vary fields ONLY, not state"
        assert drift, "the projection's fields were rewritten and replay reported NO drift"
        assert any("fields disagree" in d for d in drift), f"drift is not about fields: {drift}"
        assert "999" in " ".join(drift), f"the drift does not say what disagrees: {drift}"
        k.close()
    check("a projection whose fields disagree with the history is detected",
          replay_detects_field_drift)

    def replay_coverage_boundary_is_accurate() -> None:
        """Pin the documented gap so it cannot drift into a false claim.

        replay() reconciles the reconstructible projection. It CANNOT see
        leases, the attempt counter or typed links, because nothing appends an
        event for them. That makes an empty drift list a narrow statement, and
        this check fails the day the narrow statement stops matching the code —
        in either direction."""
        k = fresh(dsn, "m29")
        a = k.create_work_item(workflow="t", type="x", actor_id="a")
        b = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.link(a.id, b.id, "blocks")
        c = k.claim(a.id, actor_id="w1", ttl_seconds=300)
        k.transition(a.id, transition="start", actor_id="w1", attempt=c.attempt)

        # control: the covered part really is covered
        _, _, drift = k.replay(a.id)
        assert not drift, f"a clean item reported drift: {drift}"
        assert any("blocks" == lt for _, lt in k.links_from(a.id)), "the link was not stored"

        # the boundary: destroying the uncovered parts leaves replay clean
        surgery(dsn, "m29", "DELETE FROM links WHERE source_id = %s", (a.id,))
        surgery(dsn, "m29", "DELETE FROM claims WHERE work_item_id = %s", (a.id,))
        _, _, drift = k.replay(a.id)
        assert not drift, (
            "replay reported drift for a lease/link change — if it can now see these, "
            "REPLAY_DOES_NOT_COVER is out of date and the docstring understates coverage"
        )
        assert k.links_from(a.id) == [], "the link surgery did not take"
        assert set(REPLAY_DOES_NOT_COVER) >= {"leases (claims)", "typed links (links)"}, (
            "the published boundary no longer names what this check just demonstrated"
        )
        assert any("unset" in entry for entry in REPLAY_COVERS), (
            "REPLAY_COVERS no longer names field clears, but replay does reproduce them "
            "(see the shallow-merge check) -- the published boundary now UNDERSTATES "
            "coverage, which is the same defect in the other direction"
        )
        k.close()
    check("replay's documented coverage boundary matches what it actually checks",
          replay_coverage_boundary_is_accurate)

    def stale_token_never_revived() -> None:
        """Non-negotiable: no rebuild, restore or sweep may make a superseded
        fencing token valid again. claim_attempts is monotonic per item and is
        deliberately NOT derived from the claims row, so losing lease state
        cannot wind the counter back."""
        k = fresh(dsn, "m30")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        c1 = k.claim(it.id, actor_id="w1", ttl_seconds=300)
        k.release(it.id, actor_id="w1", attempt=c1.attempt)

        # a restore that lost every lease row, the worst realistic case
        surgery(dsn, "m30", "DELETE FROM claims WHERE work_item_id = %s", (it.id,))
        surgery(dsn, "m30", "DELETE FROM events WHERE work_item_id = %s AND event_seq > 0",
                (it.id,))
        c2 = k.claim(it.id, actor_id="w2", ttl_seconds=300)
        assert c2.attempt > c1.attempt, (
            f"the counter went backwards after lease state was lost: {c1.attempt} -> "
            f"{c2.attempt}. A stale token is valid again."
        )
        expect(StaleAttemptError,
               lambda: k.transition(it.id, transition="start", actor_id="w1",
                                    attempt=c1.attempt),
               "the superseded token after a lease-state restore")
        # control: the current holder's token works
        k.transition(it.id, transition="start", actor_id="w2", attempt=c2.attempt)
        # and an expiry sweep does not reset it either
        k.release(it.id, actor_id="w2", attempt=c2.attempt)
        c3 = k.claim(it.id, actor_id="w3", ttl_seconds=LOOP_TTL)
        assert c3.attempt > c2.attempt, "a takeover reissued a token"
        time.sleep(LOOP_WAIT)
        k.expire_leases()
        c4 = k.claim(it.id, actor_id="w4", ttl_seconds=300)
        assert c4.attempt > c3.attempt, "expire_leases() wound the counter back"
        for dead in (c1.attempt, c2.attempt, c3.attempt):
            expect(StaleAttemptError,
                   lambda dead=dead: k.transition(  # type: ignore[misc]
                       it.id, transition="annotate", actor_id="w4", attempt=dead),
                   f"superseded token {dead}")
        k.transition(it.id, transition="annotate", actor_id="w4", attempt=c4.attempt)
        k.close()
    check("a superseded fencing token is never valid again, even after a restore",
          stale_token_never_revived)

    print("\n\033[1mConcurrency\033[0m")

    def live_lease_contested() -> None:
        k = fresh(dsn, "m11")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.claim(it.id, actor_id="w1", ttl_seconds=SHORT_TTL)
        expect(ClaimContestedError, lambda: k.claim(it.id, actor_id="w2"), "claiming a live lease")
        time.sleep(EXPIRY_WAIT)
        k.claim(it.id, actor_id="w2")  # control: once it expires, w2 may take over
        k.close()
    check("a live lease cannot be claimed by another actor", live_lease_contested)

    print("\n\033[1mSchema refusal\033[0m")

    def refuses_legacy() -> None:
        with psycopg.connect(dsn, autocommit=True) as c:
            c.execute('DROP SCHEMA IF EXISTS m12 CASCADE')
            c.execute('CREATE SCHEMA m12')
            c.execute('CREATE TABLE m12.project_identity (id bool primary key)')
            c.execute('CREATE TABLE m12._regista_migrations (v int)')
        k = Kernel.connect(dsn, schema="m12")
        expect(UnsupportedSchemaError,
               lambda: k.initialize(os.path.join(HERE, "schema.sql")),
               "initialising over a 0.7-era schema")
        n = int(scalar(dsn, "public",
                       "SELECT count(*) FROM information_schema.tables WHERE table_schema = %s",
                       ("m12",)))
        assert n == 2, f"refusal MUTATED the old schema (now {n} tables)"
        k.close()
        # control: the same call against an EMPTY schema creates the kernel schema
        k2 = fresh(dsn, "m12b")
        assert k2.health()["schema_version"] == 1, "initialize() did not create the schema"
        k2.close()
    check("a 0.7-era schema is refused WITHOUT mutation", refuses_legacy)

    def idempotent_init() -> None:
        k = fresh(dsn, "m13")
        k.initialize(os.path.join(HERE, "schema.sql"))  # second call is a no-op
        k.close()
    check("initialising an already-current schema is a no-op", idempotent_init)

    print("\n\033[1mLease inspection\033[0m")

    def lease_is_visible() -> None:
        """There was no public way to ask who holds an item. Refusals named a
        holder, owned() needed you to already know the actor, and the one
        condition that refuses EVERY write -- an expired, unswept lease -- was
        invisible from outside entirely."""
        k = fresh(dsn, "m31")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        assert k.lease(it.id) is None, "an unclaimed item reports a lease"
        c = k.claim(it.id, actor_id="w1", ttl_seconds=SHORT_TTL)
        held = k.lease(it.id)
        assert held is not None, "a live lease is invisible through lease()"
        assert (held.actor_id, held.attempt, held.live) == ("w1", c.attempt, True), (
            f"lease() disagrees with claim(): {held}"
        )
        assert held.expires_at == c.expires_at, "lease() and claim() report different expiries"

        time.sleep(EXPIRY_WAIT)
        dead = k.lease(it.id)
        assert dead is not None, (
            "an unswept DEAD lease reports as unclaimed — the one lease condition that "
            "refuses every write is the one a caller cannot see"
        )
        assert dead.live is False, "lease() called an expired lease live"
        assert dead.actor_id == "w1", "the dead lease lost its holder"
        # The liveness it reports is the database's, so it cannot disagree with
        # what a write sees. Both ask clock_timestamp(), not the caller's clock.
        expect_exactly(
            LeaseExpiredError,
            lambda: k.transition(it.id, transition="start", actor_id="w1", attempt=c.attempt),
            "a write against the lease lease() just called dead",
        )
        assert k.expire_leases(it.id) == 1, "the per-item sweep did not remove it"
        assert k.lease(it.id) is None, "a swept lease is still reported"
        # control: a fresh lease is visible again, and an unknown item refuses
        c2 = k.claim(it.id, actor_id="w2", ttl_seconds=300)
        again = k.lease(it.id)
        assert again is not None and again.actor_id == "w2" and again.live, (
            f"the replacement lease is not visible: {again}"
        )
        assert again.attempt == c2.attempt, "lease() reported a stale attempt number"
        expect(KernelError, lambda: k.lease(uuid.uuid4()), "lease() of a nonexistent item")
        k.close()
    check("lease() shows unclaimed, live and expired, and the dead one is not hidden",
          lease_is_visible)

    def per_item_sweep_is_surgical() -> None:
        """Refusals point the caller at expire_leases(), and the only form that
        existed swept the whole store. That is a bigger hammer than the refusal
        asks for, on a store other people are using."""
        k = fresh(dsn, "m32")
        a = k.create_work_item(workflow="t", type="x", actor_id="a")
        b = k.create_work_item(workflow="t", type="x", actor_id="a")
        c = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.claim(a.id, actor_id="w1", ttl_seconds=SHORT_TTL)
        k.claim(b.id, actor_id="w1", ttl_seconds=SHORT_TTL)
        k.claim(c.id, actor_id="w2", ttl_seconds=300)
        time.sleep(EXPIRY_WAIT)

        assert k.expire_leases(a.id) == 1, "the per-item sweep removed nothing"
        assert k.lease(a.id) is None, "the named item's dead lease survived"
        assert k.lease(b.id) is not None, "the per-item sweep took ANOTHER item's lease"
        live = k.lease(c.id)
        assert live is not None and live.live, "the per-item sweep touched a live lease"
        # a live lease is never swept, whichever form is used
        assert k.expire_leases(c.id) == 0, "expire_leases(id) revoked a LIVE lease"
        # control: the store-wide form still works and still spares the live one
        assert k.expire_leases() == 1, "the store-wide sweep missed the remaining dead lease"
        assert k.lease(b.id) is None, "b's dead lease survived the store-wide sweep"
        live = k.lease(c.id)
        assert live is not None and live.live, "the store-wide sweep revoked a live lease"
        k.close()
    check("expire_leases(id) sweeps one dead lease and spares live and foreign ones",
          per_item_sweep_is_surgical)

    print("\n\033[1mWorkflow versions\033[0m")

    def workflow_version_is_honoured_or_absent() -> None:
        """version= was mandatory and then discarded: the README passed 0 and
        the registry ignored it. Now it is optional, and a value that IS passed
        is an assertion the registry checks."""
        k = fresh(dsn, "m33")  # fresh() registers WF, which asserts no version
        assert k.get_workflow("t").version == 1, "the registry did not assign version 1"
        # the round trip that a discarded parameter made impossible to reason about
        assert k.register_workflow(k.get_workflow("t")) == 1, (
            "a workflow read back from the registry cannot be re-registered"
        )
        wrong = replace(WF, version=7)
        err = expect(InvalidWorkflowError, lambda: k.register_workflow(wrong),
                     "asserting the wrong version for already-registered content")
        assert "7" in str(err) and "1" in str(err), f"the refusal names neither version: {err}"
        changed = replace(WF_V2, version=1)
        expect(InvalidWorkflowError, lambda: k.register_workflow(changed),
               "asserting an existing version for NEW content")
        expect(InvalidWorkflowError, lambda: k.register_workflow(replace(WF, version=-1)),
               "a negative version")
        assert [v for _, v, _ in k.list_workflows()] == [1], (
            "a refused registration still wrote a version"
        )
        # control: the same new content, asserting nothing, registers as v2
        assert k.register_workflow(WF_V2) == 2, (
            "new content did not get the next version"
        )
        # ...and asserting the version it actually got is accepted
        assert k.register_workflow(replace(WF_V2, version=2)) == 2, (
            "a CORRECT assertion was refused"
        )
        assert [v for _, v, _ in k.list_workflows()] == [1, 2], "versions are not immutable"
        k.close()
    check("a workflow version is assigned, and an asserted one is checked not discarded",
          workflow_version_is_honoured_or_absent)

    print("\n\033[1mField merge and clearing (D7)\033[0m")

    def merge_is_shallow_and_clears_are_explicit() -> None:
        """Fields merge across transitions, so a rejected attempt's data
        survives into the next one. That is correct and stays; what was missing
        was any supported way to remove it."""
        k = fresh(dsn, "m34")
        it = k.create_work_item(
            workflow="t", type="x", actor_id="a",
            fields={"keep": 1, "addr": {"city": "Y", "zip": "Z"}, "stale": "from a reject"},
        )
        item = k.transition(it.id, transition="start", actor_id="a",
                            fields={"addr": {"city": "X"}}, unset_fields=("stale",))
        assert item.fields["addr"] == {"city": "X"}, (
            f"a supplied object was DEEP-merged instead of replacing: {item.fields['addr']}"
        )
        assert item.fields["keep"] == 1, "an unmentioned field was lost"
        assert "stale" not in item.fields, "unset_fields did not clear the key"
        assert k.get(it.id).fields == item.fields, "the returned item disagrees with the store"
        # clearing a key that is not there is a no-op: a clear has to be safe to retry
        k.transition(it.id, transition="annotate", actor_id="a", unset_fields=("never_set",))
        assert k.get(it.id).fields == item.fields, "clearing an absent key changed something"

        # the clear is recorded ON THE EVENT, which is the only reason replay
        # can reproduce it rather than resurrecting the field
        ev = next(e for e in k.history(it.id) if e.transition == "start")
        assert ev.payload.get("unset") == ["stale"], (
            f"the event did not record the clear: {ev.payload}"
        )
        _, fields, drift = k.replay(it.id)
        assert not drift, f"a clear produced drift: {drift}"
        assert "stale" not in fields, (
            "the cleared field came back on replay — the reducer is ignoring the clear, "
            "so the history and the projection now disagree"
        )
        assert fields == k.get(it.id).fields, "replay and the projection disagree after a clear"
        k.close()
    check("a clear removes the field, survives replay, and the merge stays shallow",
          merge_is_shallow_and_clears_are_explicit)

    def set_and_clear_together_is_refused() -> None:
        k = fresh(dsn, "m35")
        it = k.create_work_item(workflow="t", type="x", actor_id="a", fields={"n": 1})
        err = expect(InvalidFieldError,
                     lambda: k.transition(it.id, transition="start", actor_id="a",
                                          fields={"n": 2}, unset_fields=("n",)),
                     "setting and clearing the same key in one call")
        assert "'n'" in str(err), f"the refusal does not name the key: {err}"
        assert k.get(it.id).state == "open", "the refused call left an effect"
        assert k.get(it.id).fields["n"] == 1, "the refused call changed the field"
        # controls: either half alone is fine
        k.transition(it.id, transition="start", actor_id="a", fields={"n": 2})
        assert k.get(it.id).fields["n"] == 2, "the legitimate set did not land"
        k.transition(it.id, transition="annotate", actor_id="a", unset_fields=("n",))
        assert "n" not in k.get(it.id).fields, "the legitimate clear did not land"
        k.close()
    check("naming one key in both fields and unset_fields refuses; either alone works",
          set_and_clear_together_is_refused)

    def a_clear_cannot_dodge_a_required_field() -> None:
        """The requirement is validated AFTER the clear is applied. Validating
        before would let a transition clear the very field it requires."""
        k = fresh(dsn, "m36")
        it = k.create_work_item(workflow="t", type="x", actor_id="a",
                                fields={"note": "carried forward", "spare": 1})
        k.transition(it.id, transition="start", actor_id="a")
        err = expect(InvalidFieldError,
                     lambda: k.transition(it.id, transition="submit", actor_id="a",
                                          unset_fields=("note",)),
                     "clearing the field this very transition requires")
        assert "note" in str(err), f"the refusal does not name the field: {err}"
        assert k.get(it.id).state == "doing", "the refused write moved the item"
        assert k.get(it.id).fields["note"] == "carried forward", "the refused write cleared it"
        # control: clearing something the transition does NOT require is allowed
        item = k.transition(it.id, transition="submit", actor_id="a", unset_fields=("spare",))
        assert item.state == "review", "the legitimate transition was blocked"
        assert "spare" not in item.fields and item.fields["note"] == "carried forward", (
            f"the wrong field was cleared: {item.fields}"
        )
        k.close()
    check("clearing a required field refuses; clearing another field does not",
          a_clear_cannot_dodge_a_required_field)

    def null_is_a_value_but_not_an_answer() -> None:
        """The decided interaction: null is stored, round-trips and is
        distinguishable from absence -- and does NOT satisfy a required field,
        because otherwise a workflow's own gate passes on nothing."""
        k = fresh(dsn, "m37")
        it = k.create_work_item(workflow="t", type="x", actor_id="a", fields={"note": None})
        k.transition(it.id, transition="start", actor_id="a")
        err = expect(InvalidFieldError,
                     lambda: k.transition(it.id, transition="submit", actor_id="a"),
                     "a required field that is present but null")
        assert "null" in str(err), (
            f"the refusal does not distinguish null from absent, and they need different "
            f"fixes: {err}"
        )
        # ...and null is a real value everywhere else
        stored = k.get(it.id).fields
        assert "note" in stored and stored["note"] is None, "null was not stored as a value"
        assert [i.id for i in k.list_items(where_fields={"note": None})] == [it.id], (
            "a null-valued field cannot be found by filtering for null"
        )
        _, replayed, drift = k.replay(it.id)
        assert not drift and replayed["note"] is None, f"null did not survive replay: {drift}"
        # absence is NOT null: clearing it makes the null filter stop matching
        k.transition(it.id, transition="annotate", actor_id="a", unset_fields=("note",))
        assert k.list_items(where_fields={"note": None}) == [], (
            "an ABSENT field matched a filter for null — the two are being conflated"
        )
        # control: a real value satisfies the requirement
        k.transition(it.id, transition="submit", actor_id="a", fields={"note": "an answer"})
        assert k.get(it.id).state == "review", "a genuine value did not satisfy the field"
        k.close()
    check("null is stored and findable but does not satisfy a required field",
          null_is_a_value_but_not_an_answer)

    def a_clear_is_part_of_the_request() -> None:
        """If the request hash ignored unset_fields, two DIFFERENT calls would
        share one idempotency key and the second would silently return the
        first's result without clearing anything."""
        k = fresh(dsn, "m38")
        it = k.create_work_item(workflow="t", type="x", actor_id="a", fields={"n": 1})
        k.transition(it.id, transition="start", actor_id="a", idempotency_key="K")
        expect(IdempotencyConflictError,
               lambda: k.transition(it.id, transition="start", actor_id="a",
                                    unset_fields=("n",), idempotency_key="K"),
               "reusing a key for a call that also clears a field")
        assert k.get(it.id).fields["n"] == 1, "the refused conflict cleared the field anyway"
        # control: the genuinely identical call is still a replay, not a duplicate
        k.transition(it.id, transition="start", actor_id="a", idempotency_key="K")
        assert k.get(it.id).last_event_seq == 1, "the identical retry duplicated an effect"
        k.close()
    check("a clear is part of what an idempotency key identifies", a_clear_is_part_of_the_request)

    print("\n\033[1mLink-aware blocked query (D6)\033[0m")

    def blocked(k: Kernel, sat: tuple[str, ...],
                direction: Literal["incoming", "outgoing"] = "incoming",
                ) -> list[uuid.UUID]:
        return [i.id for i in k.blocked(link_type="blocks", direction=direction,
                                        satisfied_states=sat)]

    def terminal_is_not_satisfaction() -> None:
        """The edge intuition gets wrong. A rejected blocker is TERMINAL and is
        emphatically not satisfaction; only the caller's own list decides."""
        k = fresh(dsn, "m39")
        k.register_workflow(WF_DEP)
        blocker = k.create_work_item(workflow="dep", type="x", actor_id="a")
        dependent = k.create_work_item(workflow="dep", type="x", actor_id="a")
        k.link(blocker.id, dependent.id, "blocks")
        assert blocked(k, ("done",)) == [dependent.id], "an open blocker does not block"

        k.transition(blocker.id, transition="start", actor_id="a")
        k.transition(blocker.id, transition="reject", actor_id="a")
        assert k.get(blocker.id).state == "rejected", "the blocker is not in the terminal state"
        assert blocked(k, ("done",)) == [dependent.id], (
            "a REJECTED blocker stopped blocking — terminality is being treated as "
            "satisfaction, and a rejected dependency is precisely not satisfied"
        )
        # the caller may decide otherwise; that is a policy it STATES
        assert blocked(k, ("done", "rejected")) == [], (
            "the caller's own satisfaction list was ignored"
        )
        # control: genuine completion releases the dependent too
        b2 = k.create_work_item(workflow="dep", type="x", actor_id="a")
        d2 = k.create_work_item(workflow="dep", type="x", actor_id="a")
        k.link(b2.id, d2.id, "blocks")
        assert d2.id in blocked(k, ("done",)), "a new unfinished blocker does not block"
        k.transition(b2.id, transition="start", actor_id="a")
        k.transition(b2.id, transition="finish", actor_id="a")
        assert d2.id not in blocked(k, ("done",)), "a genuinely finished blocker still blocks"
        k.close()
    check("a rejected blocker still blocks; only the caller's satisfied states release it",
          terminal_is_not_satisfaction)

    def direction_and_type_are_the_callers() -> None:
        k = fresh(dsn, "m40")
        k.register_workflow(WF_DEP)
        a = k.create_work_item(workflow="dep", type="x", actor_id="a")
        b = k.create_work_item(workflow="dep", type="x", actor_id="a")
        k.link(a.id, b.id, "blocks")
        assert blocked(k, ("done",), "incoming") == [b.id], (
            "'incoming' named the wrong end: the counterpart is the link's SOURCE"
        )
        assert blocked(k, ("done",), "outgoing") == [a.id], (
            "'outgoing' named the wrong end: the counterpart is the link's TARGET"
        )
        assert k.blocked(link_type="follows", direction="incoming",
                         satisfied_states=("done",)) == [], (
            "a link type nobody used matched something"
        )
        expect(InvalidQueryError,
               # deliberately outside the Literal: the runtime guard is what
               # protects the CLI and every untyped caller
               lambda: k.blocked(link_type="blocks", direction="sideways",  # type: ignore[arg-type]
                                 satisfied_states=("done",)),
               "an unknown direction")
        err = expect(InvalidQueryError,
                     lambda: k.blocked(link_type="blocks", direction="incoming",
                                       satisfied_states=("dnoe",)),
                     "a MISSPELLED satisfied state")
        assert "dnoe" in str(err), f"the refusal does not name the bad state: {err}"
        # control: the corrected call answers
        assert blocked(k, ("done",)) == [b.id], "the corrected query stopped working"
        k.close()
    check("direction and link type are the caller's, and a misspelled satisfied state refuses",
          direction_and_type_are_the_callers)

    def blocked_is_single_hop() -> None:
        """Deliberately NOT transitive. a blocks b blocks c: once b finishes, c
        is free even though a has not. Anyone 'fixing' this into a graph walk is
        building the dependency scheduler Plan 032 forbids."""
        k = fresh(dsn, "m41")
        k.register_workflow(WF_DEP)
        a = k.create_work_item(workflow="dep", type="x", actor_id="a")
        b = k.create_work_item(workflow="dep", type="x", actor_id="a")
        c = k.create_work_item(workflow="dep", type="x", actor_id="a")
        k.link(a.id, b.id, "blocks")
        k.link(b.id, c.id, "blocks")
        assert set(blocked(k, ("done",))) == {b.id, c.id}, "the one-hop baseline is wrong"
        k.transition(b.id, transition="start", actor_id="a")
        k.transition(b.id, transition="finish", actor_id="a")
        assert blocked(k, ("done",)) == [b.id], (
            "c is still reported as blocked after its DIRECT blocker finished — the query "
            "walked the chain to a, which is the transitive scheduler this must not become"
        )
        k.close()
    check("the link query is single-hop and does not walk the chain", blocked_is_single_hop)

    print("\n\033[1mEnumeration and paging\033[0m")

    def enumeration_hides_nothing() -> None:
        """Measured, not reported: the default listing used to drop an item the
        moment somebody leased it, and said nothing about having done so."""
        k = fresh(dsn, "m42")
        ids = [k.create_work_item(workflow="t", type="x", actor_id="a").id for _ in range(4)]
        assert [i.id for i in k.list_items()] == ids, "the full listing is not the full set"
        k.claim(ids[0], actor_id="w1", ttl_seconds=300)
        assert [i.id for i in k.list_items()] == ids, (
            "a leased item VANISHED from the full listing — the answer looks complete "
            "and is not"
        )
        shown = [i.id for i in k.available()]
        assert ids[0] not in shown and len(shown) == 3, (
            "available() is not filtering by lease, which is the one thing it means"
        )
        err = expect(InvalidQueryError, lambda: k.in_states(()), "in_states with no states")
        assert "list_items()" in str(err), (
            f"the refusal does not point at the query that DOES enumerate: {err}"
        )
        # control: the narrowed queries still answer
        assert len(k.in_states(("open",))) == 4, "in_states stopped working"
        assert len(k.owned("w1")) == 1, "owned stopped working"
        k.close()
    check("the full listing withholds nothing, and the empty-state query refuses",
          enumeration_hides_nothing)

    def pages_do_not_overlap_or_skip() -> None:
        k = fresh(dsn, "m43")
        ids = [k.create_work_item(workflow="t", type="x", actor_id="a").id for _ in range(7)]
        seen: list[uuid.UUID] = []
        cursor: uuid.UUID | None = None
        for _ in range(10):  # bounded, so a non-advancing cursor fails loudly
            page = k.list_items(limit=3, after=cursor)
            if not page:
                break
            seen += [i.id for i in page]
            cursor = page[-1].id
        assert seen == ids, f"paging lost, repeated or reordered rows:\n{seen}\n{ids}"
        assert len(set(seen)) == len(seen), "a row appeared on two pages"
        err = expect(InvalidQueryError, lambda: k.list_items(after=uuid.uuid4()),
                     "a cursor naming no work item")
        assert "after=" in str(err), f"the refusal does not name the argument: {err}"
        expect(InvalidQueryError, lambda: k.list_items(limit=0), "limit=0")
        expect(InvalidQueryError, lambda: k.list_items(limit=10_000), "an unbounded limit")
        # control
        assert len(k.list_items(limit=1)) == 1, "a legitimate page was refused"
        k.close()
    check("keyset paging covers every row exactly once, and a dead cursor refuses",
          pages_do_not_overlap_or_skip)

    def field_filtering_is_bounded_and_exact() -> None:
        k = fresh(dsn, "m44")
        hit = k.create_work_item(workflow="t", type="x", actor_id="a",
                                 fields={"host": "web-01", "tier": 1, "tags": ["a"]})
        k.create_work_item(workflow="t", type="y", actor_id="a", fields={"host": "web-02"})
        assert [i.id for i in k.list_items(where_fields={"host": "web-01"})] == [hit.id]
        assert [i.id for i in k.list_items(where_fields={"host": "web-01", "tier": 1})] == [hit.id]
        assert k.list_items(where_fields={"host": "web-01", "tier": 2}) == [], (
            "the filters are ORed, not ANDed"
        )
        assert k.list_items(where_fields={"host": "web-0"}) == [], (
            "a PREFIX matched — this filter promises equality"
        )
        assert [i.id for i in k.available(where_fields={"host": "web-01"})] == [hit.id], (
            "the filter is not available on every item query"
        )
        err = expect(InvalidQueryError,
                     lambda: k.list_items(where_fields={"tags": ["a"]}),
                     "filtering on a list value")
        assert "scalar" in str(err), f"the refusal does not say why: {err}"
        expect(InvalidQueryError,
               lambda: k.list_items(where_fields={f"k{i}": i for i in range(9)}),
               "more filter keys than the bound allows")
        err = expect(InvalidQueryError,
                     lambda: k.list_items(where_fields={"when": datetime(2026, 1, 1)}),
                     "a datetime as a filter value")
        assert "datetime" in str(err), f"the refusal does not name the type: {err}"
        # a float is scalar, so it reaches the FIELD TYPES gate rather than the
        # scalar gate -- and NaN has no jsonb representation to compare against
        expect(InvalidFieldError, lambda: k.list_items(where_fields={"n": float("nan")}),
               "NaN as a filter value")
        # control
        assert len(k.list_items(where_fields={f"k{i}": i for i in range(8)})) == 0, (
            "the largest allowed filter was refused"
        )
        assert len(k.list_items()) == 2, "filtering leaked into the unfiltered listing"
        k.close()
    check("custom-field filtering is exact, ANDed, scalar-only and bounded",
          field_filtering_is_bounded_and_exact)

    def every_collection_query_is_bounded() -> None:
        """And the coverage list is itself checked: a NEW public query that
        forgot its limit would otherwise pass here by not being listed."""
        k = fresh(dsn, "m45")
        k.register_workflow(WF_DEP)
        a = k.create_work_item(workflow="t", type="x", actor_id="a")
        b = k.create_work_item(workflow="t", type="x", actor_id="a")
        c = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.link(a.id, b.id, "blocks")
        k.link(a.id, c.id, "follows")
        k.claim(c.id, actor_id="w1", ttl_seconds=300)
        k.transition(a.id, transition="start", actor_id="a")
        k.transition(a.id, transition="annotate", actor_id="a", fields={"n": 1})

        pages: dict[str, Callable[[int], list[Any]]] = {
            "list_items": lambda n: k.list_items(limit=n),
            "available": lambda n: k.available(limit=n),
            "owned": lambda n: k.owned("w1", limit=n),
            "in_states": lambda n: k.in_states(("open",), limit=n),
            "blocked": lambda n: k.blocked(link_type="blocks", direction="incoming",
                                           satisfied_states=("done",), limit=n),
            "links_from": lambda n: k.links_from(a.id, limit=n),
            "history": lambda n: k.history(a.id, limit=n),
            "list_workflows": lambda n: k.list_workflows(limit=n),
        }
        for name, call in pages.items():
            assert len(call(1)) == 1, f"{name}() returned {len(call(1))} rows for limit=1"
            expect(InvalidQueryError, lambda call=call: call(0),  # type: ignore[misc]
                   f"{name}() with limit=0")
            expect(InvalidQueryError, lambda call=call: call(10_000),  # type: ignore[misc]
                   f"{name}() with an unbounded limit")
        # resumable, not merely truncated
        assert k.history(a.id, limit=1, after=0)[0].seq == 1, "history's cursor does not resume"
        assert k.links_from(a.id, limit=1, after=("blocks", b.id))[0][1] == "follows", (
            "links_from's cursor does not resume"
        )
        assert k.list_workflows(limit=1, after=("dep", 1))[0][0] == "t", (
            "list_workflows' cursor does not resume"
        )

        public = {n for n in dir(Kernel) if not n.startswith("_")}
        assert public == KERNEL_PUBLIC_SURFACE, (
            "Kernel's public surface changed — added "
            f"{sorted(public - KERNEL_PUBLIC_SURFACE)}, removed "
            f"{sorted(KERNEL_PUBLIC_SURFACE - public)}. Classify the new name: if it "
            "returns a collection it needs limit= and after= and a row in this check, "
            "and this check cannot tell you that by itself."
        )
        k.close()
    check("every collection query is bounded and resumable, and the coverage list is checked",
          every_collection_query_is_bounded)

    print("\n\033[1mWorkflow documents\033[0m")

    def the_document_round_trips() -> None:
        """as_document() and from_document() must be inverses, or a workflow
        cannot be read out, edited and put back -- which is the whole point of
        having an authoring format."""
        for wf in (WF, WF_V2, WF_DEP):
            back = Workflow.from_document(wf.as_document())
            assert back == replace(wf, version=0), (
                f"{wf.name} did not survive as_document -> from_document: "
                f"{back} != {replace(wf, version=0)}"
            )
        # The two shipped documents are the ones the scenarios register, so a
        # round trip through them is a round trip through real content.
        for name in ("remediation.workflow.yaml", "ingest.workflow.yaml"):
            wf = load_workflow(os.path.join(HERE, name))
            assert Workflow.from_document(wf.as_document()) == wf, (
                f"{name} did not survive the round trip"
            )
        # Control: the round trip is not vacuously true because both sides are
        # empty -- the documents carry roles and required fields.
        rem = load_workflow(os.path.join(HERE, "remediation.workflow.yaml"))
        assert rem.roles and rem.required_fields and rem.terminal and rem.role_names, (
            "the round-trip check is running on a document with no policy in it"
        )
    check("a workflow survives as_document() -> from_document() unchanged",
          the_document_round_trips)

    def every_07_key_is_carried_or_explained() -> None:
        """A 0.7 key that is neither accepted nor named is a SILENT drop, and
        several of them (allowed_roles, validator, privileged) are restrictions:
        dropping one silently turns a closed transition into an open one."""
        old_path = os.path.join(HERE, "..", "..", "src", "regista", "_workflow_schema.json")
        # This pin reads the 0.7 tree, which F1 deletes. When that happens the
        # check should be RETIRED by hand, in the same commit — not left to
        # fail with a FileNotFoundError that check() does not catch and that
        # aborts every check after it.
        assert os.path.exists(old_path), (
            f"{old_path} is gone, so this pin has outlived the tree it compares "
            "against. Delete this check in the commit that deleted 0.7's schema; "
            "WORKFLOW_DOCUMENT_REMOVED_KEYS stays, because an author's own file "
            "may still carry those keys."
        )
        with open(old_path, encoding="utf-8") as fh:
            old = json.load(fh)
        new = workflow_schema()
        pairs = [
            ("document", old["properties"], new["properties"]),
            ("transition",
             old["properties"]["transitions"]["items"]["properties"],
             new["properties"]["transitions"]["items"]["properties"]),
        ]
        for scope, old_props, new_props in pairs:
            explained = set(WORKFLOW_DOCUMENT_REMOVED_KEYS[scope])
            unaccounted = sorted(set(old_props) - set(new_props) - explained)
            assert not unaccounted, (
                f"0.7 {scope} key(s) {unaccounted} are neither accepted by the 0.8 "
                f"schema nor listed in WORKFLOW_DOCUMENT_REMOVED_KEYS[{scope!r}]. A "
                "document carrying one would be refused with 'additional properties "
                "are not allowed', which does not say what happened to the feature."
            )
            # ...and nothing is listed as removed that the schema still accepts,
            # which would be an explanation for a key that works fine.
            contradictory = sorted(explained & set(new_props))
            assert not contradictory, (
                f"{scope} key(s) {contradictory} are listed as removed AND accepted"
            )
        # Control: the pin can fail. A key the 0.7 schema really has must be in
        # one of the two sets, so removing a known entry must break it.
        assert "validator" in WORKFLOW_DOCUMENT_REMOVED_KEYS["transition"], (
            "the check's premise is gone: 'validator' is no longer the example"
        )
    check("every 0.7 workflow key is either accepted or refused by name",
          every_07_key_is_carried_or_explained)

    def removed_keys_are_refused_by_name() -> None:
        explained = "is not part of the 0.8 workflow document"
        base = load_workflow(os.path.join(HERE, "remediation.workflow.yaml")).as_document()
        assert not validate_workflow_document(base), "the clean document does not validate"
        for key in WORKFLOW_DOCUMENT_REMOVED_KEYS["document"]:
            doc = json.loads(json.dumps(base))
            doc[key] = "anything"
            problems = validate_workflow_document(doc)
            assert problems and key in problems[0], (
                f"a document carrying {key!r} was not refused by name: {problems}"
            )
            # The schema's own "Additional properties are not allowed
            # ('extends' was unexpected)" also contains the key, so naming the
            # key is not enough to tell the two apart. The EXPLANATION is.
            assert explained in problems[0], (
                f"{key!r} was refused by the schema, not explained: {problems[0]}"
            )
        for key in WORKFLOW_DOCUMENT_REMOVED_KEYS["transition"]:
            doc = json.loads(json.dumps(base))
            doc["transitions"][0][key] = "anything"
            problems = validate_workflow_document(doc)
            assert problems and key in problems[0], (
                f"a transition carrying {key!r} was not refused by name: {problems}"
            )
            assert doc["transitions"][0]["name"] in problems[0], (
                f"the refusal for {key!r} does not say WHICH transition: {problems}"
            )
            assert explained in problems[0], (
                f"{key!r} was refused by the schema, not explained: {problems[0]}"
            )
        # The 0.7 object forms, which the schema alone would report as a type error.
        for key in ("work_item_types", "roles"):
            doc = json.loads(json.dumps(base))
            doc[key] = [{"name": "whatever"}]
            problems = validate_workflow_document(doc)
            assert problems and "list of NAMES" in problems[0], (
                f"the 0.7 object form of {key!r} was not explained: {problems}"
            )
    check("every removed 0.7 key is refused BY NAME, and the clean document passes",
          removed_keys_are_refused_by_name)

    def the_validation_matrix_holds() -> None:
        """One entry per rule, each PAIRED with the clean document that must
        still validate -- otherwise 'it refused' is indistinguishable from 'it
        refuses everything'."""
        base = load_workflow(os.path.join(HERE, "remediation.workflow.yaml")).as_document()

        def mutate(fn: Callable[[dict[str, Any]], None]) -> tuple[str, ...]:
            doc = json.loads(json.dumps(base))
            fn(doc)
            return validate_workflow_document(doc)

        cases: list[tuple[str, Callable[[dict[str, Any]], None], str]] = [
            ("no document version", lambda d: d.pop("kernel_workflow"), "kernel_workflow"),
            ("a future document version",
             lambda d: d.update(kernel_workflow=WORKFLOW_DOCUMENT_VERSION + 1),
             "kernel_workflow"),
            ("no name", lambda d: d.pop("name"), "name"),
            ("an empty name", lambda d: d.update(name=""), "non-empty"),
            ("no initial state",
             lambda d: d["states"][0].pop("initial"), "exactly one state"),
            ("two initial states",
             lambda d: d["states"][1].update(initial=True), "exactly one state"),
            ("a repeated state name",
             lambda d: d["states"].append({"name": "open"}), "more than once"),
            ("a repeated transition name",
             lambda d: d["transitions"].append({"name": "start", "from": "open",
                                                "to": "done"}), "more than once"),
            ("a transition into an unknown state",
             lambda d: d["transitions"][0].update(to="nowhere"), "unknown state"),
            ("a transition out of an unknown state",
             lambda d: d["transitions"][0].update(**{"from": "nowhere"}), "unknown state"),
            ("an unreachable state",
             lambda d: d["states"].append({"name": "orphan"}), "unreachable"),
            ("a role named on a transition but not declared",
             lambda d: d["transitions"][3].update(roles=["reviwer"]), "undeclared role"),
            ("a declared role no transition uses",
             lambda d: d["roles"].append("auditor"), "restrict no transition"),
            # This one asserts the MESSAGE, not just a refusal. Dropping the
            # catalogue entirely is already caught by the undeclared-role rule,
            # so the "declares no role_names" branch is a message refinement
            # rather than an independent gate -- and a mutation run proved it:
            # removing that branch changed nothing until this case existed.
            ("a role restriction with no catalogue at all",
             lambda d: d.pop("roles"), "declares no role_names"),
            ("no work-item types", lambda d: d.update(work_item_types=[]), "non-empty"),
            ("a repeated work-item type",
             lambda d: d["work_item_types"].append("finding"), "unique"),
            ("a key the format does not have",
             lambda d: d.update(colour="blue"), "colour"),
            ("a key a transition does not have",
             lambda d: d["transitions"][0].update(colour="blue"), "colour"),
        ]
        for label, mutation, expected in cases:
            problems = mutate(mutation)
            assert problems, f"{label} was ACCEPTED — this rule does not exist"
            assert any(expected in p for p in problems), (
                f"{label} was refused, but no message mentions {expected!r}: {problems}"
            )
        assert not validate_workflow_document(base), (
            "the unmutated document no longer validates — every case above proves nothing"
        )
    check("the document validation matrix refuses each rule and passes the clean file",
          the_validation_matrix_holds)

    def yaml_duplicate_keys_are_refused() -> None:
        """yaml.safe_load keeps the LAST of two identical keys and discards the
        first in silence. In a workflow that is a whole block vanishing."""
        good = """
kernel_workflow: 1
name: dup
states:
  - {name: open, initial: true}
  - {name: done, terminal: true}
work_item_types: [x]
transitions:
  - {name: finish, from: open, to: done}
"""
        bad = good + """
transitions:
  - {name: finish, from: open, to: done}
"""
        with tempfile.TemporaryDirectory() as d:
            ok_path = os.path.join(d, "ok.yaml")
            bad_path = os.path.join(d, "dup.yaml")
            txt_path = os.path.join(d, "wf.txt")
            json_path = os.path.join(d, "ok.json")
            for path, body in ((ok_path, good), (bad_path, bad), (txt_path, good)):
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(body)
            with open(json_path, "w", encoding="utf-8") as fh:
                json.dump(yaml.safe_load(good), fh)

            loaded = load_workflow(ok_path)
            assert loaded.name == "dup", "the control document did not load"
            err = expect(InvalidWorkflowError, lambda: load_workflow_document(bad_path),
                         "a document with a duplicated mapping key")
            assert "duplicate key" in str(err) and "transitions" in str(err), (
                f"the refusal does not name the duplicated key: {err}"
            )
            # Same content, two extensions: the parser follows the extension.
            assert load_workflow(json_path) == loaded, (
                "the same workflow loaded from .json and .yaml differ"
            )
            err = expect(InvalidWorkflowError, lambda: load_workflow_document(txt_path),
                         "a document with an extension the loader does not parse")
            assert ".txt" in str(err), f"the refusal does not name the extension: {err}"
    check("a duplicated YAML key is refused, not silently last-one-wins",
          yaml_duplicate_keys_are_refused)

    print("\n\033[1mWork-item types and version pinning\033[0m")

    def undeclared_types_are_refused() -> None:
        k = fresh(dsn, "m40")  # WF declares types ("x", "y")
        item = k.create_work_item(workflow="t", type="x", actor_id="a")
        assert item.state == "open", "the declared type did not create an item"
        err = expect(InvalidWorkflowError,
                     lambda: k.create_work_item(workflow="t", type="xs", actor_id="a"),
                     "an undeclared work-item type")
        assert "'x'" in str(err) and "'y'" in str(err), (
            f"the refusal does not list the declared types: {err}"
        )
        # The refusal leaves nothing behind: a partially-created item would be
        # invisible to every type filter and present in every count.
        assert len(k.list_items()) == 1, "a refused create still wrote a row"
        assert k._conn.info.transaction_status.name == "IDLE", (
            "the refusal left the connection in a transaction"
        )
        # ...and a workflow that declares no type cannot reach the registry at all.
        expect(InvalidWorkflowError,
               lambda: k.register_workflow(replace(WF, name="untyped", types=())),
               "a workflow declaring no work-item types")
        assert k.register_workflow(replace(WF, name="typed", types=("z",))) == 1, (
            "declaring a type was not enough to register"
        )
        k.close()
    check("an undeclared work-item type is refused and a declared one is created",
          undeclared_types_are_refused)

    def a_work_item_is_pinned_to_its_workflow_version() -> None:
        """The keep table names this by name: 'immutable registered versions,
        work-item version pinning'. An item created under v1 must keep v1's
        rules after v2 exists, or a registry that assigns versions is
        decoration."""
        k = fresh(dsn, "m41")  # WF registered as v1
        old = k.create_work_item(workflow="t", type="x", actor_id="a")
        assert old.workflow_version == 1, "the first item was not pinned to v1"
        k.transition(old.id, transition="start", actor_id="a")

        assert k.register_workflow(WF_V2) == 2, "WF_V2 did not register as v2"
        err = expect(TransitionRefusedError,
                     lambda: k.transition(old.id, transition="park", actor_id="a"),
                     "a v2-only transition on a v1-pinned item")
        assert "v1" in str(err), f"the refusal does not name the pinned version: {err}"

        # Control: the SAME transition on an item created after v2 succeeds, so
        # the refusal above is about the pin and not about 'park' being broken.
        new = k.create_work_item(workflow="t", type="x", actor_id="a")
        assert new.workflow_version == 2, "a new item did not pick up the latest version"
        k.transition(new.id, transition="start", actor_id="a")
        assert k.transition(new.id, transition="park", actor_id="a").state == "parked", (
            "the v2 transition does not work on a v2 item either"
        )

        # ...and a caller may pin deliberately, which must pin to the OLD rules.
        pinned = k.create_work_item(workflow="t", type="x", actor_id="a",
                                    workflow_version=1)
        assert pinned.workflow_version == 1, "an explicit workflow_version was ignored"
        k.transition(pinned.id, transition="start", actor_id="a")
        expect(TransitionRefusedError,
               lambda: k.transition(pinned.id, transition="park", actor_id="a"),
               "a v2-only transition on an explicitly v1-pinned item")

        # The v1 definition itself is unchanged by v2 existing.
        assert "park" not in k.get_workflow("t", 1).transitions, "v1 gained v2's transition"
        assert "park" in k.get_workflow("t", 2).transitions, "v2 lost its own transition"
        k.close()
    check("a work item keeps its workflow version's rules after a v2 is registered",
          a_work_item_is_pinned_to_its_workflow_version)

    def the_workflow_surface_is_pinned() -> None:
        # dataclass fields WITHOUT a default are not class attributes, so dir()
        # alone silently omits half of them — and a pin that cannot see a name
        # cannot notice it appearing.
        public = ({f.name for f in dataclass_fields(Workflow)}
                  | {n for n in vars(Workflow) if not n.startswith("_")})
        assert public == WORKFLOW_PUBLIC_SURFACE, (
            "Workflow's public surface changed — added "
            f"{sorted(public - WORKFLOW_PUBLIC_SURFACE)}, removed "
            f"{sorted(WORKFLOW_PUBLIC_SURFACE - public)}. A new field has to be "
            "classified: does as_json() carry it (and change every content hash), "
            "does as_document() carry it, and does validate() check it?"
        )
    check("Workflow's public surface is pinned", the_workflow_surface_is_pinned)

    print(f"\n\033[1m{len(PASS)} passed, {len(FAIL)} failed\033[0m")
    return 1 if FAIL else 0


def _wait_until_blocked(dsn: str, app_name: str, deadline: float = 15.0) -> datetime:
    """Block until a session tagged app_name is waiting on a lock; return when
    its transaction started. Raises if it never blocks, so a check built on this
    cannot quietly pass because the race did not happen."""
    end = time.monotonic() + deadline
    with psycopg.connect(dsn, autocommit=True) as c:
        while time.monotonic() < end:
            row = c.execute(
                "SELECT xact_start FROM pg_stat_activity WHERE application_name = %s "
                "AND wait_event_type = 'Lock' AND xact_start IS NOT NULL",
                (app_name,),
            ).fetchone()
            if row is not None:
                started: datetime = row[0]
                return started
            time.sleep(0.02)
    raise AssertionError(
        f"no session named {app_name!r} ever blocked on the row lock — the premise of this "
        "check did not hold, so its result means nothing"
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
