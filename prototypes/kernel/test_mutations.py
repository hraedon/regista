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

import os
import sys
import threading
import time
import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import psycopg
from kernel import (
    REPLAY_DOES_NOT_COVER,
    ClaimContestedError,
    IdempotencyConflictError,
    InvalidFieldError,
    Kernel,
    LeaseExpiredError,
    LeaseNotHeldError,
    ReservedPayloadKeyError,
    StaleAttemptError,
    TransitionRefusedError,
    UnsupportedSchemaError,
    Workflow,
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
    name="t", version=0,
    states=("open", "doing", "review", "done"), initial="open",
    transitions={"start": (("open",), "doing"), "submit": (("doing",), "review"),
                 # A self-loop: a transition that changes fields but not state.
                 # Truncating its event moves neither the state nor the chain,
                 # which is exactly the case replay used to miss.
                 "annotate": (("doing",), "doing"),
                 "accept": (("review",), "done")},
    roles={"accept": ("reviewer",)},
    required_fields={"submit": ("note",)},
    terminal=("done",),
)

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
            ("list_workflows", k.list_workflows),
            ("health", k.health),
            ("replay", lambda: k.replay(a.id)),
        ]
        for label, call in reads:
            call()
            assert open_transactions(dsn, app) == 0, (
                f"{label}() left its transaction open"
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
        for key in ("from", "to", "fields", "created"):
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
