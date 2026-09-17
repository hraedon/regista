"""Mutation checks — prove the scenario's assertions can actually fail.

A green scenario that cannot go red manufactures confidence in the next
reviewer. Each case here breaks one guarantee and asserts the kernel notices.

Run:  python test_mutations.py "postgresql://..."
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import psycopg
from kernel import (
    ClaimContestedError,
    IdempotencyConflictError,
    InvalidFieldError,
    Kernel,
    StaleAttemptError,
    TransitionRefusedError,
    UnsupportedSchemaError,
    Workflow,
)
from psycopg.types.json import Jsonb

HERE = os.path.dirname(os.path.abspath(__file__))
WF = Workflow(
    name="t", version=0,
    states=("open", "doing", "review", "done"), initial="open",
    transitions={"start": (("open",), "doing"), "submit": (("doing",), "review"),
                 "accept": (("review",), "done")},
    roles={"accept": ("reviewer",)},
    required_fields={"submit": ("note",)},
    terminal=("done",),
)

PASS, FAIL = [], []


def check(name: str, fn) -> None:
    try:
        fn()
        PASS.append(name)
        print(f"  \033[32m✓\033[0m {name}")
    except AssertionError as e:
        FAIL.append(name)
        print(f"  \033[31m✗ {name}: {e}\033[0m")


def expect(exc, fn, what: str):
    try:
        fn()
    except exc:
        return
    except Exception as e:
        raise AssertionError(f"{what}: raised {type(e).__name__} not {exc.__name__}: {e}")
    raise AssertionError(f"{what}: NOTHING was raised — the check is vacuous")


def fresh(dsn: str, schema: str) -> Kernel:
    with psycopg.connect(dsn, autocommit=True) as c:
        c.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        c.execute(f'CREATE SCHEMA "{schema}"')
    k = Kernel.connect(dsn, schema=schema)
    k.initialize(os.path.join(HERE, "schema.sql"))
    k.register_workflow(WF)
    return k


def main(dsn: str) -> int:
    print("\n\033[1mFencing\033[0m")

    def fencing_bites():
        k = fresh(dsn, "m1")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        c1 = k.claim(it.id, actor_id="w1", ttl_seconds=300)
        # control: the CURRENT attempt is accepted
        k.transition(it.id, transition="start", actor_id="w1", attempt=c1.attempt)
        # expire and take over
        with k._conn.cursor() as cur:
            cur.execute("UPDATE claims SET expires_at = now() - interval '1s' "
                        "WHERE work_item_id = %s", (it.id,))
        k._conn.commit()
        k.expire_leases()
        c2 = k.claim(it.id, actor_id="w2", ttl_seconds=300)
        assert c2.attempt != c1.attempt, "takeover reissued the same fencing token"
        expect(StaleAttemptError,
               lambda: k.transition(it.id, transition="submit", actor_id="w1",
                                    attempt=c1.attempt, fields={"note": "stale"}),
               "stale attempt")
        k.close()
    check("a stale attempt is refused, and the current one is not", fencing_bites)

    def attempt_required():
        k = fresh(dsn, "m2")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.claim(it.id, actor_id="w1", ttl_seconds=300)
        expect(StaleAttemptError,
               lambda: k.transition(it.id, transition="start", actor_id="w2"),
               "omitted attempt under a live lease")
        k.close()
    check("omitting attempt under a live lease is refused", attempt_required)

    def attempt_monotonic():
        k = fresh(dsn, "m3")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        seen = set()
        for i in range(4):
            c = k.claim(it.id, actor_id=f"w{i}", ttl_seconds=300)
            assert c.attempt not in seen, f"attempt {c.attempt} was reissued"
            seen.add(c.attempt)
            with k._conn.cursor() as cur:
                cur.execute("UPDATE claims SET expires_at = now() - interval '1s' "
                            "WHERE work_item_id = %s", (it.id,))
            k._conn.commit()
            k.expire_leases()
        assert seen == {1, 2, 3, 4}, f"attempts not monotonic: {sorted(seen)}"
        k.close()
    check("attempt numbers are monotonic across takeovers", attempt_monotonic)

    print("\n\033[1mWorkflow validation\033[0m")

    def bad_transition():
        k = fresh(dsn, "m4")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        expect(TransitionRefusedError,
               lambda: k.transition(it.id, transition="accept", actor_id="a", role="reviewer"),
               "transition from the wrong state")
        expect(TransitionRefusedError,
               lambda: k.transition(it.id, transition="nope", actor_id="a"),
               "unknown transition")
        k.close()
    check("wrong-state and unknown transitions are refused", bad_transition)

    def role_gate():
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

    def required_field():
        k = fresh(dsn, "m6")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.transition(it.id, transition="start", actor_id="a")
        expect(InvalidFieldError,
               lambda: k.transition(it.id, transition="submit", actor_id="a"),
               "missing required field")
        k.transition(it.id, transition="submit", actor_id="a", fields={"note": "n"})  # control
        k.close()
    check("a missing required field refuses, supplying it passes", required_field)

    def terminal():
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

    print("\n\033[1mIdempotency\033[0m")

    def idem():
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
        k.close()
    check("identical retry is a no-op; conflicting reuse refuses with no partial effect", idem)

    print("\n\033[1mReplay / chain\033[0m")

    def chain_detects_tamper():
        k = fresh(dsn, "m9")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.transition(it.id, transition="start", actor_id="a")
        _, _, drift = k.replay(it.id)
        assert not drift, f"clean history reported drift: {drift}"      # control
        with k._conn.cursor() as cur:                                    # mutate a payload
            cur.execute("UPDATE events SET payload = %s WHERE work_item_id = %s "
                        "AND event_seq = 1", (Jsonb({"from": "open", "to": "done"}), it.id))
        k._conn.commit()
        _, _, drift = k.replay(it.id)
        assert drift, "an edited payload produced NO drift — the chain check is vacuous"
        k.close()
    check("an edited event payload is detected on replay", chain_detects_tamper)

    def chain_detects_deletion():
        k = fresh(dsn, "m10")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.transition(it.id, transition="start", actor_id="a")
        k.transition(it.id, transition="submit", actor_id="a", fields={"note": "n"})
        with k._conn.cursor() as cur:
            cur.execute("DELETE FROM events WHERE work_item_id = %s AND event_seq = 1", (it.id,))
        k._conn.commit()
        _, _, drift = k.replay(it.id)
        assert drift, "a deleted middle event produced NO drift"
        k.close()
    check("a removed middle event is detected on replay", chain_detects_deletion)

    print("\n\033[1mConcurrency\033[0m")

    def live_lease_contested():
        k = fresh(dsn, "m11")
        it = k.create_work_item(workflow="t", type="x", actor_id="a")
        k.claim(it.id, actor_id="w1", ttl_seconds=300)
        expect(ClaimContestedError, lambda: k.claim(it.id, actor_id="w2"), "claiming a live lease")
        k.close()
    check("a live lease cannot be claimed by another actor", live_lease_contested)

    print("\n\033[1mSchema refusal\033[0m")

    def refuses_legacy():
        with psycopg.connect(dsn, autocommit=True) as c:
            c.execute('DROP SCHEMA IF EXISTS m12 CASCADE')
            c.execute('CREATE SCHEMA m12')
            c.execute('CREATE TABLE m12.project_identity (id bool primary key)')
            c.execute('CREATE TABLE m12._regista_migrations (v int)')
        k = Kernel.connect(dsn, schema="m12")
        expect(UnsupportedSchemaError,
               lambda: k.initialize(os.path.join(HERE, "schema.sql")),
               "initialising over a 0.7-era schema")
        with psycopg.connect(dsn, autocommit=True) as c:
            n = c.execute("SELECT count(*) FROM information_schema.tables "
                          "WHERE table_schema='m12'").fetchone()[0]
        assert n == 2, f"refusal MUTATED the old schema (now {n} tables)"
        k.close()
    check("a 0.7-era schema is refused WITHOUT mutation", refuses_legacy)

    def idempotent_init():
        k = fresh(dsn, "m13")
        k.initialize(os.path.join(HERE, "schema.sql"))  # second call is a no-op
        k.close()
    check("initialising an already-current schema is a no-op", idempotent_init)

    print(f"\n\033[1m{len(PASS)} passed, {len(FAIL)} failed\033[0m")
    return 1 if FAIL else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
