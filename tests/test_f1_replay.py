from __future__ import annotations

import gc
import hashlib
import json
import time
import tracemalloc
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import psycopg
import pytest
from psycopg.sql import SQL, Identifier
from psycopg.types.json import Jsonb

from regista import REPLAY_COVERS, REPLAY_DOES_NOT_COVER, Kernel


def item(k: Kernel) -> uuid.UUID:
    created = k.create_work_item(workflow="review", type="task", actor_id="w", fields={"x": 1})
    k.transition(created.id, transition="start", actor_id="w")
    k.transition(created.id, transition="edit", actor_id="w", fields={"x": 2})
    return created.id


@pytest.mark.parametrize(
    "case",
    [
        "state",
        "fields",
        "payload",
        "middle_deleted",
        "tail_deleted",
        "all_deleted",
        "chain",
        "sequence",
        "orphan_created",
        "orphan_noncreated",
    ],
)
def test_replay_detects_damage(registered: Kernel, dsn: str, schema: str, case: str) -> None:
    work_id = item(registered)
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
        if case == "state":
            conn.execute(
                "UPDATE work_items_current SET current_state='new' WHERE work_item_id=%s",
                (work_id,),
            )
        elif case == "fields":
            conn.execute(
                "UPDATE work_items_current SET custom_fields='{}' WHERE work_item_id=%s", (work_id,)
            )
        elif case == "payload":
            conn.execute(
                'UPDATE events SET payload = payload || \'{"annotation": "edited"}\' '
                "WHERE work_item_id=%s AND event_seq=1",
                (work_id,),
            )
        elif case in ("middle_deleted", "tail_deleted", "all_deleted"):
            conn.execute(
                "DELETE FROM events WHERE work_item_id=%s AND (%s OR event_seq=%s)",
                (work_id, case == "all_deleted", 1 if case == "middle_deleted" else 2),
            )
        elif case == "chain":
            conn.execute(
                "UPDATE events SET prev_event_hash='\\x01' WHERE work_item_id=%s AND event_seq=1",
                (work_id,),
            )
        elif case == "sequence":
            conn.execute(
                "UPDATE events SET event_seq=10 WHERE work_item_id=%s AND event_seq=2", (work_id,)
            )
        else:
            # Corruption fixture: bypass only the FK, never the kernel for normal setup.
            conn.execute("SET session_replication_role=replica")
            conn.execute("DELETE FROM claims WHERE work_item_id=%s", (work_id,))
            conn.execute("DELETE FROM claim_attempts WHERE work_item_id=%s", (work_id,))
            conn.execute("DELETE FROM work_items_current WHERE work_item_id=%s", (work_id,))
            if case == "orphan_noncreated":
                conn.execute("DELETE FROM events WHERE work_item_id=%s AND event_seq=0", (work_id,))
            conn.execute("SET session_replication_role=origin")
    drift = registered.replay(work_id)[2]
    expected = {
        "state": "projection says",
        "fields": "fields disagree",
        "payload": "payload does not match",
        "middle_deleted": "sequence gap",
        "tail_deleted": "last_event_seq",
        "all_deleted": "no events",
        "chain": "chain link",
        "sequence": "sequence gap",
        "orphan_created": "projection row is missing",
        "orphan_noncreated": "projection row is missing",
    }[case]
    assert any(expected in d for d in drift), drift


def test_replay_clean_and_boundary(registered: Kernel, dsn: str, schema: str) -> None:
    work_id = item(registered)
    other = item(registered)
    before = registered.get(work_id)
    held = registered.claim(work_id, actor_id="w")
    registered.link(work_id, other, "blocks")
    assert REPLAY_COVERS == (
        "current_state",
        "custom_fields",
        "custom field clears (unset_fields)",
        "last_event_seq",
        "event payload hashes",
        "event chain links",
        "event sequence density",
        "stored transition names against the pinned workflow version",
    )
    assert REPLAY_DOES_NOT_COVER == (
        "leases (claims)",
        "the attempt/fencing counter (claim_attempts)",
        "typed links (links)",
        "idempotency keys",
    )
    assert registered.replay(work_id) == (before.state, before.fields, [])
    assert registered.lease(work_id) == held
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("DELETE FROM {}.claims").format(Identifier(schema)))
        conn.execute(SQL("DELETE FROM {}.links").format(Identifier(schema)))
    assert registered.replay(work_id) == (before.state, before.fields, [])
    assert registered.lease(work_id) is None and registered.links_from(work_id) == []
    # Replay does not reset the persisted counter or revalidate an old attempt.
    next_held = registered.claim(work_id, actor_id="w")
    assert next_held.attempt == held.attempt + 1


def test_replay_read_only_no_temp_residue(registered: Kernel, dsn: str, schema: str) -> None:
    work_id = item(registered)
    # libpq options work for URI and keyword DSNs, without embedding credentials.
    params: dict[str, Any] = psycopg.conninfo.conninfo_to_dict(dsn)
    params["options"] = "-c default_transaction_read_only=on"
    readonly = Kernel.connect(psycopg.conninfo.make_conninfo(**params), schema=schema)
    try:
        before = readonly.get(work_id)
        for _ in range(3):
            assert readonly.replay(work_id) == (before.state, before.fields, [])
        assert readonly.get(work_id) == before
        with psycopg.connect(dsn) as conn:
            assert conn.execute(
                "SELECT count(*) FROM pg_class WHERE relname LIKE 'kernel_replay%' "
                "AND relnamespace IN (SELECT oid FROM pg_namespace WHERE nspname LIKE 'pg_temp%')"
            ).fetchone() == (0,)
    finally:
        readonly.close()


def test_replay_repeatable_snapshot(registered: Kernel, dsn: str, schema: str) -> None:
    work_id = item(registered)
    # Pause a real SELECT inside replay after its snapshot is established.
    key = int(uuid.uuid4().hex[:7], 16)
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
        admin.execute("ALTER TABLE work_items_current RENAME TO item_data")
        admin.execute(
            SQL(
                "CREATE FUNCTION {}.pause_replay(jsonb) RETURNS jsonb LANGUAGE plpgsql AS "
                "$$ BEGIN PERFORM pg_advisory_xact_lock({}); RETURN $1; END $$"
            ).format(Identifier(schema), SQL(str(key)))
        )
        admin.execute(
            "CREATE VIEW work_items_current AS SELECT work_item_id, workflow_name, "
            "workflow_version, work_item_type, current_state, "
            "pause_replay(custom_fields) AS custom_fields, last_event_seq, next_event_seq, "
            "last_event_at, created_at FROM item_data"
        )
        admin.execute("SELECT pg_advisory_lock(%s)", (key,))
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(registered.replay, work_id)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    blocked = admin.execute(
                        "SELECT count(*) FROM pg_locks WHERE locktype='advisory' "
                        "AND objid=%s AND NOT granted",
                        (key,),
                    ).fetchone()
                    if blocked and blocked[0] > 0:
                        break
                    time.sleep(0.01)
                else:
                    pytest.fail("replay did not reach the database snapshot barrier")
                # A concurrent consistent edit. The snapshot must still see x=2.
                payload = {"from": "doing", "to": "doing", "fields": {"x": 999}}
                digest = hashlib.sha256(
                    json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
                ).digest()
                admin.execute(
                    "UPDATE events SET payload=%s, payload_hash=%s "
                    "WHERE work_item_id=%s AND event_seq=2",
                    (Jsonb(payload), digest, work_id),
                )
                admin.execute(
                    "UPDATE item_data SET custom_fields=%s WHERE work_item_id=%s",
                    (Jsonb({"x": 999}), work_id),
                )
            finally:
                admin.execute("SELECT pg_advisory_unlock(%s)", (key,))
            assert future.result(timeout=10) == ("doing", {"x": 2}, [])
    assert registered.replay(work_id) == ("doing", {"x": 999}, [])


def test_replay_memory_bound(registered: Kernel) -> None:
    work_id = item(registered)
    payload = {"note": "x" * 8192}

    def grow(count: int) -> None:
        for _ in range(count):
            registered.transition(work_id, transition="edit", actor_id="w", payload=payload)

    def peaks() -> list[int]:
        registered.replay(work_id)
        gc.collect()
        result = []
        for _ in range(3):
            tracemalloc.start()
            try:
                assert registered.replay(work_id)[2] == []
                result.append(tracemalloc.get_traced_memory()[1])
            finally:
                tracemalloc.stop()
        return result

    grow(80)
    small = peaks()
    grow(560)
    big = peaks()
    assert max(big) < max(small) * 3, (small, big)
    assert max(big) < 640 * 8192 / 2, big
    assert max(big) < min(big) * 1.5, big


def test_replay_stream_plan_has_no_sort(registered: Kernel, dsn: str, schema: str) -> None:
    work_id = item(registered)
    # Other histories make the target selective. Seeding unrelated rows through
    # SQL is confined to this planner fixture; no claimed replay/hash validity.
    others = [
        registered.create_work_item(workflow="review", type="task", actor_id="w").id
        for _ in range(20)
    ]
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
        conn.execute(
            "INSERT INTO events (event_id,work_item_id,event_seq,actor_id,actor_kind,"
            "transition,payload,payload_hash) "
            "SELECT gen_random_uuid(), id, n, 'planner', 'system', 'edit', "
            "jsonb_build_object('note', repeat('x', 1024)), decode('00','hex') "
            "FROM unnest(%s::uuid[]) AS id CROSS JOIN generate_series(1,300) AS n",
            (others,),
        )
        conn.execute("ANALYZE events")
        plan = conn.execute(
            "EXPLAIN (COSTS OFF) DECLARE f1_plan CURSOR FOR "
            "SELECT event_seq, transition, payload, payload_hash, prev_event_hash "
            "FROM events WHERE work_item_id=%s ORDER BY event_seq",
            (work_id,),
        ).fetchall()
    text = "\n".join(r[0] for r in plan)
    assert "Sort" not in text and "Index Scan" in text, text
