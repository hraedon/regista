from __future__ import annotations

import os
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest
from psycopg.rows import dict_row
from psycopg.sql import SQL, Identifier

from regista import Regista, RegistaError
from regista._errors import ErrorCode
from regista._integrity import REGISTA_VERSION
from regista._testing import raw_transaction

_DEFAULT_DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"


def _resolve_dsn() -> str:
    try:
        import conftest
    except ImportError:
        return os.environ.get("REGISTA_TEST_DSN", _DEFAULT_DSN)
    return getattr(conftest, "DSN", os.environ.get("REGISTA_TEST_DSN", _DEFAULT_DSN))


DSN = _resolve_dsn()

ESCALATION_WORKFLOW = f"""\
name: escalation_wf
version: 1
regista_version: "{REGISTA_VERSION}"

states:
  - name: new
    initial: true
  - name: working
  - name: done
    terminal: true

transitions:
  - name: start
    from: new
    to: working
  - name: finish
    from: working
    to: done

roles: []
work_item_types:
  - name: task
    custom_fields: []

attempt_threshold: 1
"""

CUSTOM_FIELD_WORKFLOW = f"""\
name: custom_field_wf
version: 1
regista_version: "{REGISTA_VERSION}"

states:
  - name: new
    initial: true
  - name: working
  - name: done
    terminal: true

transitions:
  - name: start
    from: new
    to: working
  - name: finish
    from: working
    to: done

roles: []
work_item_types:
  - name: task
    custom_fields:
      - name: x
        type: integer
"""


def _transitions(events: list[Any]) -> list[str]:
    return [e.transition for e in events]


def _make_task(sub: Regista, workflow_name: str) -> uuid.UUID:
    wi, _ = sub.create_work_item(workflow_name, "task", "alice")
    return wi.work_item_id


def test_escalation_appends_distinct_event_seq_and_replays_clean(sub: Regista) -> None:
    sub.register_workflow(ESCALATION_WORKFLOW)
    work_item_id = _make_task(sub, "escalation_wf")

    sub.acquire_claim(work_item_id, "alice", ttl_seconds=300)

    events = sub.read_events(work_item_id=work_item_id)
    transitions = _transitions(events)
    assert transitions == ["created", "claim_acquired", "escalated"]

    seqs = [e.event_seq for e in events]
    assert len(set(seqs)) == len(seqs)
    assert seqs[0] < seqs[1] < seqs[2]

    report = sub.replay()
    assert report.replayed_drift == 0
    assert report.halted == 0


def test_claim_extend_emits_heartbeat_and_replays_clean(sub: Regista, make_feature) -> None:
    work_item = make_feature()

    first = sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=5)
    time.sleep(1.3)
    extended = sub.acquire_claim(work_item.work_item_id, "alice", ttl_seconds=60)

    assert extended.attempt_number == first.attempt_number
    assert extended.expires_at > first.expires_at

    transitions = _transitions(sub.read_events(work_item_id=work_item.work_item_id))
    assert "claim_heartbeat" in transitions

    report = sub.replay()
    assert report.replayed_drift == 0


def test_release_fence_refuses_stale_attempt(sub: Regista, make_feature) -> None:
    work_item = make_feature()
    work_item_id = work_item.work_item_id

    sub.acquire_claim(work_item_id, "A", ttl_seconds=1)
    time.sleep(1.3)
    stolen = sub.acquire_claim(work_item_id, "B", ttl_seconds=300)
    assert stolen.attempt_number == 2

    with pytest.raises(RegistaError) as exc:
        sub.release_claim(work_item_id, "B", expected_attempt_number=1)
    assert exc.value.code is ErrorCode.CLAIM_LOST

    sub.release_claim(work_item_id, "B", expected_attempt_number=2)
    refreshed = sub.get_work_item(work_item_id)
    assert refreshed is not None
    assert refreshed.claimed_by is None


def _build_untracked(conn: Any, schema: str) -> None:
    conn.execute(
        SQL("CREATE TABLE {}.events (event_id UUID PRIMARY KEY, note TEXT)").format(
            Identifier(schema)
        )
    )
    conn.execute(
        SQL("INSERT INTO {}.events (event_id, note) VALUES (%s, %s)").format(
            Identifier(schema)
        ),
        [uuid.uuid4(), "keep"],
    )


def _build_versions(conn: Any, schema: str) -> None:
    conn.execute(
        SQL("CREATE TABLE {}.events (event_id UUID PRIMARY KEY, note TEXT)").format(
            Identifier(schema)
        )
    )
    conn.execute(
        SQL("INSERT INTO {}.events (event_id, note) VALUES (%s, %s)").format(
            Identifier(schema)
        ),
        [uuid.uuid4(), "keep"],
    )
    conn.execute(
        SQL(
            "CREATE TABLE {}._regista_migrations "
            "(version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        ).format(Identifier(schema))
    )
    conn.execute(
        SQL("INSERT INTO {}._regista_migrations (version) VALUES (1), (50)").format(
            Identifier(schema)
        )
    )


def _build_substrate(conn: Any, schema: str) -> None:
    conn.execute(
        SQL(
            "CREATE TABLE {}._substrate_migrations "
            "(version INTEGER PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        ).format(Identifier(schema))
    )
    conn.execute(
        SQL("INSERT INTO {}._substrate_migrations (version) VALUES (1)").format(
            Identifier(schema)
        )
    )


def _snapshot(conn: Any, schema: str) -> tuple[list[tuple[Any, ...]], dict[str, int]]:
    columns = conn.execute(
        "SELECT table_name, column_name, data_type, is_nullable "
        "FROM information_schema.columns WHERE table_schema = %s "
        "ORDER BY table_name, ordinal_position",
        [schema],
    ).fetchall()
    column_snapshot = [
        (c["table_name"], c["column_name"], c["data_type"], c["is_nullable"])
        for c in columns
    ]

    tables = conn.execute(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema = %s AND table_type = 'BASE TABLE' "
        "ORDER BY table_name",
        [schema],
    ).fetchall()
    counts: dict[str, int] = {}
    for t in tables:
        table = t["table_name"]
        row = conn.execute(
            SQL("SELECT count(*) AS n FROM {}.{}").format(
                Identifier(schema), Identifier(table)
            )
        ).fetchone()
        counts[table] = int(row["n"])
    return column_snapshot, counts


@pytest.mark.parametrize(
    "build",
    [_build_untracked, _build_versions, _build_substrate],
    ids=["missing_tracker", "unknown_version_50", "pre_rename"],
)
def test_old_or_unknown_schema_refused_without_mutation(
    project: str, build: Callable[[Any, str], None]
) -> None:
    schema = project
    with psycopg.connect(DSN, autocommit=True, row_factory=dict_row) as conn:
        conn.execute(SQL("CREATE SCHEMA {}").format(Identifier(schema)))
        build(conn, schema)
        before = _snapshot(conn, schema)

    with pytest.raises(RegistaError) as exc:
        Regista(DSN, schema)
    assert exc.value.code is ErrorCode.UNSUPPORTED_SCHEMA_VERSION

    with psycopg.connect(DSN, autocommit=True, row_factory=dict_row) as conn:
        after = _snapshot(conn, schema)
    assert after == before


def test_unvisited_projection_row_is_reported_as_drift(sub: Regista, make_feature) -> None:
    work_item = make_feature()

    with raw_transaction(sub) as conn:
        conn.execute(
            "DELETE FROM events WHERE work_item_id = %s",
            [work_item.work_item_id],
        )

    report = sub.replay()

    assert report.replayed_drift >= 1
    assert any(
        entry.detail is not None and "no events" in entry.detail
        for entry in report.entries
    )


def test_transition_custom_fields_idempotency(sub: Regista) -> None:
    sub.register_workflow(CUSTOM_FIELD_WORKFLOW)
    work_item_id = _make_task(sub, "custom_field_wf")
    event_id = uuid.uuid4()

    first = sub.transition(
        work_item_id, "start", "alice", custom_fields={"x": 1}, event_id=event_id
    )
    second = sub.transition(
        work_item_id, "start", "alice", custom_fields={"x": 1}, event_id=event_id
    )

    assert second.event_id == first.event_id
    assert second.event_seq == first.event_seq

    with pytest.raises(RegistaError) as exc:
        sub.transition(
            work_item_id, "start", "alice", custom_fields={"x": 2}, event_id=event_id
        )
    assert exc.value.code is ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD


def test_link_idempotency_returns_stored_link_id(sub: Regista, make_feature) -> None:
    source = make_feature()
    target = make_feature()
    event_id = uuid.uuid4()

    first = sub.create_link(
        source.work_item_id, target.work_item_id, "blocks", "alice", event_id=event_id
    )
    second = sub.create_link(
        source.work_item_id, target.work_item_id, "blocks", "alice", event_id=event_id
    )

    assert second.link_id == first.link_id

    created = sub.read_events(
        work_item_id=source.work_item_id, transition="link_created"
    )
    assert len(created) == 1
    assert created[0].payload is not None
    assert created[0].payload["link_id"] == str(first.link_id)

    live = sub.list_links(source.work_item_id)
    assert len(live) == 1
    assert live[0].link_id == first.link_id


def test_append_event_rejects_unknown_entity_kind(sub: Regista, make_feature) -> None:
    work_item = make_feature()

    with pytest.raises(RegistaError) as exc:
        sub.append_event(
            work_item.work_item_id,
            "a",
            entity_kind="project",
            transition="custom_thing",
        )
    assert exc.value.code is ErrorCode.INVALID_ARGUMENT


def test_update_not_before_idempotency_conflict(sub: Regista, make_feature) -> None:
    work_item = make_feature()
    event_id = uuid.uuid4()
    t1 = datetime.now(UTC) + timedelta(hours=1)
    t2 = datetime.now(UTC) + timedelta(hours=2)

    sub.update_not_before(work_item.work_item_id, t1, "a", event_id=event_id)

    with pytest.raises(RegistaError) as exc:
        sub.update_not_before(work_item.work_item_id, t2, "a", event_id=event_id)
    assert exc.value.code is ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD
