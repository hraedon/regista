"""Retained assertions found while auditing the remaining §A callers."""

from __future__ import annotations

import uuid
from dataclasses import replace
from typing import Any

import psycopg
import pytest
from kernel import InvalidFieldError, Kernel, Workflow, WorkItemNotFoundError
from psycopg.sql import SQL, Identifier


def test_history_cursor_windows(registered: Kernel) -> None:
    made = registered.create_work_item(workflow="review", type="task", actor_id="w")
    registered.transition(made.id, transition="start", actor_id="w")
    for n in range(10):
        registered.transition(made.id, transition="edit", actor_id="w", payload={"n": n})
    history = registered.history(made.id, limit=100)
    assert [e.seq for e in history] == list(range(12))
    pages = [registered.history(made.id, after=0, limit=3)]
    while pages[-1]:
        pages.append(registered.history(made.id, after=pages[-1][-1].seq, limit=3))
    assert [[e.seq for e in p] for p in pages] == [[1, 2, 3], [4, 5, 6], [7, 8, 9], [10, 11], []]
    assert registered.history(made.id, after=11) == []
    assert registered.history(made.id, after=0, limit=100) == history[1:]
    with pytest.raises(WorkItemNotFoundError):
        registered.history(uuid.uuid4())


def test_generic_review_note_and_mixed_actors(kernel: Kernel, workflow: Workflow) -> None:
    wf = replace(workflow, required_fields={**workflow.required_fields, "reject": ("review_note",)})
    kernel.register_workflow(wf)
    made = kernel.create_work_item(workflow="review", type="task", actor_id="author")
    kernel.transition(made.id, transition="start", actor_id="author")
    kernel.transition(made.id, transition="submit", actor_id="author", fields={"note": "ready"})
    before = kernel.get(made.id), kernel.history(made.id)
    with pytest.raises(InvalidFieldError):
        kernel.transition(made.id, transition="reject", actor_id="critic", role="reviewer")
    assert (kernel.get(made.id), kernel.history(made.id)) == before
    kernel.transition(made.id, transition="reject", actor_id="critic", role="reviewer",
                      fields={"review_note": "repair the transaction"})
    assert kernel.get(made.id).state == "changes"
    kernel.transition(made.id, transition="start", actor_id="author")
    kernel.transition(made.id, transition="submit", actor_id="author")
    final = kernel.transition(made.id, transition="approve", actor_id="human", actor_kind="human",
                              role="reviewer")
    assert final.state == "done"
    assert {e.actor_kind for e in kernel.history(made.id)} == {"agent", "human"}
    assert kernel.replay(made.id) == (final.state, final.fields, [])


@pytest.mark.parametrize("phase", ["create", "transition"])
def test_declared_fields_positive_roundtrip(kernel: Kernel, workflow: Workflow, phase: str) -> None:
    rule: dict[str, Any] = {
        "type": "object", "additionalProperties": False,
        "properties": {"priority": {"enum": ["low", "high"]}, "metadata": {"type": "object"}},
    }
    kernel.register_workflow(replace(workflow, field_schemas={"task": rule}))
    fields = {"priority": "high", "metadata": {"nested": True, "list": [1, None, {"a": 2}]}}
    made = kernel.create_work_item(workflow="review", type="task", actor_id="w",
                                   fields=fields if phase == "create" else {})
    if phase == "transition":
        made = kernel.transition(made.id, transition="start", actor_id="w", fields=fields)
    assert kernel.get(made.id).fields == fields
    assert kernel.replay(made.id) == (made.state, fields, [])


def test_schema_is_flat(dsn: str, schema: str, kernel: Kernel) -> None:
    with psycopg.connect(dsn) as conn:
        assert conn.execute(
            "SELECT count(*) FROM pg_partitioned_table p JOIN pg_class c ON c.oid=p.partrelid "
            "JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s", (schema,),
        ).fetchone() == (0,)
    assert kernel.health()["schema_version"] == 1


def test_stamps_use_one_database_instant(registered: Kernel, dsn: str, schema: str) -> None:
    with psycopg.connect(dsn) as clock:
        before = clock.execute("SELECT clock_timestamp()").fetchone()
        assert before is not None
    made = registered.create_work_item(workflow="review", type="task", actor_id="w")
    registered.transition(made.id, transition="start", actor_id="w")
    with psycopg.connect(dsn) as conn:
        after = conn.execute("SELECT clock_timestamp()").fetchone()
        assert after is not None
        assert all(before[0] <= e.occurred_at <= after[0] for e in registered.history(made.id))
        assert conn.execute(
            SQL("SELECT w.created_at=e.occurred_at FROM {}.work_items_current w "
                "JOIN {}.events e USING(work_item_id) WHERE w.work_item_id=%s AND e.event_seq=0")
            .format(Identifier(schema), Identifier(schema)), (made.id,),
        ).fetchone() == (True,)
        assert conn.execute(
            SQL("SELECT w.last_event_at=e.occurred_at FROM {}.work_items_current w "
                "JOIN {}.events e USING(work_item_id) WHERE w.work_item_id=%s AND e.event_seq=1")
            .format(Identifier(schema), Identifier(schema)), (made.id,),
        ).fetchone() == (True,)
    assert all(e.occurred_at.tzinfo is not None for e in registered.history(made.id))


def test_scoped_replay_ignores_other_damage(registered: Kernel, dsn: str, schema: str) -> None:
    clean, damaged = [registered.create_work_item(workflow="review", type="task", actor_id="w")
                      for _ in range(2)]
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("UPDATE {}.work_items_current SET current_state='wrong' "
                         "WHERE work_item_id=%s").format(Identifier(schema)), (damaged.id,))
    assert registered.replay(clean.id) == (clean.state, clean.fields, [])
    assert registered.replay(damaged.id)[2]


@pytest.mark.parametrize("events_per_item", [10, 100])
def test_many_item_replay(registered: Kernel, events_per_item: int) -> None:
    items = []
    for _ in range(100):
        made = registered.create_work_item(workflow="review", type="task", actor_id="w")
        registered.transition(made.id, transition="start", actor_id="w")
        for n in range(events_per_item - 2):
            registered.transition(made.id, transition="edit", actor_id="w", fields={"n": n})
        items.append(registered.get(made.id))
    assert registered.health()["events"] == 100 * events_per_item
    for made in items:
        assert made.last_event_seq == events_per_item - 1
        assert registered.replay(made.id) == (made.state, made.fields, [])


def test_links_at_scale(registered: Kernel) -> None:
    sources, targets = [], []
    for _ in range(50):
        sources.append(registered.create_work_item(workflow="review", type="task", actor_id="w"))
        targets.append(registered.create_work_item(workflow="review", type="source", actor_id="w"))
    for i, source in enumerate(sources):
        expected = [(targets[(i + j + 1) % 50].id, "fixes") for j in range(5)]
        for target, kind in expected:
            registered.link(source.id, target, kind)
        expected.sort(key=lambda pair: (pair[1], pair[0]))
        first = registered.links_from(source.id, limit=3)
        last = first[-1]
        second = registered.links_from(source.id, limit=3, after=(last[1], last[0]))
        assert first + second == expected
    assert registered.blocked(link_type="fixes", direction="outgoing", satisfied_states=("done",),
                              limit=100) == sources


@pytest.mark.parametrize("key", ["privileged", "validator", "validator_params", "allowed_roles",
                                "hooks", "extends", "regista_version", "attempt_threshold",
                                "hook_defaults", "link_types"])
def test_legacy_document_keys_fail_closed(kernel: Kernel, workflow: Workflow, key: str) -> None:
    from kernel import InvalidWorkflowError, validate_workflow_document

    doc = workflow.as_document()
    if key in ("privileged", "validator", "validator_params", "allowed_roles", "hooks"):
        doc["transitions"][0][key] = True if key == "privileged" else "old-contract"
    else:
        doc[key] = "old-contract"
    problems = validate_workflow_document(doc)
    assert problems and any(key in problem for problem in problems)
    with pytest.raises(InvalidWorkflowError):
        kernel.register_workflow(Workflow.from_document(doc))
    assert kernel.list_workflows() == []


def test_event_sequence_constraint(registered: Kernel, dsn: str, schema: str) -> None:
    made = registered.create_work_item(workflow="review", type="task", actor_id="w")
    before = registered.history(made.id)
    with psycopg.connect(dsn) as conn:
        with pytest.raises(psycopg.errors.UniqueViolation):
            conn.execute(SQL(
                "INSERT INTO {}.events (event_id,work_item_id,event_seq,actor_id,actor_kind,"
                "transition,payload,payload_hash) "
                "VALUES (%s,%s,0,'duplicate','agent',NULL,'{{}}',%s)"
            ).format(Identifier(schema)), (uuid.uuid4(), made.id, b"x" * 32))
    assert registered.history(made.id) == before


def test_replay_key_order_is_irrelevant(registered: Kernel, dsn: str, schema: str) -> None:
    import json

    made = registered.create_work_item(workflow="review", type="task", actor_id="w")
    final = registered.transition(made.id, transition="start", actor_id="w",
                                 payload={"alpha": 1, "beta": 2}, fields={"z": 1, "a": 2})
    before = registered.history(made.id)
    original = before[-1].payload
    reordered = {name: original[name] for name in reversed(original)}
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("UPDATE {}.events SET payload=%s::jsonb "
                         "WHERE work_item_id=%s AND event_seq=1").format(Identifier(schema)),
                     (json.dumps(reordered), made.id))
    assert registered.history(made.id) == before
    assert registered.replay(made.id) == (final.state, final.fields, [])


def test_sweep_preserves_replacement_lease(registered: Kernel, dsn: str, schema: str) -> None:
    from concurrent.futures import ThreadPoolExecutor

    made = registered.create_work_item(workflow="review", type="task", actor_id="w")
    held = registered.claim(made.id, actor_id="old")
    for _ in range(10):
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(SQL("UPDATE {}.claims SET "
                             "expires_at=clock_timestamp()-interval '1 second' "
                             "WHERE work_item_id=%s").format(Identifier(schema)), (made.id,))
        with ThreadPoolExecutor(max_workers=2) as pool:
            sweep = pool.submit(registered.expire_leases)
            takeover = pool.submit(registered.claim, made.id, actor_id="replacement")
            assert sweep.result(timeout=10) in (0, 1)
            fresh = takeover.result(timeout=10)
        assert fresh.attempt > held.attempt
        assert registered.lease(made.id) == fresh
        assert registered.expire_leases() == 0
        assert registered.lease(made.id) == fresh
        held = fresh
