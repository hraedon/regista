from __future__ import annotations

import gc
import json
import tracemalloc
import uuid
from collections.abc import Callable
from dataclasses import replace
from typing import Any

import kernel as api
import psycopg
import pytest
from kernel import InvalidQueryError, Kernel, KernelError, Workflow
from psycopg.sql import SQL, Identifier
from test_f1_cli import cli


def history_item(k: Kernel) -> uuid.UUID:
    made = k.create_work_item(workflow="review", type="task", actor_id="w")
    k.transition(made.id, transition="start", actor_id="w")
    for _ in range(4):
        k.transition(made.id, transition="edit", actor_id="w")
    return made.id


@pytest.mark.parametrize(
    "before,after,newest,limit,expected",
    [
        (None, None, True, 3, [3, 4, 5]),
        (None, None, True, 1, [5]),
        (4, None, True, 2, [2, 3]),
        (4, None, False, 100, [0, 1, 2, 3]),
        (0, None, True, 100, []),
        (1, None, False, 100, [0]),
        (5, 1, False, 2, [2, 3]),
        (5, 1, True, 2, [3, 4]),
        (2, 2, True, 100, []),
    ],
    ids=[
        "suffix",
        "suffix_one",
        "before_suffix",
        "before_prefix",
        "empty",
        "creation_only",
        "both_prefix",
        "both_suffix",
        "empty_interval",
    ],
)
def test_history_windows_a4(
    registered: Kernel,
    before: int | None,
    after: int | None,
    newest: bool,
    limit: int,
    expected: list[int],
) -> None:
    work_id = history_item(registered)
    events = registered.history(work_id, before=before, after=after, newest=newest, limit=limit)
    assert [e.seq for e in events] == expected
    all_events = registered.history(work_id, limit=100)
    assert events == [all_events[i] for i in expected]


@pytest.mark.parametrize("cursor", [-1, True, 1.5, "2"])
@pytest.mark.parametrize("side", ["before", "after"])
def test_history_cursor_refusal_a4(registered: Kernel, cursor: Any, side: str) -> None:
    work_id = history_item(registered)
    with pytest.raises(InvalidQueryError, match=side):
        registered.history(work_id, **{side: cursor})
    assert len(registered.history(work_id)) == 6


@pytest.mark.parametrize("newest", [False, True])
def test_cli_history_window_a4(registered: Kernel, dsn: str, schema: str, newest: bool) -> None:
    work_id = history_item(registered)
    args = ["history", str(work_id), "--before", "5", "--after", "0", "--limit", "2"]
    if newest:
        args.append("--newest")
    out = cli(dsn, schema, args)
    assert out.returncode == 0, out.stderr
    assert [e["seq"] for e in json.loads(out.stdout)] == ([3, 4] if newest else [1, 2])
    text = cli(dsn, schema, args, False)
    assert text.returncode == 0, text.stderr
    assert ("resume with --before 3" if newest else "resume with --after 2") in text.stdout


@pytest.mark.parametrize("name", ["not_registered", "v2_only"])
def test_replay_transition_pin_a4(
    registered: Kernel, workflow: Workflow, dsn: str, schema: str, name: str
) -> None:
    work_id = history_item(registered)
    v2 = replace(workflow, transitions={**workflow.transitions, "v2_only": (("doing",), "doing")})
    assert registered.register_workflow(v2) == 2
    assert registered.replay(work_id)[2] == []
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            SQL("UPDATE {}.events SET transition=%s WHERE work_item_id=%s AND event_seq=2").format(
                Identifier(schema)
            ),
            (name, work_id),
        )
    drift = registered.replay(work_id)[2]
    assert any("unknown transition" in d and name in d and "v1" in d for d in drift), drift
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            SQL(
                "UPDATE {}.events SET transition='edit' WHERE work_item_id=%s AND event_seq=2"
            ).format(Identifier(schema)),
            (work_id,),
        )
    assert registered.replay(work_id)[2] == []
    new = registered.create_work_item(workflow="review", type="task", actor_id="w")
    registered.transition(new.id, transition="start", actor_id="w")
    registered.transition(new.id, transition="v2_only", actor_id="w")
    assert registered.replay(new.id)[2] == []


def test_replay_unknown_item_a4(registered: Kernel, dsn: str, schema: str) -> None:
    work_id = uuid.uuid4()
    with pytest.raises(KernelError) as exc:
        registered.replay(work_id)
    assert type(exc.value).__name__ == "WorkItemNotFoundError"
    with pytest.raises(type(exc.value)):
        registered.get(work_id)
    out = cli(dsn, schema, ["replay", str(work_id)])
    assert out.returncode == 2, out.stdout
    assert json.loads(out.stdout)["error"] == "WorkItemNotFoundError"
    assert registered.replay(history_item(registered))[2] == []


@pytest.mark.parametrize("batch_size", [1, 2, 50])
def test_replay_namespace_a4(
    registered: Kernel, dsn: str, schema: str, schema_factory: Callable[[], str], batch_size: int
) -> None:
    assert list(registered.replay_all(batch_size=batch_size)) == []
    good, bad, missing_history, orphan = [history_item(registered) for _ in range(4)]
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
        conn.execute(
            "UPDATE work_items_current SET current_state='wrong' WHERE work_item_id=%s", (bad,)
        )
        conn.execute("DELETE FROM events WHERE work_item_id=%s", (missing_history,))
        conn.execute("SET session_replication_role=replica")
        conn.execute("DELETE FROM work_items_current WHERE work_item_id=%s", (orphan,))
    sibling = Kernel.connect(dsn, schema=schema_factory())
    try:
        sibling.initialize(str(api.__file__).replace("kernel.py", "schema.sql"))
        sibling.register_workflow(registered.get_workflow("review"))
        assert list(sibling.replay_all()) == []
    finally:
        sibling.close()
    reports = list(registered.replay_all(batch_size=batch_size))
    assert [r.work_item_id for r in reports] == sorted([good, bad, missing_history, orphan])
    assert [r.work_item_id for r in reports if not r.drift] == [good]
    assert all((r.state, r.fields, r.drift) == registered.replay(r.work_item_id) for r in reports)
    iterator = registered.replay_all(batch_size=1)
    next(iterator)
    assert registered.health()["pool_available"] >= 1
    iterator.close()
    assert len(list(registered.replay_all())) == 4


@pytest.mark.parametrize("as_json", [False, True])
def test_cli_namespace_replay_a4(registered: Kernel, dsn: str, schema: str, as_json: bool) -> None:
    good, bad = history_item(registered), history_item(registered)
    out = cli(dsn, schema, ["replay"], as_json)
    assert out.returncode == 0, out.stderr
    if as_json:
        assert {json.loads(line)["work_item_id"] for line in out.stdout.splitlines()} == {
            str(good),
            str(bad),
        }
    else:
        assert str(good) in out.stdout and str(bad) in out.stdout
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            SQL(
                "UPDATE {}.work_items_current SET current_state='wrong' WHERE work_item_id=%s"
            ).format(Identifier(schema)),
            (bad,),
        )
    out = cli(dsn, schema, ["replay"], as_json)
    assert out.returncode == 1, out.stderr
    assert "projection says" in out.stdout


def test_replay_namespace_memory_bound_a4(registered: Kernel) -> None:
    def grow(count: int) -> None:
        for _ in range(count):
            registered.create_work_item(
                workflow="review", type="task", actor_id="w", fields={"note": "x" * 8192}
            )

    def peak() -> int:
        gc.collect()
        tracemalloc.start()
        try:
            for report in registered.replay_all(batch_size=8):
                assert not report.drift
            return tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()

    grow(40)
    small = peak()
    grow(360)
    big = peak()
    assert big < small * 3, (small, big)
    assert big < 400 * 8192 / 2, big


def sized_mapping(size: int, unicode: bool = False) -> dict[str, str]:
    text = "é" * ((size - 8) // 2) if unicode else "x" * (size - 8)
    return {"x": text}


@pytest.mark.parametrize("entry", ["create", "fields", "payload"])
@pytest.mark.parametrize("size", [65536, 65537, 70000])
def test_json_input_limit_a4(registered: Kernel, entry: str, size: int) -> None:
    work_id = history_item(registered)
    data = sized_mapping(size)
    assert len(json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()) == size
    before = registered.get(work_id)
    count = registered.health()["work_items"]

    def write() -> Any:
        if entry == "create":
            return registered.create_work_item(
                workflow="review", type="task", actor_id="w", fields=data
            )
        kwargs: dict[str, Any] = {entry: data}
        return registered.transition(work_id, transition="edit", actor_id="w", **kwargs)

    if size == 65536:
        made = write()
        assert not registered.replay(made.id)[2]
    else:
        with pytest.raises(KernelError, match="65536") as exc:
            write()
        assert type(exc.value).__name__ == "InputTooLargeError"
        assert registered.get(work_id) == before
        assert registered.health()["work_items"] == count
        registered.transition(work_id, transition="edit", actor_id="w", payload={"ok": True})


def test_input_limit_unicode_and_merge_a4(registered: Kernel) -> None:
    data = sized_mapping(65536, True)
    made = registered.create_work_item(workflow="review", type="task", actor_id="w", fields=data)
    registered.transition(made.id, transition="start", actor_id="w")
    with pytest.raises(KernelError, match="65536") as exc:
        registered.transition(made.id, transition="edit", actor_id="w", fields={"y": 1})
    assert type(exc.value).__name__ == "InputTooLargeError"
    assert registered.get(made.id).fields == data
    assert registered.transition(
        made.id, transition="edit", actor_id="w", fields={"y": 1}, unset_fields=("x",)
    ).fields == {"y": 1}
    assert registered.replay(made.id)[2] == []


@pytest.mark.parametrize("entry", ["actor", "claim_actor", "link", "workflow", "key", "role"])
def test_name_input_limit_a4(registered: Kernel, workflow: Workflow, entry: str) -> None:
    first, second = history_item(registered), history_item(registered)
    value = "x" * 256
    actions: dict[str, Callable[[], Any]] = {
        "actor": lambda: registered.transition(first, transition="edit", actor_id=value),
        "claim_actor": lambda: registered.claim(first, actor_id=value),
        "link": lambda: registered.link(first, second, value),
        "workflow": lambda: registered.register_workflow(replace(workflow, name=value)),
        "key": lambda: registered.transition(
            first, transition="edit", actor_id="w", idempotency_key=value
        ),
        "role": lambda: registered.transition(first, transition="edit", actor_id="w", role=value),
    }
    before = registered.get(first)
    with pytest.raises(KernelError, match="255") as exc:
        actions[entry]()
    assert type(exc.value).__name__ == "InputTooLargeError"
    assert registered.get(first) == before
    assert registered.lease(first) is None
    assert registered.links_from(first) == []
    assert registered.transition(first, transition="edit", actor_id="x" * 255).state == "doing"


def test_workflow_input_limit_a4(registered: Kernel, workflow: Workflow) -> None:
    huge = replace(
        workflow,
        field_schemas={
            "task": {"type": "object", "properties": {"x": {"enum": ["x" * (256 * 1024)]}}}
        },
    )
    with pytest.raises(KernelError, match="262144") as exc:
        registered.register_workflow(huge)
    assert type(exc.value).__name__ == "InputTooLargeError"
    assert registered.register_workflow(workflow) == 1


def test_replay_diagnostics_bounded_a4(registered: Kernel, dsn: str, schema: str) -> None:
    work_id = history_item(registered)
    for _ in range(120):
        registered.transition(work_id, transition="edit", actor_id="w")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            SQL(
                "UPDATE {}.events SET transition='unknown' WHERE work_item_id=%s "
                "AND transition IS NOT NULL"
            ).format(Identifier(schema)),
            (work_id,),
        )
    drift = registered.replay(work_id)[2]
    assert len(drift) == 101
    assert "25 additional drift diagnostics omitted" == drift[-1]
    assert next(registered.replay_all()).drift == drift


def test_large_workflow_document_refuses_cleanly_a4(
    registered: Kernel, workflow: Workflow, tmp_path: Any, dsn: str, schema: str
) -> None:
    doc = replace(workflow, name="x" * 256).as_document()
    out_file = tmp_path / "large.json"
    out_file.write_text(json.dumps(doc))
    for command in ("validate", "register"):
        out = cli(dsn, schema, ["workflow", command, "--file", str(out_file)])
        assert out.returncode in (1, 2)
        assert "255" in out.stdout
        assert "Traceback" not in out.stderr
    assert api.validate_workflow_document(workflow.as_document()) == ()


@pytest.mark.parametrize("data", [None, {"note": "small"}, {"note": "x" * 70000}])
def test_actor_metadata_parameter_retired_a4(registered: Kernel, data: Any) -> None:
    with pytest.raises(TypeError, match="actor_metadata"):
        registered.create_work_item(
            workflow="review", type="task", actor_id="w", **{"actor_metadata": data}
        )
    made = registered.create_work_item(workflow="review", type="task", actor_id="w")
    assert registered.history(made.id)[0].actor_id == "w"


@pytest.mark.parametrize("data", [None, {}, {"note": "small"}])
def test_json_input_small_a4(registered: Kernel, data: dict[str, Any] | None) -> None:
    made = registered.create_work_item(workflow="review", type="task", actor_id="w", fields=data)
    assert made.fields == (data or {})
    registered.transition(made.id, transition="start", actor_id="w", payload=data)
    assert registered.replay(made.id)[2] == []


def test_name_utf8_limit_a4(registered: Kernel) -> None:
    with pytest.raises(KernelError, match="255") as exc:
        registered.create_work_item(workflow="review", type="task", actor_id="é" * 128)
    assert type(exc.value).__name__ == "InputTooLargeError"
    made = registered.create_work_item(workflow="review", type="task", actor_id="é" * 127 + "x")
    assert registered.history(made.id)[0].actor_id == "é" * 127 + "x"


def test_unset_input_limit_a4(registered: Kernel) -> None:
    work_id = history_item(registered)
    with pytest.raises(KernelError, match="65536") as exc:
        registered.transition(
            work_id, transition="edit", actor_id="w", unset_fields=("unused",) * 10000
        )
    assert type(exc.value).__name__ == "InputTooLargeError"
    assert (
        registered.transition(
            work_id, transition="edit", actor_id="w", unset_fields=("unused",)
        ).state
        == "doing"
    )


def test_namespace_name_limit_a4(registered: Kernel, dsn: str, schema: str) -> None:
    def open_long() -> None:
        handle = Kernel.connect(dsn, schema=schema + "x" * (64 - len(schema)))
        handle.close()

    with pytest.raises(KernelError, match="63") as exc:
        open_long()
    assert type(exc.value).__name__ == "InputTooLargeError"
    boundary = schema + "x" * (63 - len(schema))
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("CREATE SCHEMA {}").format(Identifier(boundary)))
        handle: Kernel | None = None
        try:
            handle = Kernel.connect(dsn, schema=boundary)
            handle.initialize(str(api.__file__).replace("kernel.py", "schema.sql"))
            assert handle.health()["work_items"] == registered.health()["work_items"] == 0
        finally:
            if handle is not None:
                handle.close()
            conn.execute(SQL("DROP SCHEMA {} CASCADE").format(Identifier(boundary)))
