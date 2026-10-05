from __future__ import annotations

import hashlib
import io
import json
import signal
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Any

import kernel as api
import psycopg
import pytest
import yaml
from kernel import (
    DatabaseOperationError,
    IdempotencyConflictError,
    InputTooLargeError,
    InvalidQueryError,
    InvalidWorkflowError,
    Kernel,
    Workflow,
    WorkItemNotFoundError,
    load_workflow_document,
    parse_workflow_document,
)
from psycopg.sql import SQL, Identifier
from psycopg.types.json import Jsonb
from test_f1_cli import cli


def corrupt_payload(dsn: str, schema: str, item: uuid.UUID, seq: int, payload: Any,
                    rehash: bool = False) -> None:
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("UPDATE {}.events SET payload=%s WHERE work_item_id=%s AND event_seq=%s")
                     .format(Identifier(schema)), (Jsonb(payload), item, seq))
        if rehash:
            digest = hashlib.sha256(json.dumps(payload, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False).encode()).digest()
            conn.execute(SQL("UPDATE {}.events SET payload_hash=%s "
                             "WHERE work_item_id=%s AND event_seq=%s").format(Identifier(schema)),
                         (digest, item, seq))


@pytest.mark.parametrize("damage", [
    "fields_list", "fields_null", "fields_string", "unset_string", "unset_object",
    "unset_null", "unset_members", "missing_fields", "missing_state", "state_list",
    "object_missing", "payload_list", "payload_null", "payload_bool", "payload_number",
    "payload_string", "deep",
])
@pytest.mark.parametrize("seq", [0, 2])
def test_replay_malformed_a5(registered: Kernel, dsn: str, schema: str,
                             damage: str, seq: int) -> None:
    items = [registered.create_work_item(workflow="review", type="task", actor_id="w")
             for _ in range(3)]
    for item in items:
        registered.transition(item.id, transition="start", actor_id="w")
        registered.transition(item.id, transition="edit", actor_id="w", fields={"note": "kept"})
    bad = min(items, key=lambda i: i.id)
    payload: Any = registered.history(bad.id)[seq].payload
    body = payload["created"] if seq == 0 else payload
    if damage.startswith("fields_"):
        body["fields"] = {"list": [1, 2], "null": None, "string": "wrong"}[damage[7:]]
    elif damage.startswith("unset_"):
        payload["unset"] = {"string": "note", "object": {}, "null": None,
                            "members": [{}, 1, False]}[damage[6:]]
    elif damage == "missing_fields":
        del body["fields"]
    elif damage == "missing_state":
        del body["state" if seq == 0 else "to"]
    elif damage == "state_list":
        body["state" if seq == 0 else "to"] = []
    elif damage == "object_missing":
        payload = {}
    elif damage.startswith("payload_"):
        payload = {"list": [1, 2], "null": None, "bool": True, "number": 12,
                   "string": "bad"}[damage[8:]]
    elif damage == "deep":
        nested: Any = None
        for _ in range(40):
            nested = [nested]
        body["fields"] = {"deep": nested}
    # A matching checksum is insufficient: the shape itself must be checked.
    corrupt_payload(dsn, schema, bad.id, seq, payload, rehash=True)
    drift = registered.replay(bad.id)[2]
    assert any("malformed payload" in line for line in drift), drift
    reports = list(registered.replay_all(batch_size=1))
    assert [r.work_item_id for r in reports] == sorted(i.id for i in items)
    assert reports[0].drift
    assert all(not r.drift and r.state == "doing" and r.fields == {"note": "kept"}
               for r in reports[1:])


@pytest.mark.parametrize("payload", [[1, 2], None, {"from": "doing", "to": "doing",
                                                       "fields": [1, 2]},
                                     {"from": "doing", "to": "doing", "fields": {},
                                      "unset": {"note": True}}])
@pytest.mark.parametrize("as_json", [False, True])
def test_cli_replay_malformed_a5(registered: Kernel, dsn: str, schema: str,
                                 payload: Any, as_json: bool) -> None:
    bad = registered.create_work_item(workflow="review", type="task", actor_id="w")
    good = registered.create_work_item(workflow="review", type="task", actor_id="w")
    registered.transition(bad.id, transition="start", actor_id="w")
    corrupt_payload(dsn, schema, bad.id, 1, payload)
    for args in (["replay", str(bad.id)], ["replay"]):
        result = cli(dsn, schema, args, as_json=as_json)
        assert result.returncode == 1, result.stdout + result.stderr
        assert "malformed payload" in result.stdout
        assert "Traceback" not in result.stderr
        if len(args) == 1:
            assert str(good.id) in result.stdout and str(bad.id) in result.stdout


def test_create_idempotency_a5(registered: Kernel, workflow: Workflow) -> None:
    request: dict[str, Any] = dict(workflow="review", type="task", actor_id="w",
                                   fields={"note": "original"}, idempotency_key="create-key")
    made = registered.create_work_item(**request)
    assert registered.create_work_item(**request) == made
    registered.transition(made.id, transition="start", actor_id="w", fields={"note": "later"})
    registered.register_workflow(replace(workflow, required_fields={}))
    assert registered.create_work_item(**request) == made
    assert registered.health()["work_items"] == 1 and registered.health()["events"] == 2
    assert len(registered.list_items()) == 1
    assert len([e for e in registered.history(made.id) if e.transition is None]) == 1
    assert registered.get(made.id).fields == {"note": "later"}


@pytest.mark.parametrize("change", ["workflow", "workflow_version", "type", "actor_id",
                                     "actor_kind", "fields"])
def test_create_idempotency_conflict_a5(registered: Kernel, change: str) -> None:
    request: dict[str, Any] = dict(workflow="review", type="task", actor_id="w",
                                   actor_kind="agent", fields={}, idempotency_key="create-key")
    made = registered.create_work_item(**request)
    before = registered.health()
    other = {"workflow": "missing", "workflow_version": 1, "type": "source",
             "actor_id": "other", "actor_kind": "human", "fields": {"x": 1}}
    with pytest.raises(IdempotencyConflictError):
        registered.create_work_item(**{**request, change: other[change]})
    after = registered.health()
    assert (after["events"], after["work_items"]) == (before["events"], before["work_items"])
    assert registered.list_items() == [made] and len(registered.history(made.id)) == 1
    assert registered.create_work_item(**request) == made


@pytest.mark.parametrize("first", ["create", "transition"])
def test_idempotency_shared_namespace_a5(registered: Kernel, first: str) -> None:
    made = registered.create_work_item(workflow="review", type="task", actor_id="w",
                                       idempotency_key="shared" if first == "create" else None)
    if first == "create":
        with pytest.raises(IdempotencyConflictError):
            registered.transition(made.id, transition="start", actor_id="w",
                                  idempotency_key="shared")
        assert registered.get(made.id) == made
    else:
        changed = registered.transition(made.id, transition="start", actor_id="w",
                                         idempotency_key="shared")
        with pytest.raises(IdempotencyConflictError):
            registered.create_work_item(workflow="review", type="task", actor_id="w",
                                         idempotency_key="shared")
        assert registered.list_items() == [changed]
    assert registered.health()["work_items"] == 1
    assert len(registered.history(made.id)) == (1 if first == "create" else 2)


def test_create_concurrent_a5(registered: Kernel) -> None:
    barrier = threading.Barrier(4)

    def create(_: int) -> Any:
        barrier.wait(timeout=5)
        return registered.create_work_item(workflow="review", type="task", actor_id="w",
                                           idempotency_key="raced")

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(create, range(12)))
    assert all(r == results[0] for r in results)
    assert registered.list_items() == [results[0]]
    assert registered.health()["events"] == 1 and registered.health()["work_items"] == 1
    assert len(registered.history(results[0].id)) == 1


def test_create_key_lock_a5(registered: Kernel, dsn: str, schema: str) -> None:
    # Hold the actual key lock to make removing create's serialization deterministically red.
    with psycopg.connect(dsn) as admin, ThreadPoolExecutor(max_workers=1) as pool:
        admin.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                      (f"regista-kernel:{schema}:idempotency:locked",))
        future = pool.submit(registered.create_work_item, workflow="review", type="task",
                             actor_id="w", idempotency_key="locked")
        try:
            deadline = time.monotonic() + 3
            waiting = False
            while time.monotonic() < deadline and not future.done():
                waiting = bool(admin.execute(
                    "SELECT 1 FROM pg_locks held JOIN pg_locks waiter "
                    "ON (waiter.locktype, waiter.database, waiter.classid, waiter.objid, "
                    "waiter.objsubid) = (held.locktype, held.database, held.classid, "
                    "held.objid, held.objsubid) "
                    "WHERE held.pid=pg_backend_pid() AND held.locktype='advisory' "
                    "AND held.granted AND NOT waiter.granted"
                ).fetchone())
                if waiting:
                    break
                time.sleep(.01)
            assert waiting and not future.done(), "create did not serialize on its idempotency key"
        finally:
            admin.rollback()
        made = future.result(timeout=5)
    assert registered.create_work_item(workflow="review", type="task", actor_id="w",
                                       idempotency_key="locked") == made
    assert registered.health()["events"] == 1


def test_cli_create_idempotency_a5(registered: Kernel, dsn: str, schema: str) -> None:
    args = ["create", "--workflow", "review", "--type", "task", "--actor", "w",
            "--idempotency-key", "cli-create"]
    a, b = cli(dsn, schema, args), cli(dsn, schema, args)
    assert a.returncode == b.returncode == 0, a.stderr + b.stderr
    assert json.loads(a.stdout) == json.loads(b.stdout)
    conflict = cli(dsn, schema, [*args, "--field", "x=changed"])
    assert conflict.returncode == 2 and "different request" in conflict.stderr
    assert registered.health()["work_items"] == 1 and registered.health()["events"] == 1


@pytest.mark.parametrize("command", ["health", "show", "history", "replay"])
@pytest.mark.parametrize("as_json", [False, True])
def test_cli_unsupported_diagnostics_a5(registered: Kernel, dsn: str, schema: str,
                                        command: str, as_json: bool) -> None:
    made = registered.create_work_item(workflow="review", type="task", actor_id="w")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("UPDATE {}.kernel_meta SET kernel_schema_version=999")
                     .format(Identifier(schema)))
    args = [command, *([] if command == "health" else [str(made.id)])]
    result = cli(dsn, schema, args, as_json=as_json)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "not writable" not in result.stderr
    if command == "health":
        assert "999" in result.stdout
    handle = Kernel.connect(dsn, schema=schema, require_existing=True)
    try:
        assert handle.health()["schema_version"] == 999
        with pytest.raises(api.UnsupportedSchemaError, match="not writable"):
            handle.create_work_item(workflow="review", type="task", actor_id="w")
        assert handle.health()["events"] == 1
    finally:
        handle.close()


def helper_write(k: Kernel) -> None:
    k._conn.execute("DELETE FROM claim_attempts")


@pytest.mark.parametrize("variant", ["direct", "helper", "cte", "lowercase"])
@pytest.mark.parametrize("restart", [False, True])
def test_reads_enforced_a5(registered: Kernel, variant: str, restart: bool) -> None:
    made = registered.create_work_item(workflow="review", type="task", actor_id="w")

    # Deliberately synthetic misdeclared method. Private access here tests the
    # pooled boundary itself; normal setup/effects/control still use public API.
    @api._pooled_operation(access="read")
    def probe(k: Kernel) -> None:
        if restart:
            k._conn.rollback()
        if variant == "helper":
            helper_write(k)
        else:
            sql = {"direct": "DELETE FROM claim_attempts",
                   "cte": "WITH d AS (DELETE FROM claim_attempts RETURNING *) SELECT * FROM d",
                   "lowercase": "delete from claim_attempts"}[variant]
            k._conn.execute(sql)
        k._conn.commit()

    with pytest.raises(DatabaseOperationError, match="ReadOnlySqlTransaction"):
        probe(registered)
    assert registered.get(made.id) == made
    # A stolen fencing counter would make this fail, and a read-only setting
    # left on a returned connection would also prevent legitimate claims.
    held = registered.claim(made.id, actor_id="w")
    assert held.attempt == 1
    registered.release(made.id, actor_id="w", attempt=held.attempt)


@pytest.mark.parametrize("format", ["yaml", "json"])
@pytest.mark.parametrize("kind", ["file", "text"])
def test_workflow_raw_limit_a5(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                format: str, kind: str) -> None:
    maximum = api.MAX_WORKFLOW_BYTES
    raw = b" " * (maximum + 1)
    calls: list[int | None] = []

    class Bounded(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            calls.append(size)
            assert size == maximum + 1, "workflow file read was unbounded"
            return super().read(size)

    def refuse_parser(*args: Any, **kwargs: Any) -> Any:
        pytest.fail("oversized raw workflow reached the parser")

    monkeypatch.setattr(json, "loads", refuse_parser)
    monkeypatch.setattr(yaml, "scan", refuse_parser)
    if kind == "file":
        monkeypatch.setattr("builtins.open", lambda *a, **kw: Bounded(raw))
        with pytest.raises(InvalidWorkflowError, match="raw UTF-8 bytes"):
            load_workflow_document(str(tmp_path / f"large.{format}"))
        assert calls == [maximum + 1]
    else:
        with pytest.raises(InvalidWorkflowError, match="raw UTF-8 bytes"):
            parse_workflow_document(raw.decode(), format=format)


@pytest.mark.parametrize("kind", ["bomb", "anchor", "alias", "cycle"])
def test_workflow_alias_bounded_a5(tmp_path: Path, kind: str) -> None:
    # Depth 8 is the review reproducer; no validation should ever traverse its
    # exponential expansion. The alarm makes a removed parser guard fail fast.
    text = "roles:\n  a: &a [reviewer]\n"
    for level in range(1, 9):
        before, current = chr(96 + level), chr(97 + level)
        text += f"  {current}: &{current} [" + ", ".join([f"*{before}"] * 10) + "]\n"
    text = {"bomb": text, "anchor": "roles: &roles [reviewer]\n",
            "alias": "roles: *missing\n", "cycle": "roles: &roles [*roles]\n"}[kind]
    path = tmp_path / "alias.yaml"
    path.write_text(text)

    def timed_out(*args: Any) -> None:
        pytest.fail("workflow alias refusal exceeded 0.7 seconds")

    prior = signal.signal(signal.SIGALRM, timed_out)
    signal.setitimer(signal.ITIMER_REAL, .7)
    start = time.monotonic()
    try:
        with pytest.raises(InvalidWorkflowError, match="anchors and aliases"):
            load_workflow_document(str(path))
        assert time.monotonic() - start < .5
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prior)
    assert parse_workflow_document("roles: [reviewer]") == {"roles": ["reviewer"]}


@pytest.mark.parametrize("kind", ["size", "name", "json"])
@pytest.mark.parametrize("operation", ["validate", "register", "document"])
def test_workflow_error_type_a5(registered: Kernel, workflow: Workflow,
                                 kind: str, operation: str) -> None:
    bad = {"size": replace(workflow, field_schemas={"task": {"type": "object",
                    "properties": {"x": {"enum": ["x" * api.MAX_WORKFLOW_BYTES]}}}}),
           "name": replace(workflow, name="x" * 256),
           "json": replace(workflow, field_schemas={"task": {"bad": float("inf")}})}[kind]
    with pytest.raises(InvalidWorkflowError):
        if operation == "validate":
            bad.validate()
        elif operation == "register":
            registered.register_workflow(bad)
        else:
            Workflow.from_document(bad.as_document())
    assert len(registered.list_workflows()) == 1
    assert registered.register_workflow(workflow) == 1


def test_projection_summary_visible_a5(registered: Kernel, dsn: str, schema: str) -> None:
    made = registered.create_work_item(workflow="review", type="task", actor_id="w")
    registered.transition(made.id, transition="start", actor_id="w")
    for _ in range(110):
        registered.transition(made.id, transition="edit", actor_id="w")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("UPDATE {}.events SET transition='unknown' WHERE event_seq>0")
                     .format(Identifier(schema)))
        conn.execute(SQL("UPDATE {}.work_items_current SET current_state='new', "
                         "custom_fields='[]', last_event_seq=999").format(Identifier(schema)))
    drift = registered.replay(made.id)[2]
    assert len(drift) <= 101
    assert any("projection says" in line for line in drift)
    assert any("fields disagree" in line for line in drift)
    assert any("projection's last_event_seq" in line for line in drift)
    assert drift[-1] == "14 additional drift diagnostics omitted"


def test_history_unknown_a5(registered: Kernel, dsn: str, schema: str) -> None:
    with pytest.raises(WorkItemNotFoundError):
        registered.history(uuid.uuid4())
    result = cli(dsn, schema, ["history", str(uuid.uuid4())])
    assert result.returncode == 2 and "no such work item" in result.stderr
    made = registered.create_work_item(workflow="review", type="task", actor_id="w")
    assert registered.history(made.id, before=0) == []
    assert len(registered.history(made.id)) == 1


@pytest.mark.parametrize("newest", ["yes", 1, 0, None, [], {}])
def test_history_newest_type_a5(registered: Kernel, newest: Any) -> None:
    made = registered.create_work_item(workflow="review", type="task", actor_id="w")
    with pytest.raises(InvalidQueryError, match="bool"):
        registered.history(made.id, newest=newest)
    assert len(registered.history(made.id, newest=True)) == 1


@pytest.mark.parametrize("query", ["owned", "workflow", "type", "link", "links_from",
                                   "get_workflow", "workflow_after", "link_after",
                                   "state", "many_states", "satisfied", "many_satisfied",
                                   "states_bytes"])
def test_read_input_limits_a5(registered: Kernel, query: str) -> None:
    big = "x" * 256
    made = registered.create_work_item(workflow="review", type="task", actor_id="w")
    calls: dict[str, Callable[[], Any]] = {
        "owned": lambda: registered.owned(big),
        "workflow": lambda: registered.list_items(workflow=big),
        "type": lambda: registered.available(type=big),
        "link": lambda: registered.blocked(link_type=big, direction="incoming",
                                           satisfied_states=()),
        "links_from": lambda: registered.links_from(made.id, link_type=big),
        "get_workflow": lambda: registered.get_workflow(big),
        "workflow_after": lambda: registered.list_workflows(after=(big, 1)),
        "link_after": lambda: registered.links_from(made.id, after=(big, made.id)),
        "states_bytes": lambda: registered.in_states(("x" * 255,) * 500),
        "state": lambda: registered.in_states((big,)),
        "many_states": lambda: registered.in_states(("new",) * 10000),
        "satisfied": lambda: registered.blocked(link_type="blocks", direction="incoming",
                                               satisfied_states=(big,)),
        "many_satisfied": lambda: registered.blocked(link_type="blocks", direction="incoming",
                                                    satisfied_states=("new",) * 10000),
    }
    with pytest.raises(InputTooLargeError):
        calls[query]()
    assert registered.list_items(workflow="review", states=("new",)) == [made]
    assert registered.get_workflow("review").name == "review"


def test_release_docstring_a5() -> None:
    assert Kernel.release.__doc__ and "Release a lease" in Kernel.release.__doc__


@pytest.mark.parametrize("kind", ["integer", "nesting"])
def test_replay_decoder_damage_a5(registered: Kernel, dsn: str, schema: str, kind: str) -> None:
    items = [registered.create_work_item(workflow="review", type="task", actor_id="w")
             for _ in range(3)]
    bad = min(items, key=lambda item: item.id)
    raw = ("9" * 10000 if kind == "integer" else "[" * 1100 + "0" + "]" * 1100)
    # Feed raw JSON to Postgres so Python's encoder/decoder cannot refuse in setup.
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("UPDATE {}.events SET payload=%s::jsonb WHERE work_item_id=%s")
                     .format(Identifier(schema)), (raw, bad.id))
    drift = registered.replay(bad.id)[2]
    assert any("malformed" in line for line in drift), drift
    reports = list(registered.replay_all(batch_size=1))
    assert [r.work_item_id for r in reports] == sorted(i.id for i in items)
    assert reports[0].drift and all(not r.drift for r in reports[1:])
    result = cli(dsn, schema, ["replay"])
    assert result.returncode == 1 and "malformed" in result.stdout
    assert "Traceback" not in result.stderr
    assert all(str(item.id) in result.stdout for item in items)


@pytest.mark.parametrize("kind", ["integer", "nesting"])
def test_workflow_decoder_error_type_a5(kind: str) -> None:
    raw = ("9" * 10000 if kind == "integer" else "[" * 1100 + "0" + "]" * 1100)
    try:
        json.loads(raw)
    except (ValueError, RecursionError):
        with pytest.raises(InvalidWorkflowError, match="cannot parse workflow"):
            parse_workflow_document(raw, format="json")
    else:
        # CPython 3.14's iterative decoder accepts this nesting; the document
        # validator still refuses it, while 3.11 refuses during decoding.
        with pytest.raises(InvalidWorkflowError):
            Workflow.from_document(parse_workflow_document(raw, format="json"))
    assert parse_workflow_document("{}", format="json") == {}
