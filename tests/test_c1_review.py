"""Failing-first regressions for the final Daybreak Blue review."""
from __future__ import annotations

import inspect
import json
import threading
import tracemalloc
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import psycopg
import pytest
from psycopg.rows import dict_row
from psycopg.sql import SQL, Identifier
from test_f1_cli import cli

from regista import InvalidFieldError, Kernel, LeaseExpiredError, UnsupportedSchemaError, Workflow


@pytest.mark.parametrize("name", ["$user", "pg_temp", "pg_temp_42", "pg_toast",
                                  "pg_toast_temp_42", "pg_catalog", "information_schema"])
def test_special_namespace_refused(dsn: str, name: str) -> None:
    with pytest.raises(InvalidFieldError, match=r"reserved.*schema"):
        handle = Kernel.connect(dsn, schema=name)
        handle.close()


def test_namespace_resolution_verified(kernel: Kernel, dsn: str, schema: str) -> None:
    with psycopg.connect(dsn, row_factory=dict_row) as conn:
        conn.execute("SET search_path TO pg_catalog")
        with pytest.raises(UnsupportedSchemaError, match="namespace"):
            kernel._verify_namespace(conn)


def test_initializer_has_no_sql_path(kernel: Kernel, tmp_path: Path) -> None:
    assert list(inspect.signature(Kernel.initialize).parameters) == ["self"]
    poison = tmp_path / "poison.sql"
    poison.write_text("DROP SCHEMA public CASCADE")
    with pytest.raises(TypeError):
        kernel.initialize(schema_sql_path=str(poison))


@pytest.mark.parametrize("damage", ["counterfeit", "partial", "extra", "index", "column",
                                   "constraint", "function", "type"])
def test_baseline_manifest_refuses_before_write(
    kernel: Kernel, dsn: str, schema: str, workflow: Workflow, damage: str,
) -> None:
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("SET search_path TO {}").format(Identifier(schema)))
        statements = {
            "counterfeit": "DROP TABLE work_items_current CASCADE; CREATE TABLE business(v text); "
                           "INSERT INTO business VALUES ('preserve')",
            "partial": "DROP TABLE links",
            "extra": "CREATE TABLE business(v text); INSERT INTO business VALUES ('preserve')",
            "index": "DROP INDEX idx_wic_state",
            "column": "ALTER TABLE workflow_registry ADD COLUMN counterfeit text",
            "constraint": "ALTER TABLE links DROP CONSTRAINT links_no_self",
            "function": "CREATE FUNCTION foreign_function() RETURNS int LANGUAGE sql "
                        "AS $$ SELECT 1 $$",
            "type": "CREATE TYPE foreign_type AS ENUM ('a')",
        }
        conn.execute(statements[damage])
        before = conn.execute("SELECT * FROM workflow_registry").fetchall()
    for action in [kernel.initialize, lambda: kernel.register_workflow(workflow)]:
        with pytest.raises(UnsupportedSchemaError, match="baseline"):
            action()
    with psycopg.connect(dsn) as conn:
        assert conn.execute(SQL("SELECT * FROM {}.workflow_registry").format(
            Identifier(schema))).fetchall() == before
    with pytest.raises(UnsupportedSchemaError, match="baseline"):
        Kernel.connect(dsn, schema=schema)


def test_release_expired_preserves_fence(registered: Kernel, dsn: str, schema: str) -> None:
    item = registered.create_work_item(workflow="review", type="task", actor_id="worker")
    held = registered.claim(item.id, actor_id="worker")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("UPDATE {}.claims SET expires_at=clock_timestamp()-interval '1 second'")
                     .format(Identifier(schema)))
    registered.release(item.id, actor_id="worker", attempt=held.attempt)
    assert registered.lease(item.id) is not None
    assert not registered.lease(item.id).live
    with pytest.raises(LeaseExpiredError):
        registered.transition(item.id, transition="start", actor_id="worker")


def test_release_drains_transition(registered: Kernel, monkeypatch: pytest.MonkeyPatch) -> None:
    item = registered.create_work_item(workflow="review", type="task", actor_id="w")
    held = registered.claim(item.id, actor_id="w")
    entered, resume, releasing, released = [threading.Event() for _ in range(4)]
    original = Kernel._append_event

    def pause(self: Kernel, *args: Any, **kw: Any) -> Any:
        entered.set()
        assert resume.wait(10)
        return original(self, *args, **kw)

    def release() -> None:
        releasing.set()
        registered.release(item.id, actor_id="w", attempt=held.attempt)
        released.set()

    monkeypatch.setattr(Kernel, "_append_event", pause)
    with ThreadPoolExecutor(2) as pool:
        writer = pool.submit(registered.transition, item.id, transition="start",
                             actor_id="w", attempt=held.attempt)
        try:
            assert entered.wait(10)
            drain = pool.submit(release)
            assert releasing.wait(10)
            assert not released.wait(0.25), "release returned before the fenced writer committed"
        finally:
            resume.set()
        assert writer.result(10).state == "doing"
        drain.result(10)
    assert registered.get(item.id).state == "doing"
    assert registered.lease(item.id) is None


def test_unlink_retry_and_concurrent_noop(registered: Kernel) -> None:
    a, b = [registered.create_work_item(workflow="review", type="task", actor_id="w")
            for _ in range(2)]
    registered.link(a.id, b.id, "blocks")
    with ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(registered.remove_link, a.id, b.id, "blocks") for _ in range(2)]
        for future in futures:
            future.result(10)
    registered.remove_link(a.id, b.id, "blocks")
    assert registered.links_from(a.id) == []


@pytest.mark.parametrize("rehash", [False, True])
def test_replay_pinned_transition_semantics(
    registered: Kernel, dsn: str, schema: str, rehash: bool,
) -> None:
    import regista.kernel as implementation

    item = registered.create_work_item(workflow="review", type="task", actor_id="w")
    registered.transition(item.id, transition="start", actor_id="w")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("UPDATE {}.events SET transition='edit' WHERE event_seq=1").format(
            Identifier(schema)))
        if rehash:
            payload = conn.execute(SQL("SELECT payload FROM {}.events WHERE event_seq=1").format(
                Identifier(schema))).fetchone()[0]
            digest = implementation._event_digest("edit", payload)
            conn.execute(SQL("UPDATE {}.events SET payload_hash=%s WHERE event_seq=1").format(
                Identifier(schema)), (digest,))
    drift = registered.replay(item.id)[2]
    assert any("source" in line for line in drift), drift
    if not rehash:
        assert any("hash" in line for line in drift), drift


def test_retry_memory_is_bounded(registered: Kernel) -> None:
    item = registered.create_work_item(workflow="review", type="task", actor_id="w")
    registered.transition(item.id, transition="start", actor_id="w")
    payload = {"text": "x" * 8192}
    for _ in range(600):
        registered.transition(item.id, transition="edit", actor_id="w", payload=payload)
    result = registered.transition(item.id, transition="edit", actor_id="w",
                                   payload=payload, idempotency_key="retry-memory")
    tracemalloc.start()
    try:
        assert registered.transition(item.id, transition="edit", actor_id="w",
                                     payload=payload, idempotency_key="retry-memory") == result
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 2_000_000, f"retry peak {peak} exceeds bounded cursor budget"


@pytest.mark.parametrize("as_json", [False, True])
@pytest.mark.parametrize("bad", ["uuid", "field", "integer", "depth"])
def test_cli_malformed_refusal(registered: Kernel, dsn: str, schema: str,
                               as_json: bool, bad: str) -> None:
    args = ["show", "not-a-uuid"] if bad == "uuid" else [
        "create", "--workflow", "review", "--type", "task", "--actor", "w", "--field",
        {"field": "missing_equals", "integer": "n=" + "9" * 5000,
         "depth": "n=" + "[" * 2000 + "0" + "]" * 2000}.get(bad, ""),
    ]
    result = cli(dsn, schema, args, as_json=as_json)
    assert result.returncode == 2, result.stderr
    assert "Traceback" not in result.stderr
    assert result.stderr.startswith("refused: "), result.stderr
    if as_json:
        body = json.loads(result.stdout)
        assert body["exit_code"] == 2 and body["error"] and body["message"]
    else:
        assert result.stdout == ""


@pytest.mark.parametrize("command", ["history", "show", "list", "lease", "health"])
def test_cli_human_controls_escaped(registered: Kernel, dsn: str, schema: str,
                                   command: str) -> None:
    hostile = "attacker\nFORGED\x1b[31m\x7f\x85\u202e"
    item = registered.create_work_item(workflow="review", type="task", actor_id=hostile,
                                       fields={"note": hostile})
    registered.claim(item.id, actor_id=hostile)
    args = [command] + ([str(item.id)] if command in ("history", "show", "lease") else [])
    result = cli(dsn, schema, args, as_json=False)
    assert result.returncode == 0, result.stderr
    assert "\nFORGED" not in result.stdout
    assert not any(c in result.stdout for c in ("\x1b", "\x7f", "\x85", "\u202e"))
    if command != "health":
        assert "\\nFORGED" in result.stdout
    json_result = cli(dsn, schema, args, as_json=True)
    assert json_result.returncode == 0
    if command == "history":
        assert json.loads(json_result.stdout)[0]["actor"] == hostile


def test_namespace_tampering_refuses_operation(
    registered: Kernel, monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = psycopg.Connection.execute

    def tamper(conn: Any, query: Any, *args: Any, **kw: Any) -> Any:
        text = query.as_string(conn) if hasattr(query, "as_string") else str(query)
        if text.startswith("SET LOCAL search_path"):
            query = "SET LOCAL search_path TO pg_catalog"
        return original(conn, query, *args, **kw)

    monkeypatch.setattr(psycopg.Connection, "execute", tamper)
    with pytest.raises(UnsupportedSchemaError, match="namespace"):
        registered.create_work_item(workflow="review", type="task", actor_id="w")


def test_replay_pinned_destination(
    registered: Kernel, workflow: Workflow, dsn: str, schema: str,
) -> None:
    from dataclasses import replace

    import regista.kernel as implementation

    item = registered.create_work_item(workflow="review", type="task", actor_id="w")
    registered.transition(item.id, transition="start", actor_id="w")
    # A later version would permit the corrupted destination; the item is pinned to v1.
    registered.register_workflow(replace(workflow, transitions={
        **workflow.transitions, "start": (("new", "changes"), "review"),
    }))
    payload = {"from": "new", "to": "review", "fields": {}}
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("UPDATE {}.events SET payload=%s, payload_hash=%s WHERE event_seq=1")
                     .format(Identifier(schema)),
                     (psycopg.types.json.Jsonb(payload),
                      implementation._event_digest("start", payload)))
        conn.execute(SQL("UPDATE {}.work_items_current SET current_state='review'")
                     .format(Identifier(schema)))
    assert any("destination" in line for line in registered.replay(item.id)[2])


def test_cli_uuid_arguments_are_typed() -> None:
    import uuid

    from regista.cli import build_parser

    value = uuid.uuid4()
    args = build_parser().parse_args(["show", str(value)])
    assert args.id == value


def test_cli_recursion_limit_refusal(monkeypatch: pytest.MonkeyPatch) -> None:
    # Python 3.11's JSON decoder raises for deeply nested input; 3.14's
    # decoder parses it and the kernel depth limit refuses it instead.
    import regista.cli as commands

    def parser_limit(value: str) -> Any:
        raise RecursionError("JSON parser nesting limit")

    monkeypatch.setattr(commands.json, "loads", parser_limit)
    with pytest.raises(InvalidFieldError, match="parser limits"):
        commands._fields(["value=[]"])


@pytest.mark.parametrize("damage", ["disabled_fk", "inherited_child"])
def test_baseline_enforcement_and_inheritance(
    registered: Kernel, dsn: str, schema: str, damage: str,
    schema_factory: Any,
) -> None:
    sibling = schema_factory()
    with psycopg.connect(dsn, autocommit=True) as conn:
        if damage == "disabled_fk":
            conn.execute(SQL("ALTER TABLE {}.links DISABLE TRIGGER ALL").format(Identifier(schema)))
        else:
            conn.execute(SQL("CREATE TABLE {}.foreign_child () INHERITS ({}.work_items_current)")
                         .format(Identifier(sibling), Identifier(schema)))
    with pytest.raises(UnsupportedSchemaError, match="baseline"):
        registered.create_work_item(workflow="review", type="task", actor_id="w")
    assert registered.health()["work_items"] == 0


def test_admission_never_calls_destination_catalog_helper(
    registered: Kernel, dsn: str, schema: str,
) -> None:
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL(
            "CREATE FUNCTION {}.jsonb_build_object(text,bigint,text,jsonb,text,jsonb) "
            "RETURNS jsonb "
            "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'untrusted helper called'; END $$"
        ).format(Identifier(schema)))
    with pytest.raises(UnsupportedSchemaError, match="baseline"):
        registered.create_work_item(workflow="review", type="task", actor_id="w")


@pytest.mark.parametrize("command", [["replay", "--dsn"],
                                      ["workflow", "show", "replay", "--dsn"]])
def test_preliminary_cli_parser_refusal(command: list[str], capsys: Any) -> None:
    from regista.cli import main

    assert main(["--json", *command]) == 2
    out = capsys.readouterr()
    assert out.err.startswith("refused: ")
    assert json.loads(out.out)["exit_code"] == 2


def test_initialize_precreated_owner_without_database_create(dsn: str, schema: str) -> None:
    role = schema + "_owner"
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("CREATE ROLE {} NOLOGIN").format(Identifier(role)))
        conn.execute(
            SQL("ALTER SCHEMA {} OWNER TO {}").format(Identifier(schema), Identifier(role))
        )
    try:
        restricted = psycopg.conninfo.make_conninfo(dsn, options=f"-c role={role}")
        handle = Kernel.connect(restricted, schema=schema)
        try:
            handle.initialize()
            assert handle.health()["schema_version"] == 1
        finally:
            handle.close()
    finally:
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(SQL("DROP OWNED BY {} CASCADE").format(Identifier(role)))
            conn.execute(SQL("DROP ROLE {}").format(Identifier(role)))


def test_malformed_marker_is_unsupported(dsn: str, schema: str) -> None:
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(SQL("CREATE TABLE {}.kernel_meta(unrelated int)").format(Identifier(schema)))
    with pytest.raises(UnsupportedSchemaError, match="baseline"):
        Kernel.connect(dsn, schema=schema)
