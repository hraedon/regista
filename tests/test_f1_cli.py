from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import psycopg
import pytest
from psycopg.sql import SQL, Identifier

from regista import Kernel, Workflow

ROOT = Path(os.environ.get("REGISTA_KERNEL_TEST_ROOT", Path(__file__).parents[1] / "src"))


def cli(
    dsn: str, schema: str, args: list[str], as_json: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m", "regista.cli",
            "--dsn",
            dsn,
            "--schema",
            schema,
            *(["--json"] if as_json else []),
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )


@pytest.mark.parametrize(
    "command",
    [
        "init",
        "health",
        "workflow_validate",
        "workflow_register",
        "workflow_list",
        "workflow_show",
        "create",
        "show",
        "list",
        "claim",
        "heartbeat",
        "lease",
        "release",
        "transition",
        "link",
        "history",
        "check-history",
        "expire_leases",
    ],
)
@pytest.mark.parametrize("as_json", [False, True])
def test_each_command(
    registered: Kernel,
    workflow: Workflow,
    dsn: str,
    schema: str,
    tmp_path: Path,
    command: str,
    as_json: bool,
) -> None:
    path = tmp_path / "workflow.json"
    path.write_text(json.dumps(workflow.as_document()))
    item = registered.create_work_item(
        workflow="review", type="task", actor_id="w", fields={"discard": 1}
    )
    other = registered.create_work_item(workflow="review", type="task", actor_id="w")
    if command in ("heartbeat", "release", "lease"):
        registered.claim(item.id, actor_id="w")
    if command == "expire_leases":
        registered.claim(item.id, actor_id="w")
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(
                SQL(
                    "UPDATE {}.claims SET expires_at=clock_timestamp()-interval '1 second' "
                    "WHERE work_item_id=%s"
                ).format(Identifier(schema)),
                (item.id,),
            )
    commands = {
        "init": ["init"],
        "health": ["health"],
        "workflow_validate": ["workflow", "validate", "--file", str(path)],
        "workflow_register": ["workflow", "register", "--file", str(path)],
        "workflow_list": ["workflow", "list"],
        "workflow_show": ["workflow", "show", "review"],
        "create": [
            "create",
            "--workflow",
            "review",
            "--type",
            "task",
            "--actor",
            "cli",
            "--actor-kind",
            "human",
            "--field",
            "title=created",
        ],
        "show": ["show", str(item.id)],
        "list": ["list"],
        "claim": ["claim", str(item.id), "--actor", "w"],
        "heartbeat": ["heartbeat", str(item.id), "--actor", "w", "--attempt", "1", "--ttl", "600"],
        "lease": ["lease", str(item.id)],
        "release": ["release", str(item.id), "--actor", "w", "--attempt", "1"],
        "transition": [
            "transition",
            str(item.id),
            "--actor",
            "w",
            "--transition",
            "start",
            "--unset-field",
            "discard",
        ],
        "link": ["link", str(item.id), str(other.id), "--type", "blocks"],
        "history": ["history", str(item.id)],
        "check-history": ["check-history", str(item.id)],
        "expire_leases": ["expire-leases", str(item.id)],
    }
    result = cli(dsn, schema, commands[command], as_json)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stderr == ""
    if as_json:
        body = json.loads(result.stdout)  # also proves no logging on stdout
        if command == "health":
            assert body["work_items"] == 2 and body["events"] == 2
            assert body["schema_version"] == 1
        elif command == "show":
            assert body["id"] == str(item.id) and body["state"] == "new"
            assert body["workflow"] == "review v1"
        elif command == "check-history":
            assert body == {"state": "new", "fields": {"discard": 1}, "drift": []}
        elif command == "init":
            assert body == {"schema": schema, "status": "ready"}
        elif command == "workflow_validate":
            assert body["valid"] is True and body["workflow"] == "review"
        elif command == "workflow_register":
            assert body == {"workflow": "review", "version": 1}
        elif command == "workflow_list":
            assert [(r["name"], r["version"]) for r in body] == [("review", 1)]
        elif command == "workflow_show":
            assert (
                body["name"] == "review"
                and body["transitions"] == workflow.as_json()["transitions"]
            )
        elif command == "list":
            assert [r["id"] for r in body] == [str(item.id), str(other.id)]
        elif command == "history":
            assert len(body) == 1 and body[0]["seq"] == 0 and body[0]["actor"] == "w"
        elif command == "lease":
            assert body["actor"] == "w" and body["attempt"] == 1 and body["live"] is True
        elif command == "expire_leases":
            assert body["swept"] == 1
    else:
        assert result.stdout.strip()
        if command in ("workflow_validate", "workflow_register", "workflow_list", "workflow_show"):
            assert "review" in result.stdout
        if command in ("show", "list"):
            assert "review v1" in result.stdout
        if command == "history":
            assert "created" in result.stdout and "w (agent)" in result.stdout
        if command == "list":
            assert str(item.id) in result.stdout and str(other.id) in result.stdout
    if command == "create":
        new = registered.list_items()[-1]
        assert new.fields == {"title": "created"}
        assert registered.history(new.id)[0].actor_kind == "human"
    elif command == "transition":
        assert registered.get(item.id).state == "doing" and registered.get(item.id).fields == {}
    elif command in ("claim", "heartbeat"):
        held = registered.lease(item.id)
        assert held and held.actor_id == "w" and held.attempt == 1
    elif command in ("release", "expire_leases"):
        assert registered.lease(item.id) is None
    elif command == "link":
        assert registered.links_from(item.id) == [(other.id, "blocks")]


@pytest.mark.parametrize(
    "case",
    [
        "show",
        "workflow_show",
        "create",
        "claim",
        "heartbeat",
        "transition",
        "link",
        "limit",
        "cursor",
        "blocked",
        "unknown_command",
        "missing_argument",
        "legacy_verb",
        "invalid_workflow",
        "malformed_yaml",
    ],
)
@pytest.mark.parametrize("as_json", [False, True])
def test_cli_refusal_audit(
    registered: Kernel, dsn: str, schema: str, tmp_path: Path, case: str, as_json: bool
) -> None:
    missing = str(uuid.uuid4())
    path = tmp_path / "invalid.yaml"
    path.write_text("name: [" if case == "malformed_yaml" else "kernel_workflow: 999\n")
    commands = {
        "show": ["show", missing],
        "workflow_show": ["workflow", "show", "missing"],
        "create": ["create", "--workflow", "missing", "--type", "task", "--actor", "w"],
        "claim": ["claim", missing, "--actor", "w"],
        "heartbeat": ["heartbeat", missing, "--actor", "w", "--attempt", "1"],
        "transition": ["transition", missing, "--transition", "start", "--actor", "w"],
        "link": ["link", missing, str(uuid.uuid4()), "--type", "blocks"],
        "limit": ["list", "--limit", "0"],
        "cursor": ["list", "--after", missing],
        "blocked": ["list", "--blocked-by", "blocks"],
        "unknown_command": ["nonsense"],
        "missing_argument": ["show"],
        "legacy_verb": ["trust"],
        "invalid_workflow": ["workflow", "validate", "--file", str(path)],
        "malformed_yaml": ["workflow", "validate", "--file", str(path)],
    }
    result = cli(dsn, schema, commands[case], as_json)
    assert result.returncode != 0
    assert "Traceback" not in result.stderr
    assert registered.health()["events"] == 0
    if as_json and result.stdout:
        body = json.loads(result.stdout)
        assert body.get("valid") is False or body.get("exit_code") == result.returncode


def test_cli_drift_nonzero(registered: Kernel, dsn: str, schema: str) -> None:
    item = registered.create_work_item(workflow="review", type="task", actor_id="w")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            SQL(
                "UPDATE {}.work_items_current SET current_state='doing' WHERE work_item_id=%s"
            ).format(Identifier(schema)),
            (item.id,),
        )
    for as_json in (False, True):
        result = cli(dsn, schema, ["check-history", str(item.id)], as_json)
        assert result.returncode == 1
        if as_json:
            assert json.loads(result.stdout)["drift"]
        else:
            assert "projection says" in result.stdout


@pytest.mark.parametrize("as_json", [False, True])
def test_cli_chain_break_nonzero(registered: Kernel, dsn: str, schema: str, as_json: bool) -> None:
    item = registered.create_work_item(workflow="review", type="task", actor_id="w")
    registered.transition(item.id, transition="start", actor_id="w")
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            SQL("UPDATE {}.events SET prev_event_hash='\\x01' "
                "WHERE work_item_id=%s AND event_seq=1").format(Identifier(schema)), (item.id,),
        )
    result = cli(dsn, schema, ["check-history", str(item.id)], as_json)
    assert result.returncode == 1 and result.stderr == ""
    message = "event 1: chain link does not match predecessor"
    if as_json:
        assert json.loads(result.stdout)["drift"] == [message]
    else:
        assert message in result.stdout
    assert registered.get(item.id).state == "doing"


@pytest.mark.parametrize("extension", ["json", "yaml"])
@pytest.mark.parametrize("as_json", [False, True])
def test_cli_invalid_utf8_workflow(
    dsn: str, schema: str, tmp_path: Path, extension: str, as_json: bool,
) -> None:
    path = tmp_path / f"bad.{extension}"
    path.write_bytes(b"\xff")
    result = cli(dsn, schema, ["workflow", "validate", "--file", str(path)], as_json)
    assert result.returncode == 1 and result.stderr == ""
    assert "UnicodeDecodeError" in result.stdout
    if as_json:
        body = json.loads(result.stdout)
        assert body["valid"] is False and len(body["problems"]) == 1


def test_cli_listing_modes_and_pages(registered: Kernel, dsn: str, schema: str) -> None:
    items = [
        registered.create_work_item(workflow="review", type="task", actor_id="w", fields={"n": i})
        for i in range(3)
    ]
    registered.claim(items[0].id, actor_id="owner")
    registered.link(items[1].id, items[2].id, "blocks")
    for args, expected in [
        ([], items),
        (["--available"], items[1:]),
        (["--owned", "owner"], items[:1]),
        (["--state", "review"], []),
        (["--field", "n=1"], items[1:2]),
        (["--blocked-by", "blocks", "--satisfied", "done"], items[2:]),
    ]:
        result = cli(dsn, schema, ["list", *args])
        assert result.returncode == 0, result.stderr
        assert [r["id"] for r in json.loads(result.stdout)] == [str(i.id) for i in expected]
    first = cli(dsn, schema, ["list", "--limit", "1"], False)
    assert "more may exist" in first.stdout and str(items[0].id) in first.stdout
    after = cli(dsn, schema, ["list", "--limit", "2", "--after", str(items[0].id)])
    assert [r["id"] for r in json.loads(after.stdout)] == [str(i.id) for i in items[1:]]


@pytest.mark.parametrize("as_json", [False, True])
def test_cli_unreachable_database(schema: str, as_json: bool) -> None:
    result = cli(
        "postgresql://invalid:sentinel-secret@127.0.0.1:1/missing?connect_timeout=1",
        schema,
        ["health"],
        as_json,
    )
    assert result.returncode == 2
    assert "Traceback" not in result.stderr and "sentinel-secret" not in result.stderr
    assert "sentinel-secret" not in result.stdout
    if as_json:
        assert json.loads(result.stdout)["exit_code"] == 2


@pytest.mark.parametrize("as_json", [False, True])
def test_cli_unlink(registered: Kernel, dsn: str, schema: str, as_json: bool) -> None:
    a = registered.create_work_item(workflow="review", type="task", actor_id="w")
    b = registered.create_work_item(workflow="review", type="task", actor_id="w")
    registered.link(a.id, b.id, "blocks")
    result = cli(dsn, schema, ["unlink", str(a.id), str(b.id), "--type", "blocks"], as_json)
    assert result.returncode == 0 and registered.links_from(a.id) == []
    missing = cli(dsn, schema, ["unlink", str(a.id), str(b.id), "--type", "blocks"], as_json)
    assert missing.returncode == 2


def test_cli_fresh_init(dsn: str, schema: str) -> None:
    result = cli(dsn, schema, ["init"])
    assert result.returncode == 0 and json.loads(result.stdout)["status"] == "ready"
    opened = Kernel.connect(dsn, schema=schema)
    try:
        assert opened.health()["schema_version"] == 1
    finally:
        opened.close()


def test_cli_new_workflow(
    kernel: Kernel, workflow: Workflow, dsn: str, schema: str, tmp_path: Path
) -> None:
    path = tmp_path / "workflow.json"
    path.write_text(json.dumps(workflow.as_document()))
    result = cli(dsn, schema, ["workflow", "register", "--file", str(path)])
    assert result.returncode == 0 and json.loads(result.stdout)["version"] == 1
    assert kernel.get_workflow("review").as_json() == workflow.as_json()


@pytest.mark.parametrize(
    "command", ["init", "health", "show", "history", "check-history", "workflow_list", "claim"]
)
@pytest.mark.parametrize("as_json", [False, True])
def test_cli_missing_dsn(schema: str, command: str, as_json: bool) -> None:
    missing = str(uuid.uuid4())
    args = {"workflow_list": ["workflow", "list"], "claim": ["claim", missing, "--actor", "w"]}.get(
        command, [command] if command in ("init", "health") else [command, missing]
    )
    env = dict(os.environ)
    env.pop("REGISTA_DSN", None)
    result = subprocess.run(
        [
            sys.executable,
            "-m", "regista.cli",
            "--schema",
            schema,
            *(["--json"] if as_json else []),
            *args,
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 2
    assert "no DSN" in result.stderr and "Traceback" not in result.stderr
    if as_json:
        assert json.loads(result.stdout)["exit_code"] == 2


@pytest.mark.parametrize("destination", ["missing", "empty"])
@pytest.mark.parametrize("command", ["health", "list", "workflow_list", "workflow_show",
                                     "show", "history", "check-history", "lease"])
def test_cli_inspection_requires_existing(
    dsn: str, schema: str, destination: str, command: str,
) -> None:
    if destination == "missing":
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(SQL("DROP SCHEMA {}").format(Identifier(schema)))
    args = {
        "workflow_list": ["workflow", "list"],
        "workflow_show": ["workflow", "show", "review"],
        "health": ["health"], "list": ["list"],
    }.get(command, [command, str(uuid.uuid4())])
    result = cli(dsn, schema, args)
    assert result.returncode == 2 and "Traceback" not in result.stderr
    assert json.loads(result.stdout)["error"] == "UnsupportedSchemaError"
    with psycopg.connect(dsn) as conn:
        assert conn.execute(
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname=%s", (schema,),
        ).fetchone() == (0,)
        assert conn.execute(
            "SELECT count(*) FROM pg_namespace WHERE nspname=%s", (schema,),
        ).fetchone() == ((0,) if destination == "missing" else (1,))


def test_old_replay_command_refuses(dsn: str, schema: str) -> None:
    result = cli(dsn, schema, ["replay"])
    assert result.returncode == 2
    assert "old replay command rebuilt projections" in result.stderr
    assert "check-history" in result.stderr
    assert "Traceback" not in result.stderr
