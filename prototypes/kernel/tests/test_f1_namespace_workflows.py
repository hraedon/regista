from __future__ import annotations

import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import psycopg
import pytest
import yaml
from kernel import (
    DatabaseOperationError,
    InvalidWorkflowError,
    Kernel,
    UnsupportedSchemaError,
    Workflow,
    load_workflow,
    validate_workflow_document,
)
from psycopg.sql import SQL, Identifier

ROOT = Path(__file__).parents[1]


def test_namespace_isolation(
    registered: Kernel, dsn: str, schema_factory: Callable[[], str], workflow: Workflow
) -> None:
    other = schema_factory()
    sibling = Kernel.connect(dsn, schema=other)
    try:
        sibling.initialize(str(ROOT / "schema.sql"))
        sibling.register_workflow(workflow)
        a = registered.create_work_item(workflow="review", type="task", actor_id="w")
        b = sibling.create_work_item(workflow="review", type="task", actor_id="w")
        assert registered.list_items() == [a] and sibling.list_items() == [b]
        registered.transition(a.id, transition="start", actor_id="w")
        assert sibling.get(b.id) == b and sibling.replay(b.id) == ("new", {}, [])
        assert registered.history(b.id) == []
    finally:
        sibling.close()


def test_supplied_schema_cannot_redirect(registered: Kernel, dsn: str, schema: str) -> None:
    item = registered.create_work_item(workflow="review", type="task", actor_id="w")
    malicious = Kernel.connect(dsn, schema=f"absent_{schema}, {schema}")
    try:
        with pytest.raises(DatabaseOperationError):
            malicious.initialize(str(ROOT / "schema.sql"))
        with pytest.raises(DatabaseOperationError):
            malicious.list_items()
    finally:
        malicious.close()
    assert registered.get(item.id) == item and len(registered.history(item.id)) == 1


def test_supplied_workflow_name_is_data(registered: Kernel) -> None:
    with pytest.raises(InvalidWorkflowError):
        registered.create_work_item(
            workflow="review'; DROP TABLE events; --", type="task", actor_id="w"
        )
    assert registered.health()["events"] == 0 and len(registered.list_workflows()) == 1


def test_concurrent_initialize(dsn: str, schema: str) -> None:
    def initialize(_: int) -> int:
        k = Kernel.connect(dsn, schema=schema)
        try:
            k.initialize(str(ROOT / "schema.sql"))
            return int(k.health()["schema_version"])
        finally:
            k.close()

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(initialize, range(8))) == [1] * 8


def test_catalog_roundtrip(dsn: str, schema_factory: Callable[[], str]) -> None:
    # The kernel's catalog equivalent is pg_namespace + its per-schema kernel_meta.
    for _ in range(3):
        name = schema_factory()
        k = Kernel.connect(dsn, schema=name)
        try:
            k.initialize(str(ROOT / "schema.sql"))
            k.initialize(str(ROOT / "schema.sql"))
            assert k.health()["schema_version"] == 1
        finally:
            k.close()
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute(SQL("DROP SCHEMA {} CASCADE").format(Identifier(name)))
            conn.execute(SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(Identifier(name)))
            assert conn.execute(
                "SELECT count(*) FROM pg_namespace WHERE nspname = %s", (name,)
            ).fetchone() == (0,)
            assert conn.execute(
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "WHERE n.nspname = %s",
                (name,),
            ).fetchone() == (0,)


@pytest.mark.parametrize("kind", ["legacy", "unknown", "version", "empty_meta"])
def test_initialize_refuses_without_writes(dsn: str, schema: str, kind: str) -> None:
    k = Kernel.connect(dsn, schema=schema)
    try:
        with psycopg.connect(dsn, autocommit=True) as conn:
            if kind in ("version", "empty_meta"):
                k.initialize(str(ROOT / "schema.sql"))
                if kind == "version":
                    conn.execute(
                        SQL("UPDATE {}.kernel_meta SET kernel_schema_version=999").format(
                            Identifier(schema)
                        )
                    )
                else:
                    conn.execute(SQL("DELETE FROM {}.kernel_meta").format(Identifier(schema)))
            else:
                table = "project_identity" if kind == "legacy" else "unrelated"
                conn.execute(
                    SQL("CREATE TABLE {}.{} (sentinel text)").format(
                        Identifier(schema), Identifier(table)
                    )
                )
                conn.execute(
                    SQL("INSERT INTO {}.{} VALUES ('preserve')").format(
                        Identifier(schema), Identifier(table)
                    )
                )
            before = conn.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema=%s "
                "ORDER BY table_name",
                (schema,),
            ).fetchall()
        with pytest.raises(UnsupportedSchemaError):
            k.initialize(str(ROOT / "schema.sql"))
        with psycopg.connect(dsn) as conn:
            assert (
                conn.execute(
                    "SELECT table_name FROM information_schema.tables WHERE table_schema=%s "
                    "ORDER BY table_name",
                    (schema,),
                ).fetchall()
                == before
            )
            if kind in ("legacy", "unknown"):
                assert conn.execute(
                    SQL("SELECT sentinel FROM {}.{}").format(Identifier(schema), Identifier(table))
                ).fetchone() == ("preserve",)
    finally:
        k.close()


@pytest.mark.parametrize(
    "case",
    [
        "name",
        "states",
        "initial",
        "unknown_from",
        "unknown_to",
        "unreachable",
        "undeclared_role",
        "unused_role",
        "duplicate_state",
        "duplicate_transition",
        "format_version",
    ],
)
def test_document_semantic_refusals(kernel: Kernel, workflow: Workflow, case: str) -> None:
    doc = workflow.as_document()
    if case in ("name", "states"):
        del doc[case]
    elif case == "initial":
        doc["states"][0].pop("initial")
    elif case in ("unknown_from", "unknown_to"):
        doc["transitions"][0]["from" if case == "unknown_from" else "to"] = "missing"
    elif case == "unreachable":
        doc["states"].append({"name": "orphan"})
    elif case == "undeclared_role":
        doc["transitions"][-2]["roles"] = ["typo"]
    elif case == "unused_role":
        doc["roles"].append("unused")
    elif case == "duplicate_state":
        doc["states"].append(doc["states"][0])
    elif case == "duplicate_transition":
        doc["transitions"].append(doc["transitions"][0])
    else:
        doc["kernel_workflow"] = 999
    errors = validate_workflow_document(doc)
    assert errors and all(isinstance(e, str) for e in errors)
    with pytest.raises(InvalidWorkflowError):
        kernel.register_workflow(Workflow.from_document(doc))
    assert kernel.list_workflows() == []


@pytest.mark.parametrize("format", ["yaml", "json"])
def test_document_load_roundtrip(
    kernel: Kernel, workflow: Workflow, tmp_path: Path, format: str
) -> None:
    path = tmp_path / f"workflow.{format}"
    doc = workflow.as_document()
    path.write_text(yaml.safe_dump(doc) if format == "yaml" else json.dumps(doc))
    loaded = load_workflow(str(path))
    assert loaded == workflow
    assert validate_workflow_document(loaded.as_document()) == ()
    assert kernel.register_workflow(loaded) == 1


@pytest.mark.parametrize("case", ["syntax", "duplicate", "empty", "extension"])
def test_load_refusals(tmp_path: Path, workflow: Workflow, case: str) -> None:
    path = tmp_path / ("workflow.txt" if case == "extension" else "workflow.yaml")
    path.write_text(
        {
            "syntax": "name: [",
            "duplicate": yaml.safe_dump(workflow.as_document()) + "name: second\n",
            "empty": "",
            "extension": yaml.safe_dump(workflow.as_document()),
        }[case]
    )
    with pytest.raises(InvalidWorkflowError):
        load_workflow(str(path))
