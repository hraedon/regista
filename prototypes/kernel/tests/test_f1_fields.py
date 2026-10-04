from __future__ import annotations

import uuid
from typing import Any, cast

import pytest
from kernel import InvalidFieldError, InvalidWorkflowError, Kernel, Workflow

SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["title"],
    "properties": {
        "title": {"type": "string", "minLength": 1},
        "priority": {"type": "string", "enum": ["high", "low"]},
        "count": {"type": "integer"},
        "metadata": {"type": "object"},
        "ref": {"type": ["string", "null"], "work_item_ref": ["source", "review"]},
        "any_ref": {"type": ["string", "null"], "work_item_ref": []},
    },
}


def strict_workflow(workflow: Workflow) -> Workflow:
    # Public document front door, so an unenforced/unknown declaration fails too.
    doc = workflow.as_document()
    doc["field_schemas"] = {"task": SCHEMA}
    return Workflow.from_document(doc)


@pytest.mark.parametrize("phase", ["create", "transition"])
@pytest.mark.parametrize("case", ["required", "unknown", "type", "enum"])
def test_declared_field_refusals(kernel: Kernel, workflow: Workflow, phase: str, case: str) -> None:
    kernel.register_workflow(strict_workflow(workflow))
    fields = cast(
        dict[str, Any],
        {
            "required": {},
            "unknown": {"title": "x", "typo": 1},
            "type": {"title": 3},
            "enum": {"title": "x", "priority": "urgent"},
        }[case],
    )
    item = kernel.create_work_item(
        workflow="review", type="task", actor_id="w", fields={"title": "old"}
    )
    before = kernel.get(item.id), kernel.history(item.id), kernel.health()["work_items"]
    with pytest.raises(InvalidFieldError):
        if phase == "create":
            kernel.create_work_item(workflow="review", type="task", actor_id="w", fields=fields)
        else:
            kernel.transition(
                item.id,
                transition="start",
                actor_id="w",
                fields=fields,
                unset_fields=("title",) if case == "required" else (),
            )
    assert (kernel.get(item.id), kernel.history(item.id), kernel.health()["work_items"]) == before


@pytest.mark.parametrize("phase", ["create", "transition"])
@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "wrong_type",
        "invalid_uuid",
        "valid_source",
        "valid_review",
        "null",
        "untyped",
        "untyped_missing",
    ],
)
def test_work_item_refs(kernel: Kernel, workflow: Workflow, phase: str, case: str) -> None:
    kernel.register_workflow(strict_workflow(workflow))
    source = kernel.create_work_item(workflow="review", type="source", actor_id="w")
    review = kernel.create_work_item(workflow="review", type="review", actor_id="w")
    item = kernel.create_work_item(
        workflow="review", type="task", actor_id="w", fields={"title": "x"}
    )
    value = {
        "missing": str(uuid.uuid4()),
        "wrong_type": str(item.id),
        "invalid_uuid": "broken",
        "valid_source": str(source.id),
        "valid_review": str(review.id),
        "null": None,
        "untyped": str(item.id),
        "untyped_missing": str(uuid.uuid4()),
    }[case]
    fields = {"title": "x", "any_ref" if case.startswith("untyped") else "ref": value}
    before = kernel.get(item.id), kernel.history(item.id), kernel.health()["work_items"]

    def write() -> None:
        if phase == "create":
            kernel.create_work_item(workflow="review", type="task", actor_id="w", fields=fields)
        else:
            kernel.transition(item.id, transition="start", actor_id="w", fields=fields)

    if case in ("missing", "wrong_type", "invalid_uuid", "untyped_missing"):
        with pytest.raises(InvalidFieldError):
            write()
        assert (
            kernel.get(item.id),
            kernel.history(item.id),
            kernel.health()["work_items"],
        ) == before
    else:
        write()
        if phase == "transition":
            assert kernel.get(item.id).fields == fields
            assert kernel.replay(item.id)[2] == []
        else:
            assert kernel.list_items()[-1].fields == fields


@pytest.mark.parametrize(
    "case",
    [
        "unknown_type",
        "invalid_schema",
        "unknown_ref_type",
        "malformed_ref",
        "both_ref_forms",
        "null_ref_rule",
        "schema_reference",
        "boolean_rule",
    ],
)
def test_field_declaration_refusals(kernel: Kernel, workflow: Workflow, case: str) -> None:
    doc = workflow.as_document()
    schema: dict[str, Any] = {"type": "object", "properties": {"ref": {"type": "string"}}}
    if case == "invalid_schema":
        schema["type"] = "nonsense"
    if case == "unknown_ref_type":
        schema["properties"]["ref"]["work_item_ref"] = ["missing"]
    if case == "malformed_ref":
        schema["properties"]["ref"]["work_item_ref"] = "source"
    if case == "both_ref_forms":
        schema["properties"]["ref"].update(
            target_work_item_type="source", target_work_item_types=["source", "review"]
        )
    if case == "null_ref_rule":
        schema["properties"]["ref"]["work_item_ref"] = None
    if case == "schema_reference":
        schema["additionalProperties"] = {"$ref": "https://invalid.example/schema"}
    if case == "boolean_rule":
        schema["properties"]["ref"] = True
    doc["field_schemas"] = {"missing" if case == "unknown_type" else "task": schema}
    with pytest.raises(InvalidWorkflowError):
        kernel.register_workflow(Workflow.from_document(doc))
    assert kernel.list_workflows() == []


def test_field_schema_roundtrip(kernel: Kernel, workflow: Workflow) -> None:
    wf = strict_workflow(workflow)
    assert kernel.register_workflow(wf) == 1
    stored = kernel.get_workflow("review")
    assert stored.field_schemas == {"task": SCHEMA}
    assert Workflow.from_document(stored.as_document()).field_schemas == stored.field_schemas


def test_shallow_merge_and_atomic_clear(registered: Kernel) -> None:
    item = registered.create_work_item(
        workflow="review",
        type="task",
        actor_id="w",
        fields={"old": 1, "nested": {"a": 1, "b": 2}, "null": None},
    )
    changed = registered.transition(
        item.id,
        transition="start",
        actor_id="w",
        fields={"nested": {"a": 3}},
        unset_fields=("old", "missing"),
    )
    assert changed.fields == {"nested": {"a": 3}, "null": None}
    assert registered.replay(item.id) == ("doing", changed.fields, [])
    assert registered.list_items(where_fields={"null": None}) == [changed]
    event = registered.history(item.id)[-1]
    assert event.payload["unset"] == ["old", "missing"]


@pytest.mark.parametrize("case", ["same_key", "required_clear"])
def test_clear_refusals(registered: Kernel, case: str) -> None:
    item = registered.create_work_item(
        workflow="review", type="task", actor_id="w", fields={"note": "valid"}
    )
    registered.transition(item.id, transition="start", actor_id="w")
    before = registered.get(item.id), registered.history(item.id)
    with pytest.raises(InvalidFieldError):
        registered.transition(
            item.id,
            transition="edit" if case == "same_key" else "submit",
            actor_id="w",
            unset_fields=("note",),
            fields={"note": "new"} if case == "same_key" else {},
        )
    assert (registered.get(item.id), registered.history(item.id)) == before


@pytest.mark.parametrize(
    "value", [float("nan"), float("inf"), {1: "bad"}, (1, 2), uuid.UUID(int=0)]
)
@pytest.mark.parametrize("phase", ["create", "transition", "payload"])
def test_json_type_refusal(registered: Kernel, value: Any, phase: str) -> None:
    item = registered.create_work_item(workflow="review", type="task", actor_id="w")
    with pytest.raises(InvalidFieldError):
        if phase == "create":
            registered.create_work_item(
                workflow="review", type="task", actor_id="w", fields={"v": value}
            )
        else:
            args: dict[str, Any] = {"payload" if phase == "payload" else "fields": {"v": value}}
            registered.transition(item.id, transition="start", actor_id="w", **args)
    assert registered.get(item.id) == item and len(registered.history(item.id)) == 1
