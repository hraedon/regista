from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime
from pathlib import Path

import jsonschema
import structlog
import yaml

from ._contract import validate_json_safe_value
from ._errors import ErrorCode, SubstrateError
from ._jcs import canonicalize
from ._types import (
    CustomFieldDef,
    LinkTypeDef,
    TransitionDef,
    ValidationError,
    ValidationResult,
    WorkflowDefinition,
    WorkItemTypeDef,
)

log = structlog.get_logger()

_SCHEMA_PATH = Path(__file__).parent / "_workflow_schema.json"


def _require_unique(items: list, label: str, key_fn=None) -> None:
    from collections import Counter

    keys = [key_fn(i) for i in items] if key_fn else items
    dupes = [n for n, c in Counter(keys).items() if c > 1]
    if dupes:
        raise SubstrateError(
            ErrorCode.WORKFLOW_SEMANTIC_ERROR,
            f"Duplicate {label}: {sorted(dupes)}",
        )

_CLOSED_FIELD_TYPES = frozenset(
    {"string", "integer", "boolean", "timestamp", "json", "enum", "work_item_ref"}
)


def _load_json_schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text())


def parse_workflow_yaml(raw: str) -> dict:
    try:
        return yaml.safe_load(raw)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        line_info = f" (line {mark.line + 1})" if mark else ""
        raise SubstrateError(
            ErrorCode.WORKFLOW_VALIDATION_FAILED,
            f"YAML syntax error{line_info}: {e}",
        ) from e


def validate_json_schema(data: dict) -> None:
    schema = _load_json_schema()
    validator = jsonschema.Draft202012Validator(schema)
    errors = list(validator.iter_errors(data))
    if errors:
        first = errors[0]
        path = ".".join(str(p) for p in first.absolute_path) or "(root)"
        raise SubstrateError(
            ErrorCode.WORKFLOW_VALIDATION_FAILED,
            f"Schema validation error at {path}: {first.message}",
        )


def _validate_semantics(data: dict) -> None:
    states = {s["name"]: s for s in data.get("states", [])}
    state_names = set(states.keys())
    initial_states = [s["name"] for s in data.get("states", []) if s.get("initial", False)]
    terminal_states = {s["name"] for s in data.get("states", []) if s.get("terminal", False)}
    transitions = data.get("transitions", [])
    roles = {r["name"] for r in data.get("roles", [])}
    work_item_types = {t["name"] for t in data.get("work_item_types", [])}
    link_types = data.get("link_types", [])

    _require_unique(data.get("states", []), "state names", key_fn=lambda s: s["name"])
    _require_unique(
        data.get("work_item_types", []), "work_item_type names", key_fn=lambda t: t["name"]
    )
    _require_unique(data.get("roles", []), "role names", key_fn=lambda r: r["name"])
    _require_unique(link_types, "link_type names", key_fn=lambda lt: lt["name"])
    _require_unique(
        transitions, "transitions (name + from_state)", key_fn=lambda t: (t["name"], t["from"])
    )

    for wit in data.get("work_item_types", []):
        _require_unique(
            wit.get("custom_fields", []),
            f"custom_fields in work_item_type {wit['name']!r}",
            key_fn=lambda f: f["name"],
        )

    if len(initial_states) != 1:
        raise SubstrateError(
            ErrorCode.WORKFLOW_SEMANTIC_ERROR,
            f"Expected exactly 1 initial state, found {len(initial_states)}: {initial_states}",
        )
    initial = initial_states[0]

    reachable: set[str] = set()
    reachable.add(initial)
    changed = True
    while changed:
        changed = False
        for t in transitions:
            if t["from"] in reachable and t["to"] not in reachable:
                reachable.add(t["to"])
                changed = True

    unreachable = state_names - reachable
    if unreachable:
        raise SubstrateError(
            ErrorCode.WORKFLOW_SEMANTIC_ERROR,
            f"Unreachable states: {sorted(unreachable)}",
        )

    states_with_outgoing = {t["from"] for t in transitions}
    undeclared_terminal = (state_names - states_with_outgoing) - terminal_states
    if undeclared_terminal:
        raise SubstrateError(
            ErrorCode.WORKFLOW_SEMANTIC_ERROR,
            f"States with no outgoing transitions not declared terminal: "
            f"{sorted(undeclared_terminal)}",
        )

    for t in transitions:
        if t["from"] not in state_names:
            raise SubstrateError(
                ErrorCode.WORKFLOW_SEMANTIC_ERROR,
                f"Transition {t['name']!r} references unknown 'from' state {t['from']!r}",
            )
        if t["to"] not in state_names:
            raise SubstrateError(
                ErrorCode.WORKFLOW_SEMANTIC_ERROR,
                f"Transition {t['name']!r} references unknown 'to' state {t['to']!r}",
            )
        for role in t.get("allowed_roles", []):
            if role not in roles:
                raise SubstrateError(
                    ErrorCode.WORKFLOW_SEMANTIC_ERROR,
                    f"Transition {t['name']!r} references undeclared role {role!r}",
                )

    for wit in data.get("work_item_types", []):
        for field in wit.get("custom_fields", []):
            ftype = field["type"]
            if ftype not in _CLOSED_FIELD_TYPES:
                raise SubstrateError(
                    ErrorCode.WORKFLOW_SEMANTIC_ERROR,
                    f"Unknown field type {ftype!r} in {wit['name']}.{field['name']}",
                )
            if ftype == "work_item_ref":
                singular = field.get("target_work_item_type")
                plural = field.get("target_work_item_types")
                if singular and plural:
                    raise SubstrateError(
                        ErrorCode.WORKFLOW_SEMANTIC_ERROR,
                        f"work_item_ref field {wit['name']}.{field['name']} "
                        f"specifies both target_work_item_type and target_work_item_types",
                    )
                if singular and singular not in work_item_types:
                    raise SubstrateError(
                        ErrorCode.WORKFLOW_SEMANTIC_ERROR,
                        f"work_item_ref field {wit['name']}.{field['name']} "
                        f"references unknown work_item_type {singular!r}",
                    )
                if plural:
                    unknown = [t for t in plural if t not in work_item_types]
                    if unknown:
                        raise SubstrateError(
                            ErrorCode.WORKFLOW_SEMANTIC_ERROR,
                            f"work_item_ref field {wit['name']}.{field['name']} "
                            f"references unknown work_item_types: {sorted(unknown)}",
                        )

    for lt in link_types:
        if lt["source_type"] not in work_item_types:
            raise SubstrateError(
                ErrorCode.WORKFLOW_SEMANTIC_ERROR,
                f"Link type {lt['name']!r} references unknown source_type {lt['source_type']!r}",
            )
        if lt["target_type"] not in work_item_types:
            raise SubstrateError(
                ErrorCode.WORKFLOW_SEMANTIC_ERROR,
                f"Link type {lt['name']!r} references unknown target_type {lt['target_type']!r}",
            )


def build_definition(data: dict, raw_yaml: str) -> WorkflowDefinition:
    states_data = data["states"]
    state_names = [s["name"] for s in states_data]
    initial = next(s["name"] for s in states_data if s.get("initial", False))
    terminals = [s["name"] for s in states_data if s.get("terminal", False)]

    transitions = [
        TransitionDef(
            name=t["name"],
            from_state=t["from"],
            to_state=t["to"],
            allowed_roles=t.get("allowed_roles", []),
            validator=t.get("validator"),
            hooks=t.get("hooks", []),
        )
        for t in data.get("transitions", [])
    ]

    wits = []
    for wit in data.get("work_item_types", []):
        fields = [
            CustomFieldDef(
                name=f["name"],
                type=f["type"],
                required=f.get("required", False),
                default_value=f.get("default"),
                ui_visible=f.get("ui_visible", False),
                enum_values=f.get("enum_values"),
                target_work_item_type=f.get("target_work_item_type"),
                target_work_item_types=f.get("target_work_item_types"),
            )
            for f in wit.get("custom_fields", [])
        ]
        wits.append(WorkItemTypeDef(name=wit["name"], custom_fields=fields))

    links = [
        LinkTypeDef(name=lt["name"], source_type=lt["source_type"], target_type=lt["target_type"])
        for lt in data.get("link_types", [])
    ]

    return WorkflowDefinition(
        name=data["name"],
        version=data["version"],
        substrate_version=data["substrate_version"],
        states=state_names,
        initial_state=initial,
        terminal_states=terminals,
        transitions=transitions,
        roles=[r["name"] for r in data.get("roles", [])],
        work_item_types=wits,
        link_types=links,
        attempt_threshold=data.get("attempt_threshold"),
        hook_defaults=data.get("hook_defaults"),
        raw_yaml=raw_yaml,
    )


def parse_and_validate(raw_yaml: str) -> WorkflowDefinition:
    data = parse_workflow_yaml(raw_yaml)
    validate_json_schema(data)
    _validate_semantics(data)
    return build_definition(data, raw_yaml)


def validate_and_build(data: dict, raw_yaml: str) -> WorkflowDefinition:
    validate_json_schema(data)
    _validate_semantics(data)
    return build_definition(data, raw_yaml)


def parse_file(path: str | Path) -> WorkflowDefinition:
    from ._workflow_compose import compose_workflow

    data, _ = compose_workflow(path)
    return validate_and_build(data, "")


def validate_field_values(
    wf: WorkflowDefinition,
    work_item_type: str,
    values: dict,
) -> dict:
    wit = next((t for t in wf.work_item_types if t.name == work_item_type), None)
    if wit is None:
        raise SubstrateError(
            ErrorCode.WORK_ITEM_TYPE_NOT_DECLARED,
            f"Work-item type {work_item_type!r} not declared in workflow {wf.name!r}",
        )

    result = {}
    for field_def in wit.custom_fields:
        val = values.get(field_def.name)
        if val is None:
            if field_def.required and field_def.default_value is None:
                raise SubstrateError(
                    ErrorCode.CUSTOM_FIELD_VIOLATION,
                    f"Required field {field_def.name!r} missing",
                    detail={"field": field_def.name, "type": field_def.type},
                )
            val = field_def.default_value

        if val is not None:
            val = _coerce_field(field_def, val)
        result[field_def.name] = val

    extra = set(values.keys()) - {f.name for f in wit.custom_fields}
    if extra:
        raise SubstrateError(
            ErrorCode.CUSTOM_FIELD_VIOLATION,
            f"Unknown fields: {sorted(extra)}",
            detail={"unknown_fields": sorted(extra)},
        )

    return result


def validate_field_update(
    wf_def: dict,
    work_item_type: str,
    updates: dict,
) -> None:
    wits = wf_def.get("work_item_types", [])
    wit = next((t for t in wits if t["name"] == work_item_type), None)
    if wit is None:
        raise SubstrateError(
            ErrorCode.WORK_ITEM_TYPE_NOT_DECLARED,
            f"Work-item type {work_item_type!r} not declared",
        )

    field_defs = {f["name"]: f for f in wit.get("custom_fields", [])}

    for key, value in updates.items():
        field_def = field_defs.get(key)
        if field_def is None:
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Unknown field {key!r} in custom_fields_update",
                detail={"field": key},
            )
        fd = CustomFieldDef(
            name=field_def["name"],
            type=field_def["type"],
            required=field_def.get("required", False),
            default_value=field_def.get("default_value", field_def.get("default")),
            ui_visible=field_def.get("ui_visible", False),
            enum_values=field_def.get("enum_values"),
            target_work_item_type=field_def.get("target_work_item_type"),
            target_work_item_types=field_def.get("target_work_item_types"),
        )
        _coerce_field(fd, value)


def validate_work_item_refs(
    conn,
    wf_def: dict,
    work_item_type: str,
    values: dict,
) -> None:
    from psycopg.sql import SQL

    wits = wf_def.get("work_item_types", [])
    wit = next((t for t in wits if t["name"] == work_item_type), None)
    if wit is None:
        return

    ref_fields = [
        f
        for f in wit.get("custom_fields", [])
        if f["type"] == "work_item_ref"
    ]

    for field_def in ref_fields:
        value = values.get(field_def["name"])
        if value is None:
            continue

        try:
            ref_uuid = uuid.UUID(value)
        except ValueError:
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def['name']!r} contains invalid UUID: {value!r}",
                detail={"field": field_def["name"], "value": value},
            )
        target_type = field_def.get("target_work_item_type")
        target_types = field_def.get("target_work_item_types")

        row = conn.execute(
            SQL("SELECT work_item_type FROM work_items_current WHERE work_item_id = %s"),
            [ref_uuid],
        ).fetchone()

        if row is None:
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def['name']!r} references nonexistent work item {value}",
                detail={"field": field_def["name"], "value": value},
            )

        if target_type and row["work_item_type"] != target_type:
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def['name']!r} references work item of type "
                f"{row['work_item_type']!r}, expected {target_type!r}",
                detail={
                    "field": field_def["name"],
                    "value": value,
                    "actual_type": row["work_item_type"],
                    "expected_type": target_type,
                },
            )

        if target_types and row["work_item_type"] not in target_types:
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def['name']!r} references work item of type "
                f"{row['work_item_type']!r}, expected one of {sorted(target_types)}",
                detail={
                    "field": field_def["name"],
                    "value": value,
                    "actual_type": row["work_item_type"],
                    "expected_types": sorted(target_types),
                },
            )


def _coerce_field(field_def: CustomFieldDef, value: object) -> object:
    ftype = field_def.type
    if ftype == "string":
        if not isinstance(value, str):
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def.name!r} expects string, got {type(value).__name__}",
                detail={"field": field_def.name},
            )
        validate_json_safe_value(value, f"Field {field_def.name!r}")
    elif ftype == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def.name!r} expects integer, got {type(value).__name__}",
                detail={"field": field_def.name},
            )
    elif ftype == "boolean":
        if not isinstance(value, bool):
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def.name!r} expects boolean, got {type(value).__name__}",
                detail={"field": field_def.name},
            )
    elif ftype == "timestamp":
        if not isinstance(value, str):
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def.name!r} expects ISO 8601 timestamp string",
                detail={"field": field_def.name},
            )
        try:
            datetime.fromisoformat(value)
        except ValueError:
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def.name!r} contains invalid ISO 8601 timestamp: {value!r}",
                detail={"field": field_def.name, "value": value},
            )
    elif ftype == "json":
        if not isinstance(value, (dict, list, str, int, float, bool, type(None))):
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def.name!r} expects JSON-compatible value",
                detail={"field": field_def.name},
            )
        validate_json_safe_value(value, f"Field {field_def.name!r}")
    elif ftype == "enum":
        if value not in (field_def.enum_values or []):
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def.name!r} value {value!r} not in enum values",
                detail={"field": field_def.name, "enum_values": field_def.enum_values},
            )
    elif ftype == "work_item_ref":
        if not isinstance(value, str):
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def.name!r} expects work_item_id (UUID string)",
                detail={"field": field_def.name},
            )
        try:
            uuid.UUID(value)
        except ValueError:
            raise SubstrateError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def.name!r} contains invalid UUID: {value!r}",
                detail={"field": field_def.name, "value": value},
            )
    return value


def compute_content_hash(wf: WorkflowDefinition) -> bytes:
    d = wf.to_dict()
    d.pop("raw_yaml", None)
    canonical_bytes = canonicalize(d)
    return hashlib.sha256(canonical_bytes).digest()


def compute_content_hash_from_dict(data: dict) -> bytes:
    d = dict(data)
    d.pop("raw_yaml", None)
    canonical_bytes = canonicalize(d)
    return hashlib.sha256(canonical_bytes).digest()


def validate_yaml(source: str | Path) -> ValidationResult:
    if isinstance(source, Path):
        raw = source.read_text()
    else:
        raw = source

    errors: list[ValidationError] = []

    try:
        data = parse_workflow_yaml(raw)
    except SubstrateError as e:
        errors.append(ValidationError(path="(root)", message=str(e)))
        return ValidationResult(valid=False, errors=errors)

    if data is None:
        errors.append(ValidationError(path="(root)", message="YAML document is empty"))
        return ValidationResult(valid=False, errors=errors)

    if not isinstance(data, dict):
        errors.append(ValidationError(path="(root)", message="YAML did not parse to a dict"))
        return ValidationResult(valid=False, errors=errors)

    try:
        validate_json_schema(data)
    except SubstrateError as e:
        errors.append(ValidationError(path="(root)", message=str(e)))

    try:
        _validate_semantics(data)
    except SubstrateError as e:
        errors.append(ValidationError(path="(root)", message=str(e)))

    if errors:
        return ValidationResult(valid=False, errors=errors)

    wf = build_definition(data, raw)
    return ValidationResult(valid=True, errors=[], workflow=wf)
