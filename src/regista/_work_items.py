from __future__ import annotations

import uuid
from datetime import datetime

import psycopg
from psycopg.sql import SQL

from ._contract import Jsonb
from ._errors import ErrorCode, RegistaError
from ._events import append_event, check_idempotency
from ._keys import KeySet
from ._types import Event, QueryPage, WorkflowDefinition, WorkItem
from ._workflow import validate_field_values, validate_work_item_refs

_WORK_ITEM_FIELDS = (
    "work_item_id, workflow_name, workflow_version, work_item_type, "
    "current_state, custom_fields, needs_review, not_before, "
    "last_event_seq, last_event_at, next_event_seq, "
    "claimed_by, claim_expires_at, attempt_number"
)


def _row_to_work_item(row: dict) -> WorkItem:
    return WorkItem(
        work_item_id=row["work_item_id"],
        workflow_name=row["workflow_name"],
        workflow_version=row["workflow_version"],
        work_item_type=row["work_item_type"],
        current_state=row["current_state"],
        custom_fields=row["custom_fields"] or {},
        needs_review=row["needs_review"],
        not_before=row["not_before"],
        last_event_seq=row["last_event_seq"],
        last_event_at=row["last_event_at"],
        next_event_seq=row["next_event_seq"],
        claimed_by=row["claimed_by"],
        claim_expires_at=row["claim_expires_at"],
        attempt_number=row["attempt_number"],
    )


def _load_workflow_definition(
    conn: psycopg.Connection,
    workflow_name: str,
    workflow_version: int | None = None,
) -> tuple[dict, int]:
    if workflow_version is not None:
        row = conn.execute(
            SQL(
                "SELECT definition, version FROM workflow_registry "
                "WHERE workflow_name = %s AND version = %s"
            ),
            [workflow_name, workflow_version],
        ).fetchone()
    else:
        row = conn.execute(
            SQL(
                "SELECT definition, version FROM workflow_registry "
                "WHERE workflow_name = %s ORDER BY version DESC LIMIT 1"
            ),
            [workflow_name],
        ).fetchone()

    if row is None:
        raise RegistaError(
            ErrorCode.WORKFLOW_NOT_REGISTERED,
            f"Workflow {workflow_name!r} is not registered",
        )
    return row["definition"], row["version"]


def create_work_item(
    conn: psycopg.Connection,
    workflow_name: str,
    work_item_type: str,
    actor_id: str,
    actor_kind: str,
    actor_metadata: Jsonb | None,
    key_set: KeySet,
    custom_fields: dict | None = None,
    not_before: datetime | None = None,
    event_id: uuid.UUID | None = None,
) -> tuple[WorkItem, Event]:
    if event_id is None:
        event_id = uuid.uuid4()

    def_data, version = _load_workflow_definition(conn, workflow_name)
    wf = _rebuild_wf(def_data)

    wit_def = None
    for wt in wf.work_item_types:
        if wt.name == work_item_type:
            wit_def = wt
            break
    if wit_def is None:
        raise RegistaError(
            ErrorCode.WORK_ITEM_TYPE_NOT_DECLARED,
            f"Work-item type {work_item_type!r} not declared in workflow {workflow_name!r}",
        )

    validated_fields = validate_field_values(wf, work_item_type, custom_fields or {})
    validate_work_item_refs(conn, def_data, work_item_type, validated_fields)

    work_item_id = uuid.uuid4()
    initial_state = wf.initial_state

    try:
        conn.execute(
            SQL(
                "INSERT INTO work_items_current "
                "(work_item_id, workflow_name, workflow_version, work_item_type, "
                "current_state, custom_fields, needs_review, not_before, "
                "last_event_seq, last_event_at, next_event_seq) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 0, now(), 1)"
            ),
            [
                work_item_id,
                workflow_name,
                version,
                work_item_type,
                initial_state,
                psycopg.types.json.Jsonb(validated_fields),
                False,
                not_before,
            ],
        )
    except psycopg.errors.UniqueViolation:
        existing = check_idempotency(conn, event_id, transition="created")
        if existing is not None:
            wi_row = conn.execute(
                SQL(f"SELECT {_WORK_ITEM_FIELDS} FROM work_items_current WHERE work_item_id = %s"),
                [existing.work_item_id],
            ).fetchone()
            if wi_row is not None:
                return _row_to_work_item(wi_row), existing
        raise

    event = append_event(
        conn=conn,
        work_item_id=work_item_id,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        key_set=key_set,
        workflow_name=workflow_name,
        workflow_version=version,
        transition="created",
        payload=Jsonb({
            "work_item_type": work_item_type,
            "initial_state": initial_state,
            "custom_fields": validated_fields,
            "not_before": not_before.isoformat() if not_before else None,
        }),
        event_id=event_id,
    )

    wi_row = conn.execute(
        SQL(f"SELECT {_WORK_ITEM_FIELDS} FROM work_items_current WHERE work_item_id = %s"),
        [work_item_id],
    ).fetchone()

    return _row_to_work_item(wi_row), event


def _rebuild_wf(data: dict) -> WorkflowDefinition:
    from ._types import (
        CustomFieldDef,
        LinkTypeDef,
        TransitionDef,
        WorkflowDefinition,
        WorkItemTypeDef,
    )

    transitions = [
        TransitionDef(
            name=t["name"],
            from_state=t["from_state"],
            to_state=t["to_state"],
            allowed_roles=t.get("allowed_roles", []),
            validator=t.get("validator"),
            hooks=t.get("hooks", []),
            validator_params=t.get("validator_params"),
        )
        for t in data.get("transitions", [])
    ]

    wits = [
        WorkItemTypeDef(
            name=w["name"],
            custom_fields=[
                CustomFieldDef(
                    name=f["name"],
                    type=f["type"],
                    required=f.get("required", False),
                    default_value=f.get("default_value", f.get("default")),
                    ui_visible=f.get("ui_visible", False),
                    enum_values=f.get("enum_values"),
                    target_work_item_type=f.get("target_work_item_type"),
                    target_work_item_types=f.get("target_work_item_types"),
                )
                for f in w.get("custom_fields", [])
            ],
        )
        for w in data.get("work_item_types", [])
    ]

    links = [
        LinkTypeDef(
            name=lt["name"], source_type=lt["source_type"], target_type=lt["target_type"]
        )
        for lt in data.get("link_types", [])
    ]

    return WorkflowDefinition(
        name=data["name"],
        version=data["version"],
        regista_version=data["regista_version"],
        states=data.get("states", []),
        initial_state=data.get("initial_state", ""),
        terminal_states=data.get("terminal_states", []),
        transitions=transitions,
        roles=data.get("roles", []),
        work_item_types=wits,
        link_types=links,
        attempt_threshold=data.get("attempt_threshold"),
        raw_yaml="",
    )


def get_work_item(
    conn: psycopg.Connection,
    work_item_id: uuid.UUID,
) -> WorkItem | None:
    row = conn.execute(
        SQL(f"SELECT {_WORK_ITEM_FIELDS} FROM work_items_current WHERE work_item_id = %s"),
        [work_item_id],
    ).fetchone()
    if row is None:
        return None
    return _row_to_work_item(row)


def query_work_items(
    conn: psycopg.Connection,
    *,
    workflow_name: str | None = None,
    workflow_version: int | None = None,
    work_item_types: list[str] | None = None,
    current_states: list[str] | None = None,
    claimed_by: str | None = None,
    claimable_now: bool | None = None,
    needs_review: bool | None = None,
    has_link_type: str | None = None,
    custom_field_filters: dict[str, object] | None = None,
    cursor: uuid.UUID | None = None,
    page_size: int = 100,
) -> QueryPage[WorkItem]:
    page_size = min(max(1, page_size), 1000)
    conditions = []
    params: list = []
    idx = 0

    def _ph(value):
        nonlocal idx
        idx += 1
        params.append(value)
        return "%s"

    if cursor is not None:
        conditions.append(f"work_item_id > {_ph(cursor)}")

    if workflow_name is not None:
        conditions.append(f"workflow_name = {_ph(workflow_name)}")
    if workflow_version is not None:
        conditions.append(f"workflow_version = {_ph(workflow_version)}")
    if work_item_types:
        placeholders = ", ".join(_ph(t) for t in work_item_types)
        conditions.append(f"work_item_type IN ({placeholders})")
    if current_states:
        placeholders = ", ".join(_ph(s) for s in current_states)
        conditions.append(f"current_state IN ({placeholders})")
    if claimed_by is not None:
        conditions.append(f"claimed_by = {_ph(claimed_by)}")
    if needs_review is not None:
        conditions.append(f"needs_review = {_ph(needs_review)}")

    if claimable_now is True:
        conditions.append(
            "(claimed_by IS NULL OR claim_expires_at < clock_timestamp()) "
            "AND (not_before IS NULL OR not_before <= clock_timestamp())"
        )

    if custom_field_filters:
        import json as _json

        try:
            conditions.append(
                f"custom_fields @> {_ph(_json.dumps(custom_field_filters))}::jsonb"
            )
        except TypeError:
            from ._errors import ErrorCode, RegistaError
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "custom_field_filters contains values that cannot be serialized to JSON",
            ) from None

    if has_link_type is not None:
        conditions.append(
            f"EXISTS (SELECT 1 FROM events e_c "
            f"WHERE e_c.work_item_id = work_items_current.work_item_id "
            f"AND e_c.transition = 'link_created' "
            f"AND e_c.payload->>'link_type' = {_ph(has_link_type)} "
            f"AND NOT EXISTS ("
            f"SELECT 1 FROM events e_r "
            f"WHERE e_r.work_item_id = e_c.work_item_id "
            f"AND e_r.transition = 'link_removed' "
            f"AND e_r.payload->>'link_type' = e_c.payload->>'link_type' "
            f"AND e_r.payload->>'to_work_item_id' = e_c.payload->>'to_work_item_id' "
            f"AND e_r.event_seq > e_c.event_seq))"
        )

    where = ""
    if conditions:
        where = "WHERE " + " AND ".join(conditions)

    fetch_size = page_size + 1
    sql = (
        f"SELECT {_WORK_ITEM_FIELDS} FROM work_items_current "
        f"{where} ORDER BY work_item_id LIMIT {fetch_size}"
    )
    rows = conn.execute(SQL(sql), params).fetchall()

    has_more = len(rows) > page_size
    items_rows = rows[:page_size]

    items = [_row_to_work_item(r) for r in items_rows]
    next_cursor = None
    if has_more and items:
        last = items[-1]
        next_cursor = last.work_item_id

    return QueryPage(items=items, cursor=next_cursor, has_more=has_more)
