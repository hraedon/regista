from __future__ import annotations

import uuid

import psycopg
from psycopg.sql import SQL

from ._contract import Jsonb
from ._contract import validate_cross_project_link_type as _validate_xproject_link_type
from ._contract import validate_link_type as _validate_link_type_contract
from ._errors import ErrorCode, RegistaError
from ._events import append_event
from ._keys import KeySet
from ._types import Link


def _validate_link_type(
    conn: psycopg.Connection,
    from_type: str,
    to_type: str,
    link_type: str,
    workflow_name: str,
    workflow_version: int,
) -> None:
    row = conn.execute(
        SQL(
            "SELECT definition FROM workflow_registry "
            "WHERE workflow_name = %s AND version = %s"
        ),
        [workflow_name, workflow_version],
    ).fetchone()
    if row is None:
        raise RegistaError(
            ErrorCode.WORKFLOW_NOT_REGISTERED,
            f"Workflow {workflow_name!r} version {workflow_version} not registered",
        )

    _validate_link_type_contract(
        row["definition"].get("link_types", []),
        from_type,
        to_type,
        link_type,
    )


def _validate_cross_project_link_type(
    conn: psycopg.Connection,
    link_type: str,
    workflow_name: str,
    workflow_version: int,
) -> None:
    row = conn.execute(
        SQL(
            "SELECT definition FROM workflow_registry "
            "WHERE workflow_name = %s AND version = %s"
        ),
        [workflow_name, workflow_version],
    ).fetchone()
    if row is None:
        raise RegistaError(
            ErrorCode.WORKFLOW_NOT_REGISTERED,
            f"Workflow {workflow_name!r} version {workflow_version} not registered",
        )

    _validate_xproject_link_type(
        row["definition"].get("link_types", []),
        link_type,
    )


def create_link(
    conn: psycopg.Connection,
    from_work_item_id: uuid.UUID,
    to_work_item_id: uuid.UUID,
    link_type: str,
    actor_id: str,
    actor_kind: str,
    actor_metadata: Jsonb | None,
    key_set: KeySet,
    event_id: uuid.UUID | None = None,
    payload: Jsonb | None = None,
    target_project: str | None = None,
    target_entity_kind: str | None = None,
    content_hash: str | None = None,
) -> Link:
    if event_id is None:
        event_id = uuid.uuid4()

    if target_project is not None:
        from_row = conn.execute(
            SQL(
                "SELECT work_item_id, work_item_type, workflow_name, workflow_version "
                "FROM work_items_current WHERE work_item_id = %s FOR UPDATE"
            ),
            [from_work_item_id],
        ).fetchone()
        if from_row is None:
            raise RegistaError(
                ErrorCode.LINK_TARGET_NOT_FOUND,
                f"Source work item {from_work_item_id} not found",
            )
        to_row = None
    else:
        rows = conn.execute(
            SQL(
                "SELECT work_item_id, work_item_type, workflow_name, workflow_version "
                "FROM work_items_current "
                "WHERE work_item_id IN (%s, %s) "
                "ORDER BY work_item_id FOR UPDATE"
            ),
            [from_work_item_id, to_work_item_id],
        ).fetchall()
        row_map = {r["work_item_id"]: r for r in rows}
        from_row = row_map.get(from_work_item_id)
        to_row = row_map.get(to_work_item_id)
        if from_row is None:
            raise RegistaError(
                ErrorCode.LINK_TARGET_NOT_FOUND,
                f"Source work item {from_work_item_id} not found",
            )
        if to_row is None:
            raise RegistaError(
                ErrorCode.LINK_TARGET_NOT_FOUND,
                "Target work item not found for link",
            )

    link_id = uuid.uuid4()
    link_payload = {
        "link_id": str(link_id),
        "from_work_item_id": str(from_work_item_id),
        "to_work_item_id": str(to_work_item_id),
        "link_type": link_type,
    }
    if payload is not None:
        link_payload["link_payload"] = payload.value

    if target_project is not None:
        if not target_project or not target_project.strip():
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "target_project must be a non-empty string",
            )
        _validate_cross_project_link_type(
            conn,
            link_type,
            from_row["workflow_name"],
            from_row["workflow_version"],
        )
        link_payload["target_project"] = target_project
        link_payload["target_entity_kind"] = target_entity_kind or "work_item"
        if content_hash is not None:
            link_payload["content_hash"] = content_hash
    else:
        if from_row["workflow_name"] != to_row["workflow_name"]:
            raise RegistaError(
                ErrorCode.LINK_CROSS_PROJECT,
                "Cannot link work items from different projects",
            )

        _validate_link_type(
            conn,
            from_row["work_item_type"],
            to_row["work_item_type"],
            link_type,
            from_row["workflow_name"],
            from_row["workflow_version"],
        )

    append_event(
        conn=conn,
        work_item_id=from_work_item_id,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        key_set=key_set,
        workflow_name=from_row["workflow_name"],
        workflow_version=from_row["workflow_version"],
        transition="link_created",
        payload=Jsonb(link_payload),
        event_id=event_id,
    )

    return Link(
        link_id=link_id,
        from_work_item_id=from_work_item_id,
        to_work_item_id=to_work_item_id,
        link_type=link_type,
        payload=payload.value if payload is not None else None,
        target_project=target_project,
        target_entity_kind=(
            target_entity_kind
            if target_project is None
            else (target_entity_kind or "work_item")
        ),
        content_hash=content_hash,
    )


def remove_link(
    conn: psycopg.Connection,
    from_work_item_id: uuid.UUID,
    to_work_item_id: uuid.UUID,
    link_type: str,
    actor_id: str,
    actor_kind: str,
    actor_metadata: Jsonb | None,
    key_set: KeySet,
    event_id: uuid.UUID | None = None,
    target_project: str | None = None,
) -> None:
    if event_id is None:
        event_id = uuid.uuid4()

    if target_project is None:
        rows = conn.execute(
            SQL(
                "SELECT work_item_id, workflow_name, workflow_version "
                "FROM work_items_current "
                "WHERE work_item_id IN (%s, %s) "
                "ORDER BY work_item_id FOR UPDATE"
            ),
            [from_work_item_id, to_work_item_id],
        ).fetchall()
        row_map = {r["work_item_id"]: r for r in rows}
        from_row = row_map.get(from_work_item_id)
        to_row = row_map.get(to_work_item_id)
        if from_row is None:
            raise RegistaError(
                ErrorCode.LINK_TARGET_NOT_FOUND,
                f"Source work item {from_work_item_id} not found",
            )
        if to_row is None:
            raise RegistaError(
                ErrorCode.LINK_TARGET_NOT_FOUND,
                "Target work item not found for link removal",
            )
    else:
        from_row = conn.execute(
            SQL(
                "SELECT work_item_id, workflow_name, workflow_version "
                "FROM work_items_current WHERE work_item_id = %s FOR UPDATE"
            ),
            [from_work_item_id],
        ).fetchone()
        if from_row is None:
            raise RegistaError(
                ErrorCode.LINK_TARGET_NOT_FOUND,
                f"Source work item {from_work_item_id} not found",
            )

    live_link = conn.execute(
        SQL(
            "SELECT 1 FROM events "
            "WHERE work_item_id = %s "
            "AND transition = 'link_created' "
            "AND payload->>'to_work_item_id' = %s "
            "AND payload->>'link_type' = %s "
            "AND payload->>'target_project' IS NOT DISTINCT FROM %s "
            "AND NOT EXISTS ("
            "SELECT 1 FROM events e_r "
            "WHERE e_r.work_item_id = events.work_item_id "
            "AND e_r.transition = 'link_removed' "
            "AND e_r.payload->>'to_work_item_id' = events.payload->>'to_work_item_id' "
            "AND e_r.payload->>'link_type' = events.payload->>'link_type' "
            "AND e_r.payload->>'target_project' IS NOT DISTINCT FROM "
            "events.payload->>'target_project' "
            "AND e_r.event_seq > events.event_seq"
            ") LIMIT 1"
        ),
        [from_work_item_id, str(to_work_item_id), link_type, target_project],
    ).fetchone()

    if live_link is None:
        raise RegistaError(
            ErrorCode.LINK_NOT_FOUND,
            f"No live link of type {link_type!r} from {from_work_item_id} to {to_work_item_id}",
        )

    remove_payload = {
        "from_work_item_id": str(from_work_item_id),
        "to_work_item_id": str(to_work_item_id),
        "link_type": link_type,
    }
    if target_project is not None:
        remove_payload["target_project"] = target_project

    append_event(
        conn=conn,
        work_item_id=from_work_item_id,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        key_set=key_set,
        workflow_name=from_row["workflow_name"],
        workflow_version=from_row["workflow_version"],
        transition="link_removed",
        payload=Jsonb(remove_payload),
        event_id=event_id,
    )
