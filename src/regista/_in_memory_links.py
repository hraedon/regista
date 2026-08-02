from __future__ import annotations

import uuid
from typing import Any

from ._contract import (
    Jsonb,
    validate_content_hash,
    validate_cross_project_link_type,
    validate_link_type,
    validate_mutation_params,
)
from ._errors import ErrorCode, RegistaError
from ._event_store import InMemoryEventStore
from ._event_store import append_event as _store_append
from ._keys import KeySet
from ._types import Link


def in_memory_create_link(
    store: InMemoryEventStore,
    work_items: dict[uuid.UUID, dict[str, Any]],
    workflows: dict[tuple[str, int], dict[str, Any]],
    links: list[dict[str, Any]],
    key_set: KeySet | None,
    from_work_item_id: uuid.UUID,
    to_work_item_id: uuid.UUID,
    link_type: str,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict[str, Any] | None = None,
    *,
    event_id: uuid.UUID | None = None,
    payload: dict[str, Any] | None = None,
    target_project: str | None = None,
    target_entity_kind: str | None = None,
    content_hash: str | None = None,
) -> Link:
    validate_content_hash(content_hash)
    if event_id is None:
        event_id = uuid.uuid4()
    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        event_id=event_id,
    )

    from_wi = work_items.get(from_work_item_id)
    if from_wi is None:
        raise RegistaError(
            ErrorCode.LINK_TARGET_NOT_FOUND,
            f"Source work item {from_work_item_id} not found",
        )

    link_id = uuid.uuid4()
    link_payload: dict[str, Any] = {
        "link_id": str(link_id),
        "from_work_item_id": str(from_work_item_id),
        "to_work_item_id": str(to_work_item_id),
        "link_type": link_type,
    }
    if payload is not None:
        link_payload["link_payload"] = payload

    if target_project is not None:
        if not target_project or not target_project.strip():
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "target_project must be a non-empty string",
            )
        wf_data = workflows.get(
            (from_wi["workflow_name"], from_wi["workflow_version"])
        )
        if wf_data is not None:
            validate_cross_project_link_type(
                wf_data.get("link_types", []),
                link_type,
            )
        link_payload["target_project"] = target_project
        link_payload["target_entity_kind"] = target_entity_kind or "work_item"
        if content_hash is not None:
            link_payload["content_hash"] = content_hash
    else:
        to_wi = work_items.get(to_work_item_id)
        if to_wi is None:
            raise RegistaError(
                ErrorCode.LINK_TARGET_NOT_FOUND,
                "Target work item not found for link",
            )
        if from_wi["workflow_name"] != to_wi["workflow_name"]:
            raise RegistaError(
                ErrorCode.LINK_CROSS_PROJECT,
                "Cannot link work items from different projects",
            )

        wf_data = workflows.get(
            (from_wi["workflow_name"], from_wi["workflow_version"])
        )
        if wf_data is not None:
            validate_link_type(
                wf_data.get("link_types", []),
                from_wi["work_item_type"],
                to_wi["work_item_type"],
                link_type,
            )

    _store_append(
        store,
        work_item_id=from_wi["work_item_id"],
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=Jsonb(actor_metadata) if actor_metadata is not None else None,
        workflow_name=from_wi["workflow_name"],
        workflow_version=from_wi["workflow_version"],
        transition="link_created",
        payload=Jsonb(link_payload),
        event_id=event_id,
        key_set=key_set,
    )

    links.append({
        "link_id": link_id,
        "from_id": from_work_item_id,
        "to_id": to_work_item_id,
        "link_type": link_type,
        "payload": payload,
        "target_project": target_project,
    })

    return Link(
        link_id=link_id,
        from_work_item_id=from_work_item_id,
        to_work_item_id=to_work_item_id,
        link_type=link_type,
        payload=payload,
        target_project=target_project,
        target_entity_kind=(
            target_entity_kind
            if target_project is None
            else (target_entity_kind or "work_item")
        ),
        content_hash=content_hash,
    )


def in_memory_remove_link(
    store: InMemoryEventStore,
    work_items: dict[uuid.UUID, dict[str, Any]],
    workflows: dict[tuple[str, int], dict[str, Any]],
    links: list[dict[str, Any]],
    key_set: KeySet | None,
    from_work_item_id: uuid.UUID,
    to_work_item_id: uuid.UUID,
    link_type: str,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict[str, Any] | None = None,
    *,
    event_id: uuid.UUID | None = None,
    target_project: str | None = None,
) -> None:
    if event_id is None:
        event_id = uuid.uuid4()
    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        event_id=event_id,
    )

    from_wi = work_items.get(from_work_item_id)
    if from_wi is None:
        raise RegistaError(
            ErrorCode.LINK_TARGET_NOT_FOUND,
            f"Source work item {from_work_item_id} not found",
        )

    if target_project is None:
        to_wi = work_items.get(to_work_item_id)
        if to_wi is None:
            raise RegistaError(
                ErrorCode.LINK_TARGET_NOT_FOUND,
                "Target work item not found for link removal",
            )

    has_live = any(
        ln["from_id"] == from_work_item_id
        and ln["to_id"] == to_work_item_id
        and ln["link_type"] == link_type
        and ln.get("active", True)
        for ln in links
    )
    if not has_live:
        events = sorted(
            store.events.get(from_work_item_id, []),
            key=lambda e: e.event_seq,
            reverse=True,
        )
        most_recent = None
        for e in events:
            if e.transition in ("link_created", "link_removed"):
                p = e.payload or {}
                if (
                    p.get("to_work_item_id") == str(to_work_item_id)
                    and p.get("link_type") == link_type
                ):
                    most_recent = e.transition
                    break
        if most_recent != "link_created":
            raise RegistaError(
                ErrorCode.LINK_NOT_FOUND,
                f"No live link of type {link_type!r} "
                f"from {from_work_item_id} to {to_work_item_id}",
            )

    remove_payload = {
        "from_work_item_id": str(from_work_item_id),
        "to_work_item_id": str(to_work_item_id),
        "link_type": link_type,
    }
    if target_project is not None:
        remove_payload["target_project"] = target_project

    _store_append(
        store,
        work_item_id=from_wi["work_item_id"],
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=Jsonb(actor_metadata) if actor_metadata is not None else None,
        workflow_name=from_wi["workflow_name"],
        workflow_version=from_wi["workflow_version"],
        transition="link_removed",
        payload=Jsonb(remove_payload),
        event_id=event_id,
        key_set=key_set,
    )

    links[:] = [
        ln for ln in links
        if not (
            ln["from_id"] == from_work_item_id
            and ln["to_id"] == to_work_item_id
            and ln["link_type"] == link_type
            and ln.get("target_project") == target_project
        )
    ]
