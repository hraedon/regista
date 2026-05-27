from __future__ import annotations

import uuid

from ._contract import Jsonb, validate_link_type, validate_mutation_params
from ._errors import ErrorCode, RegistaError
from ._event_store import append_event as _store_append
from ._types import Link


def in_memory_create_link(
    store,
    work_items: dict,
    workflows: dict,
    links: list,
    key_set,
    from_work_item_id: uuid.UUID,
    to_work_item_id: uuid.UUID,
    link_type: str,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
    *,
    event_id: uuid.UUID | None = None,
    payload: dict | None = None,
) -> Link:
    if event_id is None:
        event_id = uuid.uuid4()
    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        event_id=event_id,
    )

    from_wi = work_items.get(from_work_item_id)
    to_wi = work_items.get(to_work_item_id)
    if from_wi is None or to_wi is None:
        raise RegistaError(
            ErrorCode.LINK_TARGET_NOT_FOUND,
            "One or both work items not found for link",
        )
    if from_wi["workflow_name"] != to_wi["workflow_name"]:
        raise RegistaError(
            ErrorCode.LINK_CROSS_PROJECT,
            "Cannot link work items from different projects",
        )

    wf_data = workflows.get((from_wi["workflow_name"], from_wi["workflow_version"]))
    if wf_data is not None:
        validate_link_type(
            wf_data.get("link_types", []),
            from_wi["work_item_type"],
            to_wi["work_item_type"],
            link_type,
        )

    link_id = uuid.uuid4()
    link_payload = {
        "link_id": str(link_id),
        "from_work_item_id": str(from_work_item_id),
        "to_work_item_id": str(to_work_item_id),
        "link_type": link_type,
    }
    if payload is not None:
        link_payload["link_payload"] = payload

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
    })

    return Link(
        link_id=link_id,
        from_work_item_id=from_work_item_id,
        to_work_item_id=to_work_item_id,
        link_type=link_type,
        payload=payload,
    )


def in_memory_remove_link(
    store,
    work_items: dict,
    workflows: dict,
    links: list,
    key_set,
    from_work_item_id: uuid.UUID,
    to_work_item_id: uuid.UUID,
    link_type: str,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
    *,
    event_id: uuid.UUID | None = None,
) -> None:
    if event_id is None:
        event_id = uuid.uuid4()
    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        event_id=event_id,
    )

    from_wi = work_items.get(from_work_item_id)
    to_wi = work_items.get(to_work_item_id)
    if from_wi is None or to_wi is None:
        raise RegistaError(
            ErrorCode.LINK_TARGET_NOT_FOUND,
            "One or both work items not found for link removal",
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

    _store_append(
        store,
        work_item_id=from_wi["work_item_id"],
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=Jsonb(actor_metadata) if actor_metadata is not None else None,
        workflow_name=from_wi["workflow_name"],
        workflow_version=from_wi["workflow_version"],
        transition="link_removed",
        payload=Jsonb({
            "from_work_item_id": str(from_work_item_id),
            "to_work_item_id": str(to_work_item_id),
            "link_type": link_type,
        }),
        event_id=event_id,
        key_set=key_set,
    )

    links[:] = [
        ln for ln in links
        if not (
            ln["from_id"] == from_work_item_id
            and ln["to_id"] == to_work_item_id
            and ln["link_type"] == link_type
        )
    ]
