from __future__ import annotations

import uuid

from ._contract import Jsonb as _Jsonb
from ._errors import RegistaError
from ._observability import OpTimer
from ._types import Link


def create_link(
    mgr,
    keys,
    metrics,
    project: str,
    from_work_item_id: uuid.UUID,
    to_work_item_id: uuid.UUID,
    link_type: str,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
    *,
    event_id: uuid.UUID | None = None,
    payload: dict | None = None,
    target_project: str | None = None,
    target_entity_kind: str | None = None,
    content_hash: str | None = None,
):
    from ._links import create_link as _create

    timer = OpTimer(project, "create_link")
    try:
        with mgr.transaction() as conn:
            link = _create(
                conn,
                from_work_item_id=from_work_item_id,
                to_work_item_id=to_work_item_id,
                link_type=link_type,
                actor_id=actor_id,
                actor_kind=actor_kind,
                actor_metadata=_Jsonb(actor_metadata) if actor_metadata is not None else None,
                key_set=keys,
                event_id=event_id,
                payload=_Jsonb(payload) if payload is not None else None,
                target_project=target_project,
                target_entity_kind=target_entity_kind,
                content_hash=content_hash,
            )
        metrics.inc("links_created", project)
        timer.log("ok")
        return link
    except RegistaError:
        timer.log("error")
        raise


def remove_link(
    mgr,
    keys,
    metrics,
    project: str,
    from_work_item_id: uuid.UUID,
    to_work_item_id: uuid.UUID,
    link_type: str,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
    *,
    event_id: uuid.UUID | None = None,
    target_project: str | None = None,
):
    from ._links import remove_link as _remove

    timer = OpTimer(project, "remove_link")
    try:
        with mgr.transaction() as conn:
            _remove(
                conn,
                from_work_item_id=from_work_item_id,
                to_work_item_id=to_work_item_id,
                link_type=link_type,
                actor_id=actor_id,
                actor_kind=actor_kind,
                actor_metadata=_Jsonb(actor_metadata) if actor_metadata is not None else None,
                key_set=keys,
                event_id=event_id,
                target_project=target_project,
            )
        metrics.inc("links_removed", project)
        timer.log("ok")
    except RegistaError:
        timer.log("error")
        raise


def list_links(
    mgr,
    work_item_id: uuid.UUID,
) -> list[Link]:
    """Return all live (non-removed) links from *work_item_id*."""
    from ._links import list_links as _list

    with mgr.transaction() as conn:
        return _list(conn, work_item_id)
