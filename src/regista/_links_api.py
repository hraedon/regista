from __future__ import annotations

import uuid

from ._contract import Jsonb as _Jsonb
from ._errors import RegistaError
from ._observability import OpTimer


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
            )
        metrics.inc("links_removed", project)
        timer.log("ok")
    except RegistaError:
        timer.log("error")
        raise
