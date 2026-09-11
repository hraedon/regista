from __future__ import annotations

from typing import Any

from ._errors import ErrorCode, RegistaError
from ._types import Event


def _check_create_idempotency(
    existing_event: Event | None,
    *,
    workflow_name: str,
    workflow_version: int,
    work_item_type: str,
    initial_state: str,
    custom_fields: dict[str, Any],
    not_before: Any,
    actor_id: str,
    actor_kind: str,
    actor_metadata: dict[str, Any] | None,
    source: Any = None,
) -> Event | None:
    """Validate and return an existing ``created`` event for an idempotent retry.

    Creation has no caller-supplied entity id, so the ordinary event append
    idempotency check cannot establish whether a duplicate ``event_id`` belongs to
    the same request. Compare the complete immutable creation request before the
    projection row is allocated.
    """
    if existing_event is None:
        return None
    if existing_event.entity_kind != "work_item":
        raise RegistaError(
            ErrorCode.EVENT_ID_GLOBAL_COLLISION,
            f"event_id {existing_event.event_id} already used for entity_kind "
            f"{existing_event.entity_kind!r}, not 'work_item'",
        )
    if existing_event.transition != "created":
        raise RegistaError(
            ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD,
            f"event_id {existing_event.event_id} already used with transition "
            f"{existing_event.transition!r}, not 'created'",
        )
    if existing_event.actor_id != actor_id or existing_event.actor_kind != actor_kind:
        raise RegistaError(
            ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD,
            f"event_id {existing_event.event_id} already used by a different actor",
        )
    if existing_event.actor_metadata != actor_metadata:
        raise RegistaError(
            ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD,
            f"event_id {existing_event.event_id} already used with different actor metadata",
        )
    if (
        existing_event.workflow_name != workflow_name
        or existing_event.workflow_version != workflow_version
    ):
        raise RegistaError(
            ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD,
            f"event_id {existing_event.event_id} already used for a different workflow",
        )
    expected_payload = {
        "work_item_type": work_item_type,
        "initial_state": initial_state,
        "custom_fields": custom_fields,
        "not_before": not_before.isoformat() if not_before else None,
    }
    if existing_event.payload != expected_payload:
        raise RegistaError(
            ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD,
            f"event_id {existing_event.event_id} already used with different creation facts",
        )
    if existing_event.on_behalf_of is not None:
        raise RegistaError(
            ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD,
            f"event_id {existing_event.event_id} has unexpected delegation metadata",
        )
    return existing_event
