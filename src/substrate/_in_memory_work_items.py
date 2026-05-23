from __future__ import annotations

import uuid
from datetime import UTC, datetime

from ._contract import (
    Jsonb,
    validate_actor_kind,
    validate_mutation_params,
    validate_work_item_exists,
)
from ._errors import ErrorCode, SubstrateError
from ._event_store import append_event as _store_append
from ._types import Event, QueryPage, WorkItem
from ._workflow import validate_field_values


def _dict_contains(haystack: dict, needle: dict) -> bool:
    for k, v in needle.items():
        if k not in haystack:
            return False
        h = haystack[k]
        if isinstance(v, dict) and isinstance(h, dict):
            if not _dict_contains(h, v):
                return False
        elif isinstance(v, list) and isinstance(h, list):
            for item in v:
                if item not in h:
                    return False
        elif h != v:
            return False
    return True


def in_memory_create_work_item(
    store,
    work_items: dict,
    workflows: dict,
    workflow_defs: dict,
    key_set,
    workflow_name: str,
    work_item_type: str,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
    *,
    custom_fields: dict | None = None,
    not_before: datetime | None = None,
    event_id: uuid.UUID | None = None,
    skip_event_id_version_check: bool = False,
) -> tuple[WorkItem, Event]:
    if event_id is None:
        event_id = uuid.uuid4()
    if not skip_event_id_version_check:
        validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            event_id=event_id,
            not_before=not_before,
        )
    else:
        validate_actor_kind(actor_kind)

    versions = [(k, v) for k, v in workflows.items() if k[0] == workflow_name]
    if not versions:
        raise SubstrateError(
            ErrorCode.WORKFLOW_NOT_REGISTERED,
            f"Workflow {workflow_name!r} is not registered",
        )
    versions.sort(key=lambda x: x[0][1], reverse=True)
    key, wf_data = versions[0]
    wf_def = workflow_defs[key]
    version = key[1]

    wit_def = None
    for wt in wf_def.work_item_types:
        if wt.name == work_item_type:
            wit_def = wt
            break
    if wit_def is None:
        raise SubstrateError(
            ErrorCode.WORK_ITEM_TYPE_NOT_DECLARED,
            f"Work-item type {work_item_type!r} not declared in workflow {workflow_name!r}",
        )

    validated_fields = validate_field_values(wf_def, work_item_type, custom_fields or {})
    from ._in_memory_transition import _validate_refs_in_memory

    _validate_refs_in_memory(work_items, wf_data, work_item_type, validated_fields)

    work_item_id = uuid.uuid4()
    initial_state = wf_def.initial_state
    now = datetime.now(UTC)

    wi_state = {
        "work_item_id": work_item_id,
        "workflow_name": workflow_name,
        "workflow_version": version,
        "work_item_type": work_item_type,
        "current_state": initial_state,
        "custom_fields": validated_fields,
        "needs_review": False,
        "not_before": not_before,
        "last_event_seq": 0,
        "last_event_at": now,
        "next_event_seq": 1,
        "claimed_by": None,
        "claim_expires_at": None,
        "attempt_number": 0,
    }
    work_items[work_item_id] = wi_state

    try:
        evt = _store_append(
            store,
            work_item_id=work_item_id,
            actor_id=actor_id,
            actor_kind=actor_kind,
            actor_metadata=Jsonb(actor_metadata) if actor_metadata is not None else None,
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
            key_set=key_set,
        )
    except SubstrateError:
        del work_items[work_item_id]
        raise

    return _wi_to_work_item(wi_state), evt


def in_memory_query_work_items(
    work_items: dict,
    links: list,
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
    items = list(work_items.values())

    if cursor is not None:
        items = [wi for wi in items if wi["work_item_id"] > cursor]
    if workflow_name is not None:
        items = [wi for wi in items if wi["workflow_name"] == workflow_name]
    if workflow_version is not None:
        items = [wi for wi in items if wi["workflow_version"] == workflow_version]
    if work_item_types:
        items = [wi for wi in items if wi["work_item_type"] in work_item_types]
    if current_states:
        items = [wi for wi in items if wi["current_state"] in current_states]
    if claimed_by is not None:
        items = [wi for wi in items if wi.get("claimed_by") == claimed_by]
    if needs_review is not None:
        items = [wi for wi in items if wi.get("needs_review") == needs_review]
    if claimable_now is True:
        now = datetime.now(UTC)
        items = [
            wi for wi in items
            if (
                wi.get("claimed_by") is None
                or (wi.get("claim_expires_at") and wi["claim_expires_at"] < now)
            )
            and (wi.get("not_before") is None or wi["not_before"] <= now)
        ]
    if custom_field_filters:
        items = [
            wi for wi in items
            if _dict_contains(wi.get("custom_fields", {}), custom_field_filters)
        ]
    if has_link_type is not None:
        active = set()
        for ln in links:
            if ln["link_type"] == has_link_type:
                active.add(ln["from_id"])
        items = [wi for wi in items if wi["work_item_id"] in active]

    items.sort(key=lambda wi: wi["work_item_id"])
    has_more = len(items) > page_size
    page = items[:page_size]
    next_cursor = page[-1]["work_item_id"] if has_more and page else None

    return QueryPage(
        items=[_wi_to_work_item(wi) for wi in page],
        cursor=next_cursor,
        has_more=has_more,
    )


def in_memory_update_not_before(
    store,
    work_items: dict,
    key_set,
    work_item_id: uuid.UUID,
    not_before: datetime | None,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
    *,
    event_id: uuid.UUID | None = None,
    on_behalf_of: dict | None = None,
) -> Event:
    if event_id is None:
        event_id = uuid.uuid4()
    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        event_id=event_id,
        not_before=not_before,
    )

    wi = work_items.get(work_item_id)
    validate_work_item_exists(wi, work_item_id)

    evt = _store_append(
        store,
        work_item_id=work_item_id,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=Jsonb(actor_metadata) if actor_metadata is not None else None,
        workflow_name=wi["workflow_name"],
        workflow_version=wi["workflow_version"],
        transition="not_before_set",
        payload=Jsonb({"not_before": not_before.isoformat() if not_before else None}),
        event_id=event_id,
        key_set=key_set,
        on_behalf_of=on_behalf_of,
    )
    wi["not_before"] = not_before
    return evt


def _wi_to_work_item(wi: dict) -> WorkItem:
    return WorkItem(
        work_item_id=wi["work_item_id"],
        workflow_name=wi["workflow_name"],
        workflow_version=wi["workflow_version"],
        work_item_type=wi["work_item_type"],
        current_state=wi["current_state"],
        custom_fields=wi["custom_fields"] or {},
        needs_review=wi.get("needs_review", False),
        not_before=wi.get("not_before"),
        last_event_seq=wi["last_event_seq"],
        last_event_at=wi["last_event_at"],
        next_event_seq=wi["next_event_seq"],
        claimed_by=wi.get("claimed_by"),
        claim_expires_at=wi.get("claim_expires_at"),
        attempt_number=wi.get("attempt_number", 0),
    )
