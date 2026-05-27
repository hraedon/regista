from __future__ import annotations

import uuid
from datetime import UTC, datetime

from ._contract import (
    Jsonb,
    check_actor_role_authorized,
    check_privileged_transition,
    check_role_gating,
    resolve_transition,
    validate_delegation_chain,
    validate_mutation_params,
)
from ._errors import ErrorCode, RegistaError
from ._event_store import append_event as _store_append
from ._hooks import run_validator
from ._types import Event, ValidatorContext
from ._workflow import validate_field_update


def in_memory_transition(
    store,
    work_items: dict,
    workflows: dict,
    actor_roles: set,
    validators: dict,
    claims: dict,
    hook_id_counter: int,
    hook_queue: list,
    key_set,
    work_item_id: uuid.UUID,
    transition_name: str,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
    *,
    key_id: str | None = None,
    payload: dict | None = None,
    custom_fields: dict | None = None,
    event_id: uuid.UUID | None = None,
    expected_event_seq: int | None = None,
    on_behalf_of: dict | None = None,
    strict_roles: bool = False,
) -> tuple[Event, int]:
    if event_id is None:
        event_id = uuid.uuid4()
    validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        event_id=event_id,
    )
    validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())

    wi = work_items.get(work_item_id)
    if wi is None:
        raise RegistaError(
            ErrorCode.WORK_ITEM_NOT_FOUND,
            f"Work item {work_item_id} not found",
        )

    wf_key = (wi["workflow_name"], wi["workflow_version"])
    wf_data = workflows.get(wf_key)
    if wf_data is None:
        raise RegistaError(
            ErrorCode.WORKFLOW_NOT_REGISTERED,
            f"Workflow {wi['workflow_name']!r} v{wi['workflow_version']} not found",
        )

    transition_def = resolve_transition(
        wf_data.get("transitions", []),
        wi["current_state"],
        transition_name,
        wi["workflow_name"],
        wi["workflow_version"],
    )

    check_privileged_transition(
        transition_def,
        actor_kind,
        transition_name,
    )

    role = check_role_gating(
        transition_def.get("allowed_roles", []),
        actor_metadata,
        transition_name,
    )
    if role is not None:
        registered = {r for (aid, r) in actor_roles if aid == actor_id}
        check_actor_role_authorized(
            registered, actor_id, role,
            strict=strict_roles, actor_metadata=actor_metadata,
        )

    if custom_fields:
        validate_field_update(wf_data, wi["work_item_type"], custom_fields)
        _validate_refs_in_memory(work_items, wf_data, wi["work_item_type"], custom_fields)

    new_state = transition_def["to_state"]

    am_jsonb = Jsonb(actor_metadata) if actor_metadata is not None else None

    validator_name = transition_def.get("validator")
    if validator_name:
        handler = validators.get(validator_name)
        if handler is not None:
            ctx = ValidatorContext(
                work_item_id=work_item_id,
                workflow_name=wi["workflow_name"],
                workflow_version=wi["workflow_version"],
                work_item_type=wi["work_item_type"],
                current_state=wi["current_state"],
                new_state=new_state,
                transition_name=transition_name,
                payload=payload,
                custom_fields=wi["custom_fields"] or {},
                actor_id=actor_id,
                actor_metadata=actor_metadata,
            )
            run_validator(validator_name, handler, ctx)

    stored_payload = dict(payload) if payload else {}
    if custom_fields:
        stored_payload["custom_fields_update"] = custom_fields
        merged = wi.get("custom_fields") or {}
        wi["custom_fields"] = {**merged, **custom_fields}

    evt = _store_append(
        store,
        work_item_id=work_item_id,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=am_jsonb,
        workflow_name=wi["workflow_name"],
        workflow_version=wi["workflow_version"],
        transition=transition_name,
        payload=Jsonb(stored_payload),
        event_id=event_id,
        expected_event_seq=expected_event_seq,
        key_set=key_set,
        on_behalf_of=on_behalf_of,
        _key_id=key_id,
    )

    wi["current_state"] = new_state
    wi["claimed_by"] = None
    wi["claim_expires_at"] = None
    claims.pop(work_item_id, None)

    new_counter = hook_id_counter
    hook_names = transition_def.get("hooks", [])
    if hook_names:
        hook_defaults = wf_data.get("hook_defaults") or {}
        max_retries = hook_defaults.get("max_retries", 3)
        for hn in hook_names:
            new_counter += 1
            hook_queue.append({
                "id": new_counter,
                "event_id": event_id,
                "work_item_id": work_item_id,
                "hook_name": hn,
                "hook_type": "async",
                "transition": transition_name,
                "payload": payload,
                "retry_count": 0,
                "max_retries": max_retries,
                "status": "pending",
                "updated_at": datetime.now(UTC),
            })

    return evt, new_counter


def _validate_refs_in_memory(
    work_items: dict,
    wf_data: dict,
    work_item_type: str,
    values: dict,
) -> None:
    wits = wf_data.get("work_item_types", [])
    wit = next((t for t in wits if t["name"] == work_item_type), None)
    if wit is None:
        return
    for field_def in wit.get("custom_fields", []):
        if field_def["type"] != "work_item_ref":
            continue
        value = values.get(field_def["name"])
        if value is None:
            continue
        try:
            ref_uuid = uuid.UUID(value)
        except ValueError:
            raise RegistaError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def['name']!r} has invalid UUID value {value!r}",
                detail={"field": field_def["name"], "value": value},
            )
        target_type = field_def.get("target_work_item_type")
        target_types = field_def.get("target_work_item_types")
        ref_wi = work_items.get(ref_uuid)
        if ref_wi is None:
            raise RegistaError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def['name']!r} references nonexistent work item {value}",
                detail={"field": field_def["name"], "value": value},
            )
        if target_type and ref_wi["work_item_type"] != target_type:
            raise RegistaError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def['name']!r} references work item of type "
                f"{ref_wi['work_item_type']!r}, expected {target_type!r}",
                detail={
                    "field": field_def["name"],
                    "value": value,
                    "actual_type": ref_wi["work_item_type"],
                    "expected_type": target_type,
                },
            )
        if target_types and ref_wi["work_item_type"] not in target_types:
            raise RegistaError(
                ErrorCode.CUSTOM_FIELD_VIOLATION,
                f"Field {field_def['name']!r} references work item of type "
                f"{ref_wi['work_item_type']!r}, expected one of {sorted(target_types)}",
                detail={
                    "field": field_def["name"],
                    "value": value,
                    "actual_type": ref_wi["work_item_type"],
                    "expected_types": sorted(target_types),
                },
            )
