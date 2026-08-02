from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from ._errors import ErrorCode, RegistaError
from ._recurrence import (
    _find_next_future_slot,
    compute_next_fire,
    validate_schedule,
    validate_template,
)


def in_memory_register_recurrence_rule(
    workflow_defs: dict[tuple[str, int], Any],
    recurrence_rules: dict[uuid.UUID, dict[str, Any]],
    workflow_name: str,
    workflow_version: int,
    work_item_type: str,
    template: dict[str, Any],
    schedule_kind: str,
    schedule_expr: str,
    *,
    timezone: str = "UTC",
    start_at: datetime | None = None,
    end_at: datetime | None = None,
    count: int | None = None,
    catchup_policy: str = "fire_once",
    created_by: str = "system",
) -> dict[str, Any]:
    if start_at is None:
        start_at = datetime.now(UTC)
    wf_key = (workflow_name, workflow_version)
    if wf_key not in workflow_defs:
        raise RegistaError(
            ErrorCode.WORKFLOW_NOT_REGISTERED,
            f"Workflow {workflow_name!r} v{workflow_version} not registered",
        )
    validate_schedule(schedule_kind, schedule_expr)
    validate_template(template)
    rule_id = uuid.uuid4()
    next_fire = compute_next_fire(
        schedule_kind, schedule_expr, timezone, start_at, None, end_at,
    )
    if next_fire is None:
        next_fire = start_at
    rule = {
        "rule_id": rule_id,
        "workflow_name": workflow_name,
        "workflow_version": workflow_version,
        "work_item_type": work_item_type,
        "template": template,
        "schedule_kind": schedule_kind,
        "schedule_expr": schedule_expr,
        "timezone": timezone,
        "start_at": start_at,
        "end_at": end_at,
        "count_remaining": count,
        "status": "active",
        "catchup_policy": catchup_policy,
        "last_fired_at": None,
        "next_fire_at": next_fire,
        "created_by": created_by,
        "created_at": datetime.now(UTC),
        "updated_at": datetime.now(UTC),
    }
    recurrence_rules[rule_id] = rule
    return rule


def in_memory_list_recurrence_rules(
    recurrence_rules: dict[uuid.UUID, dict[str, Any]],
    status: str | None = None,
) -> list[dict[str, Any]]:
    result = []
    for r in recurrence_rules.values():
        if status is None or r["status"] == status:
            result.append(dict(r))
    return sorted(result, key=lambda r: r["created_at"])


def in_memory_due_recurrences(
    recurrence_rules: dict[uuid.UUID, dict[str, Any]],
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    if now is None:
        now = datetime.now(UTC)
    result = []
    for r in recurrence_rules.values():
        if r["status"] == "active" and r["next_fire_at"] <= now:
            result.append(dict(r))
    return sorted(result, key=lambda r: r["next_fire_at"])


def in_memory_fire_recurrence(
    recurrence_rules: dict[uuid.UUID, dict[str, Any]],
    create_work_item_fn: Callable[..., Any],
    rule_id: uuid.UUID,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    rule = recurrence_rules.get(rule_id)
    if rule is None:
        raise RegistaError(
            ErrorCode.RECURRENCE_RULE_NOT_FOUND,
            f"Recurrence rule {rule_id} not found",
        )
    if rule["status"] != "active":
        raise RegistaError(
            ErrorCode.RECURRENCE_RULE_EXHAUSTED,
            f"Recurrence rule {rule_id} is {rule['status']!r}",
        )
    now = datetime.now(UTC)
    scheduled_fire_at = rule["next_fire_at"]
    catchup = rule.get("catchup_policy", "fire_once")

    if scheduled_fire_at > now:
        return rule, None

    if catchup == "skip":
        future_fire = _find_next_future_slot(
            rule["schedule_kind"],
            rule["schedule_expr"],
            rule["timezone"],
            rule["start_at"],
            scheduled_fire_at,
            now,
            rule["end_at"],
        )
        if future_fire is None:
            rule["status"] = "exhausted"
            rule["next_fire_at"] = now + timedelta(days=36500)
        else:
            rule["next_fire_at"] = future_fire
        rule["updated_at"] = now
        return rule, None

    next_fire = compute_next_fire(
        rule["schedule_kind"],
        rule["schedule_expr"],
        rule["timezone"],
        rule["start_at"],
        scheduled_fire_at,
        rule["end_at"],
    )

    if catchup == "fire_once" and next_fire is not None and next_fire <= now:
        future_fire = _find_next_future_slot(
            rule["schedule_kind"],
            rule["schedule_expr"],
            rule["timezone"],
            rule["start_at"],
            next_fire,
            now,
            rule["end_at"],
        )
        next_fire = future_fire

    template = rule["template"]
    not_before_offset = template.get("not_before_offset_seconds", 0)
    not_before = (
        scheduled_fire_at + timedelta(seconds=not_before_offset)
        if not_before_offset
        else scheduled_fire_at
    )
    custom_fields = template.get("custom_fields", {})
    raw = hashlib.sha256(
        rule_id.bytes + scheduled_fire_at.isoformat().encode()
    ).digest()[:16]
    event_id = uuid.UUID(bytes=bytes(raw[0:4] + raw[4:6] + raw[6:8] + raw[8:16]))
    wi, _evt = create_work_item_fn(
        workflow_name=rule["workflow_name"],
        work_item_type=rule["work_item_type"],
        actor_id="system:scheduler",
        actor_kind="system",
        actor_metadata={
            "recurrence_rule_id": str(rule_id),
            "scheduled_fire_at": scheduled_fire_at.isoformat(),
        },
        custom_fields=custom_fields,
        not_before=not_before,
        event_id=event_id,
        skip_event_id_version_check=True,
    )
    new_count = rule["count_remaining"]
    if new_count is not None:
        new_count -= 1
    if new_count is not None and new_count <= 0:
        new_status = "exhausted"
        next_fire = None
    elif next_fire is None:
        new_status = "exhausted"
    else:
        new_status = "active"
    rule["last_fired_at"] = now
    rule["next_fire_at"] = next_fire or now + timedelta(days=36500)
    rule["count_remaining"] = new_count
    rule["status"] = new_status
    rule["updated_at"] = now
    return rule, dict(wi.to_dict()) if hasattr(wi, "to_dict") else dict(wi)


def in_memory_cancel_recurrence_rule(
    recurrence_rules: dict[uuid.UUID, dict[str, Any]],
    rule_id: uuid.UUID,
) -> None:
    rule = recurrence_rules.get(rule_id)
    if rule is None:
        raise RegistaError(
            ErrorCode.RECURRENCE_RULE_NOT_FOUND,
            f"Recurrence rule {rule_id} not found",
        )
    rule["status"] = "cancelled"
    rule["updated_at"] = datetime.now(UTC)


def in_memory_update_recurrence_rule(
    recurrence_rules: dict[uuid.UUID, dict[str, Any]],
    rule_id: uuid.UUID,
    *,
    status: str | None = None,
    schedule_expr: str | None = None,
    template: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rule = recurrence_rules.get(rule_id)
    if rule is None:
        raise RegistaError(
            ErrorCode.RECURRENCE_RULE_NOT_FOUND,
            f"Recurrence rule {rule_id} not found",
        )
    if status is not None:
        rule["status"] = status
    if schedule_expr is not None:
        rule["schedule_expr"] = schedule_expr
    if template is not None:
        rule["template"] = template
    rule["updated_at"] = datetime.now(UTC)
    return dict(rule)
