from __future__ import annotations

import uuid
from datetime import UTC, datetime


def register_recurrence_rule(
    mgr,
    metrics,
    project,
    workflow_name: str,
    workflow_version: int,
    work_item_type: str,
    template: dict,
    schedule_kind: str,
    schedule_expr: str,
    *,
    timezone: str = "UTC",
    start_at: datetime | None = None,
    end_at: datetime | None = None,
    count: int | None = None,
    catchup_policy: str = "fire_once",
    created_by: str = "system",
):
    from ._recurrence import register_recurrence_rule as _register_rr

    if start_at is None:
        start_at = datetime.now(UTC)
    with mgr.transaction() as conn:
        rule = _register_rr(
            conn,
            rule_id=uuid.uuid4(),
            workflow_name=workflow_name,
            workflow_version=workflow_version,
            work_item_type=work_item_type,
            template=template,
            schedule_kind=schedule_kind,
            schedule_expr=schedule_expr,
            timezone=timezone,
            start_at=start_at,
            end_at=end_at,
            count=count,
            catchup_policy=catchup_policy,
            created_by=created_by,
        )
    metrics.inc("recurrence_rules_registered", project)
    return rule


def list_recurrence_rules(mgr, status: str | None = None) -> list:
    from ._recurrence import list_recurrence_rules as _list_rr

    with mgr.transaction() as conn:
        return _list_rr(conn, status=status)


def due_recurrences(mgr, now: datetime | None = None) -> list:
    from ._recurrence import due_recurrences as _due

    with mgr.transaction() as conn:
        return _due(conn, now=now)


def fire_recurrence(mgr, keys, metrics, project, rule_id: uuid.UUID) -> tuple[dict, dict]:
    from ._recurrence import fire_recurrence as _fire

    with mgr.transaction() as conn:
        return _fire(
            conn, rule_id, "system:scheduler", keys, metrics, project,
        )


def cancel_recurrence_rule(mgr, rule_id: uuid.UUID) -> None:
    from ._recurrence import cancel_recurrence_rule as _cancel

    with mgr.transaction() as conn:
        _cancel(conn, rule_id)


def update_recurrence_rule(
    mgr,
    rule_id: uuid.UUID,
    *,
    status: str | None = None,
    schedule_expr: str | None = None,
    template: dict | None = None,
) -> dict:
    from ._recurrence import update_recurrence_rule as _update

    with mgr.transaction() as conn:
        return _update(
            conn, rule_id, status=status, schedule_expr=schedule_expr,
            template=template,
        )
