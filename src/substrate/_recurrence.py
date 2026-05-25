from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import psycopg.types.json
import structlog

from ._errors import ErrorCode, SubstrateError

log = structlog.get_logger()


def _now() -> datetime:
    return datetime.now(UTC)


def compute_next_fire(
    schedule_kind: str,
    schedule_expr: str,
    timezone: str,
    start_at: datetime,
    last_fired_at: datetime | None,
    end_at: datetime | None,
) -> datetime | None:
    if schedule_kind == "interval":
        td = _parse_iso8601_duration(schedule_expr)
        base = last_fired_at if last_fired_at is not None else start_at
        next_fire = base + td
        if end_at is not None and next_fire > end_at:
            return None
        return next_fire
    elif schedule_kind == "rrule":
        try:
            from dateutil import rrule, tz
        except ImportError as e:
            raise SubstrateError(
                ErrorCode.RECURRENCE_SCHEDULE_INVALID,
                "python-dateutil is required for rrule schedules",
            ) from e
        tzinfo = tz.gettz(timezone) or UTC
        if last_fired_at is not None:
            after = last_fired_at.astimezone(tzinfo)
        else:
            after = start_at.astimezone(tzinfo) - timedelta(seconds=1)
        rule = rrule.rrulestr(schedule_expr, dtstart=start_at.astimezone(tzinfo))
        next_fire = rule.after(after, inc=False)
        if next_fire is None:
            return None
        next_fire_utc = next_fire.astimezone(UTC)
        if end_at is not None and next_fire_utc > end_at:
            return None
        return next_fire_utc
    else:
        raise SubstrateError(
            ErrorCode.RECURRENCE_SCHEDULE_INVALID,
            f"Unknown schedule_kind {schedule_kind!r}",
        )



def _parse_iso8601_duration(expr: str) -> timedelta:
    import re

    expr = expr.strip()
    pattern = r"""
        P
        (?: (?P<years> \d+ ) Y )?
        (?: (?P<months> \d+ ) M )?
        (?: (?P<weeks> \d+ ) W )?
        (?: (?P<days> \d+ ) D )?
        (?: T
            (?: (?P<hours> \d+ ) H )?
            (?: (?P<minutes> \d+ ) M )?
            (?: (?P<seconds> \d+(?:\.\d+)? ) S )?
        )?
    """
    m = re.fullmatch(pattern, expr, re.VERBOSE)
    if not m:
        raise SubstrateError(
            ErrorCode.RECURRENCE_SCHEDULE_INVALID,
            f"Invalid ISO-8601 duration: {expr!r}",
        )
    groups = m.groupdict()
    int_groups = {k: int(v) if v else 0
                  for k, v in groups.items() if k != "seconds"}
    seconds_val = groups.get("seconds")
    int_groups["seconds"] = float(seconds_val) if seconds_val else 0
    if all(v == 0 for v in int_groups.values()):
        raise SubstrateError(
            ErrorCode.RECURRENCE_SCHEDULE_INVALID,
            f"Invalid ISO-8601 duration: {expr!r}",
        )
    from dateutil.relativedelta import relativedelta

    rd = relativedelta(
        years=int_groups["years"],
        months=int_groups["months"],
        weeks=int_groups["weeks"],
        days=int_groups["days"],
        hours=int_groups["hours"],
        minutes=int_groups["minutes"],
        seconds=int_groups["seconds"],
    )
    base = datetime(1970, 1, 1, tzinfo=UTC)
    return (base + rd) - base


def _find_next_future_slot(
    schedule_kind: str,
    schedule_expr: str,
    timezone: str,
    start_at: datetime,
    after_slot: datetime,
    now: datetime,
    end_at: datetime | None,
) -> datetime | None:
    if schedule_kind == "interval":
        td = _parse_iso8601_duration(schedule_expr)
        if td.total_seconds() <= 0:
            return None
        elapsed = (now - after_slot).total_seconds()
        interval_secs = td.total_seconds()
        steps = int(elapsed // interval_secs) + 1
        candidate = after_slot + timedelta(seconds=steps * interval_secs)
        if end_at is not None and candidate > end_at:
            return None
        return candidate

    candidate = after_slot
    max_iterations = 10000
    for _ in range(max_iterations):
        next_candidate = compute_next_fire(
            schedule_kind, schedule_expr, timezone, start_at, candidate, end_at,
        )
        if next_candidate is None:
            return None
        if next_candidate > now:
            return next_candidate
        candidate = next_candidate
    raise SubstrateError(
        ErrorCode.RECURRENCE_SCHEDULE_INVALID,
        f"Catch-up iteration cap exceeded for rrule schedule {schedule_expr!r}",
    )


def validate_template(template: dict) -> None:
    if not isinstance(template, dict):
        raise SubstrateError(
            ErrorCode.RECURRENCE_TEMPLATE_INVALID,
            "template must be a dict",
        )
    if "custom_fields" in template and not isinstance(template["custom_fields"], dict):
        raise SubstrateError(
            ErrorCode.RECURRENCE_TEMPLATE_INVALID,
            "template.custom_fields must be a dict",
        )


def validate_schedule(schedule_kind: str, schedule_expr: str) -> None:
    if schedule_kind == "rrule":
        try:
            from dateutil import rrule

            rrule.rrulestr(schedule_expr)
        except Exception as e:
            raise SubstrateError(
                ErrorCode.RECURRENCE_SCHEDULE_INVALID,
                f"Invalid RRULE string: {e}",
            ) from e
    elif schedule_kind == "interval":
        _parse_iso8601_duration(schedule_expr)
    else:
        raise SubstrateError(
            ErrorCode.RECURRENCE_SCHEDULE_INVALID,
            f"Unknown schedule_kind {schedule_kind!r}",
        )


def register_recurrence_rule(
    conn,
    rule_id: uuid.UUID,
    workflow_name: str,
    workflow_version: int,
    work_item_type: str,
    template: dict,
    schedule_kind: str,
    schedule_expr: str,
    timezone: str,
    start_at: datetime,
    end_at: datetime | None,
    count: int | None,
    catchup_policy: str,
    created_by: str,
) -> dict:
    from psycopg.sql import SQL

    validate_schedule(schedule_kind, schedule_expr)
    validate_template(template)
    next_fire = compute_next_fire(schedule_kind, schedule_expr, timezone, start_at, None, end_at)
    if next_fire is None:
        next_fire = start_at
    row = conn.execute(
        SQL(
            "INSERT INTO recurrence_rules "
            "(rule_id, workflow_name, workflow_version, work_item_type, "
            "template, schedule_kind, schedule_expr, timezone, start_at, "
            "end_at, count_remaining, status, catchup_policy, next_fire_at, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
            "RETURNING *"
        ),
        [
            rule_id, workflow_name, workflow_version, work_item_type,
            psycopg.types.json.Jsonb(template), schedule_kind, schedule_expr, timezone, start_at,
            end_at, count, "active", catchup_policy, next_fire, created_by,
        ],
    ).fetchone()
    return dict(row)


def list_recurrence_rules(
    conn,
    status: str | None = None,
) -> list[dict]:
    from psycopg.sql import SQL

    query = SQL("SELECT * FROM recurrence_rules")
    params = []
    if status is not None:
        query = SQL("SELECT * FROM recurrence_rules WHERE status = %s")
        params = [status]
    query = query + SQL(" ORDER BY created_at")
    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def due_recurrences(conn, now: datetime | None = None) -> list[dict]:
    if now is None:
        now = _now()
    rows = conn.execute(
        "SELECT * FROM recurrence_rules WHERE status = 'active' AND next_fire_at <= %s "
        "ORDER BY next_fire_at",
        [now],
    ).fetchall()
    return [dict(r) for r in rows]


def fire_recurrence(
    conn,
    rule_id: uuid.UUID,
    scheduler_actor_id: str,
    key_set,
    metrics,
    project: str,
) -> tuple[dict, dict]:
    from psycopg.sql import SQL

    from ._work_items import create_work_item as _create_work_item

    row = conn.execute(
        "SELECT * FROM recurrence_rules WHERE rule_id = %s FOR UPDATE",
        [rule_id],
    ).fetchone()
    if row is None:
        raise SubstrateError(
            ErrorCode.RECURRENCE_RULE_NOT_FOUND,
            f"Recurrence rule {rule_id} not found",
        )
    rule = dict(row)
    if rule["status"] != "active":
        raise SubstrateError(
            ErrorCode.RECURRENCE_RULE_EXHAUSTED,
            f"Recurrence rule {rule_id} is {rule['status']!r}",
        )
    now = _now()
    scheduled_fire_at = rule["next_fire_at"]
    catchup = rule.get("catchup_policy", "fire_once")

    if scheduled_fire_at > now:
        import psycopg.types.json as _pg_json
        from psycopg.sql import SQL

        evt_row = conn.execute(
            SQL(
                "SELECT work_item_id FROM events "
                "WHERE transition = 'created' "
                "AND actor_metadata @> %s "
                "ORDER BY timestamp DESC LIMIT 1"
            ),
            [_pg_json.Jsonb({"recurrence_rule_id": str(rule_id)})],
        ).fetchone()
        existing_wi = None
        if evt_row is not None:
            wi_row = conn.execute(
                SQL("SELECT * FROM work_items_current WHERE work_item_id = %s"),
                [evt_row["work_item_id"]],
            ).fetchone()
            if wi_row is not None:
                existing_wi = dict(wi_row)
        return rule, existing_wi

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
            conn.execute(
                SQL(
                    "UPDATE recurrence_rules SET status = 'exhausted', "
                    "next_fire_at = %s, updated_at = now() WHERE rule_id = %s"
                ),
                [now + timedelta(days=36500), rule_id],
            )
            rule["status"] = "exhausted"
        else:
            conn.execute(
                SQL(
                    "UPDATE recurrence_rules SET next_fire_at = %s, updated_at = now() "
                    "WHERE rule_id = %s"
                ),
                [future_fire, rule_id],
            )
            rule["next_fire_at"] = future_fire
        metrics.inc("recurrence_fires_skipped", project)
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

    template = rule["template"]
    not_before_offset = template.get("not_before_offset_seconds", 0)
    not_before = (
        scheduled_fire_at + timedelta(seconds=not_before_offset)
        if not_before_offset
        else scheduled_fire_at
    )
    custom_fields = template.get("custom_fields", {})
    event_id = uuid.uuid5(rule_id, scheduled_fire_at.isoformat())

    from ._contract import Jsonb as _Jsonb

    wi, _evt = _create_work_item(
        conn,
        workflow_name=rule["workflow_name"],
        work_item_type=rule["work_item_type"],
        actor_id=scheduler_actor_id,
        actor_kind="system",
        actor_metadata=_Jsonb({
            "recurrence_rule_id": str(rule_id),
            "scheduled_fire_at": scheduled_fire_at.isoformat(),
        }),
        key_set=key_set,
        custom_fields=custom_fields,
        not_before=not_before,
        event_id=event_id,
    )

    conn.execute(
        SQL(
            "UPDATE recurrence_rules SET last_fired_at = %s, next_fire_at = %s, "
            "count_remaining = %s, status = %s, updated_at = now() "
            "WHERE rule_id = %s"
        ),
        [now, next_fire or now + timedelta(days=36500), new_count, new_status, rule_id],
    )

    metrics.inc("recurrence_fires_total", project)
    return rule, dict(wi.to_dict()) if hasattr(wi, "to_dict") else dict(wi)


def cancel_recurrence_rule(conn, rule_id: uuid.UUID) -> None:
    row = conn.execute(
        "UPDATE recurrence_rules SET status = 'cancelled', updated_at = now() "
        "WHERE rule_id = %s RETURNING rule_id",
        [rule_id],
    ).fetchone()
    if row is None:
        raise SubstrateError(
            ErrorCode.RECURRENCE_RULE_NOT_FOUND,
            f"Recurrence rule {rule_id} not found",
        )


def update_recurrence_rule(
    conn,
    rule_id: uuid.UUID,
    *,
    status: str | None = None,
    schedule_expr: str | None = None,
    template: dict | None = None,
) -> dict:
    row = conn.execute("SELECT * FROM recurrence_rules WHERE rule_id = %s", [rule_id]).fetchone()
    if row is None:
        raise SubstrateError(
            ErrorCode.RECURRENCE_RULE_NOT_FOUND,
            f"Recurrence rule {rule_id} not found",
        )
    rule = dict(row)
    updates = []
    params = []
    if status is not None:
        updates.append("status = %s")
        params.append(status)
    if schedule_expr is not None:
        validate_schedule(rule["schedule_kind"], schedule_expr)
        updates.append("schedule_expr = %s")
        params.append(schedule_expr)
    if template is not None:
        validate_template(template)
        updates.append("template = %s")
        params.append(psycopg.types.json.Jsonb(template))
    if not updates:
        return rule
    updates.append("updated_at = now()")
    query = "UPDATE recurrence_rules SET " + ", ".join(updates) + " WHERE rule_id = %s RETURNING *"
    params.append(rule_id)
    row = conn.execute(query, params).fetchone()
    return dict(row)
