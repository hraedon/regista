"""Replay — rebuild the projection from the event log and compare with live state.

Events are the authoritative history; ``work_items_current`` is a projection.
This module folds each work item's events in ``event_seq`` order into the state
the projection should hold, then diffs against what is actually stored. Drift is
reported, never silently corrected.

The reduced contract has no signatures, envelopes, hash chains, or principal
binding, so replay performs no cryptographic verification. It is a consistency
and rebuildability check, not a hostile-administrator tamper detector.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import structlog
from psycopg.sql import SQL

from ._connection import DictConn
from ._datetime_utils import ts_equal as _ts_equal
from ._datetime_utils import ts_equal_within as _ts_equal_within
from ._errors import ErrorCode, RegistaError
from ._types import ReplayReport, ReplayReportEntry

log = structlog.get_logger()

_EVENT_FIELDS = (
    "event_id, work_item_id, entity_kind, entity_id, event_seq, actor_id, actor_kind, "
    "actor_metadata, workflow_name, workflow_version, timestamp, transition, payload, "
    "on_behalf_of"
)

_INTRINSIC_TRANSITIONS = frozenset(
    {
        "created",
        "escalated",
        "not_before_set",
        "link_created",
        "link_removed",
        "claim_acquired",
        "claim_stolen",
        "claim_released",
        "claim_expired",
        "claim_heartbeat",
    }
)


class _ReplayHaltError(Exception):
    def __init__(self, detail: str) -> None:
        self.detail = detail
        super().__init__(detail)


def drop_old_replay_tables(conn: DictConn, schema: str) -> None:
    """Drop legacy permanent replay tables from older installations.

    Replay no longer materialises a table; this only cleans up residue left by
    pre-0.8.0 runs. The fresh baseline has no such tables, so it is a no-op
    there.
    """
    row = conn.execute(
        SQL(
            "SELECT table_name FROM information_schema.tables "
            "WHERE table_schema = %s AND table_name LIKE 'work_items_current_replay_%%'"
        ),
        [schema],
    ).fetchall()
    for r in row:
        conn.execute(SQL('DROP TABLE IF EXISTS {}.{}').format(
            SQL(schema), SQL(r["table_name"]),
        ))


def _parse_not_before(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        log.warning("replay.malformed_not_before", value=value)
        return None


def _parse_claim_expires(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        log.warning("replay.malformed_claim_expires", value=value)
        return None


def _replay_work_item(
    wi_id: Any,
    events: list[dict[str, Any]],
    wf_defs: dict[tuple[str, int], dict[str, Any]],
) -> tuple[dict[str, Any], int]:
    """Fold a work item's event prefix into projection state.

    Returns ``(state, warnings)``. Raises ``_ReplayHaltError`` when the log
    cannot be reduced at all (missing workflow, an event that claims a
    transition valid in no state).
    """
    state: str | None = None
    custom_fields: dict[str, Any] = {}
    needs_review = False
    not_before: datetime | None = None
    last_seq = 0
    attempt_number = 0
    claimed_by: str | None = None
    claim_expires_at: datetime | None = None
    claim_coalesce_threshold: float = 0.0
    warnings = 0
    seen_created = False

    for evt in events:
        transition = evt["transition"]
        last_seq = evt["event_seq"]

        if transition == "created":
            payload = evt["payload"] or {}
            state = payload.get("initial_state")
            custom_fields = payload.get("custom_fields", {}) or {}
            not_before = _parse_not_before(payload.get("not_before"))
            seen_created = True
            continue

        if not seen_created:
            raise _ReplayHaltError(
                f"work item {wi_id} has event_seq {evt['event_seq']} before any 'created' event"
            )

        if transition in _INTRINSIC_TRANSITIONS:
            payload = evt["payload"] or {}
            if transition in ("claim_acquired", "claim_stolen"):
                attempt_number += 1
            if transition == "claim_acquired":
                claimed_by = payload.get("actor_id")
                claim_expires_at = _parse_claim_expires(payload.get("expires_at"))
            elif transition == "claim_stolen":
                claimed_by = payload.get("new_actor_id")
                claim_expires_at = _parse_claim_expires(payload.get("expires_at"))
            elif transition == "claim_heartbeat":
                claim_expires_at = _parse_claim_expires(payload.get("expires_at"))
                claim_coalesce_threshold = payload.get("coalesce_threshold") or 0.0
            elif transition in ("claim_released", "claim_expired"):
                claimed_by = None
                claim_expires_at = None
                claim_coalesce_threshold = 0.0
            elif transition == "escalated":
                needs_review = True
            elif transition == "not_before_set":
                not_before = _parse_not_before(payload.get("not_before"))
            continue

        defn = wf_defs.get((evt["workflow_name"], evt["workflow_version"]))
        if defn is None:
            raise _ReplayHaltError(
                f"missing workflow {evt['workflow_name']!r} v{evt['workflow_version']}"
            )
        found = False
        for t in defn.get("transitions", []):
            if t["name"] == transition and t["from_state"] == state:
                state = t["to_state"]
                found = True
                break
        if not found:
            if any(t["name"] == transition for t in defn.get("transitions", [])):
                raise _ReplayHaltError(
                    f"transition {transition!r} is not valid from state {state!r}"
                )
            warnings += 1
            log.warning(
                "replay.unknown_transition",
                work_item_id=str(wi_id),
                event_seq=evt["event_seq"],
                transition=transition,
            )
            continue

        payload = evt["payload"] or {}
        if payload.get("custom_fields_update"):
            custom_fields = {**custom_fields, **payload["custom_fields_update"]}
        claimed_by = None
        claim_expires_at = None
        claim_coalesce_threshold = 0.0

    return (
        {
            "current_state": state,
            "custom_fields": custom_fields,
            "needs_review": needs_review,
            "not_before": not_before,
            "last_event_seq": last_seq,
            "attempt_number": attempt_number,
            "claimed_by": claimed_by,
            "claim_expires_at": claim_expires_at,
            "claim_coalesce_threshold": claim_coalesce_threshold,
        },
        warnings,
    )


def _states_match(replayed: dict[str, Any], live: dict[str, Any]) -> bool:
    if replayed["current_state"] != live["current_state"]:
        return False
    if replayed["last_event_seq"] != live["last_event_seq"]:
        return False
    if replayed["custom_fields"] != live["custom_fields"]:
        return False
    if replayed["needs_review"] != live["needs_review"]:
        return False
    if not _ts_equal(replayed["not_before"], live["not_before"]):
        return False
    if replayed["attempt_number"] != live["attempt_number"]:
        return False
    if replayed["claimed_by"] != live["claimed_by"]:
        return False
    threshold = replayed.get("claim_coalesce_threshold", 0.0)
    if not _ts_equal_within(replayed["claim_expires_at"], live["claim_expires_at"], threshold):
        return False
    return True


def _diff_fields(replayed: dict[str, Any], live: dict[str, Any]) -> list[str]:
    diffs: list[str] = []
    if replayed["current_state"] != live["current_state"]:
        diffs.append("current_state")
    if replayed["last_event_seq"] != live["last_event_seq"]:
        diffs.append("last_event_seq")
    if replayed["custom_fields"] != live["custom_fields"]:
        diffs.append("custom_fields")
    if replayed["needs_review"] != live["needs_review"]:
        diffs.append("needs_review")
    if not _ts_equal(replayed["not_before"], live["not_before"]):
        diffs.append("not_before")
    if replayed["attempt_number"] != live["attempt_number"]:
        diffs.append("attempt_number")
    if replayed["claimed_by"] != live["claimed_by"]:
        diffs.append("claimed_by")
    threshold = replayed.get("claim_coalesce_threshold", 0.0)
    if not _ts_equal_within(replayed["claim_expires_at"], live["claim_expires_at"], threshold):
        diffs.append("claim_expires_at")
    return diffs


def replay(
    conn: DictConn,
    schema: str,
    project: str,
    *,
    work_item_id: Any | None = None,
    read_only: bool = False,
) -> ReplayReport:
    """Rebuild the projection from events and compare with the live table.

    Events are streamed in ``(work_item_id, event_seq)`` order through a
    server-side cursor, so a large log is reduced one work item at a time rather
    than materialised in full. Workflow definitions and the projection's id set
    are read first, so no further query runs while the cursor is open.
    """
    wf_defs: dict[tuple[str, int], dict[str, Any]] = {
        (row["workflow_name"], row["version"]): row["definition"]
        for row in conn.execute(
            "SELECT workflow_name, version, definition FROM workflow_registry"
        ).fetchall()
    }

    where_proj = "" if work_item_id is None else " WHERE work_item_id = %s"
    proj_params: list[Any] = [] if work_item_id is None else [work_item_id]
    projection_ids = {
        row["work_item_id"]
        for row in conn.execute(
            SQL("SELECT work_item_id FROM work_items_current" + where_proj),
            proj_params,
        ).fetchall()
    }

    where = "entity_kind = 'work_item'"
    params: list[Any] = []
    if work_item_id is not None:
        where += " AND work_item_id = %s"
        params.append(work_item_id)

    ok = 0
    drift = 0
    halted = 0
    warnings = 0
    entries: list[ReplayReportEntry] = []
    visited: set[Any] = set()

    def _finish_group(wi_id: Any, evts: list[dict[str, Any]]) -> None:
        nonlocal ok, drift, halted, warnings
        try:
            replayed, w = _replay_work_item(wi_id, evts, wf_defs)
            warnings += w
        except _ReplayHaltError as exc:
            halted += 1
            entries.append(
                ReplayReportEntry(work_item_id=wi_id, category="halted", detail=exc.detail)
            )
            return
        live_row = projection_cache.get(wi_id)
        if live_row is None:
            drift += 1
            entries.append(
                ReplayReportEntry(
                    work_item_id=wi_id,
                    category="drift",
                    detail="event log has no matching work_items_current row",
                    warnings=w,
                )
            )
        elif _states_match(replayed, live_row):
            ok += 1
            entries.append(
                ReplayReportEntry(work_item_id=wi_id, category="ok", detail=None, warnings=w)
            )
        else:
            drift += 1
            diffs = _diff_fields(replayed, live_row)
            entries.append(
                ReplayReportEntry(
                    work_item_id=wi_id,
                    category="drift",
                    detail="fields differ: " + ", ".join(diffs),
                    warnings=w,
                )
            )

    projection_cache: dict[Any, dict[str, Any]] = {}
    for row in conn.execute(
        SQL(
            "SELECT work_item_id, current_state, custom_fields, needs_review, not_before, "
            "last_event_seq, attempt_number, claimed_by, claim_expires_at "
            "FROM work_items_current" + where_proj
        ),
        proj_params,
    ).fetchall():
        projection_cache[row["work_item_id"]] = dict(row)

    cur = conn.cursor("regista_replay_events")
    cur.execute(
        SQL(f"SELECT {_EVENT_FIELDS} FROM events WHERE {where} ORDER BY work_item_id, event_seq"),
        params,
    )
    current_id: Any = None
    group: list[dict[str, Any]] = []

    def _flush() -> None:
        if current_id is not None and group:
            _finish_group(current_id, group)

    for r in cur:
        row = dict(r)
        key = row["work_item_id"]
        if key != current_id:
            _flush()
            current_id = key
            group = []
            visited.add(key)
        group.append(row)
    _flush()
    cur.close()

    for missing in projection_ids - visited:
        drift += 1
        entries.append(
            ReplayReportEntry(
                work_item_id=missing,
                category="drift",
                detail="projection row has no events in the log",
            )
        )

    log.info(
        "replay.completed",
        project=project,
        ok=ok,
        drift=drift,
        halted=halted,
        warnings=warnings,
    )
    return ReplayReport(
        table_name=None,
        replayed_ok=ok,
        replayed_drift=drift,
        halted=halted,
        warnings=warnings,
        entries=tuple(entries),
    )


__all__ = ["ErrorCode", "RegistaError", "drop_old_replay_tables", "replay"]
