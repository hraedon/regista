from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, cast

import structlog

from ._connection import ConnectionManager
from ._contract import (
    Jsonb as _Jsonb,
)
from ._contract import (
    check_privileged_transition as _check_privileged_transition,
)
from ._contract import (
    check_role_gating as _check_role_gating,
)
from ._contract import (
    resolve_transition as _resolve_transition,
)
from ._contract import (
    validate_delegation_chain as _validate_delegation_chain,
)
from ._contract import (
    validate_mutation_params as _validate_mutation_params,
)
from ._errors import ErrorCode, RegistaError
from ._events import append_transition_event as _append_transition_event
from ._observability import Metrics, OpTimer
from ._types import Event

log = structlog.get_logger()


def transition(
    mgr: ConnectionManager,
    metrics: Metrics,
    project: str,
    work_item_id: uuid.UUID,
    transition_name: str,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict[str, Any] | None = None,
    *,
    payload: dict[str, Any] | None = None,
    custom_fields: dict[str, Any] | None = None,
    event_id: uuid.UUID | None = None,
    expected_event_seq: int | None = None,
    on_behalf_of: dict[str, Any] | None = None,
    strict_roles: bool = False,
    expected_attempt_number: int | None = None,
) -> Event:
    if event_id is None:
        event_id = uuid.uuid4()
    _validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata=actor_metadata,
        event_id=event_id,
    )
    _validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())

    timer = OpTimer(project, "transition")
    try:
        with mgr.transaction() as conn:
            wi_row = conn.execute(
                "SELECT workflow_name, workflow_version, current_state, "
                "work_item_type, custom_fields, attempt_number "
                "FROM work_items_current WHERE work_item_id = %s FOR UPDATE",
                [work_item_id],
            ).fetchone()
            if wi_row is None:
                raise RegistaError(
                    ErrorCode.WORK_ITEM_NOT_FOUND,
                    f"Work item {work_item_id} not found",
                )

            if (
                expected_attempt_number is not None
                and wi_row["attempt_number"] != expected_attempt_number
            ):
                raise RegistaError(
                    ErrorCode.CLAIM_LOST,
                    f"work item {work_item_id} is on attempt "
                    f"{wi_row['attempt_number']}, not {expected_attempt_number}; "
                    "the lease was lost or stolen",
                    detail={
                        "expected_attempt_number": expected_attempt_number,
                        "actual_attempt_number": wi_row["attempt_number"],
                    },
                )

            wf_data = conn.execute(
                "SELECT definition FROM workflow_registry "
                "WHERE workflow_name = %s AND version = %s",
                [wi_row["workflow_name"], wi_row["workflow_version"]],
            ).fetchone()
            if wf_data is None:
                raise RegistaError(
                    ErrorCode.WORKFLOW_NOT_REGISTERED,
                    f"Workflow {wi_row['workflow_name']!r} "
                    f"v{wi_row['workflow_version']} not found",
                )

            defn = wf_data["definition"]
            transition_def = _resolve_transition(
                defn.get("transitions", []),
                wi_row["current_state"],
                transition_name,
                wi_row["workflow_name"],
                wi_row["workflow_version"],
            )

            _check_privileged_transition(transition_def, actor_kind, transition_name)
            _check_role_gating(
                transition_def.get("allowed_roles", []),
                actor_metadata,
                transition_name,
            )
            if transition_def.get("allowed_roles") or strict_roles:
                role = (actor_metadata or {}).get("role")
                from ._actor_roles import check_actor_role_authorized

                check_actor_role_authorized(
                    conn, actor_id, cast(str, role),
                    strict=strict_roles, actor_metadata=actor_metadata,
                )

            if custom_fields:
                from ._workflow import validate_field_update, validate_work_item_refs

                validate_field_update(defn, wi_row["work_item_type"], custom_fields)
                validate_work_item_refs(conn, defn, wi_row["work_item_type"], custom_fields)

            new_state = transition_def["to_state"]

            evt = _append_transition_event(
                conn,
                work_item_id=work_item_id,
                actor_id=actor_id,
                actor_kind=actor_kind,
                actor_metadata=_Jsonb(actor_metadata) if actor_metadata is not None else None,
                transition_name=transition_name,
                new_state=new_state,
                payload=_Jsonb(payload) if payload is not None else None,
                event_id=event_id,
                expected_event_seq=expected_event_seq,
                custom_fields_update=custom_fields,
                release_claim=True,
                on_behalf_of=on_behalf_of,
            )

        metrics.inc("events_appended", project)
        metrics.inc("transitions_accepted", project)
        timer.log("ok", work_item_id=str(work_item_id), transition=transition_name)
        return evt
    except RegistaError as e:
        if e.code in (ErrorCode.INVALID_TRANSITION, ErrorCode.ROLE_NOT_PERMITTED):
            metrics.inc("transitions_rejected", project)
        timer.log("rejected", work_item_id=str(work_item_id))
        raise
