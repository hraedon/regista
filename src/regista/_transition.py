from __future__ import annotations

import uuid
from datetime import UTC, datetime

import structlog

from ._contract import VALIDATOR_HISTORY_LIMIT
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
from ._types import Event, ValidatorContext

log = structlog.get_logger()


def transition(
    mgr,
    keys,
    metrics: Metrics,
    project: str,
    validators: dict,
    hook_channel: str,
    work_item_id: uuid.UUID,
    transition_name: str,
    actor_id: str,
    actor_kind: str = "agent",
    actor_metadata: dict | None = None,
    *,
    payload: dict | None = None,
    custom_fields: dict | None = None,
    event_id: uuid.UUID | None = None,
    expected_event_seq: int | None = None,
    on_behalf_of: dict | None = None,
    strict_roles: bool = False,
    key_id: str | None = None,
) -> Event:
    if event_id is None:
        event_id = uuid.uuid4()
    _validate_mutation_params(
        actor_id=actor_id,
        actor_kind=actor_kind,
        event_id=event_id,
    )
    _validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())

    timer = OpTimer(project, "transition")
    try:
        with mgr.transaction() as conn:
            wi_row = conn.execute(
                "SELECT workflow_name, workflow_version, current_state, "
                "work_item_type, custom_fields "
                "FROM work_items_current WHERE work_item_id = %s FOR UPDATE",
                [work_item_id],
            ).fetchone()
            if wi_row is None:
                raise RegistaError(
                    ErrorCode.WORK_ITEM_NOT_FOUND,
                    f"Work item {work_item_id} not found",
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

            _check_privileged_transition(
                transition_def,
                actor_kind,
                transition_name,
            )

            _check_role_gating(
                transition_def.get("allowed_roles", []),
                actor_metadata,
                transition_name,
            )
            if transition_def.get("allowed_roles"):
                role = (actor_metadata or {}).get("role")
                from ._actor_roles import check_actor_role_authorized
                check_actor_role_authorized(
                    conn, actor_id, role,
                    strict=strict_roles, actor_metadata=actor_metadata,
                )

            if custom_fields:
                from ._workflow import validate_field_update, validate_work_item_refs
                validate_field_update(defn, wi_row["work_item_type"], custom_fields)
                validate_work_item_refs(conn, defn, wi_row["work_item_type"], custom_fields)

            new_state = transition_def["to_state"]

            validator_name = transition_def.get("validator")
            if validator_name:
                handler = validators.get(validator_name)
                if handler is not None:
                    from ._events import read_events_by_work_item
                    from ._hooks import run_validator

                    conn.execute("SET LOCAL statement_timeout = '5s'")
                    prior_events = tuple(read_events_by_work_item(
                        conn, work_item_id, limit=VALIDATOR_HISTORY_LIMIT,
                    ))
                    ctx = ValidatorContext(
                        work_item_id=work_item_id,
                        workflow_name=wi_row["workflow_name"],
                        workflow_version=wi_row["workflow_version"],
                        work_item_type=wi_row["work_item_type"],
                        current_state=wi_row["current_state"],
                        new_state=new_state,
                        transition_name=transition_name,
                        payload=payload,
                        custom_fields=wi_row["custom_fields"] or {},
                        actor_id=actor_id,
                        actor_metadata=actor_metadata,
                        actor_kind=actor_kind,
                        prior_events=prior_events,
                        on_behalf_of=(
                            dict(on_behalf_of) if on_behalf_of is not None else None
                        ),
                    )
                    try:
                        run_validator(
                            validator_name, handler, ctx,
                            metrics=metrics, project=project,
                        )
                        metrics.inc("validators_succeeded", project)
                    except RegistaError:
                        # BC-192: VALIDATOR_TIMEOUT branch removed — validators
                        # no longer have a Python-side wall-clock bound. A DB
                        # statement_timeout firing raises psycopg.QueryCanceled,
                        # not RegistaError.
                        metrics.inc("validators_failed", project)
                        raise
                else:
                    log.warning(
                        "validator.not_registered",
                        validator=validator_name,
                        transition=transition_name,
                    )

            evt = _append_transition_event(
                conn,
                work_item_id=work_item_id,
                actor_id=actor_id,
                actor_kind=actor_kind,
                actor_metadata=_Jsonb(actor_metadata) if actor_metadata is not None else None,
                key_set=keys,
                transition_name=transition_name,
                new_state=new_state,
                payload=_Jsonb(payload) if payload is not None else None,
                event_id=event_id,
                expected_event_seq=expected_event_seq,
                custom_fields_update=custom_fields,
                release_claim=True,
                on_behalf_of=on_behalf_of,
                _key_id=key_id,
            )

            hook_names = transition_def.get("hooks", [])
            if hook_names:
                from ._hooks import enqueue_hooks

                hook_defaults = defn.get("hook_defaults") or {}
                wf_max_retries = hook_defaults.get("max_retries", 3)

                enqueue_hooks(
                    conn,
                    event_id=evt.event_id,
                    work_item_id=work_item_id,
                    hook_names=hook_names,
                    transition=transition_name,
                    event_payload=payload,
                    channel=hook_channel,
                    max_retries=wf_max_retries,
                )
                metrics.inc("hooks_dispatched", project, amount=len(hook_names))

        metrics.inc("events_appended", project)
        metrics.inc("transitions_accepted", project)
        timer.log("ok", work_item_id=str(work_item_id), transition=transition_name)
        return evt
    except RegistaError as e:
        if e.code in (ErrorCode.INVALID_TRANSITION, ErrorCode.ROLE_NOT_PERMITTED):
            metrics.inc("transitions_rejected", project)
        timer.log("rejected", work_item_id=str(work_item_id))
        raise
