from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, cast

import structlog

from ._connection import ConnectionManager
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
from ._datetime_utils import v6_occurred_at
from ._errors import ErrorCode, RegistaError
from ._events import _v6_epoch_open
from ._events import append_transition_event as _append_transition_event
from ._keys import KeySet
from ._observability import Metrics, OpTimer
from ._types import AuthorizationEvidence, Event, ValidatorContext

log = structlog.get_logger()


def transition(
    mgr: ConnectionManager,
    keys: KeySet,
    metrics: Metrics,
    project: str,
    validators: dict[str, Any],
    hook_channel: str,
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
    key_id: str | None = None,
    action_delegation_credentials: tuple[dict[str, Any] | bytes, ...] = (),
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
            resolved_occurred_at = datetime.now(UTC)
            v6_producer = None
            if _v6_epoch_open(conn):
                from ._v6_writer import resolve_producer

                v6_producer = resolve_producer()
            authorization_evidence = _verify_validator_authorization(
                conn,
                work_item_id=work_item_id,
                workflow_name=wi_row["workflow_name"],
                transition_name=transition_name,
                actor_id=actor_id,
                credentials=action_delegation_credentials,
                occurred_at=resolved_occurred_at,
            )

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
                    prior_material = _prior_event_delegation_material(conn)
                    prior_authorization_principals = (
                        _verified_prior_authorization_principals(
                            conn, prior_events, material=prior_material
                        )
                    )
                    prior_adversarial_pass_authorization_principals = (
                        _verified_prior_adversarial_pass_authorization_principals(
                            conn, prior_events, material=prior_material
                        )
                    )
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
                        producer=(
                            v6_producer.as_envelope_member()
                            if v6_producer is not None
                            else None
                        ),
                        on_behalf_of=(
                            dict(on_behalf_of) if on_behalf_of is not None else None
                        ),
                        validator_params=transition_def.get("validator_params"),
                        authorization_evidence=authorization_evidence,
                        prior_authorization_principals=(
                            prior_authorization_principals
                        ),
                        prior_adversarial_pass_authorization_principals=(
                            prior_adversarial_pass_authorization_principals
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
                    finally:
                        conn.execute("SET LOCAL statement_timeout = '0'")
                else:
                    metrics.inc("validators_failed", project)
                    log.error(
                        "validator.not_registered",
                        validator=validator_name,
                        transition=transition_name,
                    )
                    raise RegistaError(
                        ErrorCode.VALIDATOR_NOT_REGISTERED,
                        f"Validator {validator_name!r} is required by transition "
                        f"{transition_name!r} but is not registered",
                        detail={
                            "validator": validator_name,
                            "transition": transition_name,
                        },
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
                action_delegation_credentials=action_delegation_credentials,
                occurred_at=resolved_occurred_at,
                producer=v6_producer,
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


def _verify_validator_authorization(
    conn: Any,
    *,
    work_item_id: uuid.UUID,
    workflow_name: str,
    transition_name: str,
    actor_id: str,
    credentials: tuple[dict[str, Any] | bytes, ...],
    occurred_at: datetime,
) -> AuthorizationEvidence:
    if not credentials:
        return AuthorizationEvidence(mode="direct", status="not_applicable")
    from ._action_delegation import (
        ActionDelegationError,
        parse_action_delegation,
        verify_action_delegation_chain,
    )
    from ._events import _lock_global_chain_head
    from ._v6_referents import store_referents, walk_project_chain
    from ._v6_writer import require_v6_epoch

    identity = require_v6_epoch(conn, writer="transition.validator_authorization")
    head = _lock_global_chain_head(conn)
    if head is None:
        raise RegistaError(
            ErrorCode.ACTION_DELEGATION_INVALID,
            "delegated transition has no project chain head",
        )
    try:
        parsed = tuple(parse_action_delegation(item) for item in credentials)
    except (ActionDelegationError, TypeError, ValueError) as exc:
        raise RegistaError(
            ErrorCode.ACTION_DELEGATION_INVALID,
            f"the action-delegation credential document is invalid: {exc}",
        ) from exc
    references = [
        {
            "credential_id": str(item.credential_id),
            "credential_hash": item.credential_hash,
        }
        for item in parsed
    ]
    envelope = {
        "project_instance_id": str(identity.project_instance_id),
        "trust_domain_id": str(identity.trust_domain_id),
        "actor": {"principal_id": actor_id},
        "entity": {"kind": "work_item", "id": str(work_item_id)},
        "workflow": {"name": workflow_name},
        "transition": transition_name,
        "occurred_at": v6_occurred_at(occurred_at),
        "authorization": {"mode": "delegated", "credentials": references},
    }
    material = store_referents(conn, label="validator transaction")
    ancestors = tuple(walk_project_chain("sha256:" + head.hex(), material))
    try:
        result = verify_action_delegation_chain(
            envelope=envelope,
            references=references,
            credentials=parsed,
            ancestors=ancestors,
            referents=material,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise RegistaError(
            ErrorCode.ACTION_DELEGATION_INVALID,
            "action-delegation verification failed closed",
        ) from exc
    if not result.verified:
        raise RegistaError(
            ErrorCode.ACTION_DELEGATION_INVALID,
            result.reason or "action-delegation chain is invalid",
        )
    return AuthorizationEvidence(
        mode="delegated",
        status=result.status.value,
        credential_hashes=result.credential_hashes,
        participating_principals=result.participating_principals,
    )


def _verified_prior_authorization_principals(
    conn: Any, events: tuple[Event, ...], *, material: Any | None = None
) -> frozenset[str]:
    return _verified_prior_delegation_principals(
        conn,
        events,
        material=material,
        include_event=lambda event: event.transition not in {
            "accept",
            "request_changes",
            "adversarial_pass",
            "reject",
            "comment",
        },
    )


def _verified_prior_adversarial_pass_authorization_principals(
    conn: Any, events: tuple[Event, ...], *, material: Any | None = None
) -> frozenset[str]:
    """Re-verify delegated adversarial-pass participants for final acceptance."""

    return _verified_prior_delegation_principals(
        conn,
        events,
        material=material,
        include_event=lambda event: event.transition == "adversarial_pass",
        include_actor=True,
    )


def _prior_event_delegation_material(conn: Any) -> Any:
    """One resolver for a validator's whole prior-event pass, built once.

    A ``StoreReferents`` index costs one scan of the store, so the two prior-principal
    questions a review gate asks (authors, adversarial-pass participants) paid for two
    scans of the same unchanged material. Both take this as ``material``.
    """

    from ._v6_referents import store_referents

    return store_referents(conn, label="validator prior-event evidence")


def _verified_prior_delegation_principals(
    conn: Any,
    events: tuple[Event, ...],
    *,
    include_event: Any,
    include_actor: bool = False,
    material: Any | None = None,
) -> frozenset[str]:
    from ._action_delegation import verify_action_delegation_chain
    from ._v6_referents import walk_project_chain
    from ._verification import V6EnvelopeError, parse_v6_envelope_strict

    if material is None:
        material = _prior_event_delegation_material(conn)
    principals: set[str] = set()
    for event in events:
        if not include_event(event):
            continue
        if not event.canonical_envelope:
            continue
        try:
            envelope = parse_v6_envelope_strict(bytes(event.canonical_envelope))
        except (V6EnvelopeError, TypeError, ValueError):
            continue
        authorization = envelope["authorization"]
        if authorization["mode"] != "delegated":
            continue
        references = authorization["credentials"]
        credentials = []
        for reference in references:
            credential = material.resolve_action_credential(
                reference["credential_hash"]
            )
            if credential is None:
                raise RegistaError(
                    ErrorCode.ACTION_DELEGATION_INVALID,
                    "validator prior-event delegation evidence is missing",
                )
            credentials.append(credential)
        ancestors = tuple(
            walk_project_chain(
                envelope["chain"]["previous_project_event_hash"], material
            )
        )
        try:
            result = verify_action_delegation_chain(
                envelope=envelope,
                references=references,
                credentials=credentials,
                ancestors=ancestors,
                referents=material,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise RegistaError(
                ErrorCode.ACTION_DELEGATION_INVALID,
                "validator prior-event delegation verification failed closed",
            ) from exc
        if not result.verified:
            raise RegistaError(
                ErrorCode.ACTION_DELEGATION_INVALID,
                result.reason or "validator prior-event delegation is invalid",
            )
        principals.update(result.participating_principals)
        if include_actor:
            principals.add(event.actor_id)
            if isinstance(event.on_behalf_of, dict):
                principal_id = event.on_behalf_of.get("principal_id")
                if isinstance(principal_id, str) and principal_id:
                    principals.add(principal_id)
    return frozenset(principals)
