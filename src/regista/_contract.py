from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from ._errors import ErrorCode, RegistaError
from ._types import Event

MAX_ACTOR_ID_LENGTH = 255
MAX_ROLE_LENGTH = 255
MAX_ACTOR_METADATA_BYTES = 65536
MAX_JSONB_BYTES = 1_048_576
VALIDATOR_HISTORY_LIMIT = 100_000

_VALID_ACTOR_KINDS = frozenset({"agent", "human", "system"})
_ALLOWED_ENTITY_KINDS = frozenset({"work_item", "session", "spec", "segment", "principal", "note"})

_RESERVED_TRANSITIONS = frozenset({
    "created",
    "claim_acquired",
    "claim_stolen",
    "claim_released",
    "claim_expired",
    "claim_heartbeat",
    "link_created",
    "link_removed",
    "escalated",
    "not_before_set",
    "hook_dead_lettered",
    "checkpoint",
})


def check_reserved_transition(transition: str | None) -> None:
    if transition in _RESERVED_TRANSITIONS:
        raise RegistaError(
            ErrorCode.TRANSITION_VIA_APPEND_BLOCKED,
            f"Transition {transition!r} is reserved and cannot be appended manually",
        )


def validate_event_id(event_id: uuid.UUID) -> None:
    if event_id.version != 4:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"event_id must be UUIDv4, got version {event_id.version}",
            detail={"event_id": str(event_id), "version": event_id.version},
        )


_MAX_NOT_BEFORE_DELTA = timedelta(days=365)


def validate_not_before_delta(not_before: datetime | None, now: datetime) -> None:
    if not_before is not None:
        nb_utc = not_before if not_before.tzinfo else not_before.replace(tzinfo=UTC)
        now_utc = now if now.tzinfo else now.replace(tzinfo=UTC)
        if (nb_utc - now_utc) > _MAX_NOT_BEFORE_DELTA:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"not_before cannot be more than {_MAX_NOT_BEFORE_DELTA.days} days in the future",
                detail={
                    "not_before": not_before.isoformat(),
                    "max_delta_days": _MAX_NOT_BEFORE_DELTA.days,
                },
            )


def validate_actor_kind(actor_kind: str) -> None:
    if actor_kind not in _VALID_ACTOR_KINDS:
        raise RegistaError(
            ErrorCode.INVALID_ACTOR_KIND,
            f"Invalid actor_kind {actor_kind!r}. Must be one of {sorted(_VALID_ACTOR_KINDS)}",
        )


def validate_entity_kind(entity_kind: str) -> None:
    if entity_kind not in _ALLOWED_ENTITY_KINDS:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Unknown entity_kind {entity_kind!r}. Allowed: {sorted(_ALLOWED_ENTITY_KINDS)}",
        )


def validate_ttl(ttl_seconds: int) -> None:
    if ttl_seconds <= 0:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "ttl_seconds must be positive",
        )


def validate_not_before(not_before: datetime | None, now: datetime) -> None:
    if not_before is not None:
        nb_utc = not_before if not_before.tzinfo else not_before.replace(tzinfo=UTC)
        now_utc = now if now.tzinfo else now.replace(tzinfo=UTC)
        if nb_utc > now_utc:
            raise RegistaError(
                ErrorCode.NOT_BEFORE_FUTURE,
                f"Work item not_before is {not_before.isoformat()}, cannot claim yet",
            )


def resolve_transition(
    transitions: list[dict],
    current_state: str,
    transition_name: str,
    workflow_name: str,
    workflow_version: int,
) -> dict:
    for t in transitions:
        if t["name"] == transition_name and t["from_state"] == current_state:
            return t
    raise RegistaError(
        ErrorCode.INVALID_TRANSITION,
        f"Transition {transition_name!r} not valid from state "
        f"{current_state!r} in {workflow_name!r} v{workflow_version}",
    )


def check_role_gating(
    allowed_roles: list[str],
    actor_metadata: dict | None,
    transition_name: str,
) -> str | None:
    if not allowed_roles:
        return None
    role = (actor_metadata or {}).get("role")
    if role not in allowed_roles:
        raise RegistaError(
            ErrorCode.ROLE_NOT_PERMITTED,
            f"Role {role!r} not permitted for transition {transition_name!r}",
        )
    return role


def check_privileged_transition(
    transition_def: dict,
    actor_kind: str,
    transition_name: str,
) -> None:
    if transition_def.get("privileged") and actor_kind != "system":
        raise RegistaError(
            ErrorCode.PRIVILEGED_TRANSITION_REQUIRED,
            f"Transition {transition_name!r} requires actor_kind='system', "
            f"got actor_kind={actor_kind!r}",
        )


def check_actor_role_authorized(
    registered_roles: set[str],
    actor_id: str,
    claimed_role: str,
    *,
    strict: bool = False,
    actor_metadata: dict | None = None,
) -> None:
    if strict:
        if not registered_roles:
            raise RegistaError(
                ErrorCode.ACTOR_ROLE_NOT_AUTHORIZED,
                f"Actor {actor_id!r} has no registered roles; "
                f"strict_roles requires registration before any transition",
                detail={"actor_id": actor_id},
            )
        role_source = (actor_metadata or {}).get("role_source")
        if role_source not in ("config", "env"):
            raise RegistaError(
                ErrorCode.ACTOR_ROLE_NOT_AUTHORIZED,
                f"Actor {actor_id!r} role_source {role_source!r} not permitted in strict mode; "
                f"must be 'config' or 'env'",
                detail={"actor_id": actor_id, "role_source": role_source},
            )
    if not registered_roles:
        return
    if claimed_role not in registered_roles:
        raise RegistaError(
            ErrorCode.ACTOR_ROLE_NOT_AUTHORIZED,
            f"Actor {actor_id!r} is not authorized for role {claimed_role!r}. "
            f"Allowed roles: {sorted(registered_roles)}",
            detail={
                "actor_id": actor_id,
                "claimed_role": claimed_role,
                "allowed_roles": sorted(registered_roles),
            },
        )


def check_append_blocked(
    transitions: list[dict],
    transition: str | None,
    workflow_name: str,
) -> None:
    if transition is None:
        return
    for t in transitions:
        if t["name"] == transition:
            raise RegistaError(
                ErrorCode.TRANSITION_VIA_APPEND_BLOCKED,
                f"Transition {transition!r} is defined in workflow "
                f"{workflow_name!r}. Use Regista.transition() instead.",
            )


def check_idempotency(
    existing_event: Event | None,
    actor_id: str | None,
    transition: str | None,
    work_item_id: uuid.UUID | None = None,
    payload: dict | None = None,
) -> Event | None:
    if existing_event is None:
        return None
    if work_item_id is not None and existing_event.work_item_id != work_item_id:
        raise RegistaError(
            ErrorCode.EVENT_ID_GLOBAL_COLLISION,
            f"event_id {existing_event.event_id} already used for work_item "
            f"{existing_event.work_item_id}, not {work_item_id}",
        )
    if actor_id is not None and existing_event.actor_id != actor_id:
        raise RegistaError(
            ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD,
            f"event_id {existing_event.event_id} already used by actor {existing_event.actor_id!r}"
            + (f", not {actor_id!r}" if actor_id else ""),
        )
    if transition is not None and existing_event.transition != transition:
        raise RegistaError(
            ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD,
            f"event_id {existing_event.event_id} already used with transition "
            f"{existing_event.transition!r}, not {transition!r}",
        )
    if payload is not None and existing_event.payload != payload:
        raise RegistaError(
            ErrorCode.IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD,
            f"event_id {existing_event.event_id} already used with different payload",
        )
    return existing_event


def check_expected_seq(
    current_next_seq: int,
    expected_event_seq: int | None,
) -> None:
    if expected_event_seq is not None and current_next_seq != expected_event_seq:
        raise RegistaError(
            ErrorCode.CONCURRENT_MODIFICATION,
            f"Expected event_seq {expected_event_seq}, but current next is {current_next_seq}",
        )


def validate_link_type(
    link_types: list[dict],
    from_type: str,
    to_type: str,
    link_type: str,
) -> None:
    for lt in link_types:
        if (
            lt["name"] == link_type
            and lt["source_type"] == from_type
            and lt["target_type"] == to_type
        ):
            return
    raise RegistaError(
        ErrorCode.LINK_TYPE_NOT_ALLOWED,
        f"Link type {link_type!r} not allowed between {from_type!r} and {to_type!r}",
    )


def validate_cross_project_link_type(
    link_types: list[dict],
    link_type: str,
) -> None:
    for lt in link_types:
        if lt["name"] == link_type:
            return
    raise RegistaError(
        ErrorCode.LINK_TYPE_NOT_ALLOWED,
        f"Link type {link_type!r} not declared in workflow",
    )


def should_escalate(
    attempt_threshold: int | None,
    has_escalated: bool,
    attempt_number: int,
) -> bool:
    if attempt_threshold is None or attempt_number < attempt_threshold:
        return False
    return not has_escalated


def validate_read_events_filters(
    before_seq: int | None,
    work_item_id: uuid.UUID | None,
    start: datetime | None,
    end: datetime | None,
) -> None:
    if before_seq is not None and work_item_id is None:
        raise RegistaError(
            ErrorCode.INVALID_FILTER,
            "before_seq requires work_item_id",
        )
    if (start is None) != (end is None):
        raise RegistaError(
            ErrorCode.INVALID_FILTER,
            "start and end must be provided together",
        )


@dataclass(frozen=True)
class ClaimAcquireResult:
    action: Literal["extend", "acquire", "steal"]
    acquired_at: datetime
    expires_at: datetime
    attempt_number: int
    prior_actor_id: str | None
    event_transition: Literal["claim_acquired", "claim_stolen"] | None
    event_payload: dict | None


def resolve_claim_acquire(
    wi_not_before: datetime | None,
    claim_actor_id: str | None,
    claim_expires_at: datetime | None,
    claim_acquired_at: datetime | None,
    claim_attempt_number: int | None,
    wi_attempt_number: int,
    actor_id: str,
    ttl_seconds: int,
    now: datetime,
) -> ClaimAcquireResult:
    validate_ttl(ttl_seconds)
    validate_not_before(wi_not_before, now)

    has_active_claim = (
        claim_actor_id is not None
        and claim_expires_at is not None
        and claim_expires_at >= now
    )

    if has_active_claim:
        if claim_actor_id == actor_id:
            new_expires = now + timedelta(seconds=ttl_seconds)
            return ClaimAcquireResult(
                action="extend",
                acquired_at=claim_acquired_at,
                expires_at=new_expires,
                attempt_number=claim_attempt_number,
                prior_actor_id=None,
                event_transition=None,
                event_payload=None,
            )
        raise RegistaError(
            ErrorCode.CLAIM_CONTESTED,
            f"Work item is already claimed by {claim_actor_id}",
        )

    has_expired_claim = claim_actor_id is not None
    prior_actor_id = claim_actor_id if has_expired_claim else None
    attempt_number = wi_attempt_number + 1

    acquired_at = now
    expires_at = acquired_at + timedelta(seconds=ttl_seconds)

    if has_expired_claim:
        return ClaimAcquireResult(
            action="steal",
            acquired_at=acquired_at,
            expires_at=expires_at,
            attempt_number=attempt_number,
            prior_actor_id=prior_actor_id,
            event_transition="claim_stolen",
            event_payload={
                "prior_actor_id": prior_actor_id,
                "new_actor_id": actor_id,
                "attempt_number": attempt_number,
                "expires_at": expires_at.isoformat(),
            },
        )

    return ClaimAcquireResult(
        action="acquire",
        acquired_at=acquired_at,
        expires_at=expires_at,
        attempt_number=attempt_number,
        prior_actor_id=None,
        event_transition="claim_acquired",
        event_payload={
            "actor_id": actor_id,
            "ttl_seconds": ttl_seconds,
            "attempt_number": attempt_number,
            "expires_at": expires_at.isoformat(),
        },
    )


@dataclass(frozen=True)
class HeartbeatResult:
    new_expires_at: datetime
    acquired_at: datetime
    attempt_number: int


_DEFAULT_COALESCE_MIN = 60.0


def compute_coalesce_threshold(ttl_seconds: int, override: float | None = None) -> float:
    if override is not None:
        return max(0.0, override)
    return max(_DEFAULT_COALESCE_MIN, ttl_seconds / 2.0)


def resolve_heartbeat(
    claim_state: dict | None,
    actor_id: str,
    ttl_seconds: int,
    expected_attempt_number: int | None,
    work_item_id: uuid.UUID,
    now: datetime,
) -> HeartbeatResult:
    validate_ttl(ttl_seconds)

    if claim_state is None:
        raise RegistaError(
            ErrorCode.CLAIM_NOT_FOUND,
            f"No claim found for work item {work_item_id}",
        )

    expires_at = claim_state.get("expires_at")
    if expires_at is None:
        raise RegistaError(
            ErrorCode.CLAIM_LOST,
            f"Claim on {work_item_id} has no expiry (invalid state)",
        )
    if expires_at < now:
        raise RegistaError(
            ErrorCode.CLAIM_LOST,
            f"Claim on {work_item_id} expired at {expires_at}",
        )

    if claim_state["actor_id"] != actor_id:
        raise RegistaError(
            ErrorCode.CLAIM_LOST,
            f"Claim on {work_item_id} is now held by {claim_state['actor_id']}, not {actor_id}",
        )

    if (
        expected_attempt_number is not None
        and claim_state["attempt_number"] != expected_attempt_number
    ):
        raise RegistaError(
            ErrorCode.CLAIM_LOST,
            f"Claim attempt_number is {claim_state['attempt_number']}, "
            f"expected {expected_attempt_number}",
        )

    new_expires = now + timedelta(seconds=ttl_seconds)
    return HeartbeatResult(
        new_expires_at=new_expires,
        acquired_at=claim_state["acquired_at"],
        attempt_number=claim_state["attempt_number"],
    )


def validate_release(
    claim_state: dict | None,
    actor_id: str,
    work_item_id: uuid.UUID,
) -> None:
    if claim_state is None:
        raise RegistaError(
            ErrorCode.CLAIM_NOT_FOUND,
            f"No claim found for work item {work_item_id}",
        )
    if claim_state["actor_id"] != actor_id:
        raise RegistaError(
            ErrorCode.CLAIM_LOST,
            f"Claim on {work_item_id} is held by {claim_state['actor_id']}, not {actor_id}",
        )


_JSONB_UNSAFE_CODES = frozenset(
    range(0xD800, 0xE000)
)


def validate_json_safe_value(value: object, label: str) -> None:
    if isinstance(value, str):
        _check_string_safe(value, label)
    elif isinstance(value, dict):
        for k, v in value.items():
            _check_string_safe(k, f"{label} key")
            validate_json_safe_value(v, f"{label}.{k}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            validate_json_safe_value(item, f"{label}[{i}]")
    elif isinstance(value, float):
        import math

        if math.isnan(value) or math.isinf(value):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"{label} contains disallowed float value {value}",
            )
    elif not isinstance(value, (int, bool, type(None))):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"{label} has unsupported type {type(value).__name__} for JSON serialization",
        )


@dataclass(frozen=True)
class Jsonb:
    value: dict | None

    def __post_init__(self) -> None:
        if self.value is not None:
            validate_json_safe_value(self.value, "value")
            import json

            try:
                serialized = json.dumps(self.value)
            except (TypeError, ValueError) as e:
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    f"Jsonb value is not JSON-serializable: {e}",
                )
            size = len(serialized.encode("utf-8"))
            if size > MAX_JSONB_BYTES:
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    f"JSONB value exceeds maximum size of {MAX_JSONB_BYTES} bytes",
                    detail={"size": size, "max": MAX_JSONB_BYTES},
                )


def _check_string_safe(value: str, label: str) -> None:
    if "\u0000" in value:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"{label} contains disallowed character \\u0000",
        )
    for ch in value:
        if ord(ch) in _JSONB_UNSAFE_CODES:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"{label} contains unpaired surrogate U+{ord(ch):04X}",
            )


def _actor_id_or_role_invalid(name: str, label: str, max_len: int) -> bool:
    if not name:
        return True
    if len(name) > max_len:
        return True
    for ch in name:
        if ch.isspace() or not ch.isprintable():
            return True
    return False


def validate_actor_id(actor_id: str) -> None:
    if _actor_id_or_role_invalid(actor_id, "actor_id", MAX_ACTOR_ID_LENGTH):
        msg = (
            f"actor_id must be non-empty, printable, and no longer than "
            f"{MAX_ACTOR_ID_LENGTH} characters"
        )
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            msg,
            detail={"actor_id_length": len(actor_id), "max_length": MAX_ACTOR_ID_LENGTH},
        )


def validate_role(role: str) -> None:
    if _actor_id_or_role_invalid(role, "role", MAX_ROLE_LENGTH):
        msg = (
            f"role must be non-empty, printable, and no longer than "
            f"{MAX_ROLE_LENGTH} characters"
        )
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            msg,
            detail={"role_length": len(role), "max_length": MAX_ROLE_LENGTH},
        )


def validate_actor_metadata(actor_metadata: dict | None) -> None:
    if actor_metadata is None:
        return
    try:
        import json
        serialized = json.dumps(actor_metadata)
    except (TypeError, ValueError) as e:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"actor_metadata is not JSON-serializable: {e}",
        )
    if len(serialized.encode("utf-8")) > MAX_ACTOR_METADATA_BYTES:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"actor_metadata exceeds maximum size of {MAX_ACTOR_METADATA_BYTES} bytes",
            detail={"size": len(serialized.encode("utf-8")), "max": MAX_ACTOR_METADATA_BYTES},
        )


def validate_mutation_params(
    *,
    actor_id: str | None = None,
    actor_kind: str | None = None,
    event_id: uuid.UUID | None = None,
    not_before: datetime | None = None,
    ttl_seconds: int | None = None,
    now: datetime | None = None,
) -> None:
    """Shared boundary validation for all mutation entry points.

    Call at the top of every public API method that accepts these
    parameters.  Centralising here prevents InMemory/Postgres
    divergence on input validation (GLM feedback, 2026-05-12).
    """
    if actor_id is not None:
        validate_actor_id(actor_id)
    if actor_kind is not None:
        validate_actor_kind(actor_kind)
    if event_id is not None:
        validate_event_id(event_id)
    if not_before is not None:
        validate_not_before_delta(not_before, now or datetime.now(UTC))
    if ttl_seconds is not None:
        validate_ttl(ttl_seconds)


def validate_work_item_exists(
    work_item: object,
    work_item_id: uuid.UUID,
) -> None:
    if work_item is None:
        raise RegistaError(
            ErrorCode.WORK_ITEM_NOT_FOUND,
            f"Work item {work_item_id} not found",
        )


def validate_delegation_chain(
    on_behalf_of: dict | None, *, event_timestamp: str | None = None,
) -> None:
    if on_behalf_of is None:
        return
    if not isinstance(on_behalf_of, dict):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "on_behalf_of must be a dict",
        )
    principal_id = on_behalf_of.get("principal_id")
    if not isinstance(principal_id, str) or not principal_id:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "on_behalf_of.principal_id is required and must be a non-empty string",
        )
    if "scope" in on_behalf_of and on_behalf_of["scope"] is not None:
        if not isinstance(on_behalf_of["scope"], list):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "on_behalf_of.scope must be a list",
            )
        for item in on_behalf_of["scope"]:
            if not isinstance(item, str):
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    "on_behalf_of.scope items must be strings",
                )

    def _parse_iso(label: str, value: str) -> datetime:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"on_behalf_of.{label} must be a valid RFC 3339 timestamp",
                detail={label: value},
            )

    if "authenticated_at" in on_behalf_of and on_behalf_of["authenticated_at"] is not None:
        if not isinstance(on_behalf_of["authenticated_at"], str):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "on_behalf_of.authenticated_at must be a string",
            )
        auth_ts = _parse_iso("authenticated_at", on_behalf_of["authenticated_at"])
        if event_timestamp is not None:
            evt_ts = _parse_iso("event_timestamp", event_timestamp)
            if auth_ts > evt_ts:
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    "on_behalf_of.authenticated_at cannot be after event timestamp",
                    detail={
                        "authenticated_at": on_behalf_of["authenticated_at"],
                        "event_timestamp": event_timestamp,
                    },
                )

    if "session_id" in on_behalf_of and on_behalf_of["session_id"] is not None:
        if not isinstance(on_behalf_of["session_id"], str) or not on_behalf_of["session_id"]:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "on_behalf_of.session_id must be a non-empty string when present",
            )
        try:
            uuid.UUID(on_behalf_of["session_id"])
        except ValueError:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "on_behalf_of.session_id must be a valid UUID",
                detail={"session_id": on_behalf_of["session_id"]},
            )

    if "expires_at" in on_behalf_of and on_behalf_of["expires_at"] is not None:
        if not isinstance(on_behalf_of["expires_at"], str) or not on_behalf_of["expires_at"]:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "on_behalf_of.expires_at must be a non-empty string when present",
            )
        exp_ts = _parse_iso("expires_at", on_behalf_of["expires_at"])
        if event_timestamp is not None:
            evt_ts = _parse_iso("event_timestamp", event_timestamp)
            if evt_ts >= exp_ts:
                raise RegistaError(
                    ErrorCode.DELEGATION_CHAIN_EXPIRED,
                    "on_behalf_of.expires_at is at or before event timestamp",
                    detail={
                        "expires_at": on_behalf_of["expires_at"],
                        "event_timestamp": event_timestamp,
                    },
                )

    if (
        "session_grant_event_id" in on_behalf_of
        and on_behalf_of["session_grant_event_id"] is not None
    ):
        sg = on_behalf_of["session_grant_event_id"]
        if not isinstance(sg, str) or not sg:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "on_behalf_of.session_grant_event_id must be a "
                "non-empty string when present",
            )
        try:
            uuid.UUID(sg)
        except ValueError:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "on_behalf_of.session_grant_event_id must be a valid UUID",
                detail={"session_grant_event_id": sg},
            )


def validate_key_role(role: str) -> None:
    if role not in {"actor", "auditor", "recovery"}:
        raise RegistaError(
            ErrorCode.INVALID_KEY_ROLE,
            f"unknown key role: {role}",
        )


_KEY_ROLE_POLICY: dict[str, frozenset[str]] = {
    "auditor_attestation": frozenset({"auditor"}),
    "key_rotation": frozenset({"actor", "recovery"}),
}

_DEFAULT_ALLOWED_ROLES = frozenset({"actor"})


def check_key_role_policy(role: str, transition: str | None) -> None:
    if transition is None:
        return
    if transition in _RESERVED_TRANSITIONS:
        return
    allowed = _KEY_ROLE_POLICY.get(transition, _DEFAULT_ALLOWED_ROLES)
    if role not in allowed:
        raise RegistaError(
            ErrorCode.KEY_ROLE_NOT_PERMITTED,
            f"Key with role {role!r} is not permitted to sign transition {transition!r}; "
            f"allowed roles: {sorted(allowed)}",
        )
