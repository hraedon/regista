from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar

T = TypeVar("T")


class ActorKind(Enum):
    AGENT = "agent"
    HUMAN = "human"
    SYSTEM = "system"


@dataclass(frozen=True)
class ActorMetadata:
    role: str | None = None
    channel: str | None = None
    model: str | None = None
    family: str | None = None
    gate_name: str | None = None
    attempt_n: int | None = None
    context_hash: str | None = None
    prompt_template_hash: str | None = None

    def to_dict(self) -> dict:
        d: dict[str, object] = {}
        if self.role is not None:
            d["role"] = self.role
        if self.channel is not None:
            d["channel"] = self.channel
        if self.model is not None:
            d["model"] = self.model
        if self.family is not None:
            d["family"] = self.family
        if self.gate_name is not None:
            d["gate_name"] = self.gate_name
        if self.attempt_n is not None:
            d["attempt_n"] = self.attempt_n
        if self.context_hash is not None:
            d["context_hash"] = self.context_hash
        if self.prompt_template_hash is not None:
            d["prompt_template_hash"] = self.prompt_template_hash
        return d

    @classmethod
    def from_dict(cls, data: dict) -> ActorMetadata:
        return cls(
            role=data.get("role"),
            channel=data.get("channel"),
            model=data.get("model"),
            family=data.get("family"),
            gate_name=data.get("gate_name"),
            attempt_n=data.get("attempt_n"),
            context_hash=data.get("context_hash"),
            prompt_template_hash=data.get("prompt_template_hash"),
        )


@dataclass(frozen=True)
class DelegationChain:
    principal_id: str
    session_id: str | None = None
    authenticated_at: str | None = None
    scope: list[str] | None = None
    expires_at: str | None = None
    session_grant_event_id: str | None = None

    def to_dict(self) -> dict[str, object]:
        d: dict[str, object] = {"principal_id": self.principal_id}
        if self.session_id is not None:
            d["session_id"] = self.session_id
        if self.authenticated_at is not None:
            d["authenticated_at"] = self.authenticated_at
        if self.scope is not None:
            d["scope"] = self.scope
        if self.expires_at is not None:
            d["expires_at"] = self.expires_at
        if self.session_grant_event_id is not None:
            d["session_grant_event_id"] = self.session_grant_event_id
        return d

    @classmethod
    def from_dict(cls, data: dict) -> DelegationChain:
        return cls(
            principal_id=data["principal_id"],
            session_id=data.get("session_id"),
            authenticated_at=data.get("authenticated_at"),
            scope=data.get("scope"),
            expires_at=data.get("expires_at"),
            session_grant_event_id=data.get("session_grant_event_id"),
        )


@dataclass(frozen=True)
class Event:
    event_id: uuid.UUID
    work_item_id: uuid.UUID
    event_seq: int
    actor_id: str
    actor_kind: str
    actor_metadata: dict | None
    key_id: str
    workflow_name: str
    workflow_version: int
    timestamp: datetime
    transition: str | None
    payload: dict | None
    payload_canonical_hash: bytes
    signature: bytes
    canonical_envelope: bytes | None = None
    on_behalf_of: dict | None = None
    scheme_id: str = "hmac-sha256"
    prev_event_hash: bytes | None = None
    global_seq: int | None = None
    prev_global_event_hash: bytes | None = None
    entity_kind: str = "work_item"
    entity_id: uuid.UUID | None = None
    hash_alg: str = "sha-256"

    def __post_init__(self) -> None:
        if self.entity_id is None:
            object.__setattr__(self, "entity_id", self.work_item_id)

    @property
    def effective_entity_id(self) -> uuid.UUID:
        return self.entity_id if self.entity_id is not None else self.work_item_id

    def to_dict(self) -> dict:
        d = {
            "event_id": str(self.event_id),
            "work_item_id": str(self.work_item_id),
            "event_seq": self.event_seq,
            "actor_id": self.actor_id,
            "actor_kind": self.actor_kind,
            "actor_metadata": self.actor_metadata,
            "key_id": self.key_id,
            "workflow_name": self.workflow_name,
            "workflow_version": self.workflow_version,
            "timestamp": self.timestamp.isoformat(),
            "transition": self.transition,
            "payload": self.payload,
            "payload_canonical_hash": self.payload_canonical_hash.hex(),
            "signature": self.signature.hex(),
            "entity_kind": self.entity_kind,
            "entity_id": str(self.effective_entity_id),
            "hash_alg": self.hash_alg,
        }
        if self.canonical_envelope is not None:
            d["canonical_envelope"] = self.canonical_envelope.hex()
        if self.on_behalf_of is not None:
            d["on_behalf_of"] = self.on_behalf_of
        d["scheme_id"] = self.scheme_id
        if self.prev_event_hash is not None:
            d["prev_event_hash"] = self.prev_event_hash.hex()
        if self.global_seq is not None:
            d["global_seq"] = self.global_seq
        if self.prev_global_event_hash is not None:
            d["prev_global_event_hash"] = self.prev_global_event_hash.hex()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> Event:
        return cls(
            event_id=uuid.UUID(data["event_id"]),
            work_item_id=uuid.UUID(data["work_item_id"]),
            event_seq=data["event_seq"],
            actor_id=data["actor_id"],
            actor_kind=data["actor_kind"],
            actor_metadata=data.get("actor_metadata"),
            key_id=data["key_id"],
            workflow_name=data["workflow_name"],
            workflow_version=data["workflow_version"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            transition=data.get("transition"),
            payload=data.get("payload"),
            payload_canonical_hash=bytes.fromhex(data["payload_canonical_hash"]),
            signature=bytes.fromhex(data["signature"]),
            canonical_envelope=(
                bytes.fromhex(data["canonical_envelope"])
                if data.get("canonical_envelope")
                else None
            ),
            on_behalf_of=data.get("on_behalf_of"),
            scheme_id=data.get("scheme_id", "hmac-sha256"),
            prev_event_hash=(
                bytes.fromhex(data["prev_event_hash"])
                if data.get("prev_event_hash")
                else None
            ),
            global_seq=data.get("global_seq"),
            prev_global_event_hash=(
                bytes.fromhex(data["prev_global_event_hash"])
                if data.get("prev_global_event_hash")
                else None
            ),
            entity_kind=data.get("entity_kind", "work_item"),
            entity_id=(
                uuid.UUID(data["entity_id"])
                if data.get("entity_id")
                else None
            ),
            hash_alg=data.get("hash_alg", "sha-256"),
        )


@dataclass(frozen=True)
class WorkItem:
    work_item_id: uuid.UUID
    workflow_name: str
    workflow_version: int
    work_item_type: str
    current_state: str
    custom_fields: dict
    needs_review: bool
    not_before: datetime | None
    last_event_seq: int
    last_event_at: datetime
    next_event_seq: int
    claimed_by: str | None
    claim_expires_at: datetime | None
    attempt_number: int = 0

    def to_dict(self) -> dict:
        return {
            "work_item_id": str(self.work_item_id),
            "workflow_name": self.workflow_name,
            "workflow_version": self.workflow_version,
            "work_item_type": self.work_item_type,
            "current_state": self.current_state,
            "custom_fields": self.custom_fields,
            "needs_review": self.needs_review,
            "not_before": self.not_before.isoformat() if self.not_before else None,
            "last_event_seq": self.last_event_seq,
            "last_event_at": self.last_event_at.isoformat(),
            "next_event_seq": self.next_event_seq,
            "claimed_by": self.claimed_by,
            "claim_expires_at": (
                self.claim_expires_at.isoformat()
                if self.claim_expires_at
                else None
            ),
            "attempt_number": self.attempt_number,
        }

    @classmethod
    def from_dict(cls, data: dict) -> WorkItem:
        return cls(
            work_item_id=uuid.UUID(data["work_item_id"]),
            workflow_name=data["workflow_name"],
            workflow_version=data["workflow_version"],
            work_item_type=data["work_item_type"],
            current_state=data["current_state"],
            custom_fields=data["custom_fields"],
            needs_review=data["needs_review"],
            not_before=(
                datetime.fromisoformat(data["not_before"])
                if data.get("not_before")
                else None
            ),
            last_event_seq=data["last_event_seq"],
            last_event_at=datetime.fromisoformat(data["last_event_at"]),
            next_event_seq=data["next_event_seq"],
            claimed_by=data.get("claimed_by"),
            claim_expires_at=(
                datetime.fromisoformat(data["claim_expires_at"])
                if data.get("claim_expires_at")
                else None
            ),
            attempt_number=data.get("attempt_number", 0),
        )


@dataclass(frozen=True)
class Claim:
    work_item_id: uuid.UUID
    actor_id: str
    acquired_at: datetime
    expires_at: datetime
    attempt_number: int

    def to_dict(self) -> dict:
        return {
            "work_item_id": str(self.work_item_id),
            "actor_id": self.actor_id,
            "acquired_at": self.acquired_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "attempt_number": self.attempt_number,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Claim:
        return cls(
            work_item_id=uuid.UUID(data["work_item_id"]),
            actor_id=data["actor_id"],
            acquired_at=datetime.fromisoformat(data["acquired_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            attempt_number=data["attempt_number"],
        )


@dataclass(frozen=True)
class ConnectionInfo:
    host: str | None
    port: int | None
    database: str | None
    project: str

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "database": self.database,
            "project": self.project,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ConnectionInfo:
        return cls(
            host=data.get("host"),
            port=data.get("port"),
            database=data.get("database"),
            project=data["project"],
        )


@dataclass(frozen=True)
class CustomFieldDef:
    name: str
    type: str
    required: bool = False
    default_value: Any = None
    ui_visible: bool = False
    enum_values: list[str] | None = None
    target_work_item_type: str | None = None
    target_work_item_types: list[str] | None = None

    def to_dict(self) -> dict:
        d: dict[str, object] = {
            "name": self.name,
            "type": self.type,
            "required": self.required,
            "default_value": self.default_value,
            "ui_visible": self.ui_visible,
            "enum_values": self.enum_values,
        }
        if self.target_work_item_type is not None:
            d["target_work_item_type"] = self.target_work_item_type
        if self.target_work_item_types is not None:
            d["target_work_item_types"] = self.target_work_item_types
        return d

    @classmethod
    def from_dict(cls, data: dict) -> CustomFieldDef:
        return cls(
            name=data["name"],
            type=data["type"],
            required=data.get("required", False),
            default_value=data.get("default_value", data.get("default")),
            ui_visible=data.get("ui_visible", False),
            enum_values=data.get("enum_values"),
            target_work_item_type=data.get("target_work_item_type"),
            target_work_item_types=data.get("target_work_item_types"),
        )


@dataclass(frozen=True)
class WorkItemTypeDef:
    name: str
    custom_fields: list[CustomFieldDef]

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "custom_fields": [f.to_dict() for f in self.custom_fields],
        }

    @classmethod
    def from_dict(cls, data: dict) -> WorkItemTypeDef:
        return cls(
            name=data["name"],
            custom_fields=[CustomFieldDef.from_dict(f) for f in data["custom_fields"]],
        )


@dataclass(frozen=True)
class TransitionDef:
    name: str
    from_state: str
    to_state: str
    allowed_roles: list[str]
    validator: str | None
    hooks: list[str]
    privileged: bool = False
    validator_params: dict | None = None

    def to_dict(self) -> dict:
        result = {
            "name": self.name,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "allowed_roles": self.allowed_roles,
            "validator": self.validator,
            "hooks": self.hooks,
        }
        if self.privileged:
            result["privileged"] = True
        if self.validator_params is not None:
            result["validator_params"] = self.validator_params
        return result

    @classmethod
    def from_dict(cls, data: dict) -> TransitionDef:
        return cls(
            name=data["name"],
            from_state=data["from_state"],
            to_state=data["to_state"],
            allowed_roles=data["allowed_roles"],
            validator=data.get("validator"),
            hooks=data.get("hooks", []),
            privileged=data.get("privileged", False),
            validator_params=data.get("validator_params"),
        )


@dataclass(frozen=True)
class LinkTypeDef:
    name: str
    source_type: str
    target_type: str

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "source_type": self.source_type,
            "target_type": self.target_type,
        }

    @classmethod
    def from_dict(cls, data: dict) -> LinkTypeDef:
        return cls(
            name=data["name"],
            source_type=data["source_type"],
            target_type=data["target_type"],
        )


@dataclass(frozen=True)
class WorkflowDefinition:
    name: str
    version: int
    regista_version: str
    states: list[str]
    initial_state: str
    terminal_states: list[str]
    transitions: list[TransitionDef]
    roles: list[str]
    work_item_types: list[WorkItemTypeDef]
    link_types: list[LinkTypeDef]
    attempt_threshold: int | None
    hook_defaults: dict | None = None
    raw_yaml: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "regista_version": self.regista_version,
            "states": self.states,
            "initial_state": self.initial_state,
            "terminal_states": self.terminal_states,
            "transitions": [t.to_dict() for t in self.transitions],
            "roles": self.roles,
            "work_item_types": [w.to_dict() for w in self.work_item_types],
            "link_types": [lt.to_dict() for lt in self.link_types],
            "attempt_threshold": self.attempt_threshold,
            "hook_defaults": self.hook_defaults,
            "raw_yaml": self.raw_yaml,
        }

    @classmethod
    def from_dict(cls, data: dict) -> WorkflowDefinition:
        return cls(
            name=data["name"],
            version=data["version"],
            regista_version=data["regista_version"],
            states=data["states"],
            initial_state=data["initial_state"],
            terminal_states=data["terminal_states"],
            transitions=[TransitionDef.from_dict(t) for t in data["transitions"]],
            roles=data["roles"],
            work_item_types=[WorkItemTypeDef.from_dict(w) for w in data["work_item_types"]],
            link_types=[LinkTypeDef.from_dict(lt) for lt in data["link_types"]],
            attempt_threshold=data.get("attempt_threshold"),
            hook_defaults=data.get("hook_defaults"),
            raw_yaml=data["raw_yaml"],
        )


@dataclass(frozen=True)
class WorkflowVersion:
    name: str
    version: int
    regista_version: str
    registered_at: datetime

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "regista_version": self.regista_version,
            "registered_at": self.registered_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> WorkflowVersion:
        return cls(
            name=data["name"],
            version=data["version"],
            regista_version=data["regista_version"],
            registered_at=datetime.fromisoformat(data["registered_at"]),
        )


@dataclass(frozen=True)
class Link:
    link_id: uuid.UUID
    from_work_item_id: uuid.UUID
    to_work_item_id: uuid.UUID
    link_type: str
    payload: dict | None = None
    target_project: str | None = None
    target_entity_kind: str | None = None
    content_hash: str | None = None

    def to_dict(self) -> dict:
        d = {
            "link_id": str(self.link_id),
            "from_work_item_id": str(self.from_work_item_id),
            "to_work_item_id": str(self.to_work_item_id),
            "link_type": self.link_type,
        }
        if self.payload is not None:
            d["payload"] = self.payload
        if self.target_project is not None:
            d["target_project"] = self.target_project
        if self.target_entity_kind is not None:
            d["target_entity_kind"] = self.target_entity_kind
        if self.content_hash is not None:
            d["content_hash"] = self.content_hash
        return d

    @classmethod
    def from_dict(cls, data: dict) -> Link:
        return cls(
            link_id=uuid.UUID(data["link_id"]),
            from_work_item_id=uuid.UUID(data["from_work_item_id"]),
            to_work_item_id=uuid.UUID(data["to_work_item_id"]),
            link_type=data["link_type"],
            payload=data.get("payload"),
            target_project=data.get("target_project"),
            target_entity_kind=data.get("target_entity_kind"),
            content_hash=data.get("content_hash"),
        )


@dataclass(frozen=True)
class QueryPage(Generic[T]):
    items: list[T]
    cursor: uuid.UUID | None
    has_more: bool

    def to_dict(self) -> dict:
        return {
            "items": [item.to_dict() if hasattr(item, "to_dict") else item for item in self.items],
            "cursor": str(self.cursor) if self.cursor else None,
            "has_more": self.has_more,
        }

    @classmethod
    def from_dict(cls, data: dict, item_from_dict: Callable[[dict], T]) -> QueryPage[T]:
        items = [item_from_dict(item) for item in data["items"]]
        return cls(
            items=items,
            cursor=uuid.UUID(data["cursor"]) if data.get("cursor") else None,
            has_more=data["has_more"],
        )


@dataclass(frozen=True)
class ReplayReport:
    table_name: str
    replayed_ok: int
    replayed_drift: int
    halted: int
    warnings: int = 0
    principal_binding_failures: int = 0
    #: Whether the principal-binding check actually ran. WI-223: a zero
    #: ``principal_binding_failures`` is only an affirmative claim when this is
    #: True. When the check did not run, ``0`` means "not checked" — surfaces
    #: must not render it as a pass.
    principal_binding_verified: bool = False

    def to_dict(self) -> dict:
        d: dict = {
            "table_name": self.table_name,
            "replayed_ok": self.replayed_ok,
            "replayed_drift": self.replayed_drift,
            "halted": self.halted,
        }
        if self.warnings > 0:
            d["warnings"] = self.warnings
        d["principal_binding_verified"] = self.principal_binding_verified
        if self.principal_binding_verified:
            d["principal_binding_failures"] = self.principal_binding_failures
        elif self.principal_binding_failures > 0:
            d["principal_binding_failures"] = self.principal_binding_failures
        return d

    @classmethod
    def from_dict(cls, data: dict) -> ReplayReport:
        return cls(
            table_name=data["table_name"],
            replayed_ok=data["replayed_ok"],
            replayed_drift=data["replayed_drift"],
            halted=data["halted"],
            warnings=data.get("warnings", 0),
            principal_binding_failures=data.get("principal_binding_failures", 0),
            principal_binding_verified=data.get("principal_binding_verified", False),
        )


@dataclass(frozen=True)
class ReplayReportEntry:
    work_item_id: uuid.UUID
    category: str
    detail: str | None

    def to_dict(self) -> dict:
        return {
            "work_item_id": str(self.work_item_id),
            "category": self.category,
            "detail": self.detail,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ReplayReportEntry:
        return cls(
            work_item_id=uuid.UUID(data["work_item_id"]),
            category=data["category"],
            detail=data.get("detail"),
        )


@dataclass(frozen=True)
class ValidatorContext:
    """Context passed to a sync transition validator (runs in-transition).

    ``actor_kind`` is the authoritative kind of the actor performing this
    transition. ``prior_events`` is the work-item's pre-transition event
    history in ascending ``event_seq``, capped to the most recent 100,000
    events (see ``regista._contract.VALIDATOR_HISTORY_LIMIT``); for typical
    review-gated work-items the full history is present.

    ``on_behalf_of`` is the acting actor's delegation chain for this
    transition (same shape as ``Event.on_behalf_of``, validated by
    ``_validate_delegation_chain``), or ``None`` when the actor is acting on
    their own behalf.
    """

    work_item_id: uuid.UUID
    workflow_name: str
    workflow_version: int
    work_item_type: str
    current_state: str
    new_state: str
    transition_name: str
    payload: dict | None
    custom_fields: dict
    actor_id: str
    actor_metadata: dict | None
    actor_kind: str
    prior_events: tuple[Event, ...]
    on_behalf_of: dict | None = None
    validator_params: dict | None = None

    def to_dict(self) -> dict:
        d = {
            "work_item_id": str(self.work_item_id),
            "workflow_name": self.workflow_name,
            "workflow_version": self.workflow_version,
            "work_item_type": self.work_item_type,
            "current_state": self.current_state,
            "new_state": self.new_state,
            "transition_name": self.transition_name,
            "payload": self.payload,
            "custom_fields": self.custom_fields,
            "actor_id": self.actor_id,
            "actor_metadata": self.actor_metadata,
            "actor_kind": self.actor_kind,
            "prior_events": [e.to_dict() for e in self.prior_events],
        }
        if self.on_behalf_of is not None:
            d["on_behalf_of"] = self.on_behalf_of
        if self.validator_params is not None:
            d["validator_params"] = self.validator_params
        return d

    @classmethod
    def from_dict(cls, data: dict) -> ValidatorContext:
        return cls(
            work_item_id=uuid.UUID(data["work_item_id"]),
            workflow_name=data["workflow_name"],
            workflow_version=data["workflow_version"],
            work_item_type=data["work_item_type"],
            current_state=data["current_state"],
            new_state=data["new_state"],
            transition_name=data["transition_name"],
            payload=data.get("payload"),
            custom_fields=data["custom_fields"],
            actor_id=data["actor_id"],
            actor_metadata=data.get("actor_metadata"),
            actor_kind=data.get("actor_kind", "agent"),
            prior_events=tuple(
                Event.from_dict(e) for e in data.get("prior_events", [])
            ),
            on_behalf_of=data.get("on_behalf_of"),
            validator_params=data.get("validator_params"),
        )


@dataclass(frozen=True)
class HookContext:
    hook_queue_id: int
    event_id: uuid.UUID
    work_item_id: uuid.UUID
    hook_name: str
    transition: str | None
    payload: dict | None

    def to_dict(self) -> dict:
        return {
            "hook_queue_id": self.hook_queue_id,
            "event_id": str(self.event_id),
            "work_item_id": str(self.work_item_id),
            "hook_name": self.hook_name,
            "transition": self.transition,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, data: dict) -> HookContext:
        return cls(
            hook_queue_id=data["hook_queue_id"],
            event_id=uuid.UUID(data["event_id"]),
            work_item_id=uuid.UUID(data["work_item_id"]),
            hook_name=data["hook_name"],
            transition=data.get("transition"),
            payload=data.get("payload"),
        )


@dataclass(frozen=True)
class ActorRole:
    actor_id: str
    role: str
    created_at: datetime

    def to_dict(self) -> dict:
        return {
            "actor_id": self.actor_id,
            "role": self.role,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> ActorRole:
        return cls(
            actor_id=data["actor_id"],
            role=data["role"],
            created_at=datetime.fromisoformat(data["created_at"]),
        )


@dataclass(frozen=True)
class ValidationError:
    path: str
    message: str

    def to_dict(self) -> dict:
        return {"path": self.path, "message": self.message}

    @classmethod
    def from_dict(cls, data: dict) -> ValidationError:
        return cls(path=data["path"], message=data["message"])


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: list[ValidationError]
    workflow: WorkflowDefinition | None = None

    def to_dict(self) -> dict:
        d = {
            "valid": self.valid,
            "errors": [e.to_dict() for e in self.errors],
        }
        if self.workflow is not None:
            d["workflow"] = self.workflow.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict) -> ValidationResult:
        wf = (
            WorkflowDefinition.from_dict(data["workflow"])
            if data.get("workflow")
            else None
        )
        return cls(
            valid=data["valid"],
            errors=[ValidationError.from_dict(e) for e in data["errors"]],
            workflow=wf,
        )


@dataclass(frozen=True)
class DeadLetterEntry:
    id: int
    event_id: uuid.UUID
    hook_name: str
    hook_type: str
    payload: dict | None
    retry_count: int
    max_retries: int
    error_message: str | None
    dead_lettered_at: datetime
    original_hook_queue_id: int | None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "event_id": str(self.event_id),
            "hook_name": self.hook_name,
            "hook_type": self.hook_type,
            "payload": self.payload,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "error_message": self.error_message,
            "dead_lettered_at": self.dead_lettered_at.isoformat(),
            "original_hook_queue_id": self.original_hook_queue_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> DeadLetterEntry:
        return cls(
            id=data["id"],
            event_id=uuid.UUID(data["event_id"]),
            hook_name=data["hook_name"],
            hook_type=data["hook_type"],
            payload=data.get("payload"),
            retry_count=data["retry_count"],
            max_retries=data.get("max_retries", 3),
            error_message=data.get("error_message"),
            dead_lettered_at=datetime.fromisoformat(data["dead_lettered_at"]),
            original_hook_queue_id=data.get("original_hook_queue_id"),
        )


@dataclass(frozen=True)
class RecurrenceRule:
    rule_id: uuid.UUID
    workflow_name: str
    workflow_version: int
    work_item_type: str
    template: dict
    schedule_kind: str
    schedule_expr: str
    timezone: str
    start_at: datetime
    end_at: datetime | None
    count_remaining: int | None
    status: str
    catchup_policy: str
    last_fired_at: datetime | None
    next_fire_at: datetime
    created_by: str
    created_at: datetime
    updated_at: datetime

    def to_dict(self) -> dict:
        return {
            "rule_id": str(self.rule_id),
            "workflow_name": self.workflow_name,
            "workflow_version": self.workflow_version,
            "work_item_type": self.work_item_type,
            "template": self.template,
            "schedule_kind": self.schedule_kind,
            "schedule_expr": self.schedule_expr,
            "timezone": self.timezone,
            "start_at": self.start_at.isoformat(),
            "end_at": self.end_at.isoformat() if self.end_at else None,
            "count_remaining": self.count_remaining,
            "status": self.status,
            "catchup_policy": self.catchup_policy,
            "last_fired_at": self.last_fired_at.isoformat() if self.last_fired_at else None,
            "next_fire_at": self.next_fire_at.isoformat(),
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> RecurrenceRule:
        return cls(
            rule_id=uuid.UUID(data["rule_id"]),
            workflow_name=data["workflow_name"],
            workflow_version=data["workflow_version"],
            work_item_type=data["work_item_type"],
            template=data["template"],
            schedule_kind=data["schedule_kind"],
            schedule_expr=data["schedule_expr"],
            timezone=data["timezone"],
            start_at=datetime.fromisoformat(data["start_at"]),
            end_at=datetime.fromisoformat(data["end_at"]) if data.get("end_at") else None,
            count_remaining=data.get("count_remaining"),
            status=data["status"],
            catchup_policy=data["catchup_policy"],
            last_fired_at=(
                datetime.fromisoformat(data["last_fired_at"])
                if data.get("last_fired_at")
                else None
            ),
            next_fire_at=datetime.fromisoformat(data["next_fire_at"]),
            created_by=data["created_by"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
        )


@dataclass(frozen=True)
class ProjectCatalogEntry:
    """A row in the shared ``public.projects`` catalog (Plan 012).

    The catalog is the authoritative source of truth for which regista
    projects exist and who owns each one. It lives in the ``public``
    schema (shared across all projects) — a deliberate softening of §3's
    schema-isolation tenet, with precedent in Plan 022's cross-project
    value-references.
    """

    schema_name: str
    display_name: str | None = None
    owner_actor_id: str | None = None
    created_by: str | None = None
    created_at: datetime | None = None

    def to_dict(self) -> dict:
        return {
            "schema_name": self.schema_name,
            "display_name": self.display_name,
            "owner_actor_id": self.owner_actor_id,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> ProjectCatalogEntry:
        return cls(
            schema_name=data["schema_name"],
            display_name=data.get("display_name"),
            owner_actor_id=data.get("owner_actor_id"),
            created_by=data.get("created_by"),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if data.get("created_at")
                else None
            ),
        )
