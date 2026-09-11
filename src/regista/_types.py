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
    model_lineage: str | None = None
    gate_name: str | None = None
    attempt_n: int | None = None
    context_hash: str | None = None
    prompt_template_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, object] = {}
        if self.role is not None:
            d["role"] = self.role
        if self.channel is not None:
            d["channel"] = self.channel
        if self.model is not None:
            d["model"] = self.model
        if self.family is not None:
            d["family"] = self.family
        if self.model_lineage is not None:
            d["model_lineage"] = self.model_lineage
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
    def from_dict(cls, data: dict[str, Any]) -> ActorMetadata:
        return cls(
            role=data.get("role"),
            channel=data.get("channel"),
            model=data.get("model"),
            family=data.get("family"),
            model_lineage=data.get("model_lineage"),
            gate_name=data.get("gate_name"),
            attempt_n=data.get("attempt_n"),
            context_hash=data.get("context_hash"),
            prompt_template_hash=data.get("prompt_template_hash"),
        )


@dataclass(frozen=True)
class Event:
    event_id: uuid.UUID
    work_item_id: uuid.UUID
    event_seq: int
    actor_id: str
    actor_kind: str
    actor_metadata: dict[str, Any] | None
    workflow_name: str | None
    workflow_version: int | None
    timestamp: datetime
    transition: str | None
    payload: dict[str, Any] | None
    on_behalf_of: dict[str, Any] | None = None
    entity_kind: str = "work_item"
    entity_id: uuid.UUID | None = None

    def __post_init__(self) -> None:
        if self.entity_id is None:
            object.__setattr__(self, "entity_id", self.work_item_id)

    @property
    def effective_entity_id(self) -> uuid.UUID:
        return self.entity_id if self.entity_id is not None else self.work_item_id

    def to_dict(self) -> dict[str, Any]:
        d = {
            "event_id": str(self.event_id),
            "work_item_id": str(self.work_item_id),
            "event_seq": self.event_seq,
            "actor_id": self.actor_id,
            "actor_kind": self.actor_kind,
            "actor_metadata": self.actor_metadata,
            "workflow_name": self.workflow_name,
            "workflow_version": self.workflow_version,
            "timestamp": self.timestamp.isoformat(),
            "transition": self.transition,
            "payload": self.payload,
            "entity_kind": self.entity_kind,
            "entity_id": str(self.effective_entity_id),
        }
        if self.on_behalf_of is not None:
            d["on_behalf_of"] = self.on_behalf_of
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Event:
        return cls(
            event_id=uuid.UUID(data["event_id"]),
            work_item_id=uuid.UUID(data["work_item_id"]),
            event_seq=data["event_seq"],
            actor_id=data["actor_id"],
            actor_kind=data["actor_kind"],
            actor_metadata=data.get("actor_metadata"),
            workflow_name=data.get("workflow_name"),
            workflow_version=data.get("workflow_version"),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            transition=data.get("transition"),
            payload=data.get("payload"),
            on_behalf_of=data.get("on_behalf_of"),
            entity_kind=data.get("entity_kind", "work_item"),
            entity_id=(
                uuid.UUID(data["entity_id"])
                if data.get("entity_id")
                else None
            ),
        )


@dataclass(frozen=True)
class WorkItem:
    work_item_id: uuid.UUID
    workflow_name: str
    workflow_version: int
    work_item_type: str
    current_state: str
    custom_fields: dict[str, Any]
    needs_review: bool
    not_before: datetime | None
    last_event_seq: int
    last_event_at: datetime
    next_event_seq: int
    claimed_by: str | None
    claim_expires_at: datetime | None
    attempt_number: int = 0

    def to_dict(self) -> dict[str, Any]:
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
    def from_dict(cls, data: dict[str, Any]) -> WorkItem:
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "work_item_id": str(self.work_item_id),
            "actor_id": self.actor_id,
            "acquired_at": self.acquired_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "attempt_number": self.attempt_number,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Claim:
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "database": self.database,
            "project": self.project,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ConnectionInfo:
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

    def to_dict(self) -> dict[str, Any]:
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
    def from_dict(cls, data: dict[str, Any]) -> CustomFieldDef:
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "custom_fields": [f.to_dict() for f in self.custom_fields],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkItemTypeDef:
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
    validator_params: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
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
    def from_dict(cls, data: dict[str, Any]) -> TransitionDef:
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source_type": self.source_type,
            "target_type": self.target_type,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LinkTypeDef:
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
    hook_defaults: dict[str, Any] | None = None
    raw_yaml: str = ""

    def to_dict(self) -> dict[str, Any]:
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
    def from_dict(cls, data: dict[str, Any]) -> WorkflowDefinition:
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "regista_version": self.regista_version,
            "registered_at": self.registered_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WorkflowVersion:
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
    payload: dict[str, Any] | None = None
    target_project: str | None = None
    target_entity_kind: str | None = None
    content_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
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
    def from_dict(cls, data: dict[str, Any]) -> Link:
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_dict() if hasattr(item, "to_dict") else item for item in self.items],
            "cursor": str(self.cursor) if self.cursor else None,
            "has_more": self.has_more,
        }

    @classmethod
    def from_dict(
        cls, data: dict[str, Any], item_from_dict: Callable[[dict[str, Any]], T],
    ) -> QueryPage[T]:
        items = [item_from_dict(item) for item in data["items"]]
        return cls(
            items=items,
            cursor=uuid.UUID(data["cursor"]) if data.get("cursor") else None,
            has_more=data["has_more"],
        )


@dataclass(frozen=True)
class ReplayReport:
    #: Name of the temp table holding the replayed projection, or ``None`` in
    #: read-only mode. This table exists only for the span of the replay
    #: transaction and is dropped when :func:`~regista._replay.replay` returns,
    #: so it is NOT a valid post-return handle. Use ``entries`` for portable
    #: access to per-item results.
    table_name: str | None
    replayed_ok: int
    replayed_drift: int
    halted: int
    warnings: int = 0
    #: Detailed per-work-item results, populated in BOTH modes. This is the
    #: portable access path for per-item replay outcomes; prefer it over
    #: querying ``table_name``.
    entries: tuple[ReplayReportEntry, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "table_name": self.table_name,
            "replayed_ok": self.replayed_ok,
            "replayed_drift": self.replayed_drift,
            "halted": self.halted,
        }
        if self.warnings > 0:
            d["warnings"] = self.warnings
        if self.entries:
            d["entries"] = [e.to_dict() for e in self.entries]
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReplayReport:
        return cls(
            table_name=data.get("table_name"),
            replayed_ok=data["replayed_ok"],
            replayed_drift=data["replayed_drift"],
            halted=data["halted"],
            warnings=data.get("warnings", 0),
            entries=tuple(
                ReplayReportEntry.from_dict(e) for e in data.get("entries", [])
            ),
        )


@dataclass(frozen=True)
class ReplayReportEntry:
    work_item_id: uuid.UUID
    category: str
    detail: str | None
    #: Per-work-item warning count for this entry.
    warnings: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "work_item_id": str(self.work_item_id),
            "category": self.category,
            "detail": self.detail,
            "warnings": self.warnings,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReplayReportEntry:
        return cls(
            work_item_id=uuid.UUID(data["work_item_id"]),
            category=data["category"],
            detail=data.get("detail"),
            warnings=data.get("warnings", 0),
        )








@dataclass(frozen=True)
class ActorRole:
    actor_id: str
    role: str
    created_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor_id": self.actor_id,
            "role": self.role,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ActorRole:
        return cls(
            actor_id=data["actor_id"],
            role=data["role"],
            created_at=datetime.fromisoformat(data["created_at"]),
        )


@dataclass(frozen=True)
class ValidationError:
    path: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "message": self.message}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidationError:
        return cls(path=data["path"], message=data["message"])


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    errors: list[ValidationError]
    workflow: WorkflowDefinition | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "valid": self.valid,
            "errors": [e.to_dict() for e in self.errors],
        }
        if self.workflow is not None:
            d["workflow"] = self.workflow.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidationResult:
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": self.schema_name,
            "display_name": self.display_name,
            "owner_actor_id": self.owner_actor_id,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ProjectCatalogEntry:
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
