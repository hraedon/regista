from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def _serialize(obj: Any) -> Any:
    if obj is None:
        return None
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, list):
        return [_serialize(i) for i in obj]
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    return obj


class RegisterWorkflowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    yaml_content: str


class CreateWorkItemRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workflow_name: str
    work_item_type: str
    actor_kind: str = "agent"
    actor_metadata: dict[str, Any] | None = None
    custom_fields: dict[str, Any] | None = None
    not_before: str | None = None
    event_id: str | None = None


class AppendEventRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    work_item_id: str
    actor_kind: str = "agent"
    actor_metadata: dict[str, Any] | None = None
    transition: str | None = None
    payload: dict[str, Any] | None = None
    event_id: str | None = None
    expected_event_seq: int | None = None
    on_behalf_of: dict[str, Any] | None = None
    entity_kind: Literal["work_item"] = "work_item"


class TransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    work_item_id: str
    transition_name: str
    actor_kind: str = "agent"
    actor_metadata: dict[str, Any] | None = None
    payload: dict[str, Any] | None = None
    custom_fields: dict[str, Any] | None = None
    event_id: str | None = None
    expected_event_seq: int | None = None
    on_behalf_of: dict[str, Any] | None = None


class ReadEventsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    work_item_id: str | None = None
    actor_id: str | None = None
    start: str | None = None
    end: str | None = None
    transition: str | None = None
    limit: int = 100
    before_seq: int | None = None


class ReadEventsSinceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    work_item_id: str
    after_seq: int
    limit: int = 100


class QueryWorkItemsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workflow_name: str | None = None
    workflow_version: int | None = None
    work_item_types: list[str] | None = None
    current_states: list[str] | None = None
    claimed_by: str | None = None
    claimable_now: bool | None = None
    needs_review: bool | None = None
    has_link_type: str | None = None
    custom_field_filters: dict[str, Any] | None = None
    cursor: str | None = None
    page_size: int = 100


class AcquireClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    work_item_id: str
    ttl_seconds: int = 300
    event_id: str | None = None
    actor_kind: str = "agent"
    actor_metadata: dict[str, Any] | None = None


class HeartbeatClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    work_item_id: str
    ttl_seconds: int = 300
    expected_attempt_number: int | None = None
    coalesce_threshold: float | None = None
    actor_metadata: dict[str, Any] | None = None


class ReleaseClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    work_item_id: str
    event_id: str | None = None
    actor_kind: str = "agent"
    actor_metadata: dict[str, Any] | None = None


class CreateLinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    from_work_item_id: str
    to_work_item_id: str
    link_type: str
    actor_kind: str = "agent"
    actor_metadata: dict[str, Any] | None = None
    event_id: str | None = None
    payload: dict[str, Any] | None = None
    target_project: str | None = None
    target_entity_kind: str | None = None
    content_hash: str | None = Field(default=None, max_length=256)


class RemoveLinkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    from_work_item_id: str
    to_work_item_id: str
    link_type: str
    actor_kind: str = "agent"
    actor_metadata: dict[str, Any] | None = None
    event_id: str | None = None
    target_project: str | None = None


class UpdateNotBeforeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    work_item_id: str
    not_before: str | None = None
    actor_kind: str = "agent"
    actor_metadata: dict[str, Any] | None = None
    event_id: str | None = None


class ReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    continue_on_revoked: bool = False
    verify_principal_binding: bool = False
    work_item_id: str | None = None


class RegisterActorRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str


class UnregisterActorRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: str


class RegisterRecurrenceRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workflow_name: str
    workflow_version: int
    work_item_type: str
    template: dict[str, Any]
    schedule_kind: str
    schedule_expr: str
    timezone: str = "UTC"
    start_at: str | None = None
    end_at: str | None = None
    count: int | None = None
    catchup_policy: str = "fire_once"


class CancelRecurrenceRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str


class FireRecurrenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str


class RequeueDeadLetteredHookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dead_letter_id: int


class UpdateRecurrenceRuleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_id: str
    status: str | None = None
    schedule_expr: str | None = None
    template: dict[str, Any] | None = None


class TriggerTimestampRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class VerifyTimestampBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    batch_id: str


class ClaimHooksRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_batch: int = 10
    lease_seconds: int = 60


class CompleteHookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FailHookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error: str


class RegisterWitnessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str
    headers: dict[str, str] | None = None
    event_filter: dict[str, Any] | None = None
    max_failures: int = Field(default=10, ge=1)
    max_retries: int = Field(default=3, ge=1)
    public_key: str | None = None
    key_scheme: str = "hmac-sha256"


class ReactivateWitnessRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DeliverWitnessReceiptsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ArchiveEventsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    before_timestamp: str
    dry_run: bool = False


class CreateWorkItemsBatchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[dict[str, Any]]


class ComposeWorkflowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file_path: str


class RegisterWebhookRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str
    headers: dict[str, str] | None = None
    transitions: list[str] | None = None
    work_item_types: list[str] | None = None
    workflows: list[str] | None = None
    max_failures: int = Field(default=10, ge=1)
    sign_secret: str | None = None


class VerifyEventSignatureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event: dict[str, Any]
    public_key: str | None = None


class SignSpecRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spec_yaml: str
    spec_md_hash: str
    spec_schema_version: str
    actor_metadata: dict[str, Any] | None = None
    spec_id: str | None = None


class ReadSpecEventsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    spec_id: str | None = None
    limit: int = Field(default=100, ge=1, le=10000)
