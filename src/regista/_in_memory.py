from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import structlog
import yaml

from ._contract import (
    Jsonb,
    validate_delegation_chain,
    validate_entity_kind,
)
from ._errors import ErrorCode, RegistaError
from ._event_store import InMemoryEventStore
from ._event_store import append_event as _store_append
from ._integrity import REGISTA_VERSION
from ._keys import KeySet
from ._types import (
    ActorRole,
    Claim,
    ConnectionInfo,
    DeadLetterEntry,
    Event,
    HookContext,
    Link,
    QueryPage,
    ReplayReport,
    WorkflowDefinition,
    WorkflowVersion,
    WorkItem,
)
from ._workflow import (
    compute_content_hash,
    parse_workflow_yaml,
    validate_and_build,
)

log = structlog.get_logger()


@dataclass(frozen=True)
class TransportResult:
    status_code: int
    body: dict | None = None
    error: str | None = None


class InMemoryRegista:
    def __init__(
        self,
        dsn: str = "",
        project: str = "test",
        hmac_key_path: str = "",
        *,
        pool_min: int = 1,
        pool_max: int = 10,
        prometheus_registry=None,
        strict_roles: bool = False,
        strict_asymmetric: bool = False,
        witness_transport: Callable[..., TransportResult] | None = None,
    ) -> None:
        self._project = project
        self._key_set: KeySet | None = None
        if hmac_key_path:
            self._key_set = KeySet(hmac_key_path, strict_asymmetric=strict_asymmetric)
        self._workflows: dict[tuple[str, int], dict] = {}
        self._workflow_defs: dict[tuple[str, int], WorkflowDefinition] = {}
        self._workflow_hashes: dict[tuple[str, int], bytes] = {}
        self._workflow_registered_at: dict[tuple[str, int], datetime] = {}
        self._work_items: dict[uuid.UUID, dict] = {}
        self._store = InMemoryEventStore()
        self._store.bind(self._work_items)
        self._claims: dict[uuid.UUID, dict] = {}
        self._links: list[dict] = []
        self._actor_roles: set[tuple[str, str]] = set()
        self._actor_role_created: dict[tuple[str, str], datetime] = {}
        from ._review_validators import BUILTIN_REVIEW_VALIDATORS

        self._validators: dict[str, Callable] = dict(BUILTIN_REVIEW_VALIDATORS)
        self._hook_handlers: dict[str, Callable] = {}
        self._hook_queue: list[dict] = []
        self._hook_id_counter = 0
        self._dead_letter: dict[int, dict] = {}
        self._hook_consumer_running = False
        self._recurrence_rules: dict[uuid.UUID, dict] = {}
        self._strict_roles = strict_roles
        self._witness_transport = witness_transport
        self._witnesses: dict[uuid.UUID, dict] = {}
        self._witness_receipts: list[dict] = []
        self._witness_delivery_lock = threading.Lock()

    @classmethod
    def create_project(
        cls,
        dsn: str = "",
        project: str = "test",
        hmac_key_path: str = "",
        *,
        pool_min: int = 1,
        pool_max: int = 10,
        prometheus_registry=None,
        strict_roles: bool = False,
        strict_asymmetric: bool = False,
        witness_transport: Callable[..., TransportResult] | None = None,
    ) -> InMemoryRegista:
        return cls(
            dsn, project, hmac_key_path,
            pool_min=pool_min, pool_max=pool_max,
            prometheus_registry=prometheus_registry,
            strict_roles=strict_roles,
            strict_asymmetric=strict_asymmetric,
            witness_transport=witness_transport,
        )

    def close(self) -> None:
        pass

    def export_public_keys(self) -> list[dict[str, object]]:
        if self._key_set is None:
            return []
        return self._key_set.export_public_keys()

    def verify_event_signature(
        self, event: Event, *, public_key: bytes | None = None,
    ) -> bool:
        from ._signing import verify_event_with_public_key

        if public_key is None:
            if self._key_set is None:
                return False
            try:
                key_entry = self._key_set.get_key(event.key_id)
            except RegistaError:
                return False
            if key_entry.public_key is not None:
                public_key = key_entry.public_key
            else:
                public_key = key_entry.secret
        return verify_event_with_public_key(event, public_key)

    @property
    def project(self) -> str:
        return self._project

    @property
    def regista_version(self) -> str:
        return REGISTA_VERSION

    @property
    def prometheus_registry(self):
        return None

    @property
    def connection_info(self) -> ConnectionInfo:
        return ConnectionInfo(host=None, port=None, database=None, project=self._project)

    def register_validator(self, name: str, handler: Callable) -> None:
        # Validators are trusted, run synchronously in the caller's thread.
        # See Regista.register_validator docstring and BC-192.
        updated = dict(self._validators)
        updated[name] = handler
        self._validators = updated

    def register_hook_handler(self, name: str, handler: Callable) -> None:
        updated = dict(self._hook_handlers)
        updated[name] = handler
        self._hook_handlers = updated

    def start_hook_consumer(self) -> None:
        self._hook_consumer_running = True

    def stop_hook_consumer(self) -> None:
        self._hook_consumer_running = False

    def _move_to_dead_letter(
        self,
        entry: dict,
        error_message: str,
    ) -> None:
        from ._in_memory_hooks import _in_memory_move_to_dead_letter

        _in_memory_move_to_dead_letter(
            entry, self._dead_letter, self._work_items,
            self._store, self._key_set, error_message,
        )

    def poll_hooks(self) -> int:
        from ._in_memory_hooks import in_memory_poll_hooks

        return in_memory_poll_hooks(
            self._hook_queue, self._hook_handlers, self._dead_letter,
            self._work_items, self._store, self._key_set,
        )

    def register_workflow(self, yaml_content: str) -> WorkflowVersion:
        raw_dict = parse_workflow_yaml(yaml_content)
        wf = validate_and_build(raw_dict, yaml_content)
        content_hash = compute_content_hash(wf)
        key = (wf.name, wf.version)

        if key in self._workflows:
            existing_hash = self._workflow_hashes.get(key)
            if existing_hash is not None and existing_hash != content_hash:
                raise RegistaError(
                    ErrorCode.WORKFLOW_VERSION_CONFLICT,
                    f"Workflow {wf.name!r} v{wf.version} already registered with different content",
                )
            return WorkflowVersion(
                name=key[0],
                version=key[1],
                regista_version=(
                    self._workflow_defs[key].regista_version
                ),
                registered_at=self._workflow_registered_at[key],
            )

        now = datetime.now(UTC)
        self._workflows[key] = wf.to_dict()
        self._workflow_defs[key] = wf
        self._workflow_hashes[key] = content_hash
        self._workflow_registered_at[key] = now

        return WorkflowVersion(
            name=wf.name,
            version=wf.version,
            regista_version=wf.regista_version,
            registered_at=now,
        )

    def register_workflow_file(self, path: str | Path) -> WorkflowVersion:
        from ._workflow_compose import resolve_includes

        p = Path(path)
        raw_text = p.read_text()
        raw_dict = parse_workflow_yaml(raw_text)
        if "extends" in raw_dict:
            composed, _ = resolve_includes(p, compose_root=p.parent)
            composed_yaml = yaml.dump(composed, default_flow_style=False, sort_keys=False)
        else:
            composed_yaml = raw_text
        return self.register_workflow(composed_yaml)

    def get_workflow(self, workflow_name: str, version: int) -> WorkflowDefinition:
        key = (workflow_name, version)
        wf_def = self._workflow_defs.get(key)
        if wf_def is None:
            raise RegistaError(
                ErrorCode.WORKFLOW_NOT_REGISTERED,
                f"Workflow {workflow_name!r} v{version} not found",
            )
        return wf_def

    def _create_work_item(
        self,
        workflow_name: str,
        work_item_type: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict | None = None,
        *,
        custom_fields: dict | None = None,
        not_before: datetime | None = None,
        event_id: uuid.UUID | None = None,
        skip_event_id_version_check: bool = False,
    ) -> tuple[WorkItem, Event]:
        from ._in_memory_work_items import in_memory_create_work_item

        return in_memory_create_work_item(
            self._store, self._work_items, self._workflows,
            self._workflow_defs, self._key_set,
            workflow_name, work_item_type, actor_id, actor_kind,
            actor_metadata,
            custom_fields=custom_fields,
            not_before=not_before,
            event_id=event_id,
            skip_event_id_version_check=skip_event_id_version_check,
        )

    def create_work_item(
        self,
        workflow_name: str,
        work_item_type: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict | None = None,
        *,
        custom_fields: dict | None = None,
        not_before: datetime | None = None,
        event_id: uuid.UUID | None = None,
    ) -> tuple[WorkItem, Event]:
        wi, evt = self._create_work_item(
            workflow_name,
            work_item_type,
            actor_id,
            actor_kind,
            actor_metadata,
            custom_fields=custom_fields,
            not_before=not_before,
            event_id=event_id,
        )
        self._try_create_witness_receipts(evt)
        return wi, evt

    def append_event(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict | None = None,
        *,
        key_id: str | None = None,
        transition: str | None = None,
        payload: dict | None = None,
        event_id: uuid.UUID | None = None,
        expected_event_seq: int | None = None,
        on_behalf_of: dict | None = None,
        entity_kind: str = "work_item",
        hash_alg: str = "sha-256",
    ) -> Event:
        from ._in_memory_events import in_memory_append_event

        validate_entity_kind(entity_kind)
        validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())
        evt = in_memory_append_event(
            self._store, self._work_items, self._workflows, self._key_set,
            work_item_id, actor_id, actor_kind, actor_metadata,
            key_id=key_id,
            transition=transition,
            payload=payload,
            event_id=event_id,
            expected_event_seq=expected_event_seq,
            on_behalf_of=on_behalf_of,
            entity_kind=entity_kind,
            hash_alg=hash_alg,
        )
        self._try_create_witness_receipts(evt)
        return evt

    def transition(
        self,
        work_item_id: uuid.UUID,
        transition_name: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict | None = None,
        *,
        key_id: str | None = None,
        payload: dict | None = None,
        custom_fields: dict | None = None,
        event_id: uuid.UUID | None = None,
        expected_event_seq: int | None = None,
        on_behalf_of: dict | None = None,
    ) -> Event:
        from ._in_memory_transition import in_memory_transition

        validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())
        evt, new_counter = in_memory_transition(
            self._store, self._work_items, self._workflows,
            self._actor_roles, self._validators, self._claims,
            self._hook_id_counter, self._hook_queue, self._key_set,
            work_item_id, transition_name, actor_id, actor_kind,
            actor_metadata,
            key_id=key_id,
            payload=payload,
            custom_fields=custom_fields,
            event_id=event_id,
            expected_event_seq=expected_event_seq,
            on_behalf_of=on_behalf_of,
            strict_roles=self._strict_roles,
        )
        self._hook_id_counter = new_counter
        self._try_create_witness_receipts(evt)
        return evt

    def read_events(
        self,
        *,
        work_item_id: uuid.UUID | None = None,
        actor_id: str | None = None,
        start: datetime | None = None,
        end: datetime | None = None,
        transition: str | None = None,
        limit: int = 100,
        before_seq: int | None = None,
    ) -> list[Event]:
        from ._in_memory_events import in_memory_read_events

        return in_memory_read_events(
            self._store,
            work_item_id=work_item_id,
            actor_id=actor_id,
            start=start,
            end=end,
            transition=transition,
            limit=limit,
            before_seq=before_seq,
        )

    def read_events_since(
        self,
        work_item_id: uuid.UUID,
        after_seq: int,
        *,
        limit: int = 100,
    ) -> list[Event]:
        from ._in_memory_events import in_memory_read_events_since

        return in_memory_read_events_since(
            self._store, work_item_id, after_seq, limit=limit,
        )

    def query_work_items(
        self,
        *,
        workflow_name: str | None = None,
        workflow_version: int | None = None,
        work_item_types: list[str] | None = None,
        current_states: list[str] | None = None,
        claimed_by: str | None = None,
        claimable_now: bool | None = None,
        needs_review: bool | None = None,
        has_link_type: str | None = None,
        custom_field_filters: dict[str, object] | None = None,
        cursor: uuid.UUID | None = None,
        page_size: int = 100,
    ) -> QueryPage[WorkItem]:
        from ._in_memory_work_items import in_memory_query_work_items

        return in_memory_query_work_items(
            self._work_items, self._links,
            workflow_name=workflow_name,
            workflow_version=workflow_version,
            work_item_types=work_item_types,
            current_states=current_states,
            claimed_by=claimed_by,
            claimable_now=claimable_now,
            needs_review=needs_review,
            has_link_type=has_link_type,
            custom_field_filters=custom_field_filters,
            cursor=cursor,
            page_size=page_size,
        )

    def get_work_item(self, work_item_id: uuid.UUID) -> WorkItem | None:
        from ._in_memory_work_items import _wi_to_work_item

        wi = self._work_items.get(work_item_id)
        if wi is None:
            return None
        return _wi_to_work_item(wi)

    def acquire_claim(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        ttl_seconds: int = 300,
        *,
        event_id: uuid.UUID | None = None,
        actor_kind: str = "agent",
    ) -> Claim:
        from ._in_memory_claims import in_memory_acquire_claim

        return in_memory_acquire_claim(
            self._store, self._work_items, self._claims, self._workflows,
            self._key_set, work_item_id, actor_id, ttl_seconds,
            event_id=event_id, actor_kind=actor_kind,
        )

    def heartbeat_claim(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        ttl_seconds: int = 300,
        *,
        expected_attempt_number: int | None = None,
        coalesce_threshold: float | None = None,
        actor_kind: str = "agent",
    ) -> Claim:
        from ._in_memory_claims import in_memory_heartbeat_claim

        return in_memory_heartbeat_claim(
            self._store, self._work_items, self._claims, self._key_set,
            work_item_id, actor_id, ttl_seconds,
            expected_attempt_number=expected_attempt_number,
            coalesce_threshold=coalesce_threshold,
            actor_kind=actor_kind,
        )

    def release_claim(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        *,
        event_id: uuid.UUID | None = None,
        actor_kind: str = "agent",
    ) -> None:
        from ._in_memory_claims import in_memory_release_claim

        in_memory_release_claim(
            self._store, self._work_items, self._claims, self._key_set,
            work_item_id, actor_id, event_id=event_id, actor_kind=actor_kind,
        )

    def sweep_expired_claims(self) -> int:
        from ._in_memory_claims import in_memory_sweep_expired_claims

        return in_memory_sweep_expired_claims(
            self._store, self._work_items, self._claims, self._key_set,
        )

    def create_link(
        self,
        from_work_item_id: uuid.UUID,
        to_work_item_id: uuid.UUID,
        link_type: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict | None = None,
        *,
        event_id: uuid.UUID | None = None,
        payload: dict | None = None,
        target_project: str | None = None,
        target_entity_kind: str | None = None,
        content_hash: str | None = None,
    ) -> Link:
        from ._in_memory_links import in_memory_create_link

        return in_memory_create_link(
            self._store, self._work_items, self._workflows, self._links,
            self._key_set, from_work_item_id, to_work_item_id, link_type,
            actor_id, actor_kind, actor_metadata, event_id=event_id,
            payload=payload,
            target_project=target_project,
            target_entity_kind=target_entity_kind,
            content_hash=content_hash,
        )

    def remove_link(
        self,
        from_work_item_id: uuid.UUID,
        to_work_item_id: uuid.UUID,
        link_type: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict | None = None,
        *,
        event_id: uuid.UUID | None = None,
        target_project: str | None = None,
    ) -> None:
        from ._in_memory_links import in_memory_remove_link

        in_memory_remove_link(
            self._store, self._work_items, self._workflows, self._links,
            self._key_set, from_work_item_id, to_work_item_id, link_type,
            actor_id, actor_kind, actor_metadata, event_id=event_id,
            target_project=target_project,
        )

    def replay(
        self,
        *,
        continue_on_revoked: bool = False,
        verify_timestamps: bool = False,
        work_item_id: uuid.UUID | None = None,
    ) -> ReplayReport:
        if work_item_id is not None and work_item_id not in self._work_items:
            if work_item_id not in self._store.events:
                raise RegistaError(
                    ErrorCode.WORK_ITEM_NOT_FOUND,
                    f"Work item {work_item_id} not found for scoped replay",
                )
        from ._in_memory_replay import in_memory_replay

        return in_memory_replay(
            self._work_items,
            self._workflows,
            self._store,
            self._key_set,
            continue_on_revoked=continue_on_revoked,
            work_item_id=work_item_id,
        )

    def requeue_dead_lettered_hook(self, dead_letter_id: int) -> None:
        from ._in_memory_hooks import in_memory_requeue_dead_lettered_hook

        self._hook_id_counter = in_memory_requeue_dead_lettered_hook(
            self._dead_letter, self._hook_queue, self._hook_id_counter,
            dead_letter_id,
        )

    def list_dead_lettered_hooks(self, limit: int = 100) -> list[DeadLetterEntry]:
        from ._in_memory_hooks import in_memory_list_dead_lettered_hooks

        return in_memory_list_dead_lettered_hooks(self._dead_letter, limit=limit)

    def claim_hooks(
        self,
        max_batch: int = 10,
        lease_seconds: int = 60,
        actor_id: str | None = None,
    ) -> list[HookContext]:
        now = datetime.now(UTC)
        lease_expires_at = now + timedelta(seconds=lease_seconds)

        pending = [
            e for e in self._hook_queue
            if e.get("status", "pending") == "pending"
            and (
                e.get("next_retry_at") is None
                or e["next_retry_at"] <= now
            )
        ][:max_batch]

        valid = []
        result = []
        for entry in pending:
            work_item_id = entry.get("work_item_id")
            if work_item_id is None:
                continue
            valid.append(entry)
            result.append(HookContext(
                hook_queue_id=entry["id"],
                event_id=entry["event_id"],
                work_item_id=work_item_id,
                hook_name=entry["hook_name"],
                transition=entry.get("transition"),
                payload=entry.get("payload"),
            ))

        for entry in valid:
            entry["status"] = "in_progress"
            entry["lease_expires_at"] = lease_expires_at
            entry["claimed_by"] = actor_id
            entry["updated_at"] = now

        return result

    def complete_hook(self, hook_queue_id: int, actor_id: str | None = None) -> None:
        entry = next(
            (e for e in self._hook_queue if e.get("id") == hook_queue_id),
            None,
        )
        if entry is None:
            raise RegistaError(
                ErrorCode.HOOK_NOT_FOUND,
                f"Hook {hook_queue_id} not found",
            )
        if entry.get("status") != "in_progress":
            raise RegistaError(
                ErrorCode.HOOK_NOT_FOUND,
                f"Hook {hook_queue_id} not found or not in progress "
                f"(status={entry.get('status')})",
            )
        if actor_id is not None and entry.get("claimed_by") != actor_id:
            raise RegistaError(
                ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER,
                f"Hook {hook_queue_id} is not claimed by {actor_id!r}",
            )
        entry["status"] = "completed"
        entry["lease_expires_at"] = None
        entry["claimed_by"] = None
        entry["updated_at"] = datetime.now(UTC)

    def fail_hook(self, hook_queue_id: int, error: str, actor_id: str | None = None) -> None:
        from ._in_memory_hooks import _in_memory_move_to_dead_letter

        entry = next(
            (e for e in self._hook_queue if e.get("id") == hook_queue_id),
            None,
        )
        if entry is None:
            raise RegistaError(
                ErrorCode.HOOK_NOT_FOUND,
                f"Hook {hook_queue_id} not found",
            )

        if actor_id is not None and entry.get("claimed_by") != actor_id:
            raise RegistaError(
                ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER,
                f"Hook {hook_queue_id} is not claimed by {actor_id!r}",
            )
        if entry.get("status") != "in_progress":
            raise RegistaError(
                ErrorCode.HOOK_NOT_FOUND,
                f"Hook {hook_queue_id} not found or not in progress "
                f"(status={entry.get('status')})",
            )

        retry_count = entry.get("retry_count", 0) + 1
        max_retries = entry.get("max_retries", 3)

        if retry_count >= max_retries:
            _in_memory_move_to_dead_letter(
                entry, self._dead_letter, self._work_items,
                self._store, self._key_set, error,
            )
        else:
            entry["retry_count"] = retry_count
            entry["status"] = "pending"
            entry["lease_expires_at"] = None
            entry["claimed_by"] = None
            entry["updated_at"] = datetime.now(UTC)

    def sweep_expired_hook_leases(self) -> int:
        now = datetime.now(UTC)
        swept = 0
        for entry in self._hook_queue:
            if (
                entry.get("status") == "in_progress"
                and entry.get("lease_expires_at") is not None
                and entry["lease_expires_at"] < now
            ):
                entry["status"] = "pending"
                entry["lease_expires_at"] = None
                entry["claimed_by"] = None
                entry["updated_at"] = now
                swept += 1
        return swept

    def ensure_event_partitions(self, months_ahead: int = 3) -> list[str]:
        return []

    def update_not_before(
        self,
        work_item_id: uuid.UUID,
        not_before: datetime | None,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict | None = None,
        *,
        event_id: uuid.UUID | None = None,
        on_behalf_of: dict | None = None,
    ) -> Event:
        from ._in_memory_work_items import in_memory_update_not_before

        return in_memory_update_not_before(
            self._store, self._work_items, self._key_set,
            work_item_id, not_before, actor_id, actor_kind,
            actor_metadata, event_id=event_id,
            on_behalf_of=on_behalf_of,
        )

    def register_actor_role(self, actor_id: str, role: str) -> None:
        from ._contract import validate_actor_id

        validate_actor_id(actor_id)
        key = (actor_id, role)
        if key in self._actor_roles:
            return
        self._actor_roles.add(key)
        self._actor_role_created[key] = datetime.now(UTC)

    def unregister_actor_role(self, actor_id: str, role: str) -> None:
        from ._contract import validate_actor_id

        validate_actor_id(actor_id)
        key = (actor_id, role)
        if key not in self._actor_roles:
            raise RegistaError(
                ErrorCode.ACTOR_ROLE_NOT_REGISTERED,
                f"Role {role!r} not registered for actor {actor_id!r}",
            )
        self._actor_roles.discard(key)
        del self._actor_role_created[key]

    def list_actor_roles(self, actor_id: str | None = None) -> list[ActorRole]:
        result = []
        for (aid, role), created_at in self._actor_role_created.items():
            if actor_id is None or aid == actor_id:
                result.append(ActorRole(actor_id=aid, role=role, created_at=created_at))
        return sorted(result, key=lambda r: (r.actor_id, r.role))

    def register_recurrence_rule(
        self,
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
    ) -> dict:
        from ._in_memory_recurrence import in_memory_register_recurrence_rule

        return in_memory_register_recurrence_rule(
            self._workflow_defs, self._recurrence_rules,
            workflow_name, workflow_version, work_item_type,
            template, schedule_kind, schedule_expr,
            timezone=timezone, start_at=start_at, end_at=end_at,
            count=count, catchup_policy=catchup_policy,
            created_by=created_by,
        )

    def list_recurrence_rules(self, status: str | None = None) -> list[dict]:
        from ._in_memory_recurrence import in_memory_list_recurrence_rules

        return in_memory_list_recurrence_rules(self._recurrence_rules, status)

    def due_recurrences(self, now: datetime | None = None) -> list[dict]:
        from ._in_memory_recurrence import in_memory_due_recurrences

        return in_memory_due_recurrences(self._recurrence_rules, now)

    def fire_recurrence(self, rule_id: uuid.UUID) -> tuple[dict, dict]:
        from ._in_memory_recurrence import in_memory_fire_recurrence

        return in_memory_fire_recurrence(
            self._recurrence_rules,
            lambda **kw: self._create_work_item(**kw),
            rule_id,
        )

    def cancel_recurrence_rule(self, rule_id: uuid.UUID) -> None:
        from ._in_memory_recurrence import in_memory_cancel_recurrence_rule

        in_memory_cancel_recurrence_rule(self._recurrence_rules, rule_id)

    def update_recurrence_rule(
        self,
        rule_id: uuid.UUID,
        *,
        status: str | None = None,
        schedule_expr: str | None = None,
        template: dict | None = None,
    ) -> dict:
        from ._in_memory_recurrence import in_memory_update_recurrence_rule

        return in_memory_update_recurrence_rule(
            self._recurrence_rules, rule_id,
            status=status, schedule_expr=schedule_expr, template=template,
        )

    @staticmethod
    def validate_actor_metadata(
        event: Event,
        expected_schema: dict | None = None,
    ) -> list[str]:
        from ._lint import validate_actor_metadata as _validate
        return _validate(event, expected_schema)

    @staticmethod
    def actor_metadata_complete(
        events: list[Event],
        expected_keys: list[str],
    ) -> list[Event]:
        from ._lint import actor_metadata_complete as _complete
        return _complete(events, expected_keys)

    def refresh_hook_queue_metrics(self) -> None:
        """Emit structured log lines with hook_queue depth counts.

        The InMemory backend has no Prometheus registry, so this emits
        ``regista.maintenance.hook_queue_depth`` log lines instead.
        The maintenance thread (Plan 009) will call this after every sweep cycle.
        """
        status_counts: dict[str, int] = {}
        for entry in self._hook_queue:
            s = entry.get("status", "pending")
            status_counts[s] = status_counts.get(s, 0) + 1
        dead_count = len(self._dead_letter)
        log.info(
            "regista.maintenance.hook_queue_depth",
            project=self._project,
            pending=status_counts.get("pending", 0),
            in_progress=status_counts.get("in_progress", 0),
            completed=status_counts.get("completed", 0),
            dead_letter=dead_count,
        )

    @property
    def maintenance_healthy(self) -> bool:
        """InMemory backend has no maintenance thread; always returns True."""
        return True

    @property
    def witnesses(self) -> _InMemoryWitnessOps:
        return _InMemoryWitnessOps(self)

    def start_maintenance(
        self,
        *,
        sweep_interval: float = 30.0,
        recurrence_interval: float = 10.0,
        hook_poll_interval: float = 2.0,
        partition_interval: float = 3600.0,
        timestamp_interval: float = 3600.0,
        tsa_config=None,
        witness_interval: float = 30.0,
    ) -> None:
        pass

    def stop_maintenance(self) -> None:
        pass

    def _append_simple_event(
        self, wi: dict, event_id: uuid.UUID,
        actor_id: str, actor_kind: str, actor_metadata: Jsonb | None,
        transition: str, payload: Jsonb | None,
    ) -> None:
        return _store_append(
            self._store,
            work_item_id=wi["work_item_id"],
            actor_id=actor_id,
            actor_kind=actor_kind,
            actor_metadata=actor_metadata,
            workflow_name=wi["workflow_name"],
            workflow_version=wi["workflow_version"],
            transition=transition,
            payload=payload,
            event_id=event_id,
            key_set=self._key_set,
        )

    def _resolve_wf_def(self, workflow_name: str) -> tuple[dict, WorkflowDefinition, int]:
        versions = [(k, v) for k, v in self._workflows.items() if k[0] == workflow_name]
        if not versions:
            raise RegistaError(
                ErrorCode.WORKFLOW_NOT_REGISTERED,
                f"Workflow {workflow_name!r} is not registered",
            )
        versions.sort(key=lambda x: x[0][1], reverse=True)
        key, data = versions[0]
        wf_def = self._workflow_defs[key]
        return data, wf_def, key[1]

    def register_witness(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        event_filter: dict | None = None,
        max_failures: int = 10,
        max_retries: int = 3,
        *,
        mode: str = "witness",
        sign_secret: bytes | None = None,
        public_key: bytes | None = None,
        key_scheme: str = "hmac-sha256",
    ) -> uuid.UUID:
        from ._witness import _validate_event_filter, _validate_url

        _validate_url(url)
        event_filter = _validate_event_filter(event_filter)
        if mode not in ("witness", "push"):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"mode must be 'witness' or 'push', got {mode!r}",
            )
        if max_failures < 1:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"max_failures must be >= 1, got {max_failures}",
            )
        if max_retries < 1:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"max_retries must be >= 1, got {max_retries}",
            )
        if key_scheme not in ("hmac-sha256", "ed25519"):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"key_scheme must be 'hmac-sha256' or 'ed25519', got {key_scheme!r}",
            )
        if key_scheme == "ed25519":
            if public_key is None:
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    "public_key is required when key_scheme is 'ed25519'",
                )
            if len(public_key) != 32:
                raise RegistaError(
                    ErrorCode.INVALID_ARGUMENT,
                    "ed25519 public_key must be exactly 32 bytes, "
                    f"got {len(public_key)}",
                )
        witness_id = uuid.uuid4()
        self._witnesses[witness_id] = {
            "witness_id": witness_id,
            "url": url,
            "headers": dict(headers) if headers else None,
            "event_filter": dict(event_filter) if event_filter else None,
            "status": "active",
            "max_failures": max_failures,
            "consecutive_failures": 0,
            "max_retries": max_retries,
            "mode": mode,
            "sign_secret": sign_secret,
            "public_key": public_key,
            "key_scheme": key_scheme,
            "last_success_at": None,
            "last_failure_at": None,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }
        return witness_id

    def unregister_witness(self, witness_id: uuid.UUID) -> None:
        if witness_id not in self._witnesses:
            raise RegistaError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"witness {witness_id} not found",
            )
        del self._witnesses[witness_id]
        self._witness_receipts = [
            r for r in self._witness_receipts
            if r["witness_id"] != witness_id
        ]

    def pause_witness(self, witness_id: uuid.UUID) -> None:
        if witness_id not in self._witnesses:
            raise RegistaError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"witness {witness_id} not found",
            )
        self._witnesses[witness_id]["status"] = "paused"

    def reactivate_witness(self, witness_id: uuid.UUID) -> None:
        if witness_id not in self._witnesses:
            raise RegistaError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"witness {witness_id} not found",
            )
        w = self._witnesses[witness_id]
        w["status"] = "active"
        w["consecutive_failures"] = 0

    def list_witnesses(self, status: str | None = None, mode: str | None = None) -> list[dict]:
        results = []
        for w in self._witnesses.values():
            if status is not None and w["status"] != status:
                continue
            if mode is not None and w.get("mode") != mode:
                continue
            d = dict(w)
            d["witness_id"] = str(d["witness_id"])
            d.pop("sign_secret", None)
            for key in ("last_success_at", "last_failure_at", "created_at", "updated_at"):
                if d.get(key) is not None:
                    d[key] = d[key].isoformat()
            results.append(d)
        return results

    def list_witness_receipts(
        self,
        event_id: uuid.UUID | None = None,
        witness_id: uuid.UUID | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        results = []
        for r in self._witness_receipts:
            if event_id is not None and r["event_id"] != event_id:
                continue
            if witness_id is not None and r["witness_id"] != witness_id:
                continue
            if status is not None and r["status"] != status:
                continue
            d = dict(r)
            d["receipt_id"] = str(d["receipt_id"])
            d["witness_id"] = str(d["witness_id"])
            d["event_id"] = str(d["event_id"])
            for key in ("submitted_at", "last_attempt_at", "confirmed_at", "created_at"):
                if d.get(key) is not None:
                    d[key] = d[key].isoformat()
            if d.get("witness_signature") is not None:
                d["witness_signature"] = bytes(d["witness_signature"]).hex()
            results.append(d)
        return results[:limit]

    def deliver_pending_witness_receipts(self) -> int:
        if self._witness_transport is None:
            return 0
        import hashlib
        import hmac as _hmac
        import json

        with self._witness_delivery_lock:
            total = 0
            active_witnesses = [
                w for w in self._witnesses.values()
                if w["status"] == "active"
            ]

            for w in active_witnesses:
                witness_id = w["witness_id"]
                url = w["url"]
                base_headers = dict(w["headers"]) if w["headers"] else {}
                max_retries = w["max_retries"]
                max_failures = w["max_failures"]
                sign_secret = w["sign_secret"]
                witness_key_scheme = w["key_scheme"]

                pending = [
                    r for r in self._witness_receipts
                    if r["witness_id"] == witness_id and r["status"] == "pending"
                ]
                if not pending:
                    continue

                for receipt in pending:
                    receipt["status"] = "in_progress"
                    receipt["last_attempt_at"] = datetime.now(UTC)

                for receipt in pending:
                    event_id = receipt["event_id"]
                    event = self._store.find_by_event_id(event_id)
                    if event is None:
                        now = datetime.now(UTC)
                        receipt["status"] = "pending"
                        receipt["retry_count"] += 1
                        receipt["error_message"] = "event not found"
                        receipt["last_attempt_at"] = now
                        receipt["witness_scheme"] = witness_key_scheme
                        if receipt["retry_count"] >= max_retries:
                            receipt["status"] = "paused"
                        continue

                    try:
                        evt_dict = event.to_dict()
                        payload = {
                            "event": evt_dict,
                            "receipt_id": str(receipt["receipt_id"]),
                            "witness_id": str(witness_id),
                            "submitted_at": datetime.now(UTC).isoformat(),
                        }
                        body = json.dumps(payload)
                    except Exception as exc:
                        now = datetime.now(UTC)
                        receipt["status"] = "pending"
                        receipt["retry_count"] += 1
                        receipt["last_attempt_at"] = now
                        receipt["error_message"] = f"payload error: {str(exc)[:400]}"
                        receipt["witness_scheme"] = witness_key_scheme
                        w["consecutive_failures"] += 1
                        w["last_failure_at"] = now
                        w["updated_at"] = now
                        if receipt["retry_count"] >= max_retries:
                            receipt["status"] = "paused"
                        if w["consecutive_failures"] >= max_failures:
                            w["status"] = "paused"
                            log.warning(
                                "witness.auto_paused",
                                project=self._project,
                                witness_id=str(witness_id),
                                consecutive_failures=w["consecutive_failures"],
                            )
                        continue
                    req_headers = {
                        "Content-Type": "application/json",
                        "User-Agent": "regista-delivery/0",
                        **base_headers,
                    }
                    if sign_secret:
                        sig = _hmac.new(
                            sign_secret, body.encode(), hashlib.sha256,
                        ).hexdigest()
                        req_headers["X-Regista-Signature"] = f"sha256={sig}"

                    try:
                        result = self._witness_transport(url, req_headers, payload)
                    except Exception as exc:
                        result = TransportResult(
                            status_code=0, error=str(exc)[:500],
                        )

                    now = datetime.now(UTC)

                    if 200 <= result.status_code < 300 and result.error is None:
                        witness_sig = None
                        if result.body and "witness_signature" in result.body:
                            try:
                                witness_sig = bytes.fromhex(
                                    result.body["witness_signature"],
                                )
                            except (ValueError, TypeError):
                                witness_sig = None

                        witness_pubkey = w.get("public_key")
                        sig_verified = True
                        if witness_key_scheme == "ed25519":
                            sig_verified = False
                            if (
                                witness_pubkey is not None
                                and witness_sig is not None
                                and event.canonical_envelope is not None
                                and event.payload_canonical_hash is not None
                            ):
                                try:
                                    from ._signing_scheme import Ed25519Scheme

                                    sig_verified = Ed25519Scheme().verify(
                                        event.canonical_envelope,
                                        witness_sig,
                                        event.payload_canonical_hash,
                                        witness_pubkey,
                                    )
                                except Exception:
                                    sig_verified = False

                        if sig_verified:
                            receipt["status"] = "confirmed"
                            receipt["confirmed_at"] = now
                            receipt["witness_response"] = result.body
                            receipt["witness_signature"] = witness_sig
                            receipt["witness_scheme"] = witness_key_scheme
                            receipt["submitted_at"] = receipt["submitted_at"] or now
                            receipt["error_message"] = None
                            w["consecutive_failures"] = 0
                            w["last_success_at"] = now
                            w["updated_at"] = now
                            total += 1
                        else:
                            error_msg = "ed25519 signature verification failed"
                            receipt["retry_count"] += 1
                            receipt["last_attempt_at"] = now
                            receipt["error_message"] = error_msg
                            receipt["witness_scheme"] = witness_key_scheme
                            receipt["status"] = "pending"

                            w["consecutive_failures"] += 1
                            w["last_failure_at"] = now
                            w["updated_at"] = now

                            if receipt["retry_count"] >= max_retries:
                                receipt["status"] = "paused"

                            if w["consecutive_failures"] >= max_failures:
                                w["status"] = "paused"
                                log.warning(
                                    "witness.auto_paused",
                                    project=self._project,
                                    witness_id=str(witness_id),
                                    consecutive_failures=w["consecutive_failures"],
                                )
                    else:
                        error_msg = result.error or f"HTTP {result.status_code}"
                        receipt["retry_count"] += 1
                        receipt["last_attempt_at"] = now
                        receipt["error_message"] = error_msg
                        receipt["witness_scheme"] = witness_key_scheme
                        receipt["status"] = "pending"

                        w["consecutive_failures"] += 1
                        w["last_failure_at"] = now
                        w["updated_at"] = now

                        if receipt["retry_count"] >= max_retries:
                            receipt["status"] = "paused"

                        if w["consecutive_failures"] >= max_failures:
                            w["status"] = "paused"
                            log.warning(
                                "witness.auto_paused",
                                project=self._project,
                                witness_id=str(witness_id),
                                consecutive_failures=w["consecutive_failures"],
                            )

            return total

    def sweep_stuck_witness_receipts(self, max_age_seconds: int = 300) -> int:
        return self.witnesses.sweep_stuck(max_age_seconds)

    def sweep_stale_timestamp_batches(self, max_age_seconds: int = 300) -> int:
        return 0

    def _try_create_witness_receipts(self, event: Event) -> None:
        from ._witness import event_matches_filter

        try:
            for w in list(self._witnesses.values()):
                if w["status"] != "active":
                    continue
                if not event_matches_filter(event.to_dict(), w.get("event_filter")):
                    continue
                receipt_id = uuid.uuid4()
                self._witness_receipts.append({
                    "receipt_id": receipt_id,
                    "witness_id": w["witness_id"],
                    "event_id": event.event_id,
                    "status": "pending",
                    "retry_count": 0,
                    "submitted_at": None,
                    "last_attempt_at": None,
                    "confirmed_at": None,
                    "witness_signature": None,
                    "witness_response": None,
                    "witness_scheme": None,
                    "error_message": None,
                    "created_at": datetime.now(UTC),
                })
        except Exception:
            import structlog
            structlog.get_logger().warning(
                "witness.create_receipts_failed_in_memory",
                event_id=str(event.event_id),
            )



class _InMemoryWitnessOps:
    def __init__(self, sub: InMemoryRegista) -> None:
        self._sub = sub

    def register(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        event_filter: dict | None = None,
        max_failures: int = 10,
        max_retries: int = 3,
        *,
        mode: str = "witness",
        sign_secret: bytes | None = None,
        public_key: bytes | None = None,
        key_scheme: str = "hmac-sha256",
    ) -> uuid.UUID:
        return self._sub.register_witness(
            url, headers=headers, event_filter=event_filter,
            max_failures=max_failures, max_retries=max_retries,
            mode=mode, sign_secret=sign_secret,
            public_key=public_key, key_scheme=key_scheme,
        )

    def unregister(self, witness_id: uuid.UUID) -> None:
        self._sub.unregister_witness(witness_id)

    def pause(self, witness_id: uuid.UUID) -> None:
        self._sub.pause_witness(witness_id)

    def reactivate(self, witness_id: uuid.UUID) -> None:
        self._sub.reactivate_witness(witness_id)

    def list(self, status: str | None = None, mode: str | None = None) -> list[dict]:
        witnesses = self._sub.list_witnesses(status=status)
        if mode is not None:
            witnesses = [w for w in witnesses if w.get("mode") == mode]
        return witnesses

    def receipts(
        self,
        event_id: uuid.UUID | None = None,
        witness_id: uuid.UUID | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        return self._sub.list_witness_receipts(
            event_id=event_id, witness_id=witness_id,
            status=status, limit=limit,
        )

    def deliver(self) -> int:
        return self._sub.deliver_pending_witness_receipts()

    def sweep_stuck(self, max_age_seconds: int = 300) -> int:
        if max_age_seconds <= 0:
            from ._errors import ErrorCode, RegistaError

            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "max_age_seconds must be a positive integer",
            )
        now = datetime.now(UTC)
        threshold = now - timedelta(seconds=max_age_seconds)
        count = 0
        with self._sub._witness_delivery_lock:
            for r in self._sub._witness_receipts:
                if r["status"] == "in_progress" and r.get("last_attempt_at") is not None:
                    if r["last_attempt_at"] < threshold:
                        r["status"] = "pending"
                        count += 1
        return count

    def create_receipts_for_event(self, event_dict: dict) -> int:
        from regista._types import Event
        evt_id = uuid.UUID(event_dict["event_id"])
        self._sub._try_create_witness_receipts(Event(**event_dict))
        return sum(
            1 for r in self._sub._witness_receipts
            if r["event_id"] == evt_id
        )

    @staticmethod
    def event_matches_filter(event_dict: dict, event_filter: dict | None) -> bool:
        from ._witness import event_matches_filter
        return event_matches_filter(event_dict, event_filter)
