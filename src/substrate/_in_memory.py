from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import structlog
import yaml

from ._contract import (
    Jsonb,
)
from ._errors import ErrorCode, SubstrateError
from ._event_store import InMemoryEventStore
from ._event_store import append_event as _store_append
from ._integrity import SUBSTRATE_VERSION
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


class InMemorySubstrate:
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
    ) -> None:
        self._project = project
        self._key_set: KeySet | None = None
        if hmac_key_path:
            self._key_set = KeySet(hmac_key_path)
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
        self._validators: dict[str, Callable] = {}
        self._hook_handlers: dict[str, Callable] = {}
        self._hook_queue: list[dict] = []
        self._hook_id_counter = 0
        self._dead_letter: dict[int, dict] = {}
        self._hook_consumer_running = False
        self._recurrence_rules: dict[uuid.UUID, dict] = {}
        self._strict_roles = strict_roles

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
    ) -> InMemorySubstrate:
        return cls(
            dsn, project, hmac_key_path,
            pool_min=pool_min, pool_max=pool_max,
            prometheus_registry=prometheus_registry,
            strict_roles=strict_roles,
        )

    def close(self) -> None:
        pass

    @property
    def project(self) -> str:
        return self._project

    @property
    def substrate_version(self) -> str:
        return SUBSTRATE_VERSION

    @property
    def prometheus_registry(self):
        return None

    @property
    def connection_info(self) -> ConnectionInfo:
        return ConnectionInfo(host=None, port=None, database=None, project=self._project)

    def register_validator(self, name: str, handler: Callable) -> None:
        # Validators are trusted, run synchronously in the caller's thread.
        # See Substrate.register_validator docstring and BC-192.
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
                raise SubstrateError(
                    ErrorCode.WORKFLOW_VERSION_CONFLICT,
                    f"Workflow {wf.name!r} v{wf.version} already registered with different content",
                )
            return WorkflowVersion(
                name=key[0],
                version=key[1],
                substrate_version=(
                    self._workflow_defs[key].substrate_version
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
            substrate_version=wf.substrate_version,
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
            raise SubstrateError(
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
        return self._create_work_item(
            workflow_name,
            work_item_type,
            actor_id,
            actor_kind,
            actor_metadata,
            custom_fields=custom_fields,
            not_before=not_before,
            event_id=event_id,
        )

    def append_event(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict | None = None,
        *,
        transition: str | None = None,
        payload: dict | None = None,
        event_id: uuid.UUID | None = None,
        expected_event_seq: int | None = None,
    ) -> Event:
        from ._in_memory_events import in_memory_append_event

        return in_memory_append_event(
            self._store, self._work_items, self._workflows, self._key_set,
            work_item_id, actor_id, actor_kind, actor_metadata,
            transition=transition,
            payload=payload,
            event_id=event_id,
            expected_event_seq=expected_event_seq,
        )

    def transition(
        self,
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
    ) -> Event:
        from ._in_memory_transition import in_memory_transition

        evt, new_counter = in_memory_transition(
            self._store, self._work_items, self._workflows,
            self._actor_roles, self._validators, self._claims,
            self._hook_id_counter, self._hook_queue, self._key_set,
            work_item_id, transition_name, actor_id, actor_kind,
            actor_metadata,
            payload=payload,
            custom_fields=custom_fields,
            event_id=event_id,
            expected_event_seq=expected_event_seq,
            strict_roles=self._strict_roles,
        )
        self._hook_id_counter = new_counter
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
    ) -> Claim:
        from ._in_memory_claims import in_memory_heartbeat_claim

        return in_memory_heartbeat_claim(
            self._store, self._work_items, self._claims, self._key_set,
            work_item_id, actor_id, ttl_seconds,
            expected_attempt_number=expected_attempt_number,
            coalesce_threshold=coalesce_threshold,
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
    ) -> Link:
        from ._in_memory_links import in_memory_create_link

        return in_memory_create_link(
            self._store, self._work_items, self._workflows, self._links,
            self._key_set, from_work_item_id, to_work_item_id, link_type,
            actor_id, actor_kind, actor_metadata, event_id=event_id,
            payload=payload,
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
    ) -> None:
        from ._in_memory_links import in_memory_remove_link

        in_memory_remove_link(
            self._store, self._work_items, self._workflows, self._links,
            self._key_set, from_work_item_id, to_work_item_id, link_type,
            actor_id, actor_kind, actor_metadata, event_id=event_id,
        )

    def replay(self, *, continue_on_revoked: bool = False) -> ReplayReport:
        from ._in_memory_replay import in_memory_replay

        return in_memory_replay(
            self._work_items,
            self._workflows,
            self._store,
            self._key_set,
            continue_on_revoked=continue_on_revoked,
        )

    def requeue_dead_lettered_hook(self, dead_letter_id: int) -> None:
        from ._in_memory_hooks import in_memory_requeue_dead_lettered_hook

        self._hook_id_counter = in_memory_requeue_dead_lettered_hook(
            self._dead_letter, self._hook_queue, self._hook_id_counter,
            dead_letter_id,
        )

    def list_dead_lettered_hooks(self) -> list[DeadLetterEntry]:
        from ._in_memory_hooks import in_memory_list_dead_lettered_hooks

        return in_memory_list_dead_lettered_hooks(self._dead_letter)

    def claim_hooks(
        self,
        max_batch: int = 10,
        lease_seconds: int = 60,
    ) -> list[HookContext]:
        now = datetime.now(UTC)
        lease_expires_at = now + timedelta(seconds=lease_seconds)

        pending = [
            e for e in self._hook_queue
            if e.get("status", "pending") == "pending"
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
            entry["updated_at"] = now

        return result

    def complete_hook(self, hook_queue_id: int) -> None:
        entry = next(
            (e for e in self._hook_queue if e.get("id") == hook_queue_id),
            None,
        )
        if entry is None:
            raise SubstrateError(
                ErrorCode.HOOK_NOT_FOUND,
                f"Hook {hook_queue_id} not found",
            )
        entry["status"] = "completed"
        entry["lease_expires_at"] = None
        entry["updated_at"] = datetime.now(UTC)

    def fail_hook(self, hook_queue_id: int, error: str) -> None:
        from ._in_memory_hooks import _in_memory_move_to_dead_letter

        entry = next(
            (e for e in self._hook_queue if e.get("id") == hook_queue_id),
            None,
        )
        if entry is None:
            raise SubstrateError(
                ErrorCode.HOOK_NOT_FOUND,
                f"Hook {hook_queue_id} not found",
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
    ) -> Event:
        from ._in_memory_work_items import in_memory_update_not_before

        return in_memory_update_not_before(
            self._store, self._work_items, self._key_set,
            work_item_id, not_before, actor_id, actor_kind,
            actor_metadata, event_id=event_id,
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
            raise SubstrateError(
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
        ``substrate.maintenance.hook_queue_depth`` log lines instead.
        The maintenance thread (Plan 009) will call this after every sweep cycle.
        """
        status_counts: dict[str, int] = {}
        for entry in self._hook_queue:
            s = entry.get("status", "pending")
            status_counts[s] = status_counts.get(s, 0) + 1
        dead_count = len(self._dead_letter)
        log.info(
            "substrate.maintenance.hook_queue_depth",
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

    def start_maintenance(
        self,
        *,
        sweep_interval: float = 30.0,
        recurrence_interval: float = 10.0,
        hook_poll_interval: float = 2.0,
        partition_interval: float = 3600.0,
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
            raise SubstrateError(
                ErrorCode.WORKFLOW_NOT_REGISTERED,
                f"Workflow {workflow_name!r} is not registered",
            )
        versions.sort(key=lambda x: x[0][1], reverse=True)
        key, data = versions[0]
        wf_def = self._workflow_defs[key]
        return data, wf_def, key[1]
