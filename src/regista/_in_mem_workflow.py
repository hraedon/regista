from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import yaml

from ._contract import (
    Jsonb,
    validate_delegation_chain,
    validate_entity_kind,
)
from ._errors import ErrorCode, RegistaError
from ._in_mem_base import _InMemoryBase
from ._types import (
    Event,
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


class InMemWorkflowMixin(_InMemoryBase):

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

    def _append_simple_event(
        self, wi: dict, event_id: uuid.UUID,
        actor_id: str, actor_kind: str, actor_metadata: Jsonb | None,
        transition: str, payload: Jsonb | None,
    ) -> None:
        from ._event_store import append_event as _store_append

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
