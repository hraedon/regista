from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import threading
    import uuid
    from collections.abc import Callable
    from datetime import datetime
    from typing import Any

    from ._contract import Jsonb
    from ._event_store import InMemoryEventStore
    from ._in_memory import TransportResult
    from ._keys import KeySet
    from ._types import Event, WorkflowDefinition, WorkItem


class _InMemoryBase:
    """Type-stub mixin providing shared attributes for InMemoryRegista mixins."""

    if TYPE_CHECKING:
        _project: str
        _key_set: KeySet | None
        _workflows: dict[tuple[str, int], dict[str, Any]]
        _workflow_defs: dict[tuple[str, int], WorkflowDefinition]
        _workflow_hashes: dict[tuple[str, int], bytes]
        _workflow_registered_at: dict[tuple[str, int], datetime]
        _work_items: dict[uuid.UUID, dict[str, Any]]
        _store: InMemoryEventStore
        _claims: dict[uuid.UUID, dict[str, Any]]
        _links: list[dict[str, Any]]
        _actor_roles: set[tuple[str, str]]
        _actor_role_created: dict[tuple[str, str], datetime]
        _validators: dict[str, Callable[..., Any]]
        _hook_handlers: dict[str, Callable[..., Any]]
        _hook_queue: list[dict[str, Any]]
        _hook_id_counter: int
        _dead_letter: dict[int, dict[str, Any]]
        _hook_consumer_running: bool
        _recurrence_rules: dict[uuid.UUID, dict[str, Any]]
        _strict_roles: bool
        _witness_transport: Callable[..., TransportResult] | None
        _witnesses: dict[uuid.UUID, dict[str, Any]]
        _witness_receipts: list[dict[str, Any]]
        _witness_delivery_lock: threading.Lock
        _enrolled_witness_keys: dict[uuid.UUID, Any]
        witnesses: Any

        def _try_create_witness_receipts(self, event: Event) -> None: ...

        def _create_work_item(
            self,
            workflow_name: str,
            work_item_type: str,
            actor_id: str,
            actor_kind: str = "agent",
            actor_metadata: dict[str, Any] | None = None,
            *,
            custom_fields: dict[str, Any] | None = None,
            not_before: datetime | None = None,
            event_id: uuid.UUID | None = None,
            key_id: str | None = None,
            skip_event_id_version_check: bool = False,
        ) -> tuple[WorkItem, Event]: ...

        def _move_to_dead_letter(self, entry: dict[str, Any], error_message: str) -> None: ...

        def _resolve_wf_def(self, workflow_name: str) -> tuple[object, ...]: ...

        def _append_simple_event(
            self, wi: dict[str, Any], event_id: uuid.UUID,
            actor_id: str, actor_kind: str, actor_metadata: Jsonb | None,
            transition: str, payload: Jsonb | None,
        ) -> Event: ...
