from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import threading
    from collections.abc import Callable

    from ._event_store import InMemoryEventStore
    from ._keys import KeySet
    from ._types import Event, WorkflowDefinition


class _InMemoryBase:
    """Type-stub mixin providing shared attributes for InMemoryRegista mixins."""

    if TYPE_CHECKING:
        _project: str
        _key_set: KeySet | None
        _workflows: dict[tuple[str, int], dict]
        _workflow_defs: dict[tuple[str, int], WorkflowDefinition]
        _workflow_hashes: dict[tuple[str, int], bytes]
        _workflow_registered_at: dict[tuple[str, int], object]
        _work_items: dict[object, dict]
        _store: InMemoryEventStore
        _claims: dict[object, dict]
        _links: list[dict]
        _actor_roles: set[tuple[str, str]]
        _actor_role_created: dict[tuple[str, str], object]
        _validators: dict[str, Callable]
        _hook_handlers: dict[str, Callable]
        _hook_queue: list[dict]
        _hook_id_counter: int
        _dead_letter: dict[int, dict]
        _hook_consumer_running: bool
        _recurrence_rules: dict[object, dict]
        _strict_roles: bool
        _witness_transport: Callable[..., object] | None
        _witnesses: dict[object, dict]
        _witness_receipts: list[dict]
        _witness_delivery_lock: threading.Lock
        _enrolled_witness_keys: dict[object, dict]

        def _try_create_witness_receipts(self, event: Event) -> None: ...

        def _create_work_item(self, *args, **kwargs) -> tuple: ...

        def _move_to_dead_letter(self, entry: dict, error_message: str) -> None: ...

        def _resolve_wf_def(self, workflow_name: str) -> tuple: ...

        def _append_simple_event(self, *args, **kwargs) -> None: ...
