from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from ._connection import ConnectionManager
    from ._hooks import HookConsumer
    from ._keys import KeySet
    from ._observability import Metrics
    from ._ops import (
        ArchiveOps,
        ClaimOps,
        EventOps,
        HookOps,
        LinkOps,
        RecurrenceOps,
        TimestampOps,
        WebhookOps,
        WitnessOps,
        WorkflowOps,
        WorkItemOps,
    )
    from ._types import Event


class _RegistaBase:
    """Type-stub mixin providing shared attributes for API mixins.

    ``Regista`` sets all of these in ``__init__``; the annotations here exist
    solely so that mixin methods can be type-checked.  At runtime this class
    adds no behaviour.
    """

    if TYPE_CHECKING:
        _mgr: ConnectionManager
        _keys: KeySet
        _metrics: Metrics
        _project: str
        _validators: dict[str, Callable]
        _hook_handlers: dict[str, Callable]
        _hook_channel: str
        _hook_consumer: HookConsumer | None
        _maintenance_thread: object | None
        _strict_roles: bool

        def _require_open(self) -> None: ...

        def _try_create_witness_receipts(self, event: Event) -> None: ...

        def start_hook_consumer(self) -> None: ...

        @property
        def workflows(self) -> WorkflowOps: ...

        @property
        def work_items(self) -> WorkItemOps: ...

        @property
        def events(self) -> EventOps: ...

        @property
        def claims(self) -> ClaimOps: ...

        @property
        def links(self) -> LinkOps: ...

        @property
        def hooks(self) -> HookOps: ...

        @property
        def recurrence(self) -> RecurrenceOps: ...

        @property
        def timestamping(self) -> TimestampOps: ...

        @property
        def witnesses(self) -> WitnessOps: ...

        @property
        def archive(self) -> ArchiveOps: ...

        @property
        def webhooks(self) -> WebhookOps: ...
