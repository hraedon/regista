from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import uuid
    from datetime import datetime
    from typing import Any

    from ._connection import ConnectionManager
    from ._observability import Metrics
    from ._ops import (
        ClaimOps,
        EventOps,
        LinkOps,
        WorkflowOps,
        WorkItemOps,
    )
    from ._types import Event


class _RegistaBase:
    """Type-stub mixin providing shared attributes for API mixins.

    ``Regista`` sets all of these in ``__init__``; the annotations here exist
    solely so that mixin methods can be type-checked. At runtime this class adds
    no behaviour.
    """

    if TYPE_CHECKING:
        _mgr: ConnectionManager
        _metrics: Metrics
        _project: str
        _strict_roles: bool
        _read_only: bool

        def _require_open(self) -> None: ...

        def append_event(
            self,
            work_item_id: uuid.UUID,
            actor_id: str,
            actor_kind: str = "agent",
            actor_metadata: dict[str, Any] | None = None,
            *,
            transition: str | None = None,
            payload: dict[str, Any] | None = None,
            event_id: uuid.UUID | None = None,
            expected_event_seq: int | None = None,
            on_behalf_of: dict[str, Any] | None = None,
            entity_kind: str = "work_item",
        ) -> Event: ...

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
        ) -> list[Event]: ...

        @property
        def project(self) -> str: ...

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
