from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ._api_base import _RegistaBase
from ._contract import validate_delegation_chain as _validate_delegation_chain
from ._errors import ErrorCode, RegistaError
from ._observability import OpTimer
from ._types import (
    Event,
    QueryPage,
    ReplayReport,
    WorkflowDefinition,
    WorkflowVersion,
    WorkItem,
)


class WorkflowApiMixin(_RegistaBase):

    def register_workflow(
        self,
        yaml_content: str,
    ) -> WorkflowVersion:
        """Parse, validate, and register a workflow definition.

        Idempotent: re-registering the same name+version with identical content
        returns the existing entry. Different content raises
        ``WORKFLOW_VERSION_CONFLICT``.
        """
        return self.workflows.register(yaml_content)

    def register_workflow_file(
        self,
        path: str | Path,
    ) -> WorkflowVersion:
        """Register a workflow from a file path."""
        return self.workflows.register_file(path)

    def get_workflow(self, workflow_name: str, version: int) -> WorkflowDefinition:
        """Retrieve a workflow definition by name and version."""
        return self.workflows.get(workflow_name, version)

    def create_work_item(
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
    ) -> tuple[WorkItem, Event]:
        """Create a new work item in the given workflow.

        ``event_id`` is an optional idempotency key: an identical retry returns
        the original work item and ``created`` event.
        """
        return self.work_items.create(
            workflow_name, work_item_type, actor_id, actor_kind,
            actor_metadata,
            custom_fields=custom_fields,
            not_before=not_before,
            event_id=event_id,
        )

    def create_work_items_batch(
        self,
        items: list[dict[str, Any]],
        actor_id: str,
        actor_kind: str = "agent",
    ) -> list[tuple[WorkItem, Event]]:
        """Create multiple work items in a single transaction."""
        return self.work_items.create_batch(items, actor_id, actor_kind)

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
        """Structured work-item query with cursor-based pagination.

        ``claimable_now=True`` returns unclaimed items whose ``not_before`` gate
        has passed. ``custom_field_filters`` applies equality filters with AND
        semantics.
        """
        return self.work_items.query(
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
        """Retrieve a single work item by ID, or ``None``."""
        return self.work_items.get(work_item_id)

    def update_not_before(
        self,
        work_item_id: uuid.UUID,
        not_before: datetime | None,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
        *,
        event_id: uuid.UUID | None = None,
        on_behalf_of: dict[str, Any] | None = None,
    ) -> Event:
        """Set or clear the ``not_before`` gate on a work item."""
        return self.work_items.update_not_before(
            work_item_id, not_before, actor_id, actor_kind,
            actor_metadata, event_id=event_id,
            on_behalf_of=on_behalf_of,
        )

    def transition(
        self,
        work_item_id: uuid.UUID,
        transition_name: str,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
        *,
        payload: dict[str, Any] | None = None,
        custom_fields: dict[str, Any] | None = None,
        event_id: uuid.UUID | None = None,
        expected_event_seq: int | None = None,
        on_behalf_of: dict[str, Any] | None = None,
        expected_attempt_number: int | None = None,
    ) -> Event:
        """Execute a workflow-defined state transition.

        Validates the transition against the pinned workflow version, checks
        role gating, applies ``custom_fields`` updates, and releases any active
        claim.

        Pass ``expected_attempt_number`` to fence against a stolen or expired
        lease: if the work item's current attempt has advanced, the transition
        is refused with ``CLAIM_LOST``.
        """
        _validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())
        self._require_open()
        from ._transition import transition as _transition_impl

        return _transition_impl(
            self._mgr, self._metrics, self._project,
            work_item_id, transition_name, actor_id,
            actor_kind=actor_kind,
            actor_metadata=actor_metadata,
            payload=payload,
            custom_fields=custom_fields,
            event_id=event_id,
            expected_event_seq=expected_event_seq,
            on_behalf_of=on_behalf_of,
            strict_roles=self._strict_roles,
            expected_attempt_number=expected_attempt_number,
        )

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
    ) -> Event:
        """Append a free-form event to the work-item log.

        Rejects transitions that match a workflow-defined transition name — use
        ``transition()`` for state changes.
        """
        self._require_open()
        _validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())
        return self.events.append(
            work_item_id, actor_id, actor_kind,
            actor_metadata=actor_metadata,
            transition=transition,
            payload=payload,
            event_id=event_id,
            expected_event_seq=expected_event_seq,
            on_behalf_of=on_behalf_of,
            entity_kind=entity_kind,
        )

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
        """Read events with structured filters (AND semantics)."""
        return self.events.read(
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
        """Read events with ``event_seq > after_seq`` for a work item."""
        return self.events.read_since(work_item_id, after_seq, limit=limit)

    def replay(
        self,
        *,
        work_item_id: uuid.UUID | None = None,
    ) -> ReplayReport:
        """Rebuild the projection from the event log and compare with live state.

        Drift is reported, not silently corrected. ``work_item_id`` scopes the
        replay to one item.
        """
        self._require_open()
        from ._replay import (
            drop_old_replay_tables,
        )
        from ._replay import (
            replay as _replay,
        )

        read_only = self._read_only
        if not read_only:
            with self._mgr.connect() as conn:
                drop_old_replay_tables(conn, self._mgr.schema)
                conn.commit()

        timer = OpTimer(self._project, "replay")
        try:
            with self._mgr.transaction_repeatable_read() as conn:
                if work_item_id is not None:
                    row = conn.execute(
                        "SELECT 1 FROM work_items_current WHERE work_item_id = %s",
                        [work_item_id],
                    ).fetchone()
                    if row is None:
                        evt = conn.execute(
                            "SELECT 1 FROM events WHERE work_item_id = %s",
                            [work_item_id],
                        ).fetchone()
                        if evt is None:
                            raise RegistaError(
                                ErrorCode.WORK_ITEM_NOT_FOUND,
                                f"Work item {work_item_id} not found for scoped replay",
                            )
                report = _replay(
                    conn, self._mgr.schema, self._project,
                    work_item_id=work_item_id,
                    read_only=read_only,
                )

            if report.replayed_drift > 0:
                self._metrics.inc("replay_drift_count", self._project, amount=report.replayed_drift)
            timer.log(
                "ok",
                detail=(
                    f"ok={report.replayed_ok} drift={report.replayed_drift} "
                    f"halted={report.halted}"
                ),
            )
            return report
        except Exception:
            timer.log("error")
            raise
