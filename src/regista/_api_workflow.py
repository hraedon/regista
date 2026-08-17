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

        Args:
            yaml_content: Workflow YAML string.

        Returns:
            The registered ``WorkflowVersion``.

        Raises:
            RegistaError: ``WORKFLOW_VALIDATION_FAILED``,
                ``WORKFLOW_SEMANTIC_ERROR``, ``WORKFLOW_VERSION_CONFLICT``.
        """
        return self.workflows.register(yaml_content)

    def register_workflow_file(
        self,
        path: str | Path,
    ) -> WorkflowVersion:
        """Register a workflow from a file path. Handles extends: composition.

        Args:
            path: Path to a workflow YAML file.

        Returns:
            The registered ``WorkflowVersion``.
        """
        return self.workflows.register_file(path)

    def get_workflow(self, workflow_name: str, version: int) -> WorkflowDefinition:
        """Retrieve a workflow definition by name and version.

        Returns:
            ``WorkflowDefinition``.

        Raises:
            RegistaError: ``WORKFLOW_NOT_REGISTERED``.
        """
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
        key_id: str | None = None,
    ) -> tuple[WorkItem, Event]:
        """Create a new work item in the given workflow.

        Args:
            workflow_name: Name of a registered workflow.
            work_item_type: Must be declared in the workflow definition.
            actor_id: Authenticated actor identifier.
            actor_kind: ``"agent"`` | ``"human"`` | ``"system"``.
            actor_metadata: Optional JSONB metadata for audit.
            custom_fields: Initial field values validated against the type schema.
            not_before: Gate timestamp; claims before this time are rejected.
            event_id: Optional UUIDv4 for idempotency.
            key_id: Pin the signing key for the ``created`` event that opens the
                chain; defaults to the key set's resolution for ``actor_id``.

        Returns:
            Tuple of ``(WorkItem, Event)``.

        Raises:
            RegistaError: ``WORKFLOW_NOT_REGISTERED``,
                ``WORK_ITEM_TYPE_NOT_DECLARED``, ``CUSTOM_FIELD_VIOLATION``.
        """
        wi, evt = self.work_items.create(
            workflow_name, work_item_type, actor_id, actor_kind,
            actor_metadata,
            custom_fields=custom_fields,
            not_before=not_before,
            event_id=event_id,
            key_id=key_id,
        )
        self._try_create_witness_receipts(evt)
        return wi, evt

    def create_work_items_batch(
        self,
        items: list[dict[str, Any]],
        actor_id: str,
        actor_kind: str = "agent",
    ) -> list[tuple[WorkItem, Event]]:
        """Create multiple work items in a single transaction.

        Args:
            items: List of dicts, each with keys ``workflow_name``,
                ``work_item_type``, and optional ``custom_fields``,
                ``not_before``, ``event_id``, ``actor_metadata``.
            actor_id: Authenticated actor.
            actor_kind: ``"agent"`` | ``"human"`` | ``"system"``.

        Returns:
            List of ``(WorkItem, Event)`` tuples.
        """
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

        Args:
            workflow_name: Filter by workflow.
            workflow_version: Filter by pinned version.
            work_item_types: Filter by type names.
            current_states: Filter by current state.
            claimed_by: Filter by claiming actor.
            claimable_now: True = unclaimed and ``not_before`` has passed.
            needs_review: Filter by escalation flag.
            has_link_type: Items with at least one active link of this type.
            custom_field_filters: Equality filters on custom field values.
                All entries must match (AND semantics). Keys not declared on
                the queried work_item_type(s) match no rows (empty result, not
                an error).
            cursor: Continue from a previous page's cursor.
            page_size: Items per page (default 100).

        Returns:
            ``QueryPage[WorkItem]`` with cursor for the next page.
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
        """Retrieve a single work item by ID.

        Returns:
            The ``WorkItem`` or ``None`` if not found.
        """
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
        """Set or clear the ``not_before`` gate on a work item.

        Args:
            work_item_id: Target work item.
            not_before: New gate timestamp, or ``None`` to clear.
            actor_id: Authenticated actor.
            actor_kind: ``"agent"`` | ``"human"`` | ``"system"``.
            actor_metadata: Optional JSONB metadata.
            event_id: UUIDv4 idempotency key.

        Returns:
            The ``not_before_set`` ``Event``.

        Raises:
            RegistaError: ``WORK_ITEM_NOT_FOUND``.
        """
        evt = self.work_items.update_not_before(
            work_item_id, not_before, actor_id, actor_kind,
            actor_metadata, event_id=event_id,
            on_behalf_of=on_behalf_of,
        )
        self._try_create_witness_receipts(evt)
        return evt

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
        key_id: str | None = None,
    ) -> Event:
        """Execute a workflow-defined state transition.

        Validates the transition against the pinned workflow version, checks
        role gating, runs sync validators, and releases any active claim.

        Args:
            work_item_id: Target work item.
            transition_name: Must match a transition in the pinned workflow version.
            actor_id: Authenticated actor.
            actor_kind: ``"agent"`` | ``"human"`` | ``"system"``.
            actor_metadata: Must include ``"role"`` when roles are enforced.
            payload: Optional JSONB payload.
            custom_fields: Partial update to custom fields (validated against schema).
            event_id: UUIDv4 idempotency key.
            expected_event_seq: Optimistic-concurrency check.
            key_id: Optional explicit signing key id (default: resolve from actor).

        Returns:
            The appended ``Event``.

        Raises:
            RegistaError: ``INVALID_TRANSITION``, ``ROLE_NOT_PERMITTED``,
                ``ACTOR_ROLE_NOT_AUTHORIZED``, ``CUSTOM_FIELD_VIOLATION``,
                ``VALIDATOR_FAILED``, ``VALIDATOR_NOT_REGISTERED``.
        """
        _validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())
        self._require_open()
        from ._transition import transition as _transition_impl

        evt = _transition_impl(
            self._mgr, self._keys, self._metrics, self._project,
            self._validators, self._hook_channel,
            work_item_id, transition_name, actor_id,
            actor_kind=actor_kind,
            actor_metadata=actor_metadata,
            payload=payload,
            custom_fields=custom_fields,
            event_id=event_id,
            expected_event_seq=expected_event_seq,
            on_behalf_of=on_behalf_of,
            strict_roles=self._strict_roles,
            key_id=key_id,
        )
        self._try_create_witness_receipts(evt)
        return evt

    def append_event(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
        *,
        key_id: str | None = None,
        transition: str | None = None,
        payload: dict[str, Any] | None = None,
        event_id: uuid.UUID | None = None,
        expected_event_seq: int | None = None,
        on_behalf_of: dict[str, Any] | None = None,
        entity_kind: str = "work_item",
        hash_alg: str = "sha-256",
    ) -> Event:
        """Append a free-form event to the work-item log.

        Rejects transitions that match a workflow-defined transition name — use
        ``transition()`` for state changes.

        Args:
            work_item_id: Target work item (or entity_id for non-work-item
                entities when ``entity_kind`` is set).
            actor_id: Authenticated actor.
            actor_kind: ``"agent"`` | ``"human"`` | ``"system"``.
            actor_metadata: Optional JSONB metadata.
            key_id: Optional explicit signing key id (default: resolve from actor).
            transition: Free-form transition label (must not collide with workflow).
            payload: Optional JSONB payload.
            event_id: UUIDv4 idempotency key.
            expected_event_seq: Optimistic-concurrency check.
            entity_kind: Entity kind (``"work_item"``, ``"note"``,
                ``"spec"``, ``"principal"``, ``"session"``, ``"segment"``).
            hash_alg: Hash algorithm for signing (default ``"sha-256"``).

        Returns:
            The appended ``Event``.

        Raises:
            RegistaError: ``WORK_ITEM_NOT_FOUND``,
                ``TRANSITION_VIA_APPEND_BLOCKED``,
                ``IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD``,
                ``CONCURRENT_MODIFICATION``.
        """
        _validate_delegation_chain(on_behalf_of, event_timestamp=datetime.now(UTC).isoformat())
        evt = self.events.append(
            work_item_id, actor_id, actor_kind,
            actor_metadata=actor_metadata,
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
        """Read events with structured filters. Multiple filter dimensions
        may be combined; results satisfy all provided criteria.

        Ordering depends on which filters are active:

        - ``work_item_id`` provided: ascending by ``event_seq``.
        - Time range (``start``/``end``) without ``work_item_id``:
          ascending by ``(timestamp, event_seq)``.
        - Otherwise: descending by ``(timestamp, event_seq)``.

        Args:
            work_item_id: Filter by work item (supports ``before_seq`` pagination).
            actor_id: Filter by actor.
            start: Range-start timestamp (requires ``end``).
            end: Range-end timestamp (requires ``start``).
            transition: Filter by transition name.
            limit: Maximum events to return.
            before_seq: Paginate backwards from this ``event_seq`` (requires
                ``work_item_id``).

        Returns:
            List of ``Event`` objects.

        Raises:
            RegistaError: ``INVALID_FILTER``.
        """
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
        """Read events for a work item with event_seq strictly greater than
        the given cursor.

        This is the primitive for hook-miss recovery: a runner persists the
        highest event_seq it has processed and calls ``read_events_since``
        on startup to catch up.

        Args:
            work_item_id: Target work item.
            after_seq: Return events with ``event_seq > after_seq``.
            limit: Maximum events to return (default 100).

        Returns:
            Events in ascending ``event_seq`` order.
        """
        return self.events.read_since(work_item_id, after_seq, limit=limit)

    def replay(
        self,
        *,
        continue_on_revoked: bool = False,
        verify_principal_binding: bool = False,
        work_item_id: uuid.UUID | None = None,
    ) -> ReplayReport:
        """Rebuild projection from the event log and compare with live state.

        The report reflects consistency as of a single point-in-time snapshot
        (Postgres REPEATABLE READ). Drift committed after snapshot acquisition
        will only be visible in a later replay run.

        Args:
            continue_on_revoked: Skip revoked-key events with warnings instead
                of halting replay.
            verify_principal_binding: Verify each event's signature against the
                principal_keys registry, closing the non-repudiation loop.
                Events whose actor_id has registered principal keys but whose
                signature does not verify under any of those keys emit a
                warning. Events whose actor_id has no registered principal keys
                are skipped (backward compatible with HMAC-only deployments).
            work_item_id: Scope replay to a single work item. Global chain
                checks are skipped; one warning is emitted to note the scoped
                verification.

        Returns:
            ``ReplayReport`` with counts of ok, drift, halted, and warnings.
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
            # Legacy cleanup of permanent residue from pre-fix runs. Skipped in
            # read-only mode: DROP is blocked under default_transaction_read_only
            # and TEMP tables (the new normal-mode backend) never appear in the
            # project schema's pg_tables anyway.
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
                    conn, self._mgr.schema, self._project, self._keys,
                    continue_on_revoked=continue_on_revoked,
                    verify_principal_binding=verify_principal_binding,
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
