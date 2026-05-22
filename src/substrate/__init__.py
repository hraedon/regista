from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import structlog

from ._connection import ConnectionManager
from ._contract import (
    validate_mutation_params as _validate_mutation_params,
)
from ._errors import ErrorCode, SubstrateError
from ._integrity import SUBSTRATE_VERSION, check_integrity
from ._keys import KeySet
from ._migrations import run_migrations
from ._observability import Metrics, OpTimer
from ._ops import ClaimOps, EventOps, HookOps, LinkOps, RecurrenceOps, WorkflowOps, WorkItemOps
from ._types import (
    ActorKind as ActorKind,
)
from ._types import (
    ActorMetadata as ActorMetadata,
)
from ._types import (
    ActorRole,
    Claim,
    ConnectionInfo,
    DeadLetterEntry,
    Event,
    Link,
    QueryPage,
    ReplayReport,
    WorkflowVersion,
    WorkItem,
)
from ._types import (
    HookContext as HookContext,
)
from ._types import (
    ReplayReportEntry as ReplayReportEntry,
)
from ._types import (
    ValidationError as ValidationError,
)
from ._types import (
    ValidationResult as ValidationResult,
)
from ._types import (
    WorkflowDefinition as WorkflowDefinition,
)
from ._workflow import parse_and_validate as parse_and_validate
from ._workflow import parse_file as parse_file
from ._workflow import parse_workflow_yaml as parse_workflow_yaml
from ._workflow import validate_yaml as validate_yaml
from ._workflow_compose import compose_workflow as compose_workflow

log = structlog.get_logger()


class Substrate:
    """Coordination and durable state for agent pipelines over Postgres.

    One Substrate instance owns one logical project namespace. Use
    ``create_project`` to bootstrap a new project, then connect via the
    constructor for subsequent sessions.
    """

    def __init__(
        self,
        dsn: str,
        project: str,
        hmac_key_path: str | None = None,
        *,
        pool_min: int = 1,
        pool_max: int = 10,
        pool_max_lifetime: float | None = None,
        require_ssl: bool = False,
        prometheus_registry=None,
        auto_partition: bool = True,
        strict_roles: bool = False,
    ) -> None:
        """Connect to an existing project.

        Args:
            dsn: Postgres connection string.
            project: Project (schema) name.
            hmac_key_path: Path to HMAC key-set JSON file (required).
            pool_min: Minimum connection-pool size.
            pool_max: Maximum connection-pool size.
            pool_max_lifetime: Maximum connection lifetime in seconds.
            require_ssl: Reject the connection if SSL is not active.
            prometheus_registry: Optional ``prometheus_client.CollectorRegistry``.
            auto_partition: Deprecated. Partitioning was removed in migration
                014; this parameter is kept for backwards compatibility and
                has no effect.

        Raises:
            SubstrateError: If migrations are pending or workflow versions are
                incompatible.
        """
        if hmac_key_path is None:
            raise SubstrateError(
                ErrorCode.UNKNOWN_KEY_ID,
                "hmac_key_path is required",
            )
        self._mgr = ConnectionManager(
            dsn, project, pool_min=pool_min, pool_max=pool_max,
            pool_max_lifetime=pool_max_lifetime, require_ssl=require_ssl,
        )
        try:
            self._mgr.open()
            self._mgr.ensure_schema()
            self._keys = KeySet(hmac_key_path)
            self._metrics = Metrics(registry=prometheus_registry)
            self._project = project
            self._validators: dict[str, Callable] = {}
            self._hook_handlers: dict[str, Callable] = {}
            self._hook_channel = f"substrate_hooks_{self._mgr.schema}"
            self._hook_consumer = None
            self._strict_roles = strict_roles
            from ._hooks import HookConsumer

            self._hook_consumer = HookConsumer(
                dsn=self._mgr.dsn,
                schema=self._mgr.schema,
                project=project,
                handlers=self._hook_handlers,
                key_set=self._keys,
                metrics=self._metrics,
            )
            self._maintenance_thread = None
            check_integrity(self._mgr)
            if auto_partition:
                self._run_auto_partition()
        except Exception:
            self._mgr.close()
            raise
        log.info("substrate.connected", project=project, substrate_version=SUBSTRATE_VERSION)

    @classmethod
    def create_project(
        cls,
        dsn: str,
        project: str,
        hmac_key_path: str,
        *,
        pool_min: int = 1,
        pool_max: int = 10,
        pool_max_lifetime: float | None = None,
        require_ssl: bool = False,
        prometheus_registry=None,
        auto_partition: bool = True,
        strict_roles: bool = False,
    ) -> Substrate:
        """Create a new project: schema, migrations, and return a connected handle.

        Args:
            dsn: Postgres connection string.
            project: Project (schema) name.
            hmac_key_path: Path to HMAC key-set JSON file.
            pool_min: Minimum connection-pool size.
            pool_max: Maximum connection-pool size.
            pool_max_lifetime: Maximum connection lifetime in seconds.
            prometheus_registry: Optional ``prometheus_client.CollectorRegistry``.
            auto_partition: Deprecated. Has no effect; kept for backwards
                compatibility.

        Returns:
            A connected ``Substrate`` instance.
        """
        mgr = ConnectionManager(
            dsn, project, pool_min=pool_min, pool_max=pool_max,
            pool_max_lifetime=pool_max_lifetime, require_ssl=require_ssl,
        )
        try:
            mgr.open()
            mgr.create_schema()
            run_migrations(mgr)
        finally:
            mgr.close()
        log.info("substrate.project_created", project=project)
        return cls(
            dsn,
            project,
            hmac_key_path,
            pool_min=pool_min,
            pool_max=pool_max,
            pool_max_lifetime=pool_max_lifetime,
            require_ssl=require_ssl,
            prometheus_registry=prometheus_registry,
            auto_partition=auto_partition,
            strict_roles=strict_roles,
        )

    def _run_auto_partition(self) -> None:
        """No-op. Partitioning was removed (RFC-001)."""
        log.warning("auto_partition.deprecated", project=self._project)

    def close(self) -> None:
        """Stop maintenance thread, hook consumer (if running), and release the connection pool."""
        if self._maintenance_thread is not None and self._maintenance_thread.is_running:
            self._maintenance_thread.stop()
        if self._hook_consumer is not None and self._hook_consumer.is_running:
            self._hook_consumer.stop()
        if self._mgr is not None:
            self._mgr.close()
            self._mgr = None
        log.info("substrate.disconnected", project=self._project)

    @property
    def project(self) -> str:
        return self._project

    @property
    def connection_info(self) -> ConnectionInfo:
        """Connection details (no credentials) for downstream test infrastructure.

        Returns:
            ``ConnectionInfo`` with host, port, database, and project.
        """
        from urllib.parse import urlparse

        parsed = urlparse(self._mgr.dsn)
        return ConnectionInfo(
            host=parsed.hostname,
            port=parsed.port,
            database=parsed.path.lstrip("/") if parsed.path else None,
            project=self._project,
        )

    @property
    def substrate_version(self) -> str:
        return SUBSTRATE_VERSION

    @property
    def prometheus_registry(self):
        return self._metrics.registry

    @property
    def workflows(self) -> WorkflowOps:
        if not hasattr(self, "_workflows_ops"):
            self._workflows_ops = WorkflowOps(self._mgr, self._metrics, self._project)
        return self._workflows_ops

    @property
    def work_items(self) -> WorkItemOps:
        if not hasattr(self, "_work_items_ops"):
            self._work_items_ops = WorkItemOps(
                self._mgr, self._keys, self._metrics, self._project, self._validators,
            )
        return self._work_items_ops

    @property
    def events(self) -> EventOps:
        if not hasattr(self, "_events_ops"):
            self._events_ops = EventOps(self._mgr, self._keys, self._metrics, self._project)
        return self._events_ops

    @property
    def claims(self) -> ClaimOps:
        if not hasattr(self, "_claims_ops"):
            self._claims_ops = ClaimOps(self._mgr, self._keys, self._metrics, self._project)
        return self._claims_ops

    @property
    def links(self) -> LinkOps:
        if not hasattr(self, "_links_ops"):
            self._links_ops = LinkOps(self._mgr, self._keys, self._metrics, self._project)
        return self._links_ops

    @property
    def hooks(self) -> HookOps:
        if not hasattr(self, "_hooks_ops"):
            self._hooks_ops = HookOps(
                self._mgr, self._keys, self._metrics, self._project,
                self._validators, self._hook_handlers, self._hook_channel, self._hook_consumer,
            )
        return self._hooks_ops

    @property
    def recurrence(self) -> RecurrenceOps:
        if not hasattr(self, "_recurrence_ops"):
            self._recurrence_ops = RecurrenceOps(
                self._mgr, self._keys, self._metrics, self._project,
            )
        return self._recurrence_ops

    def register_validator(self, name: str, handler: Callable) -> None:
        """Register a sync transition validator. Blocks the transaction on failure.

        Args:
            name: Must match a ``validator`` field in a workflow transition.
            handler: ``Callable[[ValidatorContext], None]``. Runs synchronously
                in the transaction's thread. **Trusted code**: substrate does
                not enforce wall-clock or I/O bounds (see BC-192). A validator
                that hangs or blocks hangs the transaction. The surrounding
                Postgres ``statement_timeout`` (5s) protects against blocking
                DB operations made via the transaction's connection, but not
                against pure-Python loops, sleeps, or external I/O.
        """
        self._validators[name] = handler

    def register_hook_handler(self, name: str, handler: Callable) -> None:
        """Register an async hook handler dispatched via the hook queue.

        Args:
            name: Must match a hook name listed in a workflow transition's ``hooks``.
            handler: ``Callable[[HookContext], None]``.
        """
        self._hook_handlers[name] = handler
        self._hook_consumer._handlers = self._hook_handlers

    def start_hook_consumer(self) -> None:
        """Start a background thread that LISTENs and polls the hook queue."""
        self.hooks.start_consumer()

    def stop_hook_consumer(self) -> None:
        """Stop the background hook consumer thread."""
        self.hooks.stop_consumer()

    def start_maintenance(
        self,
        *,
        sweep_interval: float = 30.0,
        recurrence_interval: float = 10.0,
        hook_poll_interval: float = 2.0,
        partition_interval: float = 3600.0,
    ) -> None:
        """Start the background maintenance thread.

        The maintenance thread periodically sweeps expired claims and hook
        leases, fires due recurrence rules, and refreshes hook queue metrics.
        It also starts the hook consumer if not already running.

        Args:
            sweep_interval: Seconds between maintenance cycles (default 30).
            recurrence_interval: Seconds between recurrence checks (default 10).
            hook_poll_interval: Hook consumer poll interval (default 2).
            partition_interval: Deprecated; kept for API compatibility.
        """
        from ._maintenance import MaintenanceThread

        if self._maintenance_thread is not None and self._maintenance_thread.is_running:
            return
        self._maintenance_thread = MaintenanceThread(
            self,
            sweep_interval=sweep_interval,
            recurrence_interval=recurrence_interval,
            hook_poll_interval=hook_poll_interval,
            partition_interval=partition_interval,
        )
        self._maintenance_thread.start()
        if not (self._hook_consumer is not None and self._hook_consumer.is_running):
            self.start_hook_consumer()

    def stop_maintenance(self) -> None:
        """Stop the maintenance thread and the hook consumer gracefully."""
        if self._maintenance_thread is not None and self._maintenance_thread.is_running:
            self._maintenance_thread.stop()
        if self._hook_consumer is not None and self._hook_consumer.is_running:
            self._hook_consumer.stop()

    def poll_hooks(self) -> int:
        """Manually drain and process pending hooks from the queue.

        Returns:
            Number of hooks processed.
        """
        return self.hooks.poll()

    def ensure_event_partitions(self, months_ahead: int = 3) -> list[str]:
        """Deprecated. Partitioning was removed (RFC-001).

        This method is kept for backwards compatibility and has no effect.

        Args:
            months_ahead: Ignored.

        Returns:
            Empty list.
        """
        log.warning("ensure_event_partitions.deprecated", project=self._project)
        return []

    def claim_hooks(
        self,
        max_batch: int = 10,
        lease_seconds: int = 60,
    ) -> list[HookContext]:
        """Claim a batch of pending hooks for external processing.

        Marks claimed rows ``in_progress`` and sets ``lease_expires_at``.
        If the caller crashes without completing or failing the hook, the
        lease expires and ``sweep_expired_hook_leases`` requeues the row.

        Args:
            max_batch: Maximum number of hooks to claim (default 10).
            lease_seconds: Lease duration in seconds (default 60).

        Returns:
            List of ``HookContext`` objects describing each claimed hook.
        """
        return self.hooks.claim(max_batch, lease_seconds)

    def complete_hook(self, hook_queue_id: int) -> None:
        """Mark a previously claimed hook as successfully completed.

        Args:
            hook_queue_id: The ``hook_queue_id`` from ``claim_hooks``.

        Raises:
            SubstrateError: ``HOOK_NOT_FOUND`` if the row does not exist.
        """
        self.hooks.complete(hook_queue_id)

    def fail_hook(self, hook_queue_id: int, error: str) -> None:
        """Record a hook processing failure.

        Increments ``retry_count``. If below ``max_retries``, requeues the
        hook to ``pending`` with exponential backoff. If exhausted, moves the
        row to ``hook_dead_letter`` and emits a ``hook_dead_lettered`` event.

        Args:
            hook_queue_id: The ``hook_queue_id`` from ``claim_hooks``.
            error: Human-readable error description.

        Raises:
            SubstrateError: ``HOOK_NOT_FOUND`` if the row does not exist.
        """
        self.hooks.fail(hook_queue_id, error)

    def sweep_expired_hook_leases(self) -> int:
        """Requeue in-progress hooks whose leases have expired.

        A hook lease expires when ``lease_expires_at < now()``. Requeued
        rows return to ``pending`` status with their retry count unchanged;
        a lease expiry is not counted as a failure.

        Returns:
            Number of hooks requeued.
        """
        return self.hooks.sweep_expired_leases()

    def refresh_hook_queue_metrics(self) -> None:
        """Query hook_queue and update the ``substrate_hook_queue_depth`` gauge.

        Updates four status labels: ``pending``, ``in_progress``, ``completed``,
        and ``dead_letter`` (the dead-letter table is separate from hook_queue
        but included for completeness as it represents backlogged work).

        This is a lightweight SELECT COUNT(*) and safe to call frequently.
        The maintenance thread (Plan 009) will call this at the end of every
        sweep cycle. Operators may also call it on demand.
        """
        self.hooks.refresh_queue_metrics()

    @property
    def maintenance_healthy(self) -> bool:
        if self._maintenance_thread is None:
            return True
        if not self._maintenance_thread.is_running:
            return True
        return self._maintenance_thread.last_cycle_ok

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
            SubstrateError: ``WORKFLOW_VALIDATION_FAILED``,
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
            SubstrateError: ``WORKFLOW_NOT_REGISTERED``.
        """
        return self.workflows.get(workflow_name, version)

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

        Returns:
            Tuple of ``(WorkItem, Event)``.

        Raises:
            SubstrateError: ``WORKFLOW_NOT_REGISTERED``,
                ``WORK_ITEM_TYPE_NOT_DECLARED``, ``CUSTOM_FIELD_VIOLATION``,
                ``VALIDATOR_FAILED``.
        """
        return self.work_items.create(
            workflow_name, work_item_type, actor_id, actor_kind,
            actor_metadata,
            custom_fields=custom_fields,
            not_before=not_before,
            event_id=event_id,
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

        Returns:
            The appended ``Event``.

        Raises:
            SubstrateError: ``INVALID_TRANSITION``, ``ROLE_NOT_PERMITTED``,
                ``ACTOR_ROLE_NOT_AUTHORIZED``, ``CUSTOM_FIELD_VIOLATION``,
                ``VALIDATOR_FAILED``.
        """
        from ._transition import transition as _transition_impl

        return _transition_impl(
            self._mgr, self._keys, self._metrics, self._project,
            self._validators, self._hook_channel,
            work_item_id, transition_name, actor_id,
            actor_kind=actor_kind,
            actor_metadata=actor_metadata,
            payload=payload,
            custom_fields=custom_fields,
            event_id=event_id,
            expected_event_seq=expected_event_seq,
            strict_roles=self._strict_roles,
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
        """Append a free-form event to the work-item log.

        Rejects transitions that match a workflow-defined transition name — use
        ``transition()`` for state changes.

        Args:
            work_item_id: Target work item.
            actor_id: Authenticated actor.
            actor_kind: ``"agent"`` | ``"human"`` | ``"system"``.
            actor_metadata: Optional JSONB metadata.
            transition: Free-form transition label (must not collide with workflow).
            payload: Optional JSONB payload.
            event_id: UUIDv4 idempotency key.
            expected_event_seq: Optimistic-concurrency check.

        Returns:
            The appended ``Event``.

        Raises:
            SubstrateError: ``WORK_ITEM_NOT_FOUND``,
                ``TRANSITION_VIA_APPEND_BLOCKED``,
                ``IDEMPOTENCY_COLLISION_WITH_DIFFERENT_PAYLOAD``,
                ``CONCURRENT_MODIFICATION``.
        """
        return self.events.append(
            work_item_id, actor_id, actor_kind,
            actor_metadata=actor_metadata,
            transition=transition,
            payload=payload,
            event_id=event_id,
            expected_event_seq=expected_event_seq,
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
            SubstrateError: ``INVALID_FILTER``.
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

    def acquire_claim(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        ttl_seconds: int = 300,
        *,
        event_id: uuid.UUID | None = None,
        actor_kind: str = "agent",
    ) -> Claim:
        """Acquire a durable claim (lease) on a work item.

        Same-actor re-acquire silently extends TTL. Cross-actor acquire on an
        expired claim auto-steals and increments attempt_number.

        Args:
            work_item_id: Target work item.
            actor_id: Claiming actor.
            ttl_seconds: Lease duration in seconds (default 300).
            event_id: UUIDv4 idempotency key.
            actor_kind: Kind of actor (default "agent").

        Returns:
            The ``Claim``.

        Raises:
            SubstrateError: ``CLAIM_CONTESTED``, ``NOT_BEFORE_FUTURE``,
                ``WORK_ITEM_NOT_FOUND``, ``INVALID_ARGUMENT``.
        """
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            event_id=event_id,
            ttl_seconds=ttl_seconds,
        )
        return self.claims.acquire(
            work_item_id, actor_id, ttl_seconds,
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
        """Renew a claim's TTL. Rejects if claim is held by a different actor.

        Args:
            work_item_id: Target work item.
            actor_id: Must match the current claim holder.
            ttl_seconds: New lease duration.
            expected_attempt_number: Detect stale sessions after claim theft.
            coalesce_threshold: Minimum seconds between emitted ``claim_heartbeat``
                events. ``None`` (default) uses ``max(60, ttl_seconds/2)``.

        Returns:
            The renewed ``Claim``.

        Raises:
            SubstrateError: ``CLAIM_LOST``, ``CLAIM_NOT_FOUND``,
                ``INVALID_ARGUMENT``.
        """
        _validate_mutation_params(actor_id=actor_id, ttl_seconds=ttl_seconds)
        return self.claims.heartbeat(
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
        """Release a claim held by the given actor.

        Args:
            work_item_id: Target work item.
            actor_id: Must match the current claim holder.
            event_id: UUIDv4 idempotency key.
            actor_kind: Kind of actor (default "agent").

        Raises:
            SubstrateError: ``CLAIM_LOST``, ``CLAIM_NOT_FOUND``.
        """
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            event_id=event_id,
        )
        self.claims.release(
            work_item_id, actor_id,
            event_id=event_id, actor_kind=actor_kind,
        )

    def sweep_expired_claims(self) -> int:
        """Delete all expired claims and emit ``claim_expired`` events.

        Returns:
            Number of expired claims swept.
        """
        return self.claims.sweep_expired()

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
        """Create a typed directed link between two work items.

        Args:
            from_work_item_id: Source work item.
            to_work_item_id: Target work item.
            link_type: Must be declared in the workflow definition.
            actor_id: Authenticated actor.
            actor_kind: ``"agent"`` | ``"human"`` | ``"system"``.
            actor_metadata: Optional JSONB metadata.
            event_id: UUIDv4 idempotency key.
            payload: Optional JSONB payload on the link.

        Returns:
            The created ``Link``.

        Raises:
            SubstrateError: ``LINK_TYPE_NOT_ALLOWED``,
                ``LINK_TARGET_NOT_FOUND``, ``LINK_CROSS_PROJECT``.
        """
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            event_id=event_id,
        )
        return self.links.create(
            from_work_item_id, to_work_item_id, link_type,
            actor_id, actor_kind, actor_metadata,
            event_id=event_id, payload=payload,
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
        """Remove a typed directed link between two work items.

        Args:
            from_work_item_id: Source work item.
            to_work_item_id: Target work item.
            link_type: The link type to remove.
            actor_id: Authenticated actor.
            actor_kind: ``"agent"`` | ``"human"`` | ``"system"``.
            actor_metadata: Optional JSONB metadata.
            event_id: UUIDv4 idempotency key.

        Raises:
            SubstrateError: ``LINK_NOT_FOUND``.
        """
        _validate_mutation_params(
            actor_id=actor_id,
            actor_kind=actor_kind,
            event_id=event_id,
        )
        self.links.remove(
            from_work_item_id, to_work_item_id, link_type,
            actor_id, actor_kind, actor_metadata,
            event_id=event_id,
        )

    def replay(self, *, continue_on_revoked: bool = False) -> ReplayReport:
        """Rebuild projection from the event log and compare with live state.

        Args:
            continue_on_revoked: Skip revoked-key events with warnings instead
                of halting replay.

        Returns:
            ``ReplayReport`` with counts of ok, drift, halted, and warnings.
        """
        from ._replay import (
            drop_old_replay_tables,
        )
        from ._replay import (
            replay as _replay,
        )

        with self._mgr.connect() as conn:
            drop_old_replay_tables(conn, self._mgr.schema)
            conn.commit()

        timer = OpTimer(self._project, "replay")
        try:
            with self._mgr.transaction() as conn:
                report = _replay(
                    conn, self._mgr.schema, self._project, self._keys,
                    continue_on_revoked=continue_on_revoked,
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

    def requeue_dead_lettered_hook(self, dead_letter_id: int) -> None:
        """Re-queue a dead-lettered hook for retry.

        Args:
            dead_letter_id: ID from ``list_dead_lettered_hooks``.

        Raises:
            SubstrateError: ``HOOK_NOT_FOUND``.
        """
        self.hooks.requeue_dead_lettered(dead_letter_id)

    def list_dead_lettered_hooks(self) -> list[DeadLetterEntry]:
        """List all dead-lettered hooks in reverse chronological order.

        Returns:
            List of ``DeadLetterEntry`` objects.
        """
        return self.hooks.list_dead_lettered()

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
            SubstrateError: ``WORK_ITEM_NOT_FOUND``.
        """
        return self.work_items.update_not_before(
            work_item_id, not_before, actor_id, actor_kind,
            actor_metadata, event_id=event_id,
        )

    def register_actor_role(self, actor_id: str, role: str) -> None:
        """Register a role for an actor. Enables role enforcement for that actor.

        Args:
            actor_id: Actor identifier.
            role: Role to register.

        Duplicate registrations are silently idempotent.
        """
        from ._contract import validate_actor_id as _validate_actor_id

        _validate_actor_id(actor_id)
        from ._actor_roles import register_actor_role as _register

        timer = OpTimer(self._project, "register_actor_role")
        try:
            with self._mgr.transaction() as conn:
                _register(conn, actor_id, role)
            timer.log("ok", detail=f"{actor_id}:{role}")
        except SubstrateError:
            timer.log("error")
            raise

    def unregister_actor_role(self, actor_id: str, role: str) -> None:
        """Remove a role from an actor's registered set.

        Args:
            actor_id: Actor identifier.
            role: Role to remove.

        Raises:
            SubstrateError: ``ACTOR_ROLE_NOT_REGISTERED``.
        """
        from ._contract import validate_actor_id as _validate_actor_id

        _validate_actor_id(actor_id)
        from ._actor_roles import unregister_actor_role as _unregister

        timer = OpTimer(self._project, "unregister_actor_role")
        try:
            with self._mgr.transaction() as conn:
                _unregister(conn, actor_id, role)
            timer.log("ok", detail=f"{actor_id}:{role}")
        except SubstrateError:
            timer.log("error")
            raise

    def list_actor_roles(self, actor_id: str | None = None) -> list[ActorRole]:
        """List registered actor roles.

        Args:
            actor_id: Filter by actor, or ``None`` for all actors.

        Returns:
            List of ``ActorRole`` objects.
        """
        from ._actor_roles import list_actor_roles as _list

        with self._mgr.transaction() as conn:
            rows = _list(conn, actor_id=actor_id)
        return [
            ActorRole(
                actor_id=r["actor_id"], role=r["role"], created_at=r["created_at"]
            )
            for r in rows
        ]

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
        return self.recurrence.register_rule(
            workflow_name, workflow_version, work_item_type, template,
            schedule_kind, schedule_expr,
            timezone=timezone, start_at=start_at, end_at=end_at,
            count=count, catchup_policy=catchup_policy, created_by=created_by,
        )

    def list_recurrence_rules(self, status: str | None = None) -> list[dict]:
        return self.recurrence.list_rules(status=status)

    def due_recurrences(self, now: datetime | None = None) -> list[dict]:
        return self.recurrence.due(now=now)

    def fire_recurrence(self, rule_id: uuid.UUID) -> tuple[dict, dict]:
        return self.recurrence.fire(rule_id)

    def cancel_recurrence_rule(self, rule_id: uuid.UUID) -> None:
        self.recurrence.cancel_rule(rule_id)

    def update_recurrence_rule(
        self,
        rule_id: uuid.UUID,
        *,
        status: str | None = None,
        schedule_expr: str | None = None,
        template: dict | None = None,
    ) -> dict:
        return self.recurrence.update_rule(
            rule_id,
            status=status, schedule_expr=schedule_expr, template=template,
        )

    @staticmethod
    def validate_actor_metadata(        event: Event,
        expected_schema: dict | None = None,
    ) -> list[str]:
        """Lint helper: validate actor_metadata against recommended fields.

        Args:
            event: Event to inspect.
            expected_schema: Optional JSON Schema to validate against.

        Returns:
            List of issue descriptions (empty if clean).
        """
        from ._lint import validate_actor_metadata as _validate

        return _validate(event, expected_schema)

    @staticmethod
    def actor_metadata_complete(
        events: list[Event],
        expected_keys: list[str],
    ) -> list[Event]:
        """Lint helper: return events missing any of the expected actor_metadata keys.

        Args:
            events: Events to inspect.
            expected_keys: List of keys that must be present in actor_metadata.

        Returns:
            List of events with incomplete actor_metadata.
        """
        from ._lint import actor_metadata_complete as _complete

        return _complete(events, expected_keys)
