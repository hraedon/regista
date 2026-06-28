from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import structlog

from ._connection import ConnectionManager
from ._contract import (
    validate_delegation_chain as _validate_delegation_chain,
)
from ._contract import (
    validate_mutation_params as _validate_mutation_params,
)
from ._errors import ErrorCode, RegistaError
from ._integrity import REGISTA_VERSION, check_integrity
from ._keys import KeySet
from ._migrations import run_migrations
from ._observability import Metrics, OpTimer
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


class Regista:
    """Coordination and durable state for agent pipelines over Postgres.

    One Regista instance owns one logical project namespace. Use
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
        strict_asymmetric: bool = False,
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
            strict_roles: Reject unregistered actors and ``prompt``-source roles.
            strict_asymmetric: Require per-principal asymmetric signing keys.
                Each actor must have a registered Ed25519 (or future PQC) key
                bound to their ``principal_id``; HMAC fallback is rejected.

        Raises:
            RegistaError: If migrations are pending or workflow versions are
                incompatible.
        """
        if hmac_key_path is None:
            raise RegistaError(
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
            self._keys = KeySet(hmac_key_path, strict_asymmetric=strict_asymmetric)
            self._metrics = Metrics(registry=prometheus_registry)
            self._project = project
            from ._review_validators import BUILTIN_REVIEW_VALIDATORS

            self._validators: dict[str, Callable] = dict(BUILTIN_REVIEW_VALIDATORS)
            self._hook_handlers: dict[str, Callable] = {}
            self._hook_channel = f"regista_hooks_{self._mgr.schema}"
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
        log.info("regista.connected", project=project, regista_version=REGISTA_VERSION)

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
        strict_asymmetric: bool = False,
    ) -> Regista:
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
            A connected ``Regista`` instance.
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
        log.info("regista.project_created", project=project)
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
            strict_asymmetric=strict_asymmetric,
        )

    def _run_auto_partition(self) -> None:
        """No-op. Partitioning was removed (RFC-001)."""
        log.warning("auto_partition.deprecated", project=self._project)

    def _require_open(self) -> None:
        if self._mgr is None:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "Regista instance has been closed",
            )

    def close(self) -> None:
        """Stop maintenance thread, hook consumer (if running), and release the connection pool."""
        if self._maintenance_thread is not None and self._maintenance_thread.is_running:
            self._maintenance_thread.stop()
        if self._hook_consumer is not None and self._hook_consumer.is_running:
            self._hook_consumer.stop()
        if self._mgr is not None:
            self._mgr.close()
            self._mgr = None
        log.info("regista.disconnected", project=self._project)

    @property
    def project(self) -> str:
        return self._project

    @property
    def connection_info(self) -> ConnectionInfo:
        """Connection details (no credentials) for downstream test infrastructure.

        Returns:
            ``ConnectionInfo`` with host, port, database, and project.
        """
        self._require_open()
        from urllib.parse import urlparse

        parsed = urlparse(self._mgr.dsn)
        return ConnectionInfo(
            host=parsed.hostname,
            port=parsed.port,
            database=parsed.path.lstrip("/") if parsed.path else None,
            project=self._project,
        )

    @property
    def regista_version(self) -> str:
        return REGISTA_VERSION

    @property
    def prometheus_registry(self):
        return self._metrics.registry

    @property
    def workflows(self) -> WorkflowOps:
        self._require_open()
        if not hasattr(self, "_workflows_ops"):
            self._workflows_ops = WorkflowOps(self._mgr, self._metrics, self._project)
        return self._workflows_ops

    @property
    def work_items(self) -> WorkItemOps:
        self._require_open()
        if not hasattr(self, "_work_items_ops"):
            self._work_items_ops = WorkItemOps(
                self._mgr, self._keys, self._metrics, self._project, self._validators,
            )
        return self._work_items_ops

    @property
    def events(self) -> EventOps:
        self._require_open()
        if not hasattr(self, "_events_ops"):
            self._events_ops = EventOps(self._mgr, self._keys, self._metrics, self._project)
        return self._events_ops

    @property
    def claims(self) -> ClaimOps:
        self._require_open()
        if not hasattr(self, "_claims_ops"):
            self._claims_ops = ClaimOps(self._mgr, self._keys, self._metrics, self._project)
        return self._claims_ops

    @property
    def links(self) -> LinkOps:
        self._require_open()
        if not hasattr(self, "_links_ops"):
            self._links_ops = LinkOps(self._mgr, self._keys, self._metrics, self._project)
        return self._links_ops

    @property
    def hooks(self) -> HookOps:
        self._require_open()
        if not hasattr(self, "_hooks_ops"):
            self._hooks_ops = HookOps(
                self._mgr, self._keys, self._metrics, self._project,
                self._validators, self._hook_handlers, self._hook_channel, self._hook_consumer,
            )
        return self._hooks_ops

    @property
    def recurrence(self) -> RecurrenceOps:
        self._require_open()
        if not hasattr(self, "_recurrence_ops"):
            self._recurrence_ops = RecurrenceOps(
                self._mgr, self._keys, self._metrics, self._project,
            )
        return self._recurrence_ops

    @property
    def timestamping(self) -> TimestampOps:
        self._require_open()
        if not hasattr(self, "_timestamping_ops"):
            self._timestamping_ops = TimestampOps(
                self._mgr, self._keys, self._metrics, self._project,
            )
        return self._timestamping_ops

    @property
    def witnesses(self) -> WitnessOps:
        self._require_open()
        if not hasattr(self, "_witness_ops"):
            self._witness_ops = WitnessOps(self._mgr, self._metrics, self._project)
        return self._witness_ops

    @property
    def archive(self) -> ArchiveOps:
        self._require_open()
        if not hasattr(self, "_archive_ops"):
            self._archive_ops = ArchiveOps(self._mgr, self._project)
        return self._archive_ops

    @property
    def webhooks(self) -> WebhookOps:
        self._require_open()
        if not hasattr(self, "_webhook_ops"):
            self._webhook_ops = WebhookOps(self._mgr, self._project)
        return self._webhook_ops

    def _try_create_witness_receipts(self, event: Event) -> None:
        from ._witness import create_receipts as _create_receipts

        try:
            count = _create_receipts(self._mgr, event.to_dict())
            if count > 0:
                self._metrics.inc("witness_receipts_created", self._project, amount=count)
        except Exception as exc:
            log.warning(
                "witness.create_receipts_failed",
                project=self._project,
                event_id=str(event.event_id),
                error=str(exc)[:500],
            )

    def register_validator(self, name: str, handler: Callable) -> None:
        """Register a sync transition validator. Blocks the transaction on failure.

        Args:
            name: Must match a ``validator`` field in a workflow transition.
            handler: ``Callable[[ValidatorContext], None]``. Runs synchronously
                in the transaction's thread. **Trusted code**: regista does
                not enforce wall-clock or I/O bounds (see BC-192). A validator
                that hangs or blocks hangs the transaction. The surrounding
                Postgres ``statement_timeout`` (5s) protects against blocking
                DB operations made via the transaction's connection, but not
                against pure-Python loops, sleeps, or external I/O.
        """
        self._validators = {**self._validators, name: handler}

    def register_hook_handler(self, name: str, handler: Callable) -> None:
        """Register an async hook handler dispatched via the hook queue.

        Args:
            name: Must match a hook name listed in a workflow transition's ``hooks``.
            handler: ``Callable[[HookContext], None]``.
        """
        self._hook_handlers = {**self._hook_handlers, name: handler}
        if self._hook_consumer is not None:
            self._hook_consumer._handlers = self._hook_handlers

    def start_hook_consumer(self) -> None:
        """Start a background thread that LISTENs and polls the hook queue."""
        self.hooks._sync_handlers(self._hook_handlers, self._hook_consumer)
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
        timestamp_interval: float = 3600.0,
        tsa_config=None,
        witness_interval: float = 30.0,
    ) -> None:
        """Start the background maintenance thread.

        The maintenance thread periodically sweeps expired claims and hook
        leases, fires due recurrence rules, refreshes hook queue metrics,
        optionally timestamps event batches via a configured TSA, and delivers
        pending witness receipts.
        It also starts the hook consumer if not already running.

        Args:
            sweep_interval: Seconds between maintenance cycles (default 30).
            recurrence_interval: Seconds between recurrence checks (default 10).
            hook_poll_interval: Hook consumer poll interval (default 2).
            partition_interval: Deprecated; kept for API compatibility.
            timestamp_interval: Seconds between timestamping triggers (default 3600).
            tsa_config: Optional ``TSAConfig`` for RFC 3161 timestamping.
            witness_interval: Seconds between witness receipt delivery cycles (default 30).
        """
        from ._maintenance import MaintenanceThread

        if self._maintenance_thread is not None and self._maintenance_thread.is_running:
            return
        if tsa_config is not None:
            self.timestamping.set_config(tsa_config)
        self._maintenance_thread = MaintenanceThread(
            self,
            sweep_interval=sweep_interval,
            recurrence_interval=recurrence_interval,
            hook_poll_interval=hook_poll_interval,
            partition_interval=partition_interval,
            timestamp_interval=timestamp_interval,
            tsa_config=tsa_config,
            witness_interval=witness_interval,
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
        self.hooks._sync_handlers(self._hook_handlers, self._hook_consumer)
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
            RegistaError: ``HOOK_NOT_FOUND`` if the row does not exist.
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
            RegistaError: ``HOOK_NOT_FOUND`` if the row does not exist.
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
        """Query hook_queue and update the ``regista_hook_queue_depth`` gauge.

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
            return False
        return self._maintenance_thread.last_cycle_ok

    @property
    def pool_healthy(self) -> bool:
        """Check if the connection pool can execute a query."""
        if self._mgr is None:
            return False
        try:
            with self._mgr.connect() as conn:
                conn.execute("SELECT 1")
            return True
        except Exception:
            return False

    def export_public_keys(self) -> list[dict[str, object]]:
        """Export public key material for external signature verification.

        Returns asymmetric keys only (Ed25519 and future PQC schemes). Secret
        material is never included. An auditor who receives this export and
        the event log can verify signatures without the signing secret.

        Returns:
            List of dicts with ``key_id``, ``scheme``, ``public_key``
            (base64), ``fingerprint``, ``principal_id``, ``status``,
            ``revoked_at``.
        """
        self._require_open()
        return self._keys.export_public_keys()

    def verify_event_signature(
        self, event: Event, *, public_key: bytes | None = None,
    ) -> bool:
        """Verify an event's cryptographic signature.

        When ``public_key`` is provided, verification uses only that key
        (no secret material needed — the independent-verification path).
        When omitted, the key is resolved from the project's key set.

        Args:
            event: The event to verify.
            public_key: Optional raw public key bytes for external
                verification. If omitted, the project's key set is used.

        Returns:
            ``True`` if the signature is valid, ``False`` otherwise.
        """
        from ._signing import verify_event_with_public_key

        if public_key is None:
            self._require_open()
            try:
                key_entry = self._keys.get_key(event.key_id)
            except RegistaError:
                return False
            if key_entry.public_key is not None:
                public_key = key_entry.public_key
            else:
                public_key = key_entry.secret
        return verify_event_with_public_key(event, public_key)

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
            RegistaError: ``WORKFLOW_NOT_REGISTERED``,
                ``WORK_ITEM_TYPE_NOT_DECLARED``, ``CUSTOM_FIELD_VIOLATION``,
                ``VALIDATOR_FAILED``.
        """
        wi, evt = self.work_items.create(
            workflow_name, work_item_type, actor_id, actor_kind,
            actor_metadata,
            custom_fields=custom_fields,
            not_before=not_before,
            event_id=event_id,
        )
        self._try_create_witness_receipts(evt)
        return wi, evt

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
        on_behalf_of: dict | None = None,
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
                ``VALIDATOR_FAILED``.
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
            entity_kind: Entity kind (``"work_item"`` only; other kinds
                blocked until entity generalization is complete).
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
            RegistaError: ``CLAIM_CONTESTED``, ``NOT_BEFORE_FUTURE``,
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
        actor_kind: str = "agent",
    ) -> Claim:
        """Renew a claim's TTL. Rejects if claim is held by a different actor.

        Args:
            work_item_id: Target work item.
            actor_id: Must match the current claim holder.
            ttl_seconds: New lease duration.
            expected_attempt_number: Detect stale sessions after claim theft.
            coalesce_threshold: Minimum seconds between emitted ``claim_heartbeat``
                events. ``None`` (default) uses ``max(60, ttl_seconds/2)``.
            actor_kind: Kind of actor (default "agent").

        Returns:
            The renewed ``Claim``.

        Raises:
            RegistaError: ``CLAIM_LOST``, ``CLAIM_NOT_FOUND``,
                ``INVALID_ARGUMENT``.
        """
        _validate_mutation_params(actor_id=actor_id, actor_kind=actor_kind, ttl_seconds=ttl_seconds)
        return self.claims.heartbeat(
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
        """Release a claim held by the given actor.

        Args:
            work_item_id: Target work item.
            actor_id: Must match the current claim holder.
            event_id: UUIDv4 idempotency key.
            actor_kind: Kind of actor (default "agent").

        Raises:
            RegistaError: ``CLAIM_LOST``, ``CLAIM_NOT_FOUND``.
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
        target_project: str | None = None,
        target_entity_kind: str | None = None,
        content_hash: str | None = None,
    ) -> Link:
        """Create a typed directed link between two work items.

        Args:
            from_work_item_id: Source work item.
            to_work_item_id: Target work item (or target entity ID for
                cross-project value-references).
            link_type: Must be declared in the workflow definition.
            actor_id: Authenticated actor.
            actor_kind: ``"agent"`` | ``"human"`` | ``"system"``.
            actor_metadata: Optional JSONB metadata.
            event_id: UUIDv4 idempotency key.
            payload: Optional JSONB payload on the link.
            target_project: If provided, creates a cross-project value-reference
                without looking up the target locally (FR-22b).
            target_entity_kind: Entity kind for cross-project references
                (defaults to ``"work_item"``).
            content_hash: Opaque referrer-supplied hash for tamper-evidence
                of what was referenced.

        Returns:
            The created ``Link``.

        Raises:
            RegistaError: ``LINK_TYPE_NOT_ALLOWED``,
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
        """Remove a typed directed link between two work items.

        Args:
            from_work_item_id: Source work item.
            to_work_item_id: Target work item.
            link_type: The link type to remove.
            actor_id: Authenticated actor.
            actor_kind: ``"agent"`` | ``"human"`` | ``"system"``.
            actor_metadata: Optional JSONB metadata.
            event_id: UUIDv4 idempotency key.
            target_project: If provided, removes a cross-project value-reference
                without looking up the target locally.

        Raises:
            RegistaError: ``LINK_NOT_FOUND``.
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
            target_project=target_project,
        )

    def replay(
        self,
        *,
        continue_on_revoked: bool = False,
        verify_timestamps: bool = False,
        work_item_id: uuid.UUID | None = None,
    ) -> ReplayReport:
        """Rebuild projection from the event log and compare with live state.

        The report reflects consistency as of a single point-in-time snapshot
        (Postgres REPEATABLE READ). Drift committed after snapshot acquisition
        will only be visible in a later replay run.

        Args:
            continue_on_revoked: Skip revoked-key events with warnings instead
                of halting replay.
            verify_timestamps: Check that events are covered by confirmed TSP
                batches and emit warnings for uncovered events.
            work_item_id: Scope replay to a single work item. Global chain and
                timestamp coverage checks are skipped; one warning is emitted
                to note the scoped verification.

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
                    verify_timestamps=verify_timestamps,
                    work_item_id=work_item_id,
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
            RegistaError: ``HOOK_NOT_FOUND``.
        """
        self.hooks.requeue_dead_letter(dead_letter_id)

    def list_dead_lettered_hooks(self, limit: int = 100) -> list[DeadLetterEntry]:
        """List all dead-lettered hooks in reverse chronological order.

        Args:
            limit: Maximum number of entries to return (default 100).

        Returns:
            List of ``DeadLetterEntry`` objects.
        """
        return self.hooks.list_dead_letter(limit=limit)

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
        except RegistaError:
            timer.log("error")
            raise

    def unregister_actor_role(self, actor_id: str, role: str) -> None:
        """Remove a role from an actor's registered set.

        Args:
            actor_id: Actor identifier.
            role: Role to remove.

        Raises:
            RegistaError: ``ACTOR_ROLE_NOT_REGISTERED``.
        """
        from ._contract import validate_actor_id as _validate_actor_id

        _validate_actor_id(actor_id)
        from ._actor_roles import unregister_actor_role as _unregister

        timer = OpTimer(self._project, "unregister_actor_role")
        try:
            with self._mgr.transaction() as conn:
                _unregister(conn, actor_id, role)
            timer.log("ok", detail=f"{actor_id}:{role}")
        except RegistaError:
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

    def register_witness(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        event_filter: dict | None = None,
        max_failures: int = 10,
        max_retries: int = 3,
        *,
        public_key: bytes | None = None,
        key_scheme: str = "hmac-sha256",
    ) -> uuid.UUID:
        """Register an external witness. Returns witness_id.

        Args:
            url: HTTP(S) endpoint to POST event data to.
            headers: Optional HTTP headers (e.g., auth).
            event_filter: Optional filter constraining which events trigger a receipt.
            max_failures: Consecutive failures before auto-pause (default 10).
            max_retries: Per-receipt retry limit before dead-lettering (default 3).
            public_key: Optional asymmetric public key (Ed25519, raw 32 bytes).
                When provided with ``key_scheme='ed25519'``, returned witness
                signatures are verified against this key (BC-297).
            key_scheme: Signing scheme for witness signature verification
                (``'hmac-sha256'`` default, or ``'ed25519'``).

        Returns:
            UUID of the registered witness.
        """
        return self.witnesses.register(
            url, headers=headers, event_filter=event_filter,
            max_failures=max_failures, max_retries=max_retries,
            public_key=public_key, key_scheme=key_scheme,
        )

    def unregister_witness(self, witness_id: uuid.UUID) -> None:
        """Remove a witness. Pending receipts are abandoned."""
        self.witnesses.unregister(witness_id)

    def pause_witness(self, witness_id: uuid.UUID) -> None:
        """Pause a witness. Pending receipts are retained but not delivered."""
        self.witnesses.pause(witness_id)

    def reactivate_witness(self, witness_id: uuid.UUID) -> None:
        """Reactivate a paused/failed witness. Resets consecutive_failures."""
        self.witnesses.reactivate(witness_id)

    def list_witnesses(self, status: str | None = None) -> list[dict]:
        """List witness registrations, optionally filtered by status."""
        return self.witnesses.list(status=status)

    def list_witness_receipts(
        self,
        event_id: uuid.UUID | None = None,
        witness_id: uuid.UUID | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """Query witness receipts. At least one filter is recommended."""
        return self.witnesses.receipts(
            event_id=event_id, witness_id=witness_id,
            status=status, limit=limit,
        )

    def deliver_pending_witness_receipts(self) -> int:
        """Manually trigger one delivery cycle. Returns count of receipts processed."""
        return self.witnesses.deliver()

    def sweep_stuck_witness_receipts(self, max_age_seconds: int = 300) -> int:
        """Reset ``in_progress`` witness receipts stuck for longer than the threshold."""
        return self.witnesses.sweep_stuck(max_age_seconds)

    def sweep_stale_timestamp_batches(self, max_age_seconds: int = 300) -> int:
        """Mark ``pending`` timestamp batches older than the threshold as ``failed``."""
        return self.timestamping.sweep_stale(max_age_seconds)

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

    def archive_events(
        self,
        before_timestamp: datetime,
        *,
        dry_run: bool = False,
    ) -> int:
        """Archive events from completed work-items older than the given timestamp.

        Only archives work-items whose most recent event is before the
        cutoff. All events for a qualifying work-item are moved together,
        preserving hash chain integrity. Moves events to an
        ``events_archive`` table with the same schema as ``events``.

        Args:
            before_timestamp: Archive work-items whose latest event
                timestamp is before this value.
            dry_run: If ``True``, return the count without moving rows.

        Returns:
            Number of events archived (or that would be archived).
        """
        return self.archive.archive_events(before_timestamp, dry_run=dry_run)

    def create_work_items_batch(
        self,
        items: list[dict],
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

    def register_webhook(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        transitions: list[str] | None = None,
        work_item_types: list[str] | None = None,
        workflows: list[str] | None = None,
        max_failures: int = 10,
        sign_secret: bytes | None = None,
    ) -> dict:
        """Register a webhook for push-model event delivery.

        Args:
            url: HTTP(S) endpoint to POST event payloads to.
            headers: Optional HTTP headers to include in POST requests.
            transitions: Filter: only fire for these transition names.
                ``None`` means fire for all transitions.
            work_item_types: Filter: only fire for these work-item types.
            workflows: Filter: only fire for these workflow names.
            max_failures: Auto-pause webhook after this many consecutive
                failures (default 10).
            sign_secret: Optional HMAC-SHA256 secret. When set, regista
                computes ``HMAC-SHA256(sign_secret, body)`` and sends the
                signature as ``X-Regista-Signature: sha256=<hex>`` on
                every delivery.

        Returns:
            Dict with ``webhook_id``, ``url``, ``status``.
        """
        return self.webhooks.register(
            url, headers=headers, transitions=transitions,
            work_item_types=work_item_types, workflows=workflows,
            max_failures=max_failures, sign_secret=sign_secret,
        )

    def list_webhooks(self, status: str | None = None) -> list[dict]:
        """List registered webhooks.

        Args:
            status: Filter by status (``"active"``, ``"paused"``, ``"failed"``).

        Returns:
            List of webhook dicts.
        """
        return self.webhooks.list(status=status)

    def unregister_webhook(self, webhook_id: uuid.UUID) -> None:
        """Remove a webhook registration.

        Args:
            webhook_id: UUID from ``register_webhook``.
        """
        self.webhooks.unregister(webhook_id)

    def pause_webhook(self, webhook_id: uuid.UUID) -> None:
        """Pause a webhook (stops delivery without removing registration)."""
        self.webhooks.pause(webhook_id)

    def resume_webhook(self, webhook_id: uuid.UUID) -> None:
        """Resume a paused webhook."""
        self.webhooks.resume(webhook_id)
