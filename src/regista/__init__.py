from __future__ import annotations

import sys as _sys
import uuid
from collections.abc import Callable

import structlog

from . import _config as _config
from . import secrets as secrets
from ._api_async import AsyncApiMixin
from ._api_claim import ClaimApiMixin
from ._api_external import ExternalApiMixin
from ._api_meta import MetaApiMixin
from ._api_workflow import WorkflowApiMixin
from ._assurance import AssuranceLevel as AssuranceLevel
from ._assurance import GateProfile as GateProfile
from ._assurance import compute_assurance_level as compute_assurance_level
from ._assurance import gate_rationale as gate_rationale
from ._assurance import same_lineage as same_lineage
from ._connection import ConnectionManager
from ._errors import ErrorCode, RegistaError
from ._integrity import REGISTA_VERSION, check_integrity
from ._keys import KeySet
from ._migrations import run_migrations
from ._observability import Metrics
from ._ops import (
    AnchorOps,
    ArchiveOps,
    AssuranceOps,
    ClaimOps,
    EventOps,
    HookOps,
    LinkOps,
    PrincipalKeyOps,
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
    ActorRole as ActorRole,
)
from ._types import (
    Claim as Claim,
)
from ._types import (
    ConnectionInfo,
    Event,
)
from ._types import (
    DeadLetterEntry as DeadLetterEntry,
)
from ._types import (
    HookContext as HookContext,
)
from ._types import (
    Link as Link,
)
from ._types import (
    ProjectCatalogEntry as ProjectCatalogEntry,
)
from ._types import (
    QueryPage as QueryPage,
)
from ._types import (
    ReplayReport as ReplayReport,
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
from ._types import (
    WorkflowVersion as WorkflowVersion,
)
from ._types import (
    WorkItem as WorkItem,
)
from ._version_info import VersionInfo as VersionInfo
from ._version_info import versions as versions
from ._workflow import canonical_workflow_yaml as canonical_workflow_yaml
from ._workflow import parse_and_validate as parse_and_validate
from ._workflow import parse_file as parse_file
from ._workflow import parse_workflow_yaml as parse_workflow_yaml
from ._workflow import validate_yaml as validate_yaml
from ._workflow_compose import compose_workflow as compose_workflow
from .principal_lifecycle import Approval as Approval
from .principal_lifecycle import ChallengeStorageScope as ChallengeStorageScope
from .principal_lifecycle import CustodyMode as CustodyMode
from .principal_lifecycle import EffectiveReceipt as EffectiveReceipt
from .principal_lifecycle import EffectiveReceiptStatus as EffectiveReceiptStatus
from .principal_lifecycle import EnrollmentRequest as EnrollmentRequest
from .principal_lifecycle import LifecycleContractError as LifecycleContractError
from .principal_lifecycle import LifecycleDigest as LifecycleDigest
from .principal_lifecycle import LifecycleErrorCode as LifecycleErrorCode
from .principal_lifecycle import LifecycleOperation as LifecycleOperation
from .principal_lifecycle import LifecycleOperationType as LifecycleOperationType
from .principal_lifecycle import LifecycleState as LifecycleState
from .principal_lifecycle import PossessionChallenge as PossessionChallenge
from .principal_lifecycle import PossessionProof as PossessionProof
from .principal_lifecycle import PrincipalDescriptor as PrincipalDescriptor
from .principal_lifecycle import PrincipalKind as PrincipalKind
from .principal_lifecycle import PrincipalLifecycle as PrincipalLifecycle
from .principal_lifecycle import ProofFormat as ProofFormat
from .principal_lifecycle import ReconciliationReport as ReconciliationReport
from .principal_lifecycle import ReconciliationStatus as ReconciliationStatus
from .principal_lifecycle import RegistryReceipt as RegistryReceipt
from .principal_lifecycle import RegistryReceiptStatus as RegistryReceiptStatus
from .principal_lifecycle import RevocationRequest as RevocationRequest
from .principal_lifecycle import RotationRequest as RotationRequest
from .principal_lifecycle import canonical_lifecycle_digest as canonical_lifecycle_digest

# Stream discipline (suite CLI contract v1 §1): unconfigured structlog prints
# to *stdout*, so any CLI that embeds regista as a library gets its --json
# stdout contaminated by regista's operational logging. Default the process to
# stderr logging unless the embedding application has already configured
# structlog — an explicit structlog.configure() anywhere (before or after this
# import) still wins, because get_logger() binds configuration lazily.
if not structlog.is_configured():
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(20),
        logger_factory=structlog.PrintLoggerFactory(file=_sys.stderr),
    )

config = _config
log = structlog.get_logger()


class Regista(
    WorkflowApiMixin,
    ClaimApiMixin,
    AsyncApiMixin,
    ExternalApiMixin,
    MetaApiMixin,
):
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
        self._hmac_key_path = hmac_key_path
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
        owner: str | None = None,
        display_name: str | None = None,
        created_by: str | None = None,
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
            owner: Optional owner actor_id for the projects catalog (Plan 012).
                Written to ``public.projects`` after migrations; ``None``
                leaves the owner unassigned.
            display_name: Optional human-friendly name for the catalog.
            created_by: Who created this project (for the catalog row).

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
            from ._projects import register_project

            with mgr.connect() as conn:
                register_project(
                    conn,
                    schema_name=project,
                    display_name=display_name,
                    owner_actor_id=owner,
                    created_by=created_by,
                )
                conn.commit()
        finally:
            mgr.close()
        log.info(
            "regista.project_created",
            project=project,
            owner=owner,
            display_name=display_name,
        )
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
    def assurance(self) -> AssuranceOps:
        self._require_open()
        if not hasattr(self, "_assurance_ops"):
            self._assurance_ops = AssuranceOps(
                lambda **kw: self.read_events(**kw), self._project,
            )
        return self._assurance_ops

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
    def anchoring(self) -> AnchorOps:
        self._require_open()
        if not hasattr(self, "_anchoring_ops"):
            self._anchoring_ops = AnchorOps(self._mgr, self._metrics, self._project)
        return self._anchoring_ops

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
            self._archive_ops = ArchiveOps(self._mgr, self._keys, self._project)
        return self._archive_ops

    @property
    def webhooks(self) -> WebhookOps:
        self._require_open()
        if not hasattr(self, "_webhook_ops"):
            self._webhook_ops = WebhookOps(self._mgr, self._project)
        return self._webhook_ops

    @property
    def principals(self) -> PrincipalKeyOps:
        self._require_open()
        if not hasattr(self, "_principal_ops"):
            self._principal_ops = PrincipalKeyOps(
                self._mgr, self._keys, self._metrics, self._project,
            )
        return self._principal_ops

    @property
    def principal_lifecycle(self) -> PrincipalLifecycle:
        """Return the public principal lifecycle facade.

        When connected to a database the facade persists operations, challenges,
        approvals, and receipts and can atomically commit registry changes.
        """
        self._require_open()
        if not hasattr(self, "_principal_lifecycle_ops"):
            self._principal_lifecycle_ops = PrincipalLifecycle(
                self._project,
                mgr=self._mgr,
                keys=self._keys,
                metrics=self._metrics,
            )
        return self._principal_lifecycle_ops

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

    @classmethod
    def list_projects(cls, dsn: str) -> list[ProjectCatalogEntry]:
        """List all registered projects from the ``public.projects`` catalog.

        This is a class-level operation — it does not require a connected
        ``Regista`` instance.  It opens a short-lived connection to query
        the catalog.

        Args:
            dsn: Postgres connection string.

        Returns:
            List of :class:`ProjectCatalogEntry` ordered by schema_name.
        """
        import psycopg
        from psycopg.rows import dict_row

        from ._projects import list_catalog_projects

        with psycopg.connect(dsn, row_factory=dict_row) as conn:
            return list_catalog_projects(conn)

    def trigger_anchoring(self, *, batch_size: int = 10_000):
        """Submit a Merkle root of pending events to the configured anchor provider.

        Requires ``start_maintenance(anchor_provider=...)`` or
        ``regista.anchoring.set_provider(...)`` to have been called first.
        """
        return self.anchoring.trigger(batch_size=batch_size)

    def upgrade_pending_anchors(self, *, max_iterations: int = 100) -> int:
        """Poll the anchor provider for upgrades of pending receipts."""
        return self.anchoring.upgrade_pending(max_iterations=max_iterations)

    def list_anchor_receipts(
        self,
        status: str | None = None,
        provider: str | None = None,
        limit: int = 100,
    ) -> list:
        """List anchor receipts, optionally filtered."""
        return self.anchoring.list_receipts(status=status, provider=provider, limit=limit)

    def get_anchor_receipt(self, receipt_id: uuid.UUID):
        """Retrieve a single anchor receipt by ID."""
        return self.anchoring.get_receipt(receipt_id)

    def verify_anchor_receipt(self, receipt_id: uuid.UUID) -> str:
        """Re-verify a stored anchor receipt against its merkle root."""
        return self.anchoring.verify(receipt_id)

    def export_audit_bundle(
        self, output_path: str, *, since_seq: int | None = None,
    ) -> dict:
        """Export events, anchor receipts, and segments as a self-contained JSON bundle.

        The bundle can be verified offline by a third-party auditor without
        production database access or private keys (Plan 019 WI-3/WI-4,
        Plan 028 WI-1.2).
        """
        return self.archive.export_bundle(output_path, since_seq=since_seq)

    @staticmethod
    def verify_audit_bundle_offline(bundle_path: str) -> dict:
        """Verify an exported audit bundle without a database connection.

        Recomputes content anchors from the bundle's events, verifies chain
        integrity, and checks anchor receipt merkle roots against recomputed
        values. Returns a detailed verification report.
        """
        from ._bundle import verify_audit_bundle_offline

        return verify_audit_bundle_offline(bundle_path).to_dict()

    def verify_archive_chain(self) -> dict:
        """Verify chain integrity across all sealed archive segments.

        Confirms each segment's internal chain, seal signature, and that
        segment N's head_hash chains to segment N+1's first_event_prev_hash.
        """
        return self.archive.verify_archive_chain()
