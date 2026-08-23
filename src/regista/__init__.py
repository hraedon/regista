from __future__ import annotations

import sys as _sys
from collections.abc import Callable
from types import TracebackType
from typing import Any

import structlog

from . import _config as _config
from . import secrets as secrets
from ._action_delegation import (
    ActionDelegationCredential as ActionDelegationCredential,
)
from ._action_delegation import ActionDelegationError as ActionDelegationError
from ._action_delegation import ActionDelegationScope as ActionDelegationScope
from ._action_delegation import (
    DelegationVerificationStatus as DelegationVerificationStatus,
)
from ._action_delegation import (
    VerifiedActionDelegation as VerifiedActionDelegation,
)
from ._action_delegation import action_delegation_hash as action_delegation_hash
from ._action_delegation import parse_action_delegation as parse_action_delegation
from ._api_async import AsyncApiMixin
from ._api_claim import ClaimApiMixin
from ._api_external import ExternalApiMixin
from ._api_genesis import GenesisApiMixin
from ._api_meta import MetaApiMixin
from ._api_workflow import WorkflowApiMixin
from ._assurance import AssuranceLevel as AssuranceLevel
from ._assurance import GateProfile as GateProfile
from ._assurance import LineageRelation as LineageRelation
from ._assurance import compute_assurance_level as compute_assurance_level
from ._assurance import gate_rationale as gate_rationale
from ._assurance import lineage_relation as lineage_relation
from ._assurance import same_lineage as same_lineage
from ._connection import ConnectionManager
from ._errors import ErrorCode, RegistaError
from ._genesis import GenesisRecovery as GenesisRecovery
from ._genesis import V6GenesisWrite as V6GenesisWrite
from ._integrity import REGISTA_VERSION, check_integrity
from ._keys import KeySet
from ._lineage import MODEL_LINEAGE_FAMILIES as MODEL_LINEAGE_FAMILIES
from ._migrations import run_migrations
from ._observability import Metrics
from ._ops import (
    ArchiveOps,
    AssuranceOps,
    ClaimOps,
    EventOps,
    HookOps,
    LinkOps,
    PrincipalKeyOps,
    RecurrenceOps,
    WebhookOps,
    WitnessOps,
    WorkflowOps,
    WorkItemOps,
)
from ._principals import validate_principal_id as validate_principal_id
from ._trust_genesis_file import load_trust_genesis_document as _load_trust_genesis_document
from ._trust_genesis_file import trust_genesis_path_from_env as _trust_genesis_path_from_env
from ._types import (
    ActorKind as ActorKind,
)
from ._types import (
    ActorMetadata as ActorMetadata,
)
from ._types import (
    ActorRole as ActorRole,
)
from ._types import AuthorizationEvidence as AuthorizationEvidence
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
from ._v6_writer import Producer as Producer
from ._v6_writer import resolve_producer as resolve_producer
from ._version_info import VersionInfo as VersionInfo
from ._version_info import versions as versions
from ._workflow import canonical_workflow_yaml as canonical_workflow_yaml
from ._workflow import parse_and_validate as parse_and_validate
from ._workflow import parse_file as parse_file
from ._workflow import parse_workflow_yaml as parse_workflow_yaml
from ._workflow import validate_yaml as validate_yaml
from ._workflow_compose import compose_workflow as compose_workflow
from .principal_lifecycle import Approval as Approval
from .principal_lifecycle import ApprovalVerifier as ApprovalVerifier
from .principal_lifecycle import ChallengeStorageScope as ChallengeStorageScope
from .principal_lifecycle import CustodyMode as CustodyMode
from .principal_lifecycle import EffectiveReceipt as EffectiveReceipt
from .principal_lifecycle import EffectiveReceiptStatus as EffectiveReceiptStatus
from .principal_lifecycle import EnrollmentRequest as EnrollmentRequest
from .principal_lifecycle import LifecycleAuthority as LifecycleAuthority
from .principal_lifecycle import LifecycleAuthorityKind as LifecycleAuthorityKind
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
from .verification import NO_REFERENTS as NO_REFERENTS
from .verification import Applicability as Applicability
from .verification import BundleReferents as BundleReferents
from .verification import EnvelopeVersion as EnvelopeVersion
from .verification import TrustLogVerificationReport as TrustLogVerificationReport
from .verification import VerificationPolicy as VerificationPolicy
from .verification import VerificationResult as VerificationResult
from .verification import bundle_referents as bundle_referents
from .verification import chain_head_hash as chain_head_hash
from .verification import make_verification_policy as make_verification_policy
from .verification import verify_event_with_referents as verify_event_with_referents

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
    GenesisApiMixin,
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
        prometheus_registry: Any = None,
        auto_partition: bool = True,
        strict_roles: bool = False,
        strict_asymmetric: bool = False,
        approval_verifier: ApprovalVerifier | None = None,
        trust_genesis_path: str | None = None,
        read_only: bool = False,
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
            approval_verifier: Optional typed step-up/approval-evidence policy
                for the principal lifecycle facade (Plan 031 WI-1.2). When
                omitted, approvals are accepted on consumer trust (historical
                behavior) and recorded as ``evidence_verified=None`` —
                *unverified* and not sufficient for release qualification.
                Release qualification requires a configured verifier so missing
                or insufficient approval evidence fails closed.
            trust_genesis_path: Operator-pinned trust-domain genesis document used
                to resolve and append principal lifecycle authority. When omitted,
                ``REGISTA_TRUST_GENESIS_PATH`` is consulted. Lifecycle commit
                fails closed when no valid document is configured.
            read_only: Open a verify-path connection intended for use
                against a read-only session (hot standby / restore). regista
                will not issue DDL and replay runs in memory; the connect
                FAILS CLOSED (raises ``MIGRATION_REQUIRED``) if the schema's
                migrations table is missing. The no-mutates guarantee holds
                only if the DSN session is actually read-only. ``create_project``
                always remains a write path and ignores this.

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
        self._read_only = read_only
        self._mgr = ConnectionManager(
            dsn, project, pool_min=pool_min, pool_max=pool_max,
            pool_max_lifetime=pool_max_lifetime, require_ssl=require_ssl,
        )
        try:
            self._mgr.open()
            self._mgr.ensure_schema()
            self._keys = KeySet(hmac_key_path, strict_asymmetric=strict_asymmetric)
            configured_genesis = (
                trust_genesis_path
                if trust_genesis_path is not None
                else _trust_genesis_path_from_env()
            )
            self._trust_genesis_document = _load_trust_genesis_document(configured_genesis)
            self._metrics = Metrics(registry=prometheus_registry)
            self._project = project
            from ._review_validators import BUILTIN_REVIEW_VALIDATORS

            self._validators: dict[str, Callable[..., Any]] = dict(BUILTIN_REVIEW_VALIDATORS)
            self._hook_handlers: dict[str, Callable[..., Any]] = {}
            self._hook_channel = f"regista_hooks_{self._mgr.schema}"
            self._hook_consumer = None
            self._strict_roles = strict_roles
            self._approval_verifier = approval_verifier
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
            check_integrity(self._mgr, read_only=read_only)
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
        prometheus_registry: Any = None,
        auto_partition: bool = True,
        strict_roles: bool = False,
        strict_asymmetric: bool = False,
        owner: str | None = None,
        display_name: str | None = None,
        created_by: str | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        trust_genesis_path: str | None = None,
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
            approval_verifier: Optional typed approval-evidence policy passed
                through to the principal lifecycle facade (see ``__init__``).
            trust_genesis_path: Operator-pinned trust-domain genesis document
                passed through to the connected handle.

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
            approval_verifier=approval_verifier,
            trust_genesis_path=trust_genesis_path,
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
            self._mgr = None  # type: ignore[assignment]
        log.info("regista.disconnected", project=self._project)

    def verify_trust_log(self) -> TrustLogVerificationReport:
        """Verify this project's pinned trust-genesis document and trust log.

        The verification runs through regista's single authority-checked trust
        log walk in a read-only transaction. A configured, valid pinned genesis
        is mandatory; a missing pin raises instead of treating an empty or
        unreachable log as verified. The returned report contains only typed
        scalar evidence and never exposes the connection or an internal
        manager.

        Raises:
            RegistaError: If the handle is closed, no pinned genesis is loaded,
                or the genesis/trust-log chain fails verification.
        """
        self._require_open()
        if self._trust_genesis_document is None:
            raise RegistaError(
                ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
                "a pinned trust-genesis document is required to verify the trust log",
                {"reason": "pinned_genesis_missing"},
            )

        from ._trust_log_writer import verify_trust_log_chain

        assert self._mgr is not None
        with self._mgr.transaction() as conn:
            conn.execute("SET TRANSACTION READ ONLY")
            chain = verify_trust_log_chain(conn, self._trust_genesis_document)

        return TrustLogVerificationReport(
            verified=True,
            # The chain walk counts every verified row, including genesis and
            # root-authorised non-lifecycle transitions.  ``chain.verified``
            # deliberately contains lifecycle transitions only.
            event_count=chain.event_count,
            trust_domain_id=chain.state.identity.trust_domain_id,
            genesis_event_hash=chain.state.genesis_event_hash,
        )

    def __enter__(self) -> Regista:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Release the pool deterministically.

        The pool also closes at interpreter exit via ``ConnectionManager``'s
        finalizer (WI-218), but ``with`` closes it at a point the caller
        controls — and stops the maintenance/hook threads, which the exit-path
        finalizer does not reach.
        """
        self.close()

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
    def prometheus_registry(self) -> Any:
        return self._metrics.registry

    @property
    def workflows(self) -> WorkflowOps:
        self._require_open()
        if not hasattr(self, "_workflows_ops"):
            self._workflows_ops = WorkflowOps(
                self._mgr, self._metrics, self._project, self._keys
            )
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
                approval_verifier=self._approval_verifier,
                trust_genesis_document=self._trust_genesis_document,
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
        return self._maintenance_thread.last_cycle_ok  # type: ignore[no-any-return]

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

    def export_audit_bundle(
        self,
        output_path: str,
        *,
        root_governance: dict[str, Any] | None = None,
        signing_principal_id: str | None = None,
        signing_key_id: str | None = None,
        external_evidence: tuple[dict[str, Any], ...] = (),
        since_seq: int | None = None,
        until_seq: int | None = None,
    ) -> dict[str, Any]:
        """Export a signed **bundle v3** audit artifact (``docs/0.6.0/BUNDLE-V3.md``).

        The artifact is a canonical-JSON document whose single signed ``statement``
        commits to the membership of every event in scope (an RFC 6962 Merkle root over
        chain-derived ordinals) and to the digest of every section. A third-party auditor
        verifies it offline, with no database access and no private keys.

        ``root_governance`` — the replayed ``{mode, threshold, signer_count}`` — is
        required and has no default: §3.2 requires the current governance state obtained
        by replaying the signed trust-domain log, and forbids copying it from genesis,
        configuration or a projection. Resolving it is §4 trust-root resolution (WI-289
        Phase C); until that lands the caller supplies the state it replayed, and export
        refuses by name rather than attesting a governance claim it invented.

        ``since_seq``/``until_seq`` **select** rows (exclusive/inclusive) so a corpus
        larger than the verifier's size cap can be chunked. They do not order them: the
        membership tree's order is derived by walking the chain, and a windowed export
        declares a ``contiguous-range`` scope anchored to the event before it.
        """
        return self.archive.export_bundle(
            output_path,
            root_governance=root_governance,
            signing_principal_id=signing_principal_id,
            signing_key_id=signing_key_id,
            external_evidence=external_evidence,
            since_seq=since_seq,
            until_seq=until_seq,
        )

    @staticmethod
    def verify_audit_bundle_offline(
        bundle_path: str, *, statement_public_key: bytes | None = None
    ) -> dict[str, Any]:
        """Verify an exported **bundle v3** artifact without a database connection.

        Recomputes the membership root, every section digest, the chain-derived ordering
        and the per-event signatures, and checks the statement signature against
        ``statement_public_key`` — which must come from the caller, because a key taken
        from the artifact it authenticates authenticates nothing (§4.3). A v1 or v2
        artifact is refused by name; it is never read as v3 (§2, §6).
        """
        from ._bundle import verify_audit_bundle_offline

        return verify_audit_bundle_offline(
            bundle_path, statement_public_key=statement_public_key
        ).to_dict()
