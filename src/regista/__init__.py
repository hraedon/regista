from __future__ import annotations

import sys as _sys
from types import TracebackType
from typing import Any

import structlog

from ._api_claim import ClaimApiMixin
from ._api_workflow import WorkflowApiMixin
from ._connection import ConnectionManager
from ._errors import ErrorCode, RegistaError
from ._integrity import REGISTA_VERSION, check_integrity
from ._migrations import run_migrations
from ._observability import Metrics
from ._ops import ClaimOps, EventOps, LinkOps, WorkflowOps, WorkItemOps
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
    ConnectionInfo as ConnectionInfo,
)
from ._types import (
    CustomFieldDef as CustomFieldDef,
)
from ._types import (
    Event as Event,
)
from ._types import (
    Link as Link,
)
from ._types import (
    LinkTypeDef as LinkTypeDef,
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
    TransitionDef as TransitionDef,
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
from ._types import (
    WorkItemTypeDef as WorkItemTypeDef,
)
from ._version_info import VersionInfo as VersionInfo
from ._version_info import versions as versions
from ._workflow import (
    canonical_workflow_yaml as canonical_workflow_yaml,
)
from ._workflow import (
    parse_and_validate as parse_and_validate,
)
from ._workflow import (
    parse_file as parse_file,
)
from ._workflow import (
    parse_workflow_yaml as parse_workflow_yaml,
)
from ._workflow import (
    validate_yaml as validate_yaml,
)

# Stream discipline: unconfigured structlog prints to *stdout*, which would
# contaminate a CLI's --json output. Default the process to stderr logging
# unless the embedding application has already configured structlog.
if not structlog.is_configured():
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(20),
        logger_factory=structlog.PrintLoggerFactory(file=_sys.stderr),
    )

log = structlog.get_logger()


class Regista(
    WorkflowApiMixin,
    ClaimApiMixin,
):
    """An embeddable work-coordination ledger over PostgreSQL.

    One ``Regista`` instance owns one logical project namespace (one Postgres
    schema). Actors are caller-supplied attribution; workflow role checks
    enforce application policy. Use :meth:`create_project` to bootstrap a new
    project, then the constructor to reconnect.
    """

    def __init__(
        self,
        dsn: str,
        project: str,
        *,
        pool_min: int = 1,
        pool_max: int = 10,
        pool_max_lifetime: float | None = None,
        require_ssl: bool = False,
        prometheus_registry: Any = None,
        strict_roles: bool = False,
        read_only: bool = False,
    ) -> None:
        """Connect to an existing project.

        Args:
            dsn: Postgres connection string.
            project: Project (schema) name.
            pool_min: Minimum connection-pool size.
            pool_max: Maximum connection-pool size.
            pool_max_lifetime: Maximum connection lifetime in seconds.
            require_ssl: Reject the connection if SSL is not active.
            prometheus_registry: Optional ``prometheus_client.CollectorRegistry``.
            strict_roles: Reject unregistered actors when role enforcement is on.
            read_only: Open a verify-path connection against a read-only session.
                No DDL is issued and replay runs in memory.

        Raises:
            RegistaError: If migrations are pending or workflow versions are
                incompatible.
        """
        self._read_only = read_only
        self._mgr = ConnectionManager(
            dsn, project, pool_min=pool_min, pool_max=pool_max,
            pool_max_lifetime=pool_max_lifetime, require_ssl=require_ssl,
        )
        try:
            self._mgr.open()
            self._mgr.ensure_schema()
            self._metrics = Metrics(registry=prometheus_registry)
            self._project = project
            self._strict_roles = strict_roles
            self._ops_workflows: WorkflowOps | None = None
            self._ops_work_items: WorkItemOps | None = None
            self._ops_events: EventOps | None = None
            self._ops_claims: ClaimOps | None = None
            self._ops_links: LinkOps | None = None
            check_integrity(self._mgr, read_only=read_only)
        except Exception:
            self._mgr.close()
            raise
        log.info("regista.connected", project=project, regista_version=REGISTA_VERSION)

    @classmethod
    def create_project(
        cls,
        dsn: str,
        project: str,
        *,
        pool_min: int = 1,
        pool_max: int = 10,
        pool_max_lifetime: float | None = None,
        require_ssl: bool = False,
        prometheus_registry: Any = None,
        strict_roles: bool = False,
        owner: str | None = None,
        display_name: str | None = None,
        created_by: str | None = None,
    ) -> Regista:
        """Create a new project (schema + migrations) and return a handle.

        Refuses to run against an old or unknown schema: migrations create the
        fresh baseline only on an empty destination.
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
            pool_min=pool_min,
            pool_max=pool_max,
            pool_max_lifetime=pool_max_lifetime,
            require_ssl=require_ssl,
            prometheus_registry=prometheus_registry,
            strict_roles=strict_roles,
        )

    def _require_open(self) -> None:
        if self._mgr is None:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "Regista instance has been closed",
            )

    @property
    def workflows(self) -> WorkflowOps:
        if self._ops_workflows is None:
            self._ops_workflows = WorkflowOps(self._mgr, self._metrics, self._project)
        return self._ops_workflows

    @property
    def work_items(self) -> WorkItemOps:
        if self._ops_work_items is None:
            self._ops_work_items = WorkItemOps(self._mgr, self._metrics, self._project)
        return self._ops_work_items

    @property
    def events(self) -> EventOps:
        if self._ops_events is None:
            self._ops_events = EventOps(self._mgr, self._metrics, self._project)
        return self._ops_events

    @property
    def claims(self) -> ClaimOps:
        if self._ops_claims is None:
            self._ops_claims = ClaimOps(self._mgr, self._metrics, self._project)
        return self._ops_claims

    @property
    def links(self) -> LinkOps:
        if self._ops_links is None:
            self._ops_links = LinkOps(self._mgr, self._metrics, self._project)
        return self._ops_links

    @property
    def project(self) -> str:
        if self._mgr is None:
            raise RegistaError(ErrorCode.INVALID_ARGUMENT, "Regista instance has been closed")
        return self._project

    @property
    def connection_info(self) -> ConnectionInfo:
        if self._mgr is None:
            raise RegistaError(ErrorCode.INVALID_ARGUMENT, "Regista instance has been closed")
        from psycopg.conninfo import conninfo_to_dict

        info = conninfo_to_dict(self._mgr.dsn)
        port = info.get("port")
        host = info.get("host")
        dbname = info.get("dbname")
        return ConnectionInfo(
            host=str(host) if host is not None else None,
            port=int(port) if port is not None else None,
            database=str(dbname) if dbname is not None else None,
            project=self._project,
        )

    @property
    def regista_version(self) -> str:
        return REGISTA_VERSION

    @property
    def prometheus_registry(self) -> Any:
        return self._metrics.registry

    @property
    def pool_healthy(self) -> bool:
        return self._mgr is not None

    def close(self) -> None:
        """Release the connection pool and mark the handle closed."""
        if self._mgr is not None:
            self._mgr.close()
            self._mgr = None  # type: ignore[assignment]
        log.info("regista.disconnected", project=self._project)

    def __enter__(self) -> Regista:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self._mgr is None else "open"
        return f"Regista(project={self._project!r}, {state})"


__all__ = [
    "ActorKind",
    "ActorMetadata",
    "ActorRole",
    "Claim",
    "ConnectionInfo",
    "CustomFieldDef",
    "ErrorCode",
    "Event",
    "Link",
    "LinkTypeDef",
    "ProjectCatalogEntry",
    "QueryPage",
    "Regista",
    "RegistaError",
    "ReplayReport",
    "ReplayReportEntry",
    "TransitionDef",
    "ValidationError",
    "ValidationResult",
    "VersionInfo",
    "WorkItem",
    "WorkItemTypeDef",
    "WorkflowDefinition",
    "WorkflowVersion",
    "canonical_workflow_yaml",
    "parse_and_validate",
    "parse_file",
    "parse_workflow_yaml",
    "validate_yaml",
    "versions",
]
