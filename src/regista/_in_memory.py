from __future__ import annotations

import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from types import TracebackType
from typing import TYPE_CHECKING, Any

import structlog

from ._event_store import InMemoryEventStore
from ._in_mem_claim import InMemClaimMixin
from ._in_mem_hook import InMemHookMixin
from ._in_mem_ops import InMemOpsMixin
from ._in_mem_witness import InMemWitnessMixin
from ._in_mem_workflow import InMemWorkflowMixin
from ._integrity import REGISTA_VERSION
from ._keys import KeySet
from ._types import ConnectionInfo

if TYPE_CHECKING:
    from ._types import WorkflowDefinition

log = structlog.get_logger()


@dataclass(frozen=True)
class TransportResult:
    status_code: int
    body: dict[str, Any] | None = None
    error: str | None = None


class InMemoryRegista(
    InMemWorkflowMixin,
    InMemClaimMixin,
    InMemHookMixin,
    InMemWitnessMixin,
    InMemOpsMixin,
):
    """In-memory backend implementing the same API surface as ``Regista``.

    No Postgres required. Event emission is skipped when ``hmac_key_path``
    is not provided.
    """

    def __init__(
        self,
        dsn: str = "",
        project: str = "test",
        hmac_key_path: str = "",
        *,
        pool_min: int = 1,
        pool_max: int = 10,
        prometheus_registry: Any = None,
        strict_roles: bool = False,
        strict_asymmetric: bool = False,
        witness_transport: Callable[..., TransportResult] | None = None,
    ) -> None:
        self._project = project
        self._hmac_key_path = hmac_key_path
        self._key_set: KeySet | None = None
        if hmac_key_path:
            self._key_set = KeySet(hmac_key_path, strict_asymmetric=strict_asymmetric)
        self._workflows: dict[tuple[str, int], dict[str, Any]] = {}
        self._workflow_defs: dict[tuple[str, int], WorkflowDefinition] = {}
        self._workflow_hashes: dict[tuple[str, int], bytes] = {}
        self._workflow_registered_at: dict[tuple[str, int], datetime] = {}
        self._work_items: dict[uuid.UUID, dict[str, Any]] = {}
        self._store = InMemoryEventStore()
        self._store.bind(self._work_items)
        self._claims: dict[uuid.UUID, dict[str, Any]] = {}
        self._links: list[dict[str, Any]] = []
        self._actor_roles: set[tuple[str, str]] = set()
        self._actor_role_created: dict[tuple[str, str], datetime] = {}
        from ._review_validators import BUILTIN_REVIEW_VALIDATORS

        self._validators: dict[str, Callable[..., Any]] = dict(BUILTIN_REVIEW_VALIDATORS)
        self._hook_handlers: dict[str, Callable[..., Any]] = {}
        self._hook_queue: list[dict[str, Any]] = []
        self._hook_id_counter = 0
        self._dead_letter: dict[int, dict[str, Any]] = {}
        self._hook_consumer_running = False
        self._recurrence_rules: dict[uuid.UUID, dict[str, Any]] = {}
        self._strict_roles = strict_roles
        self._witness_transport = witness_transport
        self._witnesses: dict[uuid.UUID, dict[str, Any]] = {}
        self._witness_receipts: list[dict[str, Any]] = []
        self._witness_delivery_lock = threading.Lock()
        self._enrolled_witness_keys: dict[uuid.UUID, Any] = {}

    @classmethod
    def create_project(
        cls,
        dsn: str = "",
        project: str = "test",
        hmac_key_path: str = "",
        *,
        pool_min: int = 1,
        pool_max: int = 10,
        prometheus_registry: Any = None,
        strict_roles: bool = False,
        strict_asymmetric: bool = False,
        witness_transport: Callable[..., TransportResult] | None = None,
        owner: str | None = None,
        display_name: str | None = None,
        created_by: str | None = None,
    ) -> InMemoryRegista:
        inst = cls(
            dsn, project, hmac_key_path,
            pool_min=pool_min, pool_max=pool_max,
            prometheus_registry=prometheus_registry,
            strict_roles=strict_roles,
            strict_asymmetric=strict_asymmetric,
            witness_transport=witness_transport,
        )
        inst.register_project_metadata(
            display_name=display_name,
            owner_actor_id=owner,
            created_by=created_by,
        )
        return inst

    def close(self) -> None:
        pass

    def __enter__(self) -> InMemoryRegista:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Mirror ``Regista``'s context-manager contract (WI-218).

        There is no pool to release, but the conformance suite exercises both
        backends through the same interface, so the double must accept ``with``.
        """
        self.close()

    @property
    def project(self) -> str:
        return self._project

    @property
    def regista_version(self) -> str:
        return REGISTA_VERSION

    @property
    def prometheus_registry(self) -> Any:
        return None

    @property
    def connection_info(self) -> ConnectionInfo:
        return ConnectionInfo(host=None, port=None, database=None, project=self._project)

    @property
    def maintenance_healthy(self) -> bool:
        """InMemory backend has no maintenance thread; always returns True."""
        return True

    @property
    def witnesses(self) -> Any:
        from ._in_mem_witness import _InMemoryWitnessOps

        return _InMemoryWitnessOps(self)

    @property
    def assurance(self) -> Any:
        from ._ops import AssuranceOps

        return AssuranceOps(self.read_events, self._project)

    @property
    def archive(self) -> Any:
        raise NotImplementedError(
            "Event archival is not supported on the InMemory backend"
        )
