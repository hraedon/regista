from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar

from ._errors import ErrorCode, RegistaError
from ._in_mem_base import _InMemoryBase
from ._types import (
    ActorRole,
    Event,
    ProjectCatalogEntry,
)

if TYPE_CHECKING:
    from ._verification import VerificationResult


class InMemOpsMixin(_InMemoryBase):

    def export_public_keys(self) -> list[dict[str, object]]:
        if self._key_set is None:
            return []
        return self._key_set.export_public_keys()

    def verify_event_signature(
        self, event: Event, *, public_key: bytes | None = None,
    ) -> bool:
        """Verify an event's signature and reconcile the row against it.

        Returns ``False`` for a keyless event. That is a *lossy* rendering of
        the truth — such an event was never signed, so it is ``unverifiable``,
        not "signature invalid". Use :meth:`verify_event_result` to tell the two
        apart (CUTOVER-POLICY §5.3).
        """
        return self.verify_event_result(event, public_key=public_key).accepted

    def verify_event_result(
        self, event: Event, *, public_key: bytes | None = None,
    ) -> VerificationResult:
        """The structured verification verdict, matching the Postgres backend.

        The InMemory store runs the same reconciliation as Postgres so the two
        backends cannot disagree about what "verified" means. Its keyless mode
        is reported as ``unverifiable`` / ``unsigned_event`` rather than being
        pushed through the strict verifier as a malformed signed event.
        """
        from ._signing import verify_event_result_with_public_key
        from ._verification import (
            Backend,
            EventRow,
            KeySetResolver,
            StaticKeyResolver,
            VerificationPolicy,
            verify_event_strict,
        )

        policy = VerificationPolicy()
        row = EventRow.from_event(event, backend=Backend.IN_MEMORY)
        if public_key is not None:
            scheme_id: str | None = None
            if self._key_set is not None:
                try:
                    scheme_id = self._key_set.get_key(event.key_id).scheme
                except RegistaError:
                    scheme_id = None
            return verify_event_result_with_public_key(
                event, public_key, scheme_id=scheme_id, backend=Backend.IN_MEMORY,
            )
        if self._key_set is None:
            return verify_event_strict(
                row, keys=StaticKeyResolver(material=b""), policy=policy,
            )
        return verify_event_strict(
            row, keys=KeySetResolver(self._key_set), policy=policy,
        )

    @staticmethod
    def validate_actor_metadata(
        event: Event,
        expected_schema: dict[str, Any] | None = None,
    ) -> list[str]:
        from ._lint import validate_actor_metadata as _validate

        return _validate(event, expected_schema)

    @staticmethod
    def actor_metadata_complete(
        events: list[Event],
        expected_keys: list[str],
    ) -> list[Event]:
        from ._lint import actor_metadata_complete as _complete

        return _complete(events, expected_keys)

    def register_actor_role(self, actor_id: str, role: str) -> None:
        from ._contract import validate_actor_id

        validate_actor_id(actor_id)
        key = (actor_id, role)
        if key in self._actor_roles:
            return
        self._actor_roles.add(key)
        self._actor_role_created[key] = datetime.now(UTC)

    def unregister_actor_role(self, actor_id: str, role: str) -> None:
        from ._contract import validate_actor_id

        validate_actor_id(actor_id)
        key = (actor_id, role)
        if key not in self._actor_roles:
            raise RegistaError(
                ErrorCode.ACTOR_ROLE_NOT_REGISTERED,
                f"Role {role!r} not registered for actor {actor_id!r}",
            )
        self._actor_roles.discard(key)
        del self._actor_role_created[key]

    def list_actor_roles(self, actor_id: str | None = None) -> list[ActorRole]:
        result = []
        for (aid, role), created_at in self._actor_role_created.items():
            if actor_id is None or aid == actor_id:
                result.append(ActorRole(actor_id=aid, role=role, created_at=created_at))
        return sorted(result, key=lambda r: (r.actor_id, r.role))

    def register_recurrence_rule(
        self,
        workflow_name: str,
        workflow_version: int,
        work_item_type: str,
        template: dict[str, Any],
        schedule_kind: str,
        schedule_expr: str,
        *,
        timezone: str = "UTC",
        start_at: datetime | None = None,
        end_at: datetime | None = None,
        count: int | None = None,
        catchup_policy: str = "fire_once",
        created_by: str = "system",
    ) -> dict[str, Any]:
        from ._in_memory_recurrence import in_memory_register_recurrence_rule

        return in_memory_register_recurrence_rule(
            self._workflow_defs, self._recurrence_rules,
            workflow_name, workflow_version, work_item_type,
            template, schedule_kind, schedule_expr,
            timezone=timezone, start_at=start_at, end_at=end_at,
            count=count, catchup_policy=catchup_policy,
            created_by=created_by,
        )

    def list_recurrence_rules(self, status: str | None = None) -> list[dict[str, Any]]:
        from ._in_memory_recurrence import in_memory_list_recurrence_rules

        return in_memory_list_recurrence_rules(self._recurrence_rules, status)

    def due_recurrences(self, now: datetime | None = None) -> list[dict[str, Any]]:
        from ._in_memory_recurrence import in_memory_due_recurrences

        return in_memory_due_recurrences(self._recurrence_rules, now)

    def fire_recurrence(self, rule_id: uuid.UUID) -> tuple[dict[str, Any], dict[str, Any] | None]:
        from ._in_memory_recurrence import in_memory_fire_recurrence

        return in_memory_fire_recurrence(
            self._recurrence_rules,
            lambda **kw: self._create_work_item(**kw),
            rule_id,
        )

    def cancel_recurrence_rule(self, rule_id: uuid.UUID) -> None:
        from ._in_memory_recurrence import in_memory_cancel_recurrence_rule

        in_memory_cancel_recurrence_rule(self._recurrence_rules, rule_id)

    def update_recurrence_rule(
        self,
        rule_id: uuid.UUID,
        *,
        status: str | None = None,
        schedule_expr: str | None = None,
        template: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        from ._in_memory_recurrence import in_memory_update_recurrence_rule

        return in_memory_update_recurrence_rule(
            self._recurrence_rules, rule_id,
            status=status, schedule_expr=schedule_expr, template=template,
        )

    def register_project_metadata(
        self,
        *,
        display_name: str | None = None,
        owner_actor_id: str | None = None,
        created_by: str | None = None,
    ) -> ProjectCatalogEntry:
        entry = ProjectCatalogEntry(
            schema_name=self._project,
            display_name=display_name,
            owner_actor_id=owner_actor_id,
            created_by=created_by,
            created_at=datetime.now(UTC),
        )
        InMemOpsMixin._get_catalog()[self._project] = entry
        return entry

    def get_project_catalog_entry(self) -> ProjectCatalogEntry | None:
        return InMemOpsMixin._get_catalog().get(self._project)

    def set_project_owner(
        self,
        owner_actor_id: str | None,
        *,
        updated_by: str | None = None,
    ) -> ProjectCatalogEntry:
        existing = InMemOpsMixin._get_catalog().get(self._project)
        if existing is None:
            entry = ProjectCatalogEntry(
                schema_name=self._project,
                display_name=None,
                owner_actor_id=owner_actor_id,
                created_by=updated_by,
                created_at=datetime.now(UTC),
            )
        else:
            entry = ProjectCatalogEntry(
                schema_name=existing.schema_name,
                display_name=existing.display_name,
                owner_actor_id=owner_actor_id,
                created_by=updated_by,
                created_at=existing.created_at,
            )
        InMemOpsMixin._get_catalog()[self._project] = entry
        return entry

    @classmethod
    def list_projects(cls) -> list[ProjectCatalogEntry]:
        return sorted(
            cls._get_catalog().values(),
            key=lambda e: e.schema_name,
        )

    _catalog: ClassVar[dict[str, ProjectCatalogEntry]] = {}

    @classmethod
    def _get_catalog(cls) -> dict[str, ProjectCatalogEntry]:
        return cls._catalog
