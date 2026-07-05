from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from ._api_base import _RegistaBase
from ._errors import ErrorCode, RegistaError
from ._types import Event

if TYPE_CHECKING:
    from ._assurance import AssuranceLevel, GateProfile

_KNOWN_SPEC_SCHEMA_VERSIONS: frozenset[str] = frozenset()


class MetaApiMixin(_RegistaBase):

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

    def verify_event_principal_binding(
        self, event: Event,
    ) -> dict[str, object]:
        """Verify an event's signature against the principal key registry.

        Looks up the active public key for the event's ``actor_id`` in the
        principal_keys registry, verifies the signature under that key, and
        confirms the actor↔signer binding. This is the non-repudiation
        verification path (Plan 026 WI-1.2).

        Args:
            event: The event to verify.

        Returns:
            Dict with ``verified`` (bool), ``principal_id`` (str|None),
            ``key_id`` (str|None), and ``error`` (str|None).
        """
        from ._signing import verify_event_with_principal_binding

        self._require_open()
        result = verify_event_with_principal_binding(event, self._mgr)
        return {
            "verified": result.verified,
            "principal_id": result.principal_id,
            "key_id": result.key_id,
            "error": result.error,
        }

    def compute_assurance(self, work_item_id: uuid.UUID) -> AssuranceLevel:
        """Compute the assurance level for a work item from its event log.

        The assurance level is a pure view over the signed event history —
        it is computed, never stored, so it can never disagree with the
        record (Plan 027 WI-1.2).

        Args:
            work_item_id: The work item to inspect.

        Returns:
            The :class:`AssuranceLevel` derived from the event log.
        """
        from ._assurance import compute_assurance_level

        self._require_open()
        events = self.read_events(work_item_id=work_item_id, limit=10000)
        return compute_assurance_level(events)

    def gate_rationale(
        self,
        work_item_id: uuid.UUID,
        *,
        profile: GateProfile | str = "relaxed",
    ) -> dict:
        """Compute the gate rationale for a work item.

        Explains why ``done`` was (or would be) permitted under the given
        gate profile (Plan 027 WI-2.2).

        Args:
            work_item_id: The work item to inspect.
            profile: Gate profile (``"relaxed"`` or ``"strict"``).

        Returns:
            Dict with ``profile``, ``reason``, ``assurance_level``,
            ``reviewer_lineage``, and ``author_lineages``.
        """
        from ._assurance import GateProfile
        from ._assurance import gate_rationale as _gate_rationale

        self._require_open()
        if isinstance(profile, str):
            profile = GateProfile(profile)
        events = self.read_events(work_item_id=work_item_id, limit=10000)
        return _gate_rationale(events, profile)

    @staticmethod
    def validate_actor_metadata(
        event: Event,
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

    def sign_spec(
        self,
        spec_yaml: str,
        spec_md_hash: str,
        spec_schema_version: str,
        actor_id: str,
        *,
        actor_kind: str = "system",
        actor_metadata: dict | None = None,
        spec_id: uuid.UUID | None = None,
        known_spec_schema_versions: frozenset[str] | None = None,
    ) -> Event:
        """Sign a ``spec.yaml`` into a project as a founding artifact.

        The spec is stored as a signed event with ``entity_kind="spec"``
        so the audit chain runs spec -> work -> review -> done. Regista
        does not parse or interpret the spec; it stores and signs it
        (Plan 025 WI-4.3).

        An unrecognized ``spec_schema_version`` is a named, non-fatal
        state: the event is stored, a warning is logged, but no error
        is raised. The caller decides whether to treat the warning as
        blocking.

        Args:
            spec_yaml: The spec.yaml content as a string.
            spec_md_hash: Hex hash of the companion spec.md.
            spec_schema_version: Declared version of the spec schema
                (owned by socratic-specification, not regista).
            actor_id: Authenticated actor signing the spec.
            actor_kind: ``"agent"`` | ``"human"`` | ``"system"``.
            actor_metadata: Optional JSONB metadata.
            spec_id: Optional UUID for the spec entity. If omitted, a
                random UUIDv4 is generated.
            known_spec_schema_versions: Optional override for the known
                versions set. If the provided ``spec_schema_version``
                is not in this set, a warning is logged. Defaults to
                an empty set (all versions flagged as unrecognized).

        Returns:
            The signed ``Event``.

        Raises:
            RegistaError: ``INVALID_ARGUMENT`` if ``spec_yaml`` is empty
                or ``spec_schema_version`` is empty.
        """
        import structlog

        from ._observability import OpTimer

        log = structlog.get_logger()

        if not spec_yaml:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "spec_yaml must not be empty",
            )
        if not spec_schema_version:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "spec_schema_version must not be empty",
            )
        if not spec_md_hash:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "spec_md_hash must not be empty",
            )

        if spec_id is None:
            spec_id = uuid.uuid4()

        known = known_spec_schema_versions
        if known is None:
            known = _KNOWN_SPEC_SCHEMA_VERSIONS

        if spec_schema_version not in known:
            log.warning(
                "spec.schema_version_unknown",
                spec_schema_version=spec_schema_version,
                spec_id=str(spec_id),
            )

        payload = {
            "spec_yaml": spec_yaml,
            "spec_md_hash": spec_md_hash,
            "spec_schema_version": spec_schema_version,
        }

        timer = OpTimer(self.project, "sign_spec")
        evt = self.append_event(
            spec_id,
            actor_id,
            actor_kind,
            actor_metadata,
            transition="spec_signed",
            payload=payload,
            entity_kind="spec",
        )
        timer.log("ok", spec_id=str(spec_id))
        return evt

    def read_spec_events(
        self,
        *,
        spec_id: uuid.UUID | None = None,
        limit: int = 100,
    ) -> list[Event]:
        """Read spec-entity events from the project.

        Args:
            spec_id: Filter to a specific spec entity. If omitted,
                returns all spec events (most recent first).
            limit: Maximum events to return.

        Returns:
            List of ``Event`` objects with ``entity_kind="spec"``.
        """
        self._require_open()
        from psycopg.sql import SQL

        from ._events import _EVENT_FIELDS, _row_to_event

        with self._mgr.transaction() as conn:
            if spec_id is not None:
                rows = conn.execute(
                    SQL(
                        f"SELECT {_EVENT_FIELDS} FROM events "
                        "WHERE entity_kind = 'spec' AND entity_id = %s "
                        "ORDER BY event_seq ASC LIMIT %s"
                    ),
                    [spec_id, limit],
                ).fetchall()
            else:
                rows = conn.execute(
                    SQL(
                        f"SELECT {_EVENT_FIELDS} FROM events "
                        "WHERE entity_kind = 'spec' "
                        "ORDER BY timestamp DESC, event_seq DESC LIMIT %s"
                    ),
                    [limit],
                ).fetchall()
            return [_row_to_event(r) for r in rows]
