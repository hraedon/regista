from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from ._api_base import _RegistaBase
from ._errors import ErrorCode, RegistaError
from ._types import Event

if TYPE_CHECKING:
    from ._assurance import AssuranceLevel, GateProfile
    from ._verification import VerificationResult

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
        """Verify an event's signature **and** that the row matches it.

        WI-267: a valid signature over the stored envelope is no longer
        sufficient. Every field the envelope version signs must also agree with
        the row's column of the same name, so this returns ``False`` for an
        event whose signature checks out but whose row was rewritten.

        When ``public_key`` is provided, verification uses only that key
        (no secret material needed — the independent-verification path).
        When omitted, the key is resolved from the project's key set.

        Args:
            event: The event to verify.
            public_key: Optional raw public key bytes for external
                verification. If omitted, the project's key set is used.

        Returns:
            ``True`` if the event is fully authenticated, or legacy-partial
            under the default policy. Use :meth:`verify_event_result` for the
            structured verdict, including which field disagreed.
        """
        return self.verify_event_result(event, public_key=public_key).accepted

    def verify_event_result(
        self, event: Event, *, public_key: bytes | None = None,
    ) -> VerificationResult:
        """The structured verification verdict for ``event``.

        Carries envelope version and schema validity, signature validity,
        trusted-key source, the row reconciliation result and *which* fields
        disagreed, authenticated vs unsigned fields, and a final applicability
        of ``fully_authenticated`` / ``legacy_partial`` / ``invalid`` /
        ``unverifiable``.
        """
        from ._signing import verify_event_result_with_public_key
        from ._verification import (
            DEFAULT_POLICY,
            EventRow,
            KeySetResolver,
            verify_event_strict,
        )

        if public_key is None:
            self._require_open()
            from ._v6_referents import store_referents

            # A v6 verdict needs the chain, not just the row: `key_binding`,
            # `workflow` and epoch position are facts about other events. The open
            # project is the material, and it is presented rather than fetched — this
            # is the caller's own store, handed over by the caller's own call.
            with self._mgr.transaction() as conn:
                return verify_event_strict(
                    EventRow.from_event(event),
                    keys=KeySetResolver(self._keys),
                    referents=store_referents(conn, label="open project"),
                    policy=DEFAULT_POLICY,
                )
        # A caller-supplied key carries no scheme metadata of its own; the
        # project key set is consulted for it where the project is open, so the
        # scheme is still not taken from the row (WI-267 / S2-interim).
        scheme_id: str | None = None
        try:
            scheme_id = self._keys.get_key(event.key_id).scheme
        except (RegistaError, AttributeError):
            scheme_id = None
        return verify_event_result_with_public_key(
            event, public_key, scheme_id=scheme_id,
        )

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
        self._require_open()
        return self.assurance.compute_assurance(work_item_id)

    def gate_rationale(
        self,
        work_item_id: uuid.UUID,
        *,
        profile: GateProfile | str = "relaxed",
    ) -> dict[str, Any]:
        """Compute the gate rationale for a work item.

        Explains why ``done`` was (or would be) permitted under the given
        gate profile (Plan 027 WI-2.2).

        Args:
            work_item_id: The work item to inspect.
            profile: Gate profile (``"relaxed"`` or ``"strict"``).

        Returns:
            Dict with ``profile``, ``reason``, ``assurance_level``,
            ``reviewer_lineage``, ``author_lineages``,
            ``agent_author_undeclared`` (WI-256: some agent author declared no
            model lineage, so distinctness cannot be established) and — once an
            ``adversarial_pass`` exists — ``lineage_verification`` (WI-215) and
            ``lineage_relation``. ``lineage_relation`` is the EFFECTIVE verdict
            the gate decided on: it already accounts for a delegated reviewer
            principal (WI-258) and for undeclared agent authors (WI-256), so it
            never reads ``"distinct"`` for a history that could not establish
            distinctness.
        """
        self._require_open()
        return self.assurance.gate_rationale(work_item_id, profile=profile)

    @staticmethod
    def validate_actor_metadata(
        event: Event,
        expected_schema: dict[str, Any] | None = None,
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
        actor_metadata: dict[str, Any] | None = None,
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

    def enroll_principal(
        self,
        principal_id: str,
        *,
        actor_id: str = "system",
        actor_kind: str = "system",
        actor_metadata: dict[str, Any] | None = None,
        private_key_dir: str | None = None,
        secret_backend: str | None = None,
        reuse_existing_key: bool = False,
    ) -> dict[str, Any]:
        """Provision and register an Ed25519 keypair for a principal.

        Reuses :func:`regista._provision.provision_principal` for key
        generation, custody, and registry insertion, then emits a signed
        ``principal_enrolled`` event into the audit chain. The event is
        emitted only when no ``principal_enrolled`` event already exists for
        the active key, so a re-enrollment after a prior event-append failure
        repairs the chain rather than short-circuiting forever (Plan 026
        WI-3.3); a normal re-enroll of an already-recorded principal is a
        no-op that emits no duplicate event.

        Custody is backend-aware (Plan 029): the private key is written to
        the configured secret backend (``file``, ``windows``, ``vault``,
        ``azure``), never silently to local disk unless the backend is
        ``file``. With ``secret_backend="operator"`` (or
        ``REGISTA_SECRET_BACKEND=operator``), enrollment fails loudly with
        ``SECRET_WRITE_EXTERNAL`` — the operator must generate and custody
        the key out-of-band and register the public key via
        ``principal register``.

        Args:
            principal_id: Identifier for the principal.
            actor_id: Actor performing the enrollment (default ``"system"``).
            actor_kind: ``"agent"`` | ``"human"`` | ``"system"``.
            actor_metadata: Optional JSONB metadata.
            private_key_dir: Optional directory for the private key file.
                Defaults to a ``principals`` subdirectory next to the key file.
                Meaningful only for the ``file`` backend.
            secret_backend: Override the secret backend for custody
                (``file``/``windows``/``vault``/``azure``/``operator``).
                Defaults to ``REGISTA_SECRET_BACKEND`` or ``file``.
            reuse_existing_key: Register the public key already present in the
                shared signing key file for this principal instead of minting
                a new keypair. Use this when the same principal must act in a
                second project that shares the key file — minting a second
                keypair there would leave the first project signing with a key
                it never registered (WI-223), so that is refused.

        Returns:
            Dict from :class:`regista._provision.PrincipalProvisionResult`.

        Raises:
            RegistaError: If ``principal_id`` is invalid, key custody fails,
                or the backend is ``operator`` (``SECRET_WRITE_EXTERNAL``).
        """
        from ._observability import OpTimer
        from ._principal_keys import principal_entity_id
        from ._provision import provision_principal

        self._require_open()

        timer = OpTimer(self.project, "enroll_principal")
        result = provision_principal(
            self._mgr.dsn,
            self._project,
            principal_id,
            hmac_key_path=self._hmac_key_path,
            private_key_dir=private_key_dir,
            secret_backend=secret_backend,
            reuse_existing_key=reuse_existing_key,
        )

        existing = self.read_principal_enrollment_events(
            principal_id=principal_id, limit=100
        )
        already_recorded = any(
            (e.payload or {}).get("key_id") == result.key_id for e in existing
        )
        if not already_recorded:
            entity_id = principal_entity_id(principal_id)
            payload = {
                "principal_id": principal_id,
                "key_id": result.key_id,
                "fingerprint": result.fingerprint,
                "scheme": result.scheme,
            }
            self.append_event(
                entity_id,
                actor_id,
                actor_kind,
                actor_metadata,
                transition="principal_enrolled",
                payload=payload,
                entity_kind="principal",
            )

        timer.log(
            "noop" if already_recorded else "ok",
            principal_id=principal_id,
            key_id=result.key_id,
        )
        return result.to_dict()

    def read_principal_enrollment_events(
        self,
        *,
        principal_id: str | None = None,
        limit: int = 100,
    ) -> list[Event]:
        """Read principal-enrollment events from the project.

        Args:
            principal_id: Filter to a specific principal. If omitted,
                returns all principal enrollment events (most recent first).
            limit: Maximum events to return.

        Returns:
            List of ``Event`` objects with ``entity_kind="principal"``.
        """
        self._require_open()
        from psycopg.sql import SQL

        from ._events import _EVENT_FIELDS, _row_to_event
        from ._principal_keys import principal_entity_id

        with self._mgr.transaction() as conn:
            if principal_id is not None:
                entity_id = principal_entity_id(principal_id)
                rows = conn.execute(
                    SQL(
                        f"SELECT {_EVENT_FIELDS} FROM events "
                        "WHERE entity_kind = 'principal' AND entity_id = %s "
                        "ORDER BY event_seq ASC LIMIT %s"
                    ),
                    [entity_id, limit],
                ).fetchall()
            else:
                rows = conn.execute(
                    SQL(
                        f"SELECT {_EVENT_FIELDS} FROM events "
                        "WHERE entity_kind = 'principal' "
                        "ORDER BY timestamp DESC, event_seq DESC LIMIT %s"
                    ),
                    [limit],
                ).fetchall()
            return [_row_to_event(r) for r in rows]
