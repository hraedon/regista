from __future__ import annotations

import uuid
from typing import Any

from ._api_base import _RegistaBase
from ._contract import validate_mutation_params as _validate_mutation_params
from ._types import (
    Claim,
    Link,
)


class ClaimApiMixin(_RegistaBase):

    def acquire_claim(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        ttl_seconds: int = 300,
        *,
        event_id: uuid.UUID | None = None,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
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
            actor_metadata: Optional JSONB metadata recorded on the emitted
                ``claim_acquired``/``claim_stolen`` event (e.g.
                ``model_lineage``, read by the ``adversarial_review`` gate).

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
            actor_metadata=actor_metadata,
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
        actor_metadata: dict[str, Any] | None = None,
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
            actor_metadata: Optional JSONB metadata recorded on the emitted
                ``claim_heartbeat`` event (e.g. ``model_lineage``).

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
            actor_metadata=actor_metadata,
        )

    def release_claim(
        self,
        work_item_id: uuid.UUID,
        actor_id: str,
        *,
        event_id: uuid.UUID | None = None,
        actor_kind: str = "agent",
        actor_metadata: dict[str, Any] | None = None,
    ) -> None:
        """Release a claim held by the given actor.

        Args:
            work_item_id: Target work item.
            actor_id: Must match the current claim holder.
            event_id: UUIDv4 idempotency key.
            actor_kind: Kind of actor (default "agent").
            actor_metadata: Optional JSONB metadata recorded on the emitted
                ``claim_released`` event (e.g. ``model_lineage``).

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
            actor_metadata=actor_metadata,
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
        actor_metadata: dict[str, Any] | None = None,
        *,
        event_id: uuid.UUID | None = None,
        payload: dict[str, Any] | None = None,
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
            actor_metadata=actor_metadata,
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
        actor_metadata: dict[str, Any] | None = None,
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
            actor_metadata=actor_metadata,
            event_id=event_id,
        )
        self.links.remove(
            from_work_item_id, to_work_item_id, link_type,
            actor_id, actor_kind, actor_metadata,
            event_id=event_id,
            target_project=target_project,
        )

    def list_links(
        self,
        work_item_id: uuid.UUID,
    ) -> list[Link]:
        """Return all live (non-removed) links originating from *work_item_id*.

        Links are derived from the event log: a ``link_created`` event is
        live unless a matching ``link_removed`` event exists (matched on
        ``to_work_item_id`` + ``link_type`` + ``target_project``).

        Returns:
            List of :class:`Link` objects, ordered by creation sequence.
        """
        self._require_open()
        return self.links.list(work_item_id)
