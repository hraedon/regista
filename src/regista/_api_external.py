from __future__ import annotations

import uuid
from datetime import datetime

import structlog

from ._api_base import _RegistaBase
from ._types import (
    ProjectCatalogEntry,
)

log = structlog.get_logger()


class ExternalApiMixin(_RegistaBase):

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
                signatures are verified against this key (BC-297), and the key
                is enrolled into the anchored principal-keys registry under the
                ``witness:<witness_id>`` principal so downstream verifiers can
                treat it as a trust root (WI-238).
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

    def rotate_witness_key(
        self,
        witness_id: uuid.UUID,
        new_public_key: bytes,
    ) -> dict:
        """Rotate an Ed25519 witness's pinned public key.

        Updates the witness registration's ``public_key`` and rotates the
        anchored principal-keys entry for ``witness:<witness_id>`` (the old
        key is superseded, the new key becomes active) in a single
        transaction. Requires the witness to use ``key_scheme='ed25519'``.

        Returns:
            The new active principal-key entry as a dict.
        """
        return self.witnesses.rotate_key(witness_id, new_public_key)

    def enrolled_witness_key(self, witness_id: uuid.UUID) -> dict | None:
        """Return the active anchored principal-key entry for a witness.

        Looks up the ``witness:<witness_id>`` principal in the anchored
        principal-keys registry (the trust root downstream verifiers
        consult). Returns ``None`` when the witness has no enrolled key.
        """
        return self.witnesses.enrolled_key(witness_id)

    def unregister_witness(self, witness_id: uuid.UUID) -> None:
        """Remove a witness. Pending receipts are abandoned.

        Any anchored principal key enrolled for ``witness:<witness_id>`` is
        revoked (it remains in the registry for historical verification).
        """
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

    def register_project_metadata(
        self,
        *,
        display_name: str | None = None,
        owner_actor_id: str | None = None,
        created_by: str | None = None,
    ) -> ProjectCatalogEntry:
        """Insert or update this project's row in the ``public.projects`` catalog.

        Idempotent — uses ``ON CONFLICT DO UPDATE``.  This is the write path
        for Plan 012 ownership: call after ``create_project`` or to update
        an existing project's display name / owner.

        Args:
            display_name: Human-friendly project name (nullable).
            owner_actor_id: The owner's durable actor_id (nullable until
                assigned — surfaced as "unassigned" in the UI).
            created_by: Who created or last updated this entry.

        Returns:
            The resulting :class:`ProjectCatalogEntry`.
        """
        self._require_open()
        from ._projects import register_project

        with self._mgr.connect() as conn:
            entry = register_project(
                conn,
                schema_name=self._project,
                display_name=display_name,
                owner_actor_id=owner_actor_id,
                created_by=created_by,
            )
            conn.commit()
        log.info(
            "regista.project_catalog_registered",
            project=self._project,
            display_name=display_name,
            owner=owner_actor_id,
        )
        return entry

    def get_project_catalog_entry(self) -> ProjectCatalogEntry | None:
        """Return this project's catalog row, or ``None`` if not registered."""
        self._require_open()
        from ._projects import get_catalog_project

        with self._mgr.connect() as conn:
            return get_catalog_project(conn, self._project)

    def set_project_owner(
        self,
        owner_actor_id: str | None,
        *,
        updated_by: str | None = None,
    ) -> ProjectCatalogEntry:
        """Set or clear the owner for this project.

        Pass ``None`` to clear (set to "unassigned").  Returns the updated
        entry, or ``None`` if the project is not in the catalog.

        Args:
            owner_actor_id: The new owner's actor_id, or ``None`` to clear.
            updated_by: Who made this change (recorded in ``created_by``).

        Returns:
            The updated :class:`ProjectCatalogEntry`, or ``None``.
        """
        self._require_open()
        from ._projects import set_catalog_owner

        with self._mgr.connect() as conn:
            entry = set_catalog_owner(
                conn,
                schema_name=self._project,
                owner_actor_id=owner_actor_id,
                updated_by=updated_by,
            )
            conn.commit()
        log.info(
            "regista.project_owner_set",
            project=self._project,
            owner=owner_actor_id,
            updated_by=updated_by,
        )
        return entry

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
