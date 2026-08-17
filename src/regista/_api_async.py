from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any

import structlog

from ._api_base import _RegistaBase
from ._errors import RegistaError
from ._observability import OpTimer
from ._types import (
    ActorRole,
    DeadLetterEntry,
    HookContext,
)

log = structlog.get_logger()


class AsyncApiMixin(_RegistaBase):

    def register_validator(self, name: str, handler: Callable[..., Any]) -> None:
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
        self._validators[name] = handler

    def register_hook_handler(self, name: str, handler: Callable[..., Any]) -> None:
        """Register an async hook handler dispatched via the hook queue.

        Args:
            name: Must match a hook name listed in a workflow transition's ``hooks``.
            handler: ``Callable[[HookContext], None]``.
        """
        self._hook_handlers[name] = handler
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
        witness_interval: float = 30.0,
    ) -> None:
        """Start the background maintenance thread.

        The maintenance thread periodically sweeps expired claims and hook
        leases, fires due recurrence rules, refreshes hook queue metrics, and
        delivers pending witness receipts.
        It also starts the hook consumer if not already running.

        Args:
            sweep_interval: Seconds between maintenance cycles (default 30).
            recurrence_interval: Seconds between recurrence checks (default 10).
            hook_poll_interval: Hook consumer poll interval (default 2).
            partition_interval: Deprecated; kept for API compatibility.
            witness_interval: Seconds between witness receipt delivery cycles (default 30).
        """
        from ._maintenance import MaintenanceThread

        if self._maintenance_thread is not None and self._maintenance_thread.is_running:
            return
        self._maintenance_thread = MaintenanceThread(
            self,
            sweep_interval=sweep_interval,
            recurrence_interval=recurrence_interval,
            hook_poll_interval=hook_poll_interval,
            partition_interval=partition_interval,
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
        actor_id: str | None = None,
    ) -> list[HookContext]:
        """Claim a batch of pending hooks for external processing.

        Marks claimed rows ``in_progress`` and sets ``lease_expires_at``.
        If the caller crashes without completing or failing the hook, the
        lease expires and ``sweep_expired_hook_leases`` requeues the row.

        Args:
            max_batch: Maximum number of hooks to claim (default 10).
            lease_seconds: Lease duration in seconds (default 60).
            actor_id: Optional actor identity stored as ``claimed_by`` on
                each claimed row.  When provided, subsequent
                ``complete_hook`` / ``fail_hook`` calls must pass the same
                ``actor_id`` or they will be rejected.

        Returns:
            List of ``HookContext`` objects describing each claimed hook.
        """
        return self.hooks.claim(max_batch, lease_seconds, actor_id=actor_id)

    def complete_hook(self, hook_queue_id: int, actor_id: str | None = None) -> None:
        """Mark a previously claimed hook as successfully completed.

        Args:
            hook_queue_id: The ``hook_queue_id`` from ``claim_hooks``.
            actor_id: When provided, the hook must have been claimed by
                this actor (``claimed_by`` column).  Mismatch raises
                ``HOOK_NOT_CLAIMED_BY_CALLER``.  ``None`` skips the check
                (backward compatible).

        Raises:
            RegistaError: ``HOOK_NOT_FOUND`` if the row does not exist.
                ``HOOK_NOT_CLAIMED_BY_CALLER`` if ``actor_id`` does not
                match the claim owner.
        """
        self.hooks.complete(hook_queue_id, actor_id=actor_id)

    def fail_hook(self, hook_queue_id: int, error: str, actor_id: str | None = None) -> None:
        """Record a hook processing failure.

        Increments ``retry_count``. If below ``max_retries``, requeues the
        hook to ``pending`` with exponential backoff. If exhausted, moves the
        row to ``hook_dead_letter`` and emits a ``hook_dead_lettered`` event.

        Args:
            hook_queue_id: The ``hook_queue_id`` from ``claim_hooks``.
            error: Human-readable error description.
            actor_id: When provided, the hook must have been claimed by
                this actor (``claimed_by`` column).  Mismatch raises
                ``HOOK_NOT_CLAIMED_BY_CALLER``.  ``None`` skips the check
                (backward compatible).

        Raises:
            RegistaError: ``HOOK_NOT_FOUND`` if the row does not exist.
                ``HOOK_NOT_CLAIMED_BY_CALLER`` if ``actor_id`` does not
                match the claim owner.
        """
        self.hooks.fail(hook_queue_id, error, actor_id=actor_id)

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
        return self.recurrence.register_rule(
            workflow_name, workflow_version, work_item_type, template,
            schedule_kind, schedule_expr,
            timezone=timezone, start_at=start_at, end_at=end_at,
            count=count, catchup_policy=catchup_policy, created_by=created_by,
        )

    def list_recurrence_rules(self, status: str | None = None) -> list[dict[str, Any]]:
        return self.recurrence.list_rules(status=status)

    def due_recurrences(self, now: datetime | None = None) -> list[dict[str, Any]]:
        return self.recurrence.due(now=now)

    def fire_recurrence(self, rule_id: uuid.UUID) -> tuple[dict[str, Any], dict[str, Any] | None]:
        return self.recurrence.fire(rule_id)

    def cancel_recurrence_rule(self, rule_id: uuid.UUID) -> None:
        self.recurrence.cancel_rule(rule_id)

    def update_recurrence_rule(
        self,
        rule_id: uuid.UUID,
        *,
        status: str | None = None,
        schedule_expr: str | None = None,
        template: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return self.recurrence.update_rule(
            rule_id,
            status=status, schedule_expr=schedule_expr, template=template,
        )
