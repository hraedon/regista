from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import structlog

from ._errors import ErrorCode, RegistaError
from ._in_mem_base import _InMemoryBase
from ._types import DeadLetterEntry, HookContext

log = structlog.get_logger()


class InMemHookMixin(_InMemoryBase):

    def register_validator(self, name: str, handler: Callable) -> None:
        self._validators[name] = handler

    def register_hook_handler(self, name: str, handler: Callable) -> None:
        self._hook_handlers[name] = handler

    def start_hook_consumer(self) -> None:
        self._hook_consumer_running = True

    def stop_hook_consumer(self) -> None:
        self._hook_consumer_running = False

    def _move_to_dead_letter(
        self,
        entry: dict,
        error_message: str,
    ) -> None:
        from ._in_memory_hooks import _in_memory_move_to_dead_letter

        _in_memory_move_to_dead_letter(
            entry, self._dead_letter, self._work_items,
            self._store, self._key_set, error_message,
        )

    def poll_hooks(self) -> int:
        from ._in_memory_hooks import in_memory_poll_hooks

        return in_memory_poll_hooks(
            self._hook_queue, self._hook_handlers, self._dead_letter,
            self._work_items, self._store, self._key_set,
        )

    def ensure_event_partitions(self, months_ahead: int = 3) -> list[str]:
        return []

    def claim_hooks(
        self,
        max_batch: int = 10,
        lease_seconds: int = 60,
        actor_id: str | None = None,
    ) -> list[HookContext]:
        now = datetime.now(UTC)
        lease_expires_at = now + timedelta(seconds=lease_seconds)

        pending = [
            e for e in self._hook_queue
            if e.get("status", "pending") == "pending"
            and (
                e.get("next_retry_at") is None
                or e["next_retry_at"] <= now
            )
        ][:max_batch]

        valid = []
        result = []
        for entry in pending:
            work_item_id = entry.get("work_item_id")
            if work_item_id is None:
                continue
            valid.append(entry)
            result.append(HookContext(
                hook_queue_id=entry["id"],
                event_id=entry["event_id"],
                work_item_id=work_item_id,
                hook_name=entry["hook_name"],
                transition=entry.get("transition"),
                payload=entry.get("payload"),
            ))

        for entry in valid:
            entry["status"] = "in_progress"
            entry["lease_expires_at"] = lease_expires_at
            entry["claimed_by"] = actor_id
            entry["updated_at"] = now

        return result

    def complete_hook(self, hook_queue_id: int, actor_id: str | None = None) -> None:
        entry = next(
            (e for e in self._hook_queue if e.get("id") == hook_queue_id),
            None,
        )
        if entry is None:
            raise RegistaError(
                ErrorCode.HOOK_NOT_FOUND,
                f"Hook {hook_queue_id} not found",
            )
        if entry.get("status") != "in_progress":
            raise RegistaError(
                ErrorCode.HOOK_NOT_FOUND,
                f"Hook {hook_queue_id} not found or not in progress "
                f"(status={entry.get('status')})",
            )
        if actor_id is not None and entry.get("claimed_by") != actor_id:
            raise RegistaError(
                ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER,
                f"Hook {hook_queue_id} is not claimed by {actor_id!r}",
            )
        entry["status"] = "completed"
        entry["lease_expires_at"] = None
        entry["claimed_by"] = None
        entry["updated_at"] = datetime.now(UTC)

    def fail_hook(self, hook_queue_id: int, error: str, actor_id: str | None = None) -> None:
        from ._in_memory_hooks import _in_memory_move_to_dead_letter

        entry = next(
            (e for e in self._hook_queue if e.get("id") == hook_queue_id),
            None,
        )
        if entry is None:
            raise RegistaError(
                ErrorCode.HOOK_NOT_FOUND,
                f"Hook {hook_queue_id} not found",
            )

        if actor_id is not None and entry.get("claimed_by") != actor_id:
            raise RegistaError(
                ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER,
                f"Hook {hook_queue_id} is not claimed by {actor_id!r}",
            )
        if entry.get("status") != "in_progress":
            raise RegistaError(
                ErrorCode.HOOK_NOT_FOUND,
                f"Hook {hook_queue_id} not found or not in progress "
                f"(status={entry.get('status')})",
            )

        retry_count = entry.get("retry_count", 0) + 1
        max_retries = entry.get("max_retries", 3)

        if retry_count >= max_retries:
            _in_memory_move_to_dead_letter(
                entry, self._dead_letter, self._work_items,
                self._store, self._key_set, error,
            )
        else:
            entry["retry_count"] = retry_count
            entry["status"] = "pending"
            entry["lease_expires_at"] = None
            entry["claimed_by"] = None
            entry["updated_at"] = datetime.now(UTC)

    def sweep_expired_hook_leases(self) -> int:
        now = datetime.now(UTC)
        swept = 0
        for entry in self._hook_queue:
            if (
                entry.get("status") == "in_progress"
                and entry.get("lease_expires_at") is not None
                and entry["lease_expires_at"] < now
            ):
                entry["status"] = "pending"
                entry["lease_expires_at"] = None
                entry["claimed_by"] = None
                entry["updated_at"] = now
                swept += 1
        return swept

    def refresh_hook_queue_metrics(self) -> None:
        """Emit structured log lines with hook_queue depth counts.

        The InMemory backend has no Prometheus registry, so this emits
        ``regista.maintenance.hook_queue_depth`` log lines instead.
        The maintenance thread (Plan 009) will call this after every sweep cycle.
        """
        status_counts: dict[str, int] = {}
        for entry in self._hook_queue:
            s = entry.get("status", "pending")
            status_counts[s] = status_counts.get(s, 0) + 1
        dead_count = len(self._dead_letter)
        log.info(
            "regista.maintenance.hook_queue_depth",
            project=self._project,
            pending=status_counts.get("pending", 0),
            in_progress=status_counts.get("in_progress", 0),
            completed=status_counts.get("completed", 0),
            dead_letter=dead_count,
        )

    def requeue_dead_lettered_hook(self, dead_letter_id: int) -> None:
        from ._in_memory_hooks import in_memory_requeue_dead_lettered_hook

        self._hook_id_counter = in_memory_requeue_dead_lettered_hook(
            self._dead_letter, self._hook_queue, self._hook_id_counter,
            dead_letter_id,
        )

    def list_dead_lettered_hooks(self, limit: int = 100) -> list[DeadLetterEntry]:
        from ._in_memory_hooks import in_memory_list_dead_lettered_hooks

        return in_memory_list_dead_lettered_hooks(self._dead_letter, limit=limit)

    def start_maintenance(
        self,
        *,
        sweep_interval: float = 30.0,
        recurrence_interval: float = 10.0,
        hook_poll_interval: float = 2.0,
        partition_interval: float = 3600.0,
        timestamp_interval: float = 3600.0,
        tsa_config=None,
        witness_interval: float = 30.0,
        anchor_provider=None,
        anchor_interval: float = 3600.0,
        anchor_upgrade_interval: float = 600.0,
    ) -> None:
        pass

    def stop_maintenance(self) -> None:
        pass
