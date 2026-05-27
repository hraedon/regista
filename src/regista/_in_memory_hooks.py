from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from ._errors import ErrorCode, RegistaError
from ._types import DeadLetterEntry, HookContext


def in_memory_poll_hooks(
    hook_queue: list,
    hook_handlers: dict,
    dead_letter: dict,
    work_items: dict,
    store,
    key_set,
) -> int:
    now = datetime.now(UTC)
    for entry in hook_queue:
        if (
            entry.get("status") == "in_progress"
            and entry.get("updated_at") is not None
            and now - entry["updated_at"] > timedelta(minutes=5)
        ):
            entry["status"] = "pending"

    pending = [e for e in hook_queue if e.get("status", "pending") == "pending"]
    processed = 0
    for entry in pending:
        handler = hook_handlers.get(entry["hook_name"])
        if handler is None:
            _in_memory_move_to_dead_letter(
                entry, dead_letter, work_items, store, key_set,
                f"Handler {entry['hook_name']!r} not registered",
            )
            processed += 1
            continue

        work_item_id = entry.get("work_item_id")
        if work_item_id is None:
            _in_memory_move_to_dead_letter(
                entry, dead_letter, work_items, store, key_set,
                "work_item_id missing from payload",
            )
            processed += 1
            continue

        ctx = HookContext(
            hook_queue_id=entry["id"],
            event_id=entry["event_id"],
            work_item_id=work_item_id,
            hook_name=entry["hook_name"],
            transition=entry.get("transition"),
            payload=entry.get("payload"),
        )

        entry["status"] = "in_progress"
        entry["updated_at"] = datetime.now(UTC)

        try:
            handler(ctx)
            entry["status"] = "completed"
            processed += 1
        except Exception:
            import structlog
            structlog.get_logger().warning(
                "hooks.in_memory_handler_failed",
                exc_info=True,
                hook_name=entry.get("hook_name", "unknown"),
            )
            entry["retry_count"] = entry.get("retry_count", 0) + 1
            max_retries = entry.get("max_retries", 3)
            if entry["retry_count"] >= max_retries:
                _in_memory_move_to_dead_letter(
                    entry, dead_letter, work_items, store, key_set,
                    "handler failed",
                )
                processed += 1
            else:
                entry["status"] = "pending"

    hook_queue[:] = [
        e for e in hook_queue
        if e.get("status") not in ("completed", "dead_lettered")
    ]
    return processed


def _in_memory_move_to_dead_letter(
    entry: dict,
    dead_letter: dict,
    work_items: dict,
    store,
    key_set,
    error_message: str,
) -> None:
    entry["status"] = "dead_lettered"
    entry["error_message"] = error_message
    entry["dead_lettered_at"] = datetime.now(UTC)
    dead_letter[entry["id"]] = {
        "id": entry["id"],
        "event_id": entry["event_id"],
        "work_item_id": entry.get("work_item_id"),
        "hook_name": entry["hook_name"],
        "hook_type": entry.get("hook_type", "async"),
        "transition": entry.get("transition"),
        "payload": entry.get("payload"),
        "retry_count": entry.get("retry_count", 0),
        "max_retries": entry.get("max_retries", 3),
        "error_message": error_message,
        "dead_lettered_at": entry["dead_lettered_at"],
        "original_hook_queue_id": entry["id"],
    }
    work_item_id = entry.get("work_item_id")
    if work_item_id:
        wi = work_items.get(work_item_id)
        if wi is not None:
            from ._in_memory_claims import _in_memory_append_claim_event

            _in_memory_append_claim_event(
                store, wi, key_set, uuid.uuid4(), "hook_dead_lettered",
                {
                    "hook_name": entry["hook_name"],
                    "hook_queue_id": entry["id"],
                    "error_message": error_message,
                },
            )


def in_memory_requeue_dead_lettered_hook(
    dead_letter: dict,
    hook_queue: list,
    hook_id_counter: int,
    dead_letter_id: int,
) -> int:
    entry = dead_letter.pop(dead_letter_id, None)
    if entry is None:
        raise RegistaError(
            ErrorCode.HOOK_NOT_FOUND,
            f"Dead letter entry {dead_letter_id} not found",
        )
    max_id = max(hook_id_counter, entry.get("original_hook_queue_id", 0))
    new_counter = max_id + 1
    hook_queue.append({
        "id": entry["original_hook_queue_id"] or new_counter,
        "event_id": entry["event_id"],
        "work_item_id": entry.get("work_item_id"),
        "hook_name": entry["hook_name"],
        "hook_type": entry["hook_type"],
        "transition": entry.get("transition"),
        "payload": entry.get("payload"),
        "retry_count": 0,
        "max_retries": entry.get("max_retries", 3),
        "status": "pending",
        "updated_at": datetime.now(UTC),
    })
    return new_counter


def in_memory_list_dead_lettered_hooks(dead_letter: dict) -> list[DeadLetterEntry]:
    return [
        DeadLetterEntry(
            id=e["id"],
            event_id=e["event_id"],
            hook_name=e["hook_name"],
            hook_type=e["hook_type"],
            payload=e.get("payload"),
            retry_count=e["retry_count"],
            max_retries=e.get("max_retries", 3),
            error_message=e.get("error_message"),
            dead_lettered_at=e["dead_lettered_at"],
            original_hook_queue_id=e.get("original_hook_queue_id"),
        )
        for e in sorted(
            dead_letter.values(),
            key=lambda x: x["dead_lettered_at"],
            reverse=True,
        )
    ]
