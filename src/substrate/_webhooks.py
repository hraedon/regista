from __future__ import annotations

import uuid

from ._connection import ConnectionManager


def register_webhook(
    mgr: ConnectionManager,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    transitions: list[str] | None = None,
    work_item_types: list[str] | None = None,
    workflows: list[str] | None = None,
    max_failures: int = 10,
    sign_secret: bytes | None = None,
    project: str = "",
) -> dict:
    from ._witness import register_witness

    event_filter = {}
    if transitions:
        event_filter["transitions"] = transitions
    if work_item_types:
        event_filter["work_item_types"] = work_item_types
    if workflows:
        event_filter["workflows"] = workflows

    witness_id = register_witness(
        mgr,
        project,
        url,
        headers=headers,
        event_filter=event_filter or None,
        max_failures=max_failures,
        max_retries=1,
        mode="push",
        sign_secret=sign_secret,
    )
    return {"webhook_id": witness_id, "url": url, "status": "active"}


def list_webhooks(
    mgr: ConnectionManager,
    status: str | None = None,
) -> list[dict]:
    from ._witness import list_witnesses

    rows = list_witnesses(mgr, status=status, mode="push")
    results = []
    for row in rows:
        ef = row.get("event_filter") or {}
        results.append({
            "webhook_id": row["witness_id"],
            "url": row["url"],
            "headers": row.get("headers") or {},
            "transitions": ef.get("transitions", []),
            "work_item_types": ef.get("work_item_types", []),
            "workflows": ef.get("workflows", []),
            "status": row["status"],
            "failure_count": row.get("consecutive_failures", 0),
            "max_failures": row.get("max_failures", 10),
            "created_at": row.get("created_at"),
        })
    return results


def unregister_webhook(mgr: ConnectionManager, webhook_id: uuid.UUID) -> None:
    from ._witness import unregister_witness

    unregister_witness(mgr, project="", witness_id=webhook_id)


def pause_webhook(mgr: ConnectionManager, webhook_id: uuid.UUID) -> None:
    from ._witness import pause_witness

    pause_witness(mgr, project="", witness_id=webhook_id)


def resume_webhook(mgr: ConnectionManager, webhook_id: uuid.UUID) -> None:
    from ._witness import reactivate_witness

    reactivate_witness(mgr, project="", witness_id=webhook_id)
