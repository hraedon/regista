from __future__ import annotations

import json
import uuid
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse

import psycopg
import psycopg.types.json
import structlog
from psycopg.sql import SQL

from ._connection import ConnectionManager
from ._errors import ErrorCode, SubstrateError
from ._types import Event

log = structlog.get_logger()

_WEBHOOK_FIELDS = (
    "webhook_id, url, headers, transitions, work_item_types, workflows, "
    "status, failure_count, max_failures, created_at"
)


def _row_to_webhook(row: dict) -> dict:
    return {
        "webhook_id": row["webhook_id"],
        "url": row["url"],
        "headers": row["headers"] or {},
        "transitions": row["transitions"] or [],
        "work_item_types": row["work_item_types"] or [],
        "workflows": row["workflows"] or [],
        "status": row["status"],
        "failure_count": row["failure_count"],
        "max_failures": row["max_failures"],
        "created_at": row["created_at"],
    }


def register_webhook(
    mgr: ConnectionManager,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    transitions: list[str] | None = None,
    work_item_types: list[str] | None = None,
    workflows: list[str] | None = None,
    max_failures: int = 10,
) -> dict:
    if not url.startswith(("http://", "https://")):
        raise SubstrateError(
            ErrorCode.INVALID_ARGUMENT,
            f"Webhook URL must start with http:// or https://, got {url!r}",
        )
    if max_failures < 1:
        raise SubstrateError(
            ErrorCode.INVALID_ARGUMENT,
            f"max_failures must be >= 1, got {max_failures}",
        )

    webhook_id = uuid.uuid4()
    with mgr.transaction() as conn:
        conn.execute(
            SQL(
                "INSERT INTO webhook_registrations "
                "(webhook_id, url, headers, transitions, work_item_types, workflows, max_failures) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)"
            ),
            [
                webhook_id,
                url,
                psycopg.types.json.Jsonb(headers or {}),
                transitions,
                work_item_types,
                workflows,
                max_failures,
            ],
        )

    log.info("webhook.registered", webhook_id=str(webhook_id), url=url)
    return {"webhook_id": webhook_id, "url": url, "status": "active"}


def list_webhooks(
    mgr: ConnectionManager,
    status: str | None = None,
) -> list[dict]:
    with mgr.transaction() as conn:
        if status:
            rows = conn.execute(
                SQL(
                    f"SELECT {_WEBHOOK_FIELDS} FROM webhook_registrations "
                    "WHERE status = %s ORDER BY created_at"
                ),
                [status],
            ).fetchall()
        else:
            rows = conn.execute(
                SQL(f"SELECT {_WEBHOOK_FIELDS} FROM webhook_registrations ORDER BY created_at"),
            ).fetchall()
    return [_row_to_webhook(r) for r in rows]


def unregister_webhook(mgr: ConnectionManager, webhook_id: uuid.UUID) -> None:
    with mgr.transaction() as conn:
        result = conn.execute(
            SQL("DELETE FROM webhook_registrations WHERE webhook_id = %s"),
            [webhook_id],
        )
        if result.rowcount == 0:
            raise SubstrateError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"Webhook {webhook_id} not found",
            )


def pause_webhook(mgr: ConnectionManager, webhook_id: uuid.UUID) -> None:
    with mgr.transaction() as conn:
        result = conn.execute(
            SQL("UPDATE webhook_registrations SET status = 'paused' WHERE webhook_id = %s"),
            [webhook_id],
        )
        if result.rowcount == 0:
            raise SubstrateError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"Webhook {webhook_id} not found",
            )


def resume_webhook(mgr: ConnectionManager, webhook_id: uuid.UUID) -> None:
    with mgr.transaction() as conn:
        result = conn.execute(
            SQL("UPDATE webhook_registrations SET status = 'active' WHERE webhook_id = %s"),
            [webhook_id],
        )
        if result.rowcount == 0:
            raise SubstrateError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"Webhook {webhook_id} not found",
            )


def _event_matches_webhook(event: dict, webhook: dict) -> bool:
    transitions = webhook.get("transitions") or []
    if transitions and event.get("transition") not in transitions:
        return False
    workflows = webhook.get("workflows") or []
    if workflows and event.get("workflow_name") not in workflows:
        return False
    work_item_types = webhook.get("work_item_types") or []
    if work_item_types:
        payload = event.get("payload") or {}
        if payload.get("work_item_type") not in work_item_types:
            return False
    return True


def deliver_webhooks(mgr: ConnectionManager, event: Event) -> int:
    event_dict = event.to_dict()
    with mgr.transaction() as conn:
        webhooks = conn.execute(
            SQL(
                f"SELECT {_WEBHOOK_FIELDS} FROM webhook_registrations WHERE status = 'active'"
            ),
        ).fetchall()

    delivered = 0
    for wh_row in webhooks:
        webhook = _row_to_webhook(wh_row)
        if not _event_matches_webhook(event_dict, webhook):
            continue
        try:
            _post_webhook(webhook, event_dict)
            delivered += 1
            if webhook["failure_count"] > 0:
                with mgr.transaction() as conn:
                    conn.execute(
                        SQL(
                            "UPDATE webhook_registrations SET failure_count = 0 "
                            "WHERE webhook_id = %s"
                        ),
                        [webhook["webhook_id"]],
                    )
        except Exception as exc:
            new_count = webhook["failure_count"] + 1
            new_status = "paused" if new_count >= webhook["max_failures"] else "active"
            with mgr.transaction() as conn:
                conn.execute(
                    SQL(
                        "UPDATE webhook_registrations SET failure_count = %s, status = %s "
                        "WHERE webhook_id = %s"
                    ),
                    [new_count, new_status, webhook["webhook_id"]],
                )
            log.warning(
                "webhook.delivery_failed",
                webhook_id=str(webhook["webhook_id"]),
                url=webhook["url"],
                failure_count=new_count,
                max_failures=webhook["max_failures"],
                auto_paused=new_status == "paused",
                error=str(exc)[:200],
            )

    return delivered


def _post_webhook(webhook: dict, event: dict) -> None:
    url = webhook["url"]
    parsed = urlparse(url)
    headers = {"Content-Type": "application/json"}
    headers.update(webhook.get("headers") or {})

    body = json.dumps(event, default=str).encode()

    if parsed.scheme == "https":
        conn = HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=10)
    else:
        conn = HTTPConnection(parsed.hostname, parsed.port or 80, timeout=10)

    try:
        conn.request("POST", parsed.path or "/", body=body, headers=headers)
        resp = conn.getresponse()
        if resp.status >= 400:
            log.warning(
                "webhook.http_error",
                url=url,
                status=resp.status,
            )
    finally:
        conn.close()
