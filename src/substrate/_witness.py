from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import psycopg
import structlog
from psycopg.sql import SQL

from ._connection import ConnectionManager
from ._errors import ErrorCode, SubstrateError

log = structlog.get_logger()


def _validate_url(url: str) -> None:
    if not url or not url.startswith(("http://", "https://")):
        raise SubstrateError(
            ErrorCode.INVALID_ARGUMENT,
            f"witness url must start with http:// or https://, got: {url!r}",
        )
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if not parsed.hostname:
        raise SubstrateError(
            ErrorCode.INVALID_ARGUMENT,
            f"witness url must have a valid hostname, got: {url!r}",
        )


def _validate_event_filter(event_filter: dict | None) -> dict | None:
    if event_filter is None:
        return None
    if not isinstance(event_filter, dict):
        raise SubstrateError(
            ErrorCode.INVALID_ARGUMENT,
            "event_filter must be a dict",
        )
    allowed_keys = {"transitions", "work_item_types", "workflows"}
    for key in event_filter:
        if key not in allowed_keys:
            raise SubstrateError(
                ErrorCode.INVALID_ARGUMENT,
                f"event_filter key {key!r} not allowed; allowed: {sorted(allowed_keys)}",
            )
        val = event_filter[key]
        if not isinstance(val, list) or not all(isinstance(v, str) for v in val):
            raise SubstrateError(
                ErrorCode.INVALID_ARGUMENT,
                f"event_filter[{key!r}] must be a list of strings",
            )
    return event_filter


def event_matches_filter(event_dict: dict, event_filter: dict | None) -> bool:
    if event_filter is None:
        return True
    transitions = event_filter.get("transitions")
    if transitions is not None:
        evt_transition = event_dict.get("transition")
        if evt_transition is None or evt_transition not in transitions:
            return False
    work_item_types = event_filter.get("work_item_types")
    if work_item_types is not None:
        evt_type = event_dict.get("work_item_type")
        if evt_type is None or evt_type not in work_item_types:
            return False
    workflows = event_filter.get("workflows")
    if workflows is not None:
        evt_workflow = event_dict.get("workflow_name")
        if evt_workflow is None or evt_workflow not in workflows:
            return False
    return True


def register_witness(
    mgr: ConnectionManager,
    project: str,
    url: str,
    headers: dict[str, str] | None = None,
    event_filter: dict | None = None,
    max_failures: int = 10,
    max_retries: int = 3,
    *,
    mode: str = "witness",
    sign_secret: bytes | None = None,
) -> uuid.UUID:
    _validate_url(url)
    event_filter = _validate_event_filter(event_filter)
    if mode not in ("witness", "push"):
        raise SubstrateError(
            ErrorCode.INVALID_ARGUMENT,
            f"mode must be 'witness' or 'push', got {mode!r}",
        )
    if max_failures < 1:
        raise SubstrateError(
            ErrorCode.INVALID_ARGUMENT,
            f"max_failures must be >= 1, got {max_failures}",
        )
    if max_retries < 1:
        raise SubstrateError(
            ErrorCode.INVALID_ARGUMENT,
            f"max_retries must be >= 1, got {max_retries}",
        )
    witness_id = uuid.uuid4()
    with mgr.transaction() as conn:
        conn.execute(
            SQL(
                "INSERT INTO witness_registrations "
                "(witness_id, url, headers, event_filter, "
                "max_failures, max_retries, mode, sign_secret) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
            ),
            [
                witness_id,
                url,
                psycopg.types.json.Jsonb(headers) if headers is not None else None,
                psycopg.types.json.Jsonb(event_filter) if event_filter is not None else None,
                max_failures,
                max_retries,
                mode,
                sign_secret,
            ],
        )
    log.info(
        "witness.registered",
        project=project,
        witness_id=str(witness_id),
        url=url,
        mode=mode,
    )
    return witness_id


def unregister_witness(
    mgr: ConnectionManager,
    project: str,
    witness_id: uuid.UUID,
) -> None:
    with mgr.transaction() as conn:
        conn.execute(
            SQL("DELETE FROM witness_receipts WHERE witness_id = %s"),
            [witness_id],
        )
        result = conn.execute(
            SQL("DELETE FROM witness_registrations WHERE witness_id = %s"),
            [witness_id],
        )
        if result.rowcount == 0:
            raise SubstrateError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"witness {witness_id} not found",
            )
    log.info("witness.unregistered", project=project, witness_id=str(witness_id))


def pause_witness(
    mgr: ConnectionManager,
    project: str,
    witness_id: uuid.UUID,
) -> None:
    with mgr.transaction() as conn:
        result = conn.execute(
            SQL(
                "UPDATE witness_registrations SET status = 'paused', updated_at = now() "
                "WHERE witness_id = %s"
            ),
            [witness_id],
        )
        if result.rowcount == 0:
            raise SubstrateError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"witness {witness_id} not found",
            )
    log.info("witness.paused", project=project, witness_id=str(witness_id))


def reactivate_witness(
    mgr: ConnectionManager,
    project: str,
    witness_id: uuid.UUID,
) -> None:
    with mgr.transaction() as conn:
        result = conn.execute(
            SQL(
                "UPDATE witness_registrations "
                "SET status = 'active', consecutive_failures = 0, updated_at = now() "
                "WHERE witness_id = %s"
            ),
            [witness_id],
        )
        if result.rowcount == 0:
            raise SubstrateError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"witness {witness_id} not found",
            )
    log.info("witness.reactivated", project=project, witness_id=str(witness_id))


def list_witnesses(
    mgr: ConnectionManager,
    status: str | None = None,
    mode: str | None = None,
) -> list[dict]:
    clauses: list[str] = []
    params: list = []
    if status is not None:
        clauses.append("status = %s")
        params.append(status)
    if mode is not None:
        clauses.append("mode = %s")
        params.append(mode)
    where = " AND ".join(clauses) if clauses else "TRUE"
    with mgr.connect() as conn:
        rows = conn.execute(
            SQL(
                "SELECT witness_id, url, headers, event_filter, status, "
                "max_failures, consecutive_failures, max_retries, mode, sign_secret, "
                "last_success_at, last_failure_at, created_at, updated_at "
                f"FROM witness_registrations WHERE {where} ORDER BY created_at"
            ),
            params,
        ).fetchall()
    results = []
    for row in rows:
        d = dict(row)
        d["witness_id"] = str(d["witness_id"])
        d.pop("sign_secret", None)
        for key in ("last_success_at", "last_failure_at", "created_at", "updated_at"):
            if d.get(key) is not None:
                d[key] = d[key].isoformat()
        results.append(d)
    return results


def create_receipts(
    mgr: ConnectionManager,
    event_dict: dict,
) -> int:
    try:
        with mgr.connect() as conn:
            rows = conn.execute(
                SQL(
                    "SELECT witness_id, event_filter FROM witness_registrations "
                    "WHERE status = 'active'"
                ),
            ).fetchall()
    except psycopg.errors.UndefinedTable:
        return 0
    if not rows:
        return 0
    created = 0
    try:
        with mgr.transaction() as conn:
            for row in rows:
                witness_id = row["witness_id"]
                event_filter = row["event_filter"]
                if not event_matches_filter(event_dict, event_filter):
                    continue
                receipt_id = uuid.uuid4()
                try:
                    conn.execute(
                        SQL(
                            "INSERT INTO witness_receipts "
                            "(receipt_id, witness_id, event_id) VALUES (%s, %s, %s)"
                        ),
                        [
                            receipt_id,
                            witness_id,
                            uuid.UUID(event_dict["event_id"]),
                        ],
                    )
                    created += 1
                except psycopg.errors.UniqueViolation:
                    pass
    except psycopg.errors.UndefinedTable:
        return 0
    return created


def list_witness_receipts(
    mgr: ConnectionManager,
    event_id: uuid.UUID | None = None,
    witness_id: uuid.UUID | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict]:
    clauses: list[str] = []
    params: list = []
    if event_id is not None:
        clauses.append("event_id = %s")
        params.append(event_id)
    if witness_id is not None:
        clauses.append("witness_id = %s")
        params.append(witness_id)
    if status is not None:
        clauses.append("status = %s")
        params.append(status)
    where = " AND ".join(clauses) if clauses else "TRUE"
    params.append(limit)
    with mgr.connect() as conn:
        rows = conn.execute(
            SQL(
                f"SELECT receipt_id, witness_id, event_id, status, retry_count, "
                f"submitted_at, last_attempt_at, confirmed_at, "
                f"witness_signature, witness_response, error_message, created_at "
                f"FROM witness_receipts WHERE {where} "
                f"ORDER BY created_at DESC LIMIT %s"
            ),
            params,
        ).fetchall()
    results = []
    for row in rows:
        d = dict(row)
        d["receipt_id"] = str(d["receipt_id"])
        d["witness_id"] = str(d["witness_id"])
        d["event_id"] = str(d["event_id"])
        for key in ("submitted_at", "last_attempt_at", "confirmed_at", "created_at"):
            if d.get(key) is not None:
                d[key] = d[key].isoformat()
        if d.get("witness_signature") is not None:
            d["witness_signature"] = bytes(d["witness_signature"]).hex()
        results.append(d)
    return results


def deliver_pending_receipts(mgr: ConnectionManager, project: str) -> int:
    import http.client
    from urllib.parse import urlparse

    total = 0
    with mgr.connect() as conn:
        witnesses = conn.execute(
            SQL(
                "SELECT witness_id, url, headers, max_retries, max_failures, "
                "consecutive_failures, status, sign_secret FROM witness_registrations "
                "WHERE status = 'active'"
            ),
        ).fetchall()
    for w in witnesses:
        witness_id = w["witness_id"]
        url = w["url"]
        headers = w["headers"] or {}
        max_retries = w["max_retries"]
        max_failures = w["max_failures"]
        sign_secret = w["sign_secret"]
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        with mgr.transaction() as conn:
            receipts = conn.execute(
                SQL(
                    "UPDATE witness_receipts "
                    "SET status = 'in_progress', last_attempt_at = now() "
                    "WHERE receipt_id IN ("
                    "  SELECT receipt_id FROM witness_receipts "
                    "  WHERE witness_id = %s AND status = 'pending' "
                    "  ORDER BY created_at LIMIT 50 "
                    "  FOR UPDATE SKIP LOCKED"
                    ") "
                    "RETURNING receipt_id, event_id"
                ),
                [witness_id],
            ).fetchall()

        if not receipts:
            continue

        for receipt in receipts:
            receipt_id = receipt["receipt_id"]
            event_id = receipt["event_id"]

            with mgr.connect() as conn_r:
                evt_rows = conn_r.execute(
                    SQL(
                        "SELECT event_id, work_item_id, event_seq, actor_id, actor_kind, "
                        "actor_metadata, key_id, workflow_name, workflow_version, "
                        "timestamp, transition, payload, payload_canonical_hash, "
                        "signature, on_behalf_of, scheme_id "
                        "FROM events WHERE event_id = %s"
                    ),
                    [event_id],
                ).fetchall()
            if not evt_rows:
                continue
            evt = dict(evt_rows[0])
            evt["event_id"] = str(evt["event_id"])
            evt["work_item_id"] = str(evt["work_item_id"])
            evt["timestamp"] = evt["timestamp"].isoformat()
            evt["payload_canonical_hash"] = evt["payload_canonical_hash"].hex()
            evt["signature"] = bytes(evt["signature"]).hex()
            if evt.get("on_behalf_of") is None:
                del evt["on_behalf_of"]

            body = json.dumps({
                "event": evt,
                "receipt_id": str(receipt_id),
                "witness_id": str(witness_id),
                "submitted_at": datetime.now(UTC).isoformat(),
            })

            status_code = 0
            response_body = None
            error_msg = None
            conn_h = None
            try:
                if parsed.scheme == "https":
                    conn_h = http.client.HTTPSConnection(host, port, timeout=10)
                else:
                    conn_h = http.client.HTTPConnection(host, port, timeout=10)
                req_headers = {
                    "Content-Type": "application/json",
                    "User-Agent": "substrate-delivery/0",
                    **headers,
                }
                if sign_secret:
                    import hashlib
                    import hmac as _hmac

                    sig = _hmac.new(sign_secret, body.encode(), hashlib.sha256).hexdigest()
                    req_headers["X-Substrate-Signature"] = f"sha256={sig}"
                conn_h.request("POST", path, body=body.encode(), headers=req_headers)
                resp = conn_h.getresponse()
                status_code = resp.status
                response_body = resp.read(1_000_000).decode("utf-8", errors="replace")
            except Exception as exc:
                error_msg = str(exc)[:500]
            finally:
                if conn_h is not None:
                    try:
                        conn_h.close()
                    except Exception:
                        log.warning("witness.connection_close_error", exc_info=True)

            now = datetime.now(UTC)

            if status_code >= 200 and status_code < 300 and error_msg is None:
                witness_sig = None
                witness_resp_dict = None
                try:
                    parsed_resp = json.loads(response_body)
                    witness_sig = (
                        bytes.fromhex(parsed_resp["witness_signature"])
                        if "witness_signature" in parsed_resp
                        else None
                    )
                    witness_resp_dict = parsed_resp
                except (json.JSONDecodeError, ValueError, KeyError):
                    witness_resp_dict = {"raw": response_body[:2000]}

                with mgr.transaction() as conn:
                    conn.execute(
                        SQL(
                            "UPDATE witness_receipts "
                            "SET status = 'confirmed', confirmed_at = %s, "
                            "witness_signature = %s, witness_response = %s, "
                            "submitted_at = COALESCE(submitted_at, %s) "
                            "WHERE receipt_id = %s AND status = 'in_progress'"
                        ),
                        [
                            now,
                            witness_sig if witness_sig else None,
                            psycopg.types.json.Jsonb(witness_resp_dict)
                            if witness_resp_dict else None,
                            now,
                            receipt_id,
                        ],
                    )
                    conn.execute(
                        SQL(
                            "UPDATE witness_registrations "
                            "SET consecutive_failures = 0, last_success_at = %s, updated_at = %s "
                            "WHERE witness_id = %s"
                        ),
                        [now, now, witness_id],
                    )
                total += 1
            else:
                if error_msg is None:
                    error_msg = f"HTTP {status_code}"
                with mgr.transaction() as conn:
                    conn.execute(
                        SQL(
                            "UPDATE witness_receipts "
                            "SET retry_count = retry_count + 1, "
                            "last_attempt_at = %s, error_message = %s, "
                            "status = 'pending' "
                            "WHERE receipt_id = %s AND status = 'in_progress'"
                        ),
                        [now, error_msg, receipt_id],
                    )
                    new_failures_row = conn.execute(
                        SQL(
                            "UPDATE witness_registrations "
                            "SET consecutive_failures = consecutive_failures + 1, "
                            "last_failure_at = %s, updated_at = %s "
                            "WHERE witness_id = %s "
                            "RETURNING consecutive_failures"
                        ),
                        [now, now, witness_id],
                    ).fetchone()
                    new_failures = new_failures_row["consecutive_failures"]
                    if new_failures >= max_failures:
                        conn.execute(
                            SQL(
                                "UPDATE witness_registrations "
                                "SET status = 'paused' WHERE witness_id = %s"
                            ),
                            [witness_id],
                        )
                        log.warning(
                            "witness.auto_paused",
                            project=project,
                            witness_id=str(witness_id),
                            consecutive_failures=new_failures,
                        )

                    receipt_row = conn.execute(
                        SQL(
                            "SELECT retry_count FROM witness_receipts WHERE receipt_id = %s"
                        ),
                        [receipt_id],
                    ).fetchone()
                    if receipt_row and receipt_row["retry_count"] >= max_retries:
                        conn.execute(
                            SQL(
                                "UPDATE witness_receipts SET status = 'paused' "
                            "WHERE receipt_id = %s"
                            ),
                            [receipt_id],
                        )

    return total
