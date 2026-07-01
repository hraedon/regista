from __future__ import annotations

import threading
import time
import uuid
from datetime import UTC, datetime, timedelta

import psycopg
import structlog
from psycopg.sql import SQL, Identifier, Literal

from ._contract import Jsonb
from ._errors import ErrorCode, RegistaError
from ._events import append_event
from ._keys import KeySet
from ._observability import Metrics
from ._types import HookContext, ValidatorContext

log = structlog.get_logger()


def run_validator(
    validator_name: str,
    handler,
    ctx: ValidatorContext,
    timeout: float = 5.0,
    metrics: Metrics | None = None,
    project: str | None = None,
) -> None:
    # Validators run synchronously in the caller's thread inside the surrounding
    # transaction. There is no enforced wall-clock bound — a hanging or
    # CPU-bound validator hangs the transaction. The Postgres-level
    # statement_timeout set by the caller protects against blocking DB
    # operations, but not against pure Python loops or sleeps. This is the
    # honest contract per BC-192: validators are trusted code.
    start = time.monotonic()
    try:
        handler(ctx)
    except RegistaError:
        raise
    except Exception as e:
        raise RegistaError(
            ErrorCode.VALIDATOR_FAILED,
            f"Validator {validator_name!r} failed: {e}",
        ) from e

    elapsed = time.monotonic() - start
    near_threshold = timeout * 0.8
    if elapsed >= near_threshold:
        log.warning(
            "validators.slow",
            validator_name=validator_name,
            elapsed_s=round(elapsed, 3),
            soft_threshold_s=timeout,
        )
        if metrics and project:
            metrics.inc("validators_near_timeout", project)


def enqueue_hooks(
    conn: psycopg.Connection,
    event_id: uuid.UUID,
    work_item_id: uuid.UUID,
    hook_names: list[str],
    transition: str | None,
    event_payload: dict | None,
    channel: str,
    max_retries: int = 3,
) -> None:
    import psycopg.types.json

    for hook_name in hook_names:
        conn.execute(
            SQL(
                "INSERT INTO hook_queue (event_id, hook_name, hook_type, payload, max_retries) "
                "VALUES (%s, %s, 'async', %s, %s)"
            ),
            [
                event_id,
                hook_name,
                psycopg.types.json.Jsonb({
                    "work_item_id": str(work_item_id),
                    "transition": transition,
                    "event_payload": event_payload,
                }),
                max_retries,
            ],
        )

    if hook_names:
        # NOTIFY payload does not support bind parameters; Literal produces
        # a properly-escaped SQL string literal for the event_id.
        conn.execute(
            SQL("NOTIFY {}, {}").format(Identifier(channel), Literal(str(event_id))),
        )


def claim_hooks(
    conn: psycopg.Connection,
    max_batch: int = 10,
    lease_seconds: int = 60,
    actor_id: str | None = None,
) -> list[HookContext]:
    rows = conn.execute(
        SQL(
            "SELECT id, event_id, hook_name, payload, retry_count, max_retries "
            "FROM hook_queue "
            "WHERE status = 'pending' "
            "AND (next_retry_at IS NULL OR next_retry_at <= now()) "
            "ORDER BY id LIMIT %s "
            "FOR UPDATE SKIP LOCKED"
        ),
        [max_batch],
    ).fetchall()

    if not rows:
        return []

    valid_ids = []
    result = []
    for row in rows:
        payload = row["payload"] or {}
        raw_wi_id = payload.get("work_item_id")
        if raw_wi_id is None:
            continue
        try:
            wi_uuid = uuid.UUID(raw_wi_id)
        except (ValueError, AttributeError):
            log.warning(
                "hooks.malformed_work_item_id",
                hook_queue_id=row["id"],
                raw_wi_id=raw_wi_id,
            )
            continue
        valid_ids.append(row["id"])
        result.append(HookContext(
            hook_queue_id=row["id"],
            event_id=row["event_id"],
            work_item_id=wi_uuid,
            hook_name=row["hook_name"],
            transition=payload.get("transition"),
            payload=payload.get("event_payload"),
        ))

    if not valid_ids:
        return []

    lease_expires_at = datetime.now(UTC) + timedelta(seconds=lease_seconds)
    conn.execute(
        SQL(
            "UPDATE hook_queue SET status = 'in_progress', "
            "lease_expires_at = %s, claimed_by = %s, updated_at = now() "
            "WHERE id = ANY(%s)"
        ),
        [lease_expires_at, actor_id, valid_ids],
    )
    return result


def complete_hook(
    conn: psycopg.Connection, hook_queue_id: int, actor_id: str | None = None,
) -> None:
    if actor_id is not None:
        result = conn.execute(
            SQL(
                "UPDATE hook_queue SET status = 'completed', "
                "lease_expires_at = NULL, claimed_by = NULL, updated_at = now() "
                "WHERE id = %s AND claimed_by = %s AND status = 'in_progress'"
            ),
            [hook_queue_id, actor_id],
        )
        if result.rowcount == 0:
            row = conn.execute(
                SQL("SELECT claimed_by, status FROM hook_queue WHERE id = %s"),
                [hook_queue_id],
            ).fetchone()
            if row is None:
                raise RegistaError(
                    ErrorCode.HOOK_NOT_FOUND,
                    f"Hook {hook_queue_id} not found",
                )
            raise RegistaError(
                ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER,
                f"Hook {hook_queue_id} is not claimed by {actor_id!r} "
                f"(status={row['status']}, claimed_by={row['claimed_by']})",
            )
    else:
        result = conn.execute(
            SQL(
                "UPDATE hook_queue SET status = 'completed', "
                "lease_expires_at = NULL, claimed_by = NULL, updated_at = now() "
                "WHERE id = %s AND status = 'in_progress'"
            ),
            [hook_queue_id],
        )
        if result.rowcount == 0:
            raise RegistaError(
                ErrorCode.HOOK_NOT_FOUND,
                f"Hook {hook_queue_id} not found or not in progress",
            )


def fail_hook(
    conn: psycopg.Connection,
    hook_queue_id: int,
    error: str,
    key_set: KeySet,
    metrics: Metrics | None = None,
    project: str | None = None,
    actor_id: str | None = None,
) -> None:
    row = conn.execute(
        SQL(
            "SELECT id, event_id, hook_name, hook_type, payload, retry_count, "
            "max_retries, claimed_by, status FROM hook_queue "
            "WHERE id = %s FOR UPDATE"
        ),
        [hook_queue_id],
    ).fetchone()

    if row is None:
        raise RegistaError(
            ErrorCode.HOOK_NOT_FOUND,
            f"Hook {hook_queue_id} not found",
        )

    if actor_id is not None and row["claimed_by"] != actor_id:
        raise RegistaError(
            ErrorCode.HOOK_NOT_CLAIMED_BY_CALLER,
            f"Hook {hook_queue_id} is not claimed by {actor_id!r}",
        )

    if row["status"] != "in_progress":
        raise RegistaError(
            ErrorCode.HOOK_NOT_FOUND,
            f"Hook {hook_queue_id} not found or not in progress "
            f"(status={row['status']})",
        )

    retry_count = row["retry_count"] + 1
    max_retries = row["max_retries"]

    if retry_count >= max_retries:
        _move_to_dead_letter(conn, row, error, key_set)
        if metrics and project:
            metrics.inc("hooks_dead_lettered", project)
    else:
        backoff = timedelta(seconds=min(2 ** retry_count, 60))
        next_retry = datetime.now(UTC) + backoff
        conn.execute(
            SQL(
                "UPDATE hook_queue SET status = 'pending', retry_count = %s, "
                "next_retry_at = %s, lease_expires_at = NULL, claimed_by = NULL, "
                "updated_at = now() WHERE id = %s"
            ),
            [retry_count, next_retry, hook_queue_id],
        )
        if metrics and project:
            metrics.inc("hooks_failed", project)
    log.warning("hooks.handler_failed", hook_queue_id=hook_queue_id, error=error)


def sweep_expired_hook_leases(conn: psycopg.Connection) -> int:
    result = conn.execute(
        SQL(
            "UPDATE hook_queue SET status = 'pending', "
            "lease_expires_at = NULL, claimed_by = NULL, updated_at = now() "
            "WHERE status = 'in_progress' AND lease_expires_at < now()"
        ),
    )
    return result.rowcount


def poll_and_process_hooks(
    conn: psycopg.Connection,
    handlers: dict,
    key_set: KeySet,
    metrics: Metrics | None,
    project: str,
) -> int:
    sweep_expired_hook_leases(conn)

    contexts = claim_hooks(conn, max_batch=100, lease_seconds=300)

    processed = 0
    for ctx in contexts:
        hook_name = ctx.hook_name
        handler = handlers.get(hook_name)

        if handler is None:
            log.warning("hooks.handler_not_registered", hook_name=hook_name)
            row = conn.execute(
                SQL(
                    "SELECT id, event_id, hook_name, hook_type, payload, "
                    "retry_count, max_retries FROM hook_queue WHERE id = %s"
                ),
                [ctx.hook_queue_id],
            ).fetchone()
            if row is not None:
                _move_to_dead_letter(conn, row, f"Handler {hook_name!r} not registered", key_set)
            if metrics:
                metrics.inc("hooks_dead_lettered", project)
            continue

        if ctx.work_item_id is None:
            log.error("hooks.missing_work_item_id", hook_id=ctx.hook_queue_id, hook_name=hook_name)
            row = conn.execute(
                SQL(
                    "SELECT id, event_id, hook_name, hook_type, payload, "
                    "retry_count, max_retries FROM hook_queue WHERE id = %s"
                ),
                [ctx.hook_queue_id],
            ).fetchone()
            if row is not None:
                _move_to_dead_letter(conn, row, "work_item_id missing from payload", key_set)
            if metrics:
                metrics.inc("hooks_dead_lettered", project)
            continue

        try:
            with conn.transaction():
                handler(ctx)
                complete_hook(conn, ctx.hook_queue_id)
                if metrics:
                    metrics.inc("hooks_succeeded", project)
            processed += 1
        except Exception as e:
            fail_hook(conn, ctx.hook_queue_id, str(e), key_set, metrics, project)
            log.warning("hooks.handler_failed", hook_name=hook_name, error=str(e))

    return processed


def _move_to_dead_letter(
    conn: psycopg.Connection,
    hook_row: dict,
    error_message: str,
    key_set: KeySet,
) -> None:
    import psycopg.types.json

    deleted = conn.execute(
        SQL(
            "DELETE FROM hook_queue WHERE id = %s "
            "RETURNING id, event_id, hook_name, hook_type, payload, "
            "retry_count, max_retries"
        ),
        [hook_row["id"]],
    ).fetchone()
    if deleted is None:
        return

    conn.execute(
        SQL(
            "INSERT INTO hook_dead_letter "
            "(event_id, hook_name, hook_type, payload, retry_count, max_retries, error_message, "
            "original_hook_queue_id) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"
        ),
        [
            deleted["event_id"],
            deleted["hook_name"],
            deleted["hook_type"],
            (
                psycopg.types.json.Jsonb(deleted["payload"])
                if deleted["payload"]
                else None
            ),
            deleted["retry_count"],
            deleted.get("max_retries", 3),
            error_message,
            deleted["id"],
        ],
    )

    evt_row = conn.execute(
        SQL(
            "SELECT work_item_id, workflow_name, workflow_version "
            "FROM events WHERE event_id = %s"
        ),
        [deleted["event_id"]],
    ).fetchone()

    if evt_row is not None:
        work_item_id = evt_row["work_item_id"]
        workflow_name = evt_row["workflow_name"]
        workflow_version = evt_row["workflow_version"]
    else:
        work_item_id = None
        workflow_name = None
        workflow_version = None
        payload = deleted.get("payload") or {}
        raw_wi = payload.get("work_item_id")
        if raw_wi is not None:
            try:
                work_item_id = uuid.UUID(raw_wi)
            except ValueError:
                work_item_id = None
        if work_item_id is not None:
            wi_row = conn.execute(
                SQL(
                    "SELECT workflow_name, workflow_version FROM work_items_current "
                    "WHERE work_item_id = %s"
                ),
                [work_item_id],
            ).fetchone()
            if wi_row is not None:
                workflow_name = wi_row["workflow_name"]
                workflow_version = wi_row["workflow_version"]
            else:
                work_item_id = None

    if work_item_id is None:
        work_item_id = uuid.UUID(int=0)
        workflow_name = workflow_name or "__orphan__"
        workflow_version = workflow_version or 0

    append_event(
        conn=conn,
        work_item_id=work_item_id,
        actor_id="system",
        actor_kind="system",
        actor_metadata=None,
        key_set=key_set,
        workflow_name=workflow_name,
        workflow_version=workflow_version,
        transition="hook_dead_lettered",
        payload=Jsonb({
            "hook_name": deleted["hook_name"],
            "hook_queue_id": deleted["id"],
            "error_message": error_message,
            "original_event_missing": evt_row is None,
        }),
        event_id=uuid.uuid4(),
    )


def requeue_dead_lettered_hook(
    conn: psycopg.Connection,
    dead_letter_id: int,
    channel: str,
    key_set: KeySet,
) -> None:
    import psycopg.types.json

    row = conn.execute(
        SQL("SELECT * FROM hook_dead_letter WHERE id = %s"),
        [dead_letter_id],
    ).fetchone()

    if row is None:
        raise RegistaError(
            ErrorCode.HOOK_NOT_FOUND,
            f"Dead-lettered hook {dead_letter_id} not found",
        )

    conn.execute(
        SQL(
            "INSERT INTO hook_queue "
            "(event_id, hook_name, hook_type, payload, retry_count, max_retries) "
            "VALUES (%s, %s, 'async', %s, 0, %s)"
        ),
        [
            row["event_id"],
            row["hook_name"],
            psycopg.types.json.Jsonb(row["payload"]) if row["payload"] else None,
            row.get("max_retries", 3),
        ],
    )

    conn.execute(
        SQL("DELETE FROM hook_dead_letter WHERE id = %s"),
        [dead_letter_id],
    )

    conn.execute(
        SQL("NOTIFY {}, {}").format(Identifier(channel), Literal(str(row["event_id"]))),
    )


class HookConsumer:
    def __init__(
        self,
        dsn: str,
        schema: str,
        project: str,
        handlers: dict,
        key_set: KeySet,
        metrics: Metrics | None,
        poll_interval: float = 30.0,
    ) -> None:
        self._dsn = dsn
        self._schema = schema
        self._project = project
        self._handlers = handlers
        self._key_set = key_set
        self._metrics = metrics
        self._poll_interval = poll_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._channel = f"regista_hooks_{schema}"
        self._processing = False
        # Test seams: tunable so unit tests can exercise the connect-exhaustion
        # path without sleeping through real backoff.
        self._max_reconnect_attempts = 10
        self._reconnect_backoff_base = 2.0

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info("hooks.consumer_started", project=self._project)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        self._processing = False
        log.info("hooks.consumer_stopped", project=self._project)

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self._processing

    def _connect(self):
        from psycopg.rows import dict_row

        conn = psycopg.connect(
            self._dsn,
            row_factory=dict_row,
            autocommit=True,
        )
        conn.execute(
            SQL("SET search_path TO {}").format(Identifier(self._schema))
        )
        conn.execute(SQL("SET synchronous_commit = on"))
        conn.execute(SQL("LISTEN {}").format(Identifier(self._channel)))
        return conn

    def _run(self) -> None:
        self._processing = True
        max_reconnect_attempts = self._max_reconnect_attempts
        reconnect_backoff_base = self._reconnect_backoff_base
        reconnect_attempts = 0

        conn = None
        while conn is None and not self._stop.is_set():
            try:
                conn = self._connect()
            except Exception as e:
                reconnect_attempts += 1
                if reconnect_attempts >= max_reconnect_attempts:
                    log.error(
                        "hooks.initial_connect_exhausted",
                        attempts=reconnect_attempts,
                        error=str(e),
                    )
                    self._processing = False
                    return
                backoff = min(
                    reconnect_backoff_base * (2 ** (reconnect_attempts - 1)),
                    60.0,
                )
                log.warning(
                    "hooks.initial_connect_failed",
                    attempt=reconnect_attempts,
                    backoff=backoff,
                    error=str(e),
                )
                time.sleep(backoff)

        if conn is None:
            self._processing = False
            return

        reconnect_attempts = 0
        self._processing = True

        try:
            while not self._stop.is_set():
                try:
                    for _notify in conn.notifies(timeout=self._poll_interval):
                        if self._stop.is_set():
                            break
                except psycopg.OperationalError as e:
                    if self._stop.is_set():
                        break
                    reconnect_attempts += 1
                    if reconnect_attempts >= max_reconnect_attempts:
                        log.error(
                            "hooks.reconnect_exhausted",
                            attempts=reconnect_attempts,
                            error=str(e),
                        )
                        break
                    backoff = min(
                        reconnect_backoff_base * (2 ** (reconnect_attempts - 1)),
                        60.0,
                    )
                    log.warning(
                        "hooks.connection_lost",
                        attempt=reconnect_attempts,
                        backoff=backoff,
                        error=str(e),
                    )
                    try:
                        conn.close()
                    except Exception:
                        log.warning("hooks.connection_close_error", exc_info=True)
                    time.sleep(backoff)
                    try:
                        conn = self._connect()
                        successful_attempt = reconnect_attempts
                        reconnect_attempts = 0
                        log.info("hooks.reconnected", attempt=successful_attempt)
                    except Exception as ce:
                        log.error("hooks.reconnect_failed", error=str(ce))
                    continue

                if self._stop.is_set():
                    break

                reconnect_attempts = 0

                try:
                    with conn.transaction():
                        poll_and_process_hooks(
                            conn,
                            self._handlers,
                            self._key_set,
                            self._metrics,
                            self._project,
                        )
                except psycopg.OperationalError as e:
                    log.error("hooks.poll_connection_error", error=str(e))
                except Exception as e:
                    log.error("hooks.poll_error", error=str(e))
        finally:
            self._processing = False
            try:
                conn.close()
            except Exception:
                log.warning("hooks.connection_close_error", exc_info=True)
