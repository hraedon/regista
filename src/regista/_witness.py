from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import psycopg
import structlog
from psycopg.sql import SQL

from ._connection import ConnectionManager
from ._errors import ErrorCode, RegistaError

log = structlog.get_logger()

_WITNESS_PRINCIPAL_PREFIX = "witness:"


def witness_principal_id(witness_id: uuid.UUID | str) -> str:
    return f"{_WITNESS_PRINCIPAL_PREFIX}{witness_id}"


def verify_witness_countersignature(
    *,
    canonical_envelope: bytes,
    row_payload_canonical_hash: bytes,
    hash_alg: str,
    witness_signature: bytes,
    witness_public_key: bytes,
) -> bool:
    """Whether an ed25519 witness countersigned this event's stored envelope bytes.

    Two independent facts, both required, previously conflated into one call that
    could not establish either for a v6 event:

    1. **The row is self-consistent** — its ``payload_canonical_hash`` column really
       is the hash of its ``canonical_envelope`` column, under that envelope's own
       version (:func:`regista._signing.compute_payload_canonical_hash`). Two columns
       compared against each other, so this is a real check, not a tautology.
    2. **The witness's signature is valid over the envelope bytes it was sent.** The
       delivery body carries ``event.canonical_envelope`` verbatim, so those bare
       bytes are what a witness signs. ``Ed25519Scheme.verify``'s contract requires
       ``envelope_hash == H(envelope)`` for whatever ``envelope`` it is handed, so
       the digest passed here is ``H(canonical_envelope)``.

    The defect this replaces passed the *row's* ``payload_canonical_hash`` as that
    ``envelope_hash`` while passing the *bare envelope* as ``envelope``. For v1-v5
    those coincide; for v6 they do not (``V6-ENVELOPE.md`` §5.3 — the column hashes
    the domain-tagged signature input), so ``compare_digest`` failed on every v6
    event and every ed25519 receipt over one was rejected as a bad signature.

    Deliberately **not** fixed by feeding the v6 signature input to the scheme
    instead. That would silently redefine what an external witness must sign, and it
    would make a witness countersignature cover byte-identical input to the *author's*
    signature over the same event — §6.1's domain registry has no witness tag, and
    giving the witness the author's tag is the one thing domain separation exists to
    prevent. Countersigning the untagged stored bytes keeps the two structurally
    distinct. A dedicated ``regista.witness.*`` domain tag would be the principled
    design, but it is a wire-format change and is not one to make from inside a
    verification bug fix.
    """

    from ._signing import compute_payload_canonical_hash
    from ._signing_scheme import Ed25519Scheme, resolve_hash_function

    try:
        expected_row_hash = compute_payload_canonical_hash(canonical_envelope, hash_alg)
        envelope_digest = resolve_hash_function(hash_alg)(canonical_envelope).digest()
    except RegistaError:
        # An unknown hash_alg on the row: unverifiable, not verified.
        return False

    import hmac as _hmac

    if not _hmac.compare_digest(expected_row_hash, row_payload_canonical_hash):
        return False
    return Ed25519Scheme().verify(
        canonical_envelope,
        witness_signature,
        envelope_digest,
        witness_public_key,
        hash_alg=hash_alg,
    )


def _refuse_witness_key_lifecycle(operation: str, *, extra: str = "") -> None:
    """Refuse a witness key-lifecycle write. Always raises.

    Witness lifecycle is **cut from 0.6.0** (``TRUST-DOMAIN.md`` §7 CUT marker,
    D-7): positive witness-independence work does not ship in this release, the
    signed witness lifecycle (``witness_registered``, ``witness_key_rotated``,
    ``witness_paused``, ``witness_resumed``, ``witness_revoked``) is struck from the
    §5.3 catalogue, and preflight measured **zero** ``witness_registrations`` and
    **zero** ``witness_receipts`` estate-wide — nothing to migrate, no deployed
    evidence to preserve.

    So there is no signed event for these paths to project from. Three options
    existed and only one is honest:

    * keep writing ``principal_keys`` with no event — that *is* the §5.1 bypass, and
      it is what happened last time;
    * skip the registry write silently — leaves ``witness_registrations`` claiming a
      key that the registry never recorded, i.e. a quieter version of the same lie;
    * **refuse by name** — this. The caller learns the capability is cut rather than
      discovering later that its key was never enrolled.

    Webhook *delivery* is unaffected: it is preserved as non-evidentiary transport
    (§7 CUT marker), which is why ``register_witness`` still works for
    ``key_scheme='hmac-sha256'``. Only the asymmetric key-lifecycle paths refuse.
    """
    raise RegistaError(
        ErrorCode.WITNESS_LIFECYCLE_CUT,
        f"{operation} is refused: witness key lifecycle is cut from 0.6.0 "
        "(TRUST-DOMAIN.md §7 CUT marker, D-7). There is no signed witness_registered "
        "or witness_key_rotated event in this release, so enrolling or rotating a "
        "witness key in principal_keys would be an unsourced projection write "
        "(§5.9 rule 2). Webhook delivery remains available as non-evidentiary "
        "transport via key_scheme='hmac-sha256'."
        + (f" {extra}" if extra else ""),
        {
            "reason": "witness_lifecycle_cut_from_0_6_0",
            "operation": operation,
            "see": "docs/0.6.0/TRUST-DOMAIN.md §7",
        },
    )


def _validate_url(url: str) -> None:
    if not url or not url.startswith(("http://", "https://")):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"witness url must start with http:// or https://, got: {url!r}",
        )
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if not parsed.hostname:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"witness url must have a valid hostname, got: {url!r}",
        )


def _validate_event_filter(event_filter: dict[str, Any] | None) -> dict[str, Any] | None:
    if event_filter is None:
        return None
    if not isinstance(event_filter, dict):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "event_filter must be a dict",
        )
    allowed_keys = {"transitions", "work_item_types", "workflows"}
    for key in event_filter:
        if key not in allowed_keys:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"event_filter key {key!r} not allowed; allowed: {sorted(allowed_keys)}",
            )
        val = event_filter[key]
        if not isinstance(val, list) or not all(isinstance(v, str) for v in val):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"event_filter[{key!r}] must be a list of strings",
            )
    return event_filter


def event_matches_filter(event_dict: dict[str, Any], event_filter: dict[str, Any] | None) -> bool:
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
    event_filter: dict[str, Any] | None = None,
    max_failures: int = 10,
    max_retries: int = 3,
    *,
    mode: str = "witness",
    sign_secret: bytes | None = None,
    public_key: bytes | None = None,
    key_scheme: str = "hmac-sha256",
) -> uuid.UUID:
    _validate_url(url)
    event_filter = _validate_event_filter(event_filter)
    if mode not in ("witness", "push"):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"mode must be 'witness' or 'push', got {mode!r}",
        )
    if max_failures < 1:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"max_failures must be >= 1, got {max_failures}",
        )
    if max_retries < 1:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"max_retries must be >= 1, got {max_retries}",
        )
    if key_scheme not in ("hmac-sha256", "ed25519"):
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"key_scheme must be 'hmac-sha256' or 'ed25519', got {key_scheme!r}",
        )
    if key_scheme == "ed25519":
        if public_key is None:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "public_key is required when key_scheme is 'ed25519'",
            )
        if len(public_key) != 32:
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "ed25519 public_key must be exactly 32 bytes, "
                f"got {len(public_key)}",
            )
        _refuse_witness_key_lifecycle("register_witness(key_scheme='ed25519')")
    witness_id = uuid.uuid4()
    with mgr.transaction() as conn:
        conn.execute(
            SQL(
                "INSERT INTO witness_registrations "
                "(witness_id, url, headers, event_filter, "
                "max_failures, max_retries, mode, sign_secret, public_key, key_scheme) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
            ),
            [
                witness_id,
                url,
                psycopg.types.json.Jsonb(headers) if headers is not None else None,  # type: ignore[attr-defined]
                psycopg.types.json.Jsonb(event_filter) if event_filter is not None else None,  # type: ignore[attr-defined]
                max_failures,
                max_retries,
                mode,
                sign_secret,
                public_key,
                key_scheme,
            ],
        )
        # Witness key enrolment used to call register_principal_key_conn here — a
        # plain INSERT into principal_keys with no event emitted anywhere
        # (TRUST-DOMAIN.md §7.1, one of the three §5.1 bypass paths). Witness
        # lifecycle is CUT from 0.6.0 (§7 CUT marker, D-7), so there is no signed
        # witness_registered event to project from and the write is refused rather
        # than quietly kept. See _refuse_witness_key_lifecycle above for why this is
        # a refusal and not a silent skip.
    log.info(
        "witness.registered",
        project=project,
        witness_id=str(witness_id),
        url=url,
        mode=mode,
        key_enrolled=key_scheme == "ed25519",
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
            raise RegistaError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"witness {witness_id} not found",
            )
        active_rows = conn.execute(
            SQL(
                "SELECT key_id FROM principal_keys "
                "WHERE principal_id = %s AND status = 'active'"
            ),
            [witness_principal_id(witness_id)],
        ).fetchall()
        if active_rows:
            # Reached only for a witness whose ed25519 key predates the 0.6.0 cut.
            # Preflight measured ZERO witness_registrations estate-wide, so this is
            # unreachable in the deployed estate — but silently leaving the key
            # active while deleting the registration would be worse than refusing,
            # and revoking it without a signed event is exactly the §5.9 bypass.
            _refuse_witness_key_lifecycle(
                "unregister_witness (witness has active principal_keys rows)",
                extra=(
                    f"{len(active_rows)} active key row(s) exist for "
                    f"{witness_principal_id(witness_id)}. Revoking them requires a "
                    "signed principal_key_revoked event, which the cut witness "
                    "lifecycle cannot produce."
                ),
            )
    log.info("witness.unregistered", project=project, witness_id=str(witness_id))


def rotate_witness_key(
    mgr: ConnectionManager,
    project: str,
    witness_id: uuid.UUID,
    new_public_key: bytes,
) -> dict[str, Any]:
    if len(new_public_key) != 32:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "ed25519 new_public_key must be exactly 32 bytes, "
            f"got {len(new_public_key)}",
        )
    principal_id = witness_principal_id(witness_id)
    with mgr.transaction() as conn:
        row = conn.execute(
            SQL(
                "SELECT key_scheme FROM witness_registrations "
                "WHERE witness_id = %s FOR UPDATE"
            ),
            [witness_id],
        ).fetchone()
        if row is None:
            raise RegistaError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"witness {witness_id} not found",
            )
        if row["key_scheme"] != "ed25519":
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                "witness key rotation requires key_scheme='ed25519' "
                f"(witness is {row['key_scheme']!r})",
            )
        # Rotating the witness's registry key was the third §5.1 bypass
        # (_witness.py:256): an UPDATE plus rotate_principal_key_conn, no event.
        # Witness key rotation is `witness_key_rotated`, struck from the §5.3
        # catalogue and cut from 0.6.0, so it is refused here — before the
        # witness_registrations UPDATE, so a refused rotation leaves no partial
        # state behind.
        _refuse_witness_key_lifecycle(
            "rotate_witness_key",
            extra=f"witness principal is {principal_id}",
        )
        raise AssertionError("unreachable: _refuse_witness_key_lifecycle always raises")


def enrolled_witness_key(
    mgr: ConnectionManager,
    witness_id: uuid.UUID,
) -> dict[str, Any] | None:
    principal_id = witness_principal_id(witness_id)
    with mgr.transaction() as conn:
        rows = conn.execute(
            SQL(
                "SELECT * FROM principal_keys "
                "WHERE principal_id = %s AND status = 'active'"
            ),
            [principal_id],
        ).fetchall()
    if not rows:
        return None
    from ._principal_keys import _row_to_entry

    return _row_to_entry(rows[0]).to_dict()


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
            raise RegistaError(
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
            raise RegistaError(
                ErrorCode.WITNESS_NOT_FOUND,
                f"witness {witness_id} not found",
            )
    log.info("witness.reactivated", project=project, witness_id=str(witness_id))


def list_witnesses(
    mgr: ConnectionManager,
    status: str | None = None,
    mode: str | None = None,
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
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
                "max_failures, consecutive_failures, max_retries, mode, "
                "key_scheme, public_key, "
                "last_success_at, last_failure_at, created_at, updated_at "
                f"FROM witness_registrations WHERE {where} ORDER BY created_at"
            ),
            params,
        ).fetchall()
    results = []
    for row in rows:
        d = dict(row)
        d["witness_id"] = str(d["witness_id"])
        for key in ("last_success_at", "last_failure_at", "created_at", "updated_at"):
            if d.get(key) is not None:
                d[key] = d[key].isoformat()
        results.append(d)
    return results


def create_receipts(
    mgr: ConnectionManager,
    event_dict: dict[str, Any],
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
) -> list[dict[str, Any]]:
    clauses: list[str] = []
    params: list[Any] = []
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
                f"witness_signature, witness_response, witness_scheme, error_message, created_at "
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


def _apply_receipt_failure(
    conn: Any,
    *,
    receipt_id: uuid.UUID,
    witness_id: uuid.UUID,
    project: str,
    error_message: str,
    witness_key_scheme: str,
    now: datetime,
    max_retries: int,
    max_failures: int,
) -> None:
    conn.execute(
        SQL(
            "UPDATE witness_receipts "
            "SET retry_count = retry_count + 1, "
            "last_attempt_at = %s, error_message = %s, witness_scheme = %s, "
            "status = 'pending' "
            "WHERE receipt_id = %s AND status = 'in_progress'"
        ),
        [now, error_message, witness_key_scheme, receipt_id],
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
    if new_failures_row is not None:
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
        SQL("SELECT retry_count FROM witness_receipts WHERE receipt_id = %s"),
        [receipt_id],
    ).fetchone()
    if receipt_row and receipt_row["retry_count"] >= max_retries:
        conn.execute(
            SQL("UPDATE witness_receipts SET status = 'paused' WHERE receipt_id = %s"),
            [receipt_id],
        )


def deliver_pending_receipts(mgr: ConnectionManager, project: str) -> int:
    import http.client
    from urllib.parse import urlparse

    total = 0
    with mgr.connect() as conn:
        witnesses = conn.execute(
            SQL(
                "SELECT witness_id, url, headers, max_retries, max_failures, "
                "consecutive_failures, status, sign_secret, public_key, key_scheme "
                "FROM witness_registrations "
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
        witness_pubkey = w["public_key"]
        witness_key_scheme = w["key_scheme"]
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
                        "SELECT event_id, work_item_id, entity_kind, entity_id, hash_alg, "
                        "event_seq, actor_id, actor_kind, "
                        "actor_metadata, key_id, workflow_name, workflow_version, "
                        "timestamp, transition, payload, payload_canonical_hash, "
                        "signature, canonical_envelope, on_behalf_of, scheme_id, "
                        "prev_event_hash, global_seq, prev_global_event_hash "
                        "FROM events WHERE event_id = %s"
                    ),
                    [event_id],
                ).fetchall()
            if not evt_rows:
                now = datetime.now(UTC)
                with mgr.transaction() as conn:
                    _apply_receipt_failure(
                        conn,
                        receipt_id=receipt_id,
                        witness_id=witness_id,
                        project=project,
                        error_message="event not found",
                        witness_key_scheme=witness_key_scheme,
                        now=now,
                        max_retries=max_retries,
                        max_failures=max_failures,
                    )
                continue
            try:
                raw_row = evt_rows[0]
                raw_env = (
                    bytes(raw_row["canonical_envelope"])
                    if raw_row["canonical_envelope"] else None
                )
                raw_hash = (
                    bytes(raw_row["payload_canonical_hash"])
                    if raw_row["payload_canonical_hash"] else None
                )
                raw_alg = str(raw_row["hash_alg"] or "sha-256")
                evt = dict(raw_row)
                evt["event_id"] = str(evt["event_id"])
                evt["work_item_id"] = str(evt["work_item_id"])
                evt["entity_id"] = str(evt.get("entity_id") or evt["work_item_id"])
                if evt.get("canonical_envelope") is not None:
                    evt["canonical_envelope"] = bytes(evt["canonical_envelope"]).hex()
                else:
                    del evt["canonical_envelope"]
                if evt.get("prev_event_hash") is not None:
                    evt["prev_event_hash"] = bytes(evt["prev_event_hash"]).hex()
                else:
                    del evt["prev_event_hash"]
                if evt.get("prev_global_event_hash") is not None:
                    evt["prev_global_event_hash"] = bytes(evt["prev_global_event_hash"]).hex()
                else:
                    del evt["prev_global_event_hash"]
                if evt.get("global_seq") is None:
                    del evt["global_seq"]
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
            except Exception as exc:
                now = datetime.now(UTC)
                with mgr.transaction() as conn:
                    _apply_receipt_failure(
                        conn,
                        receipt_id=receipt_id,
                        witness_id=witness_id,
                        project=project,
                        error_message=f"payload error: {str(exc)[:400]}",
                        witness_key_scheme=witness_key_scheme,
                        now=now,
                        max_retries=max_retries,
                        max_failures=max_failures,
                    )
                continue

            status_code = 0
            response_body = None
            error_msg = None
            conn_h: http.client.HTTPConnection | None = None
            try:
                if parsed.scheme == "https":
                    conn_h = http.client.HTTPSConnection(host, port, timeout=10)
                else:
                    conn_h = http.client.HTTPConnection(host, port, timeout=10)
                req_headers = {
                    "Content-Type": "application/json",
                    "User-Agent": "regista-delivery/0",
                    **headers,
                }
                if sign_secret:
                    import hashlib
                    import hmac as _hmac

                    sig = _hmac.new(sign_secret, body.encode(), hashlib.sha256).hexdigest()
                    req_headers["X-Regista-Signature"] = f"sha256={sig}"
                assert conn_h is not None
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
                    parsed_resp = json.loads(response_body or "")
                    witness_sig = (
                        bytes.fromhex(parsed_resp["witness_signature"])
                        if "witness_signature" in parsed_resp
                        else None
                    )
                    witness_resp_dict = parsed_resp
                except (json.JSONDecodeError, ValueError, KeyError):
                    witness_resp_dict = {"raw": (response_body or "")[:2000]}

                requires_witness_signature = witness_key_scheme == "ed25519"
                if requires_witness_signature:
                    if (
                        witness_pubkey is not None
                        and witness_sig is not None
                        and raw_env is not None
                        and raw_hash is not None
                    ):
                        sig_verified = verify_witness_countersignature(
                            canonical_envelope=raw_env,
                            row_payload_canonical_hash=raw_hash,
                            hash_alg=raw_alg,
                            witness_signature=witness_sig,
                            witness_public_key=witness_pubkey,
                        )
                    else:
                        sig_verified = False
                else:
                    sig_verified = True

                with mgr.transaction() as conn:
                    if sig_verified:
                        conn.execute(
                            SQL(
                                "UPDATE witness_receipts "
                                "SET status = 'confirmed', confirmed_at = %s, "
                                "witness_signature = %s, witness_response = %s, "
                                "witness_scheme = %s, "
                                "submitted_at = COALESCE(submitted_at, %s) "
                                "WHERE receipt_id = %s AND status = 'in_progress'"
                            ),
                            [
                                now,
                                witness_sig if witness_sig else None,
                                psycopg.types.json.Jsonb(witness_resp_dict)  # type: ignore[attr-defined]
                                if witness_resp_dict else None,
                                witness_key_scheme,
                                now,
                                receipt_id,
                            ],
                        )
                        conn.execute(
                            SQL(
                                "UPDATE witness_registrations "
                                "SET consecutive_failures = 0, "
                                "last_success_at = %s, updated_at = %s "
                                "WHERE witness_id = %s"
                            ),
                            [now, now, witness_id],
                        )
                        total += 1
                    else:
                        _apply_receipt_failure(
                            conn,
                            receipt_id=receipt_id,
                            witness_id=witness_id,
                            project=project,
                            error_message="witness signature verification failed",
                            witness_key_scheme=witness_key_scheme,
                            now=now,
                            max_retries=max_retries,
                            max_failures=max_failures,
                        )
            else:
                if error_msg is None:
                    error_msg = f"HTTP {status_code}"
                with mgr.transaction() as conn:
                    _apply_receipt_failure(
                        conn,
                        receipt_id=receipt_id,
                        witness_id=witness_id,
                        project=project,
                        error_message=error_msg,
                        witness_key_scheme=witness_key_scheme,
                        now=now,
                        max_retries=max_retries,
                        max_failures=max_failures,
                    )

    return total


def sweep_stuck_witness_receipts(mgr: ConnectionManager, max_age_seconds: int = 300) -> int:
    import structlog

    if max_age_seconds <= 0:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            "max_age_seconds must be a positive integer",
        )
    log = structlog.get_logger()
    with mgr.transaction() as conn:
        rows = conn.execute(
            "UPDATE witness_receipts "
            "SET status = 'pending' "
            "WHERE status = 'in_progress' "
            "AND last_attempt_at < clock_timestamp() - make_interval(secs => %s) "
            "RETURNING receipt_id, witness_id",
            [max_age_seconds],
        ).fetchall()
        for r in rows:
            log.info(
                "witness.swept_stuck_receipt",
                receipt_id=str(r["receipt_id"]),
                witness_id=str(r["witness_id"]),
            )
        return len(rows)
