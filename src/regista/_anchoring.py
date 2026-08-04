from __future__ import annotations

import dataclasses
import hashlib
import hmac as _hmac
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import structlog

from ._errors import ErrorCode, RegistaError
from ._signing_scheme import resolve_hash_function
from ._timestamping import TSAConfig, submit_to_tsa, verify_tsa_token

log = structlog.get_logger()

_DEFAULT_OTS_CALENDAR = "https://bitcoin.calendar.catallaxy.com/"
_BATCH_SIZE_DEFAULT = 10_000
_DEFAULT_ENVELOPE_VERSION = 5
_DEFAULT_HASH_ALGORITHM = "sha-256"

_RAW = hashlib.sha256(b"regista_anchoring").digest()
_ANCHORING_LOCK_ID: int = int.from_bytes(_RAW[:8], "big")
if _ANCHORING_LOCK_ID >= 2**63:
    _ANCHORING_LOCK_ID -= 2**64


class AnchorStatus:
    """Anchor receipt lifecycle states.

    Bundled providers only ever emit ``PENDING`` (calendar-based providers such
    as OpenTimestamps, before the calendar is upgraded) and ``CONFIRMED``
    (final, or immediate for file/RFC 3161 providers); ``FAILED``/``RETRYABLE``
    record delivery problems.

    ``COMMITTED`` is RESERVED for external/third-party providers that distinguish
    a "committed to the log" intermediate state from a final ``CONFIRMED`` one.
    No bundled provider returns it; it is kept in the status vocabulary (and the
    ``_STATUS_RANK`` / ``latest_confirmed_seq`` watermark set) so such a provider
    can be added without a schema change. Do not repurpose it (WI-206).
    """

    PENDING = "pending"
    COMMITTED = "committed"
    CONFIRMED = "confirmed"
    FAILED = "failed"
    RETRYABLE = "retryable"


@dataclass(frozen=True)
class AnchorReceipt:
    receipt_id: uuid.UUID
    provider: str
    merkle_root: bytes
    status: str
    submitted_at: datetime
    receipt_bytes: bytes | None = None
    confirmed_at: datetime | None = None
    target_global_seq: int | None = None
    failure_count: int = 0
    last_error: str | None = None
    project_name: str | None = None
    envelope_version: int | None = None
    hash_algorithm: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": str(self.receipt_id),
            "provider": self.provider,
            "merkle_root": self.merkle_root.hex(),
            "status": self.status,
            "receipt_bytes": self.receipt_bytes.hex() if self.receipt_bytes else None,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "confirmed_at": self.confirmed_at.isoformat() if self.confirmed_at else None,
            "target_global_seq": self.target_global_seq,
            "failure_count": self.failure_count,
            "last_error": self.last_error,
            "project_name": self.project_name,
            "envelope_version": self.envelope_version,
            "hash_algorithm": self.hash_algorithm,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AnchorReceipt:
        receipt_bytes = bytes.fromhex(d["receipt_bytes"]) if d.get("receipt_bytes") else None
        submitted_at = (
            datetime.fromisoformat(d["submitted_at"]) if d.get("submitted_at") else None
        )
        confirmed_at = (
            datetime.fromisoformat(d["confirmed_at"]) if d.get("confirmed_at") else None
        )
        return cls(
            receipt_id=uuid.UUID(d["receipt_id"]),
            provider=d["provider"],
            merkle_root=bytes.fromhex(d["merkle_root"]),
            status=d["status"],
            receipt_bytes=receipt_bytes,
            submitted_at=submitted_at,  # type: ignore[arg-type]
            confirmed_at=confirmed_at,
            target_global_seq=d.get("target_global_seq"),
            failure_count=d.get("failure_count", 0),
            last_error=d.get("last_error"),
            project_name=d.get("project_name"),
            envelope_version=d.get("envelope_version"),
            hash_algorithm=d.get("hash_algorithm"),
        )


@runtime_checkable
class AnchorProvider(Protocol):
    name: str

    def submit(self, merkle_root: bytes) -> AnchorReceipt: ...

    def upgrade(self, receipt: AnchorReceipt) -> AnchorReceipt: ...

    def verify(self, merkle_root: bytes, receipt: AnchorReceipt) -> str: ...


def _now_utc() -> datetime:
    return datetime.now(UTC)


def compute_content_anchor(
    chain_head_hash: bytes,
    project_name: str,
    target_global_seq: int,
    envelope_version: int,
    hash_algorithm: str,
) -> bytes:
    import json

    binding = json.dumps(
        {
            "chain_head_hash": chain_head_hash.hex(),
            "project_name": project_name,
            "target_global_seq": target_global_seq,
            "envelope_version": envelope_version,
            "hash_algorithm": hash_algorithm,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(binding).digest()


def verify_content_anchor(conn: Any, receipt: AnchorReceipt) -> bool:
    if receipt.target_global_seq is None:
        return False
    if receipt.project_name is None or receipt.envelope_version is None:
        return False
    if receipt.hash_algorithm is None:
        return False

    target_seq = receipt.target_global_seq

    rows = conn.execute(
        "SELECT event_id, global_seq, canonical_envelope, signature, "
        "prev_global_event_hash, payload_canonical_hash, hash_alg "
        "FROM events WHERE global_seq <= %s ORDER BY global_seq",
        [target_seq],
    ).fetchall()

    if not rows:
        return False

    by_prev: dict[str, list[dict[str, Any]]] = {}
    genesis_events: list[dict[str, Any]] = []
    for row in rows:
        prev_hash = row["prev_global_event_hash"]
        if prev_hash is None:
            genesis_events.append(row)
        else:
            key = bytes(prev_hash).hex()
            by_prev.setdefault(key, []).append(row)

    if not genesis_events:
        return False

    current: dict[str, Any] | None = genesis_events[0]
    chain_head_hash: bytes | None = None
    prev_chain_head_hash: bytes | None = None
    visited: set[Any] = set()
    found_target = False

    while current is not None:
        eid = current["event_id"]
        if eid in visited:
            return False
        visited.add(eid)

        env = current["canonical_envelope"]
        sig = current["signature"]
        if env is None or sig is None:
            return False

        env_bytes = bytes(env)
        sig_bytes = bytes(sig)

        # BLOCKING-2: Verify that the stored payload_canonical_hash matches a
        # recomputation from canonical_envelope.  payload_canonical_hash is
        # sha256(canonical_envelope) — a denormalised integrity column stored
        # alongside the envelope bytes.  If the two diverge, the event row has
        # been partially tampered with (one changed, the other not).
        #
        # Known limitation: this does NOT detect mutation of the ``payload``
        # jsonb column alone (without touching canonical_envelope).  The
        # ``payload`` column is a separate, denormalised copy of the payload
        # that is also embedded inside canonical_envelope.  An attacker who
        # changes only ``payload`` leaves canonical_envelope — and therefore
        # both the anchor hash and payload_canonical_hash — unchanged.  The
        # anchor will still verify.  Signature verification during replay
        # (which re-derives the canonical envelope from the ``payload`` column
        # and compares) would catch this, but the anchor itself would not.
        stored_pch = current["payload_canonical_hash"]
        if stored_pch is not None:
            event_hash_alg = current["hash_alg"] or "sha-256"
            hash_fn = resolve_hash_function(event_hash_alg)
            recomputed_pch = hash_fn(env_bytes).digest()
            if not _hmac.compare_digest(recomputed_pch, bytes(stored_pch)):
                return False

        chain_head_hash = hashlib.sha256(env_bytes + sig_bytes).digest()

        # BLOCKING-1: Verify chain link integrity.  Each event's
        # prev_global_event_hash must equal the chain_head_hash
        # (sha256(canonical_envelope + signature)) of the immediately
        # preceding event in the global chain.  Without this check the
        # hash links are used only for navigation, not validation — a
        # tampered prev_global_event_hash would go undetected.
        if prev_chain_head_hash is not None:
            prev_global_hash = current["prev_global_event_hash"]
            if prev_global_hash is None:
                return False
            if not _hmac.compare_digest(
                prev_chain_head_hash, bytes(prev_global_hash)
            ):
                return False

        if current["global_seq"] == target_seq:
            found_target = True
            break

        prev_chain_head_hash = chain_head_hash
        successors = by_prev.get(chain_head_hash.hex(), [])
        if len(successors) != 1:
            break
        current = successors[0]

    if not found_target or chain_head_hash is None:
        return False

    expected_anchor = compute_content_anchor(
        chain_head_hash=chain_head_hash,
        project_name=receipt.project_name,
        target_global_seq=target_seq,
        envelope_version=receipt.envelope_version,
        hash_algorithm=receipt.hash_algorithm,
    )

    return _hmac.compare_digest(expected_anchor, receipt.merkle_root)


class FileAnchorProvider:
    """Append-only local-file anchor.

    Not a cryptographic external anchor: the operator who can rewrite the
    event log can also rewrite this file. It provides a second tamper-evident
    copy on a (presumably separate) operator-controlled medium, useful for
    air-gapped deployments where no network anchor is reachable. For external
    verifiability against a backdating operator, use OpenTimestampsProvider
    (Bitcoin-anchored) or RFC3161AnchorProvider (trusted TSA). See Plan 019
    non-goals: this provider is the documented "no-network escape hatch," not
    a substitute for a public anchor.
    """

    name = "file"

    def __init__(self, directory: str) -> None:
        self._dir = Path(directory)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._log_path = self._dir / "anchors.log"

    def submit(self, merkle_root: bytes) -> AnchorReceipt:
        receipt_id = uuid.uuid4()
        submitted_at = _now_utc()
        line = f"{submitted_at.isoformat()} {merkle_root.hex()} {receipt_id}\n"
        with open(self._log_path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        return AnchorReceipt(
            receipt_id=receipt_id,
            provider=self.name,
            merkle_root=merkle_root,
            status=AnchorStatus.CONFIRMED,
            receipt_bytes=line.encode("utf-8"),
            submitted_at=submitted_at,
            confirmed_at=submitted_at,
        )

    def upgrade(self, receipt: AnchorReceipt) -> AnchorReceipt:
        return receipt

    def verify(self, merkle_root: bytes, receipt: AnchorReceipt) -> str:
        if not self._log_path.exists():
            return AnchorStatus.FAILED
        expected_hex = merkle_root.hex()
        with open(self._log_path, encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split(" ")
                if len(parts) != 3:
                    continue
                _ts, root_hex, _rid = parts
                if _hmac.compare_digest(root_hex, expected_hex):
                    return AnchorStatus.CONFIRMED
        return AnchorStatus.FAILED


class RFC3161AnchorProvider:
    name = "rfc3161"

    def __init__(self, config: TSAConfig) -> None:
        self._config = config

    def submit(self, merkle_root: bytes) -> AnchorReceipt:
        submitted_at = _now_utc()
        token = submit_to_tsa(merkle_root, self._config)
        return AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider=self.name,
            merkle_root=merkle_root,
            status=AnchorStatus.CONFIRMED,
            receipt_bytes=token,
            submitted_at=submitted_at,
            confirmed_at=_now_utc(),
        )

    def upgrade(self, receipt: AnchorReceipt) -> AnchorReceipt:
        return receipt

    def verify(self, merkle_root: bytes, receipt: AnchorReceipt) -> str:
        if receipt.receipt_bytes is None:
            return AnchorStatus.FAILED
        if verify_tsa_token(receipt.receipt_bytes, merkle_root, self._config):
            return AnchorStatus.CONFIRMED
        return AnchorStatus.FAILED


def _require_ots() -> Any:
    try:
        import opentimestamps
        import opentimestamps.bitcoin
        import opentimestamps.calendar
        import opentimestamps.core.timestamp
        return opentimestamps
    except ImportError as e:
        raise RegistaError(
            ErrorCode.ANCHOR_PROVIDER_UNAVAILABLE,
            "OpenTimestampsProvider requires the 'opentimestamps' library: "
            "pip install regista[anchoring]",
        ) from e


class OpenTimestampsProvider:
    name = "opentimestamps"

    def __init__(
        self,
        calendar_urls: str | list[str] | None = None,
    ) -> None:
        _require_ots()
        if calendar_urls is None:
            self._calendar_urls = [_DEFAULT_OTS_CALENDAR]
        elif isinstance(calendar_urls, str):
            self._calendar_urls = [calendar_urls]
        else:
            self._calendar_urls = list(calendar_urls)

    def _make_calendar(self, ots: Any) -> Any:
        return ots.calendar.RemoteCalendar(self._calendar_urls[0])

    def submit(self, merkle_root: bytes) -> AnchorReceipt:
        ots = _require_ots()
        calendar = self._make_calendar(ots)
        timestamp = calendar.stamp(merkle_root)
        proof_bytes = timestamp.serialize()
        return AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider=self.name,
            merkle_root=merkle_root,
            status=AnchorStatus.PENDING,
            receipt_bytes=proof_bytes,
            submitted_at=_now_utc(),
        )

    def upgrade(self, receipt: AnchorReceipt) -> AnchorReceipt:
        ots = _require_ots()
        if receipt.receipt_bytes is None:
            return receipt
        try:
            timestamp = ots.core.timestamp.deserialize(BytesIO(receipt.receipt_bytes))
        except (ValueError, OSError) as e:
            log.warning("anchoring.ots_deserialize_failed", error=str(e))
            return receipt
        calendar = self._make_calendar(ots)
        timestamp.upgrade(calendar)
        result = ots.bitcoin.verify_timestamp(timestamp, receipt.merkle_root)
        if result is not None:
            upgraded_proof = timestamp.serialize()
            return dataclasses.replace(
                receipt,
                status=AnchorStatus.CONFIRMED,
                receipt_bytes=upgraded_proof,
                confirmed_at=_now_utc(),
            )
        return receipt

    def verify(self, merkle_root: bytes, receipt: AnchorReceipt) -> str:
        ots = _require_ots()
        if receipt.receipt_bytes is None:
            return AnchorStatus.FAILED
        try:
            timestamp = ots.core.timestamp.deserialize(BytesIO(receipt.receipt_bytes))
        except (ValueError, OSError):
            return AnchorStatus.FAILED
        result = ots.bitcoin.verify_timestamp(timestamp, merkle_root)
        if result is not None:
            return AnchorStatus.CONFIRMED
        if self._has_attestation(timestamp):
            return AnchorStatus.PENDING
        return AnchorStatus.FAILED

    @staticmethod
    def _has_attestation(timestamp: Any) -> bool:
        return bool(getattr(timestamp, "ops", None))


# Status ranking for MAJOR-2: when a conflict occurs in create_anchor_receipt
# and the existing row is 'retryable', a new receipt with a higher-ranked status
# (confirmed/pending) should replace it.  Lower rank = worse.
_STATUS_RANK: dict[str, int] = {
    AnchorStatus.FAILED: 0,
    AnchorStatus.RETRYABLE: 1,
    AnchorStatus.PENDING: 2,
    AnchorStatus.COMMITTED: 3,
    AnchorStatus.CONFIRMED: 4,
}


def _row_to_receipt(row: dict[str, Any]) -> AnchorReceipt:
    return AnchorReceipt(
        receipt_id=row["receipt_id"],
        provider=row["provider"],
        merkle_root=bytes(row["merkle_root"]),
        status=row["status"],
        receipt_bytes=bytes(row["receipt_bytes"]) if row["receipt_bytes"] else None,
        submitted_at=row["submitted_at"],
        confirmed_at=row["confirmed_at"],
        target_global_seq=row["target_global_seq"],
        failure_count=row["failure_count"],
        last_error=row["last_error"],
        project_name=row["project_name"] if "project_name" in row.keys() else None,
        envelope_version=(
            row["envelope_version"] if "envelope_version" in row.keys() else None
        ),
        hash_algorithm=(
            row["hash_algorithm"] if "hash_algorithm" in row.keys() else None
        ),
    )


def create_anchor_receipt(conn: Any, receipt: AnchorReceipt) -> AnchorReceipt:
    """Insert a receipt, returning the persisted row.

    On (provider, merkle_root) conflict the existing row is locked ``FOR UPDATE``
    and, if it is ``retryable`` and the new receipt has a higher-ranked status,
    upgraded in place (MAJOR-2).  The returned receipt always reflects the
    database's current state, so callers can rely on ``result.receipt_id``
    even when the INSERT was skipped.
    """
    row = conn.execute(
        "INSERT INTO anchor_receipts "
        "(receipt_id, provider, merkle_root, status, receipt_bytes, "
        "target_global_seq, submitted_at, confirmed_at, failure_count, last_error, "
        "project_name, envelope_version, hash_algorithm) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) "
        "ON CONFLICT (provider, merkle_root) DO NOTHING RETURNING *",
        [
            receipt.receipt_id,
            receipt.provider,
            receipt.merkle_root,
            receipt.status,
            receipt.receipt_bytes,
            receipt.target_global_seq,
            receipt.submitted_at,
            receipt.confirmed_at,
            receipt.failure_count,
            receipt.last_error,
            receipt.project_name,
            receipt.envelope_version,
            receipt.hash_algorithm,
        ],
    ).fetchone()
    if row is None:
        # MAJOR-1: The INSERT was skipped due to a conflict.  Fetch the
        # existing row (locked FOR UPDATE so we can safely decide whether
        # to upgrade it) instead of discarding the result.
        row = conn.execute(
            "SELECT * FROM anchor_receipts "
            "WHERE provider = %s AND merkle_root = %s "
            "FOR UPDATE",
            [receipt.provider, receipt.merkle_root],
        ).fetchone()
        if row is not None:
            existing_status = row["status"]
            # MAJOR-2: If the existing receipt is retryable and the new
            # receipt carries a higher-ranked status (confirmed/pending),
            # upgrade the row so a successful re-submission is not lost.
            if existing_status == AnchorStatus.RETRYABLE:
                new_rank = _STATUS_RANK.get(receipt.status, 0)
                existing_rank = _STATUS_RANK.get(existing_status, 0)
                if new_rank > existing_rank:
                    update_anchor_receipt(
                        conn,
                        row["receipt_id"],
                        status=receipt.status,
                        receipt_bytes=receipt.receipt_bytes,
                        confirmed_at=receipt.confirmed_at,
                        failure_count=receipt.failure_count,
                        last_error=receipt.last_error,
                    )
                    row = conn.execute(
                        "SELECT * FROM anchor_receipts WHERE receipt_id = %s",
                        [row["receipt_id"]],
                    ).fetchone()
    if row is None:
        # Should not happen — the conflict target guarantees a row exists.
        return receipt
    return _row_to_receipt(row)


def update_anchor_receipt(conn: Any, receipt_id: uuid.UUID, **fields: Any) -> None:
    if not fields:
        return
    allowed = {
        "status", "receipt_bytes", "confirmed_at",
        "failure_count", "last_error", "target_global_seq",
        "project_name", "envelope_version", "hash_algorithm",
    }
    unknown = set(fields) - allowed
    if unknown:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Cannot update anchor receipt fields: {sorted(unknown)}",
        )
    assignments = [f"{k} = %s" for k in fields]
    values = list(fields.values())
    values.append(receipt_id)
    conn.execute(
        f"UPDATE anchor_receipts SET {', '.join(assignments)} WHERE receipt_id = %s",
        values,
    )


def get_anchor_receipt(conn: Any, receipt_id: uuid.UUID) -> AnchorReceipt | None:
    row = conn.execute(
        "SELECT * FROM anchor_receipts WHERE receipt_id = %s",
        [receipt_id],
    ).fetchone()
    if row is None:
        return None
    return _row_to_receipt(row)


def list_anchor_receipts(
    conn: Any,
    *,
    status: str | None = None,
    provider: str | None = None,
    limit: int = 100,
    order: str = "newest",
) -> list[AnchorReceipt]:
    """List receipts. ``order`` is ``"newest"`` (submitted_at DESC, the
    operator-facing default) or ``"target_seq"`` (target_global_seq ASC,
    NULLS LAST) — bundle export uses the latter so a limited fetch keeps the
    receipts a prefix bundle can actually prove (WI-240 review F4)."""
    clauses: list[str] = []
    params: list[Any] = []
    if status is not None:
        clauses.append("status = %s")
        params.append(status)
    if provider is not None:
        clauses.append("provider = %s")
        params.append(provider)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    order_sql = (
        "target_global_seq ASC NULLS LAST"
        if order == "target_seq"
        else "submitted_at DESC"
    )
    params.append(limit)
    rows = conn.execute(
        f"SELECT * FROM anchor_receipts {where} ORDER BY {order_sql} LIMIT %s",
        params,
    ).fetchall()
    return [_row_to_receipt(r) for r in rows]


def latest_confirmed_seq(conn: Any) -> int:
    row = conn.execute(
        "SELECT MAX(target_global_seq) AS max_seq FROM anchor_receipts "
        "WHERE status IN ('pending', 'committed', 'confirmed', 'retryable')"
    ).fetchone()
    return row["max_seq"] or 0


def trigger_anchoring(
    mgr: Any,
    provider: AnchorProvider,
    *,
    batch_size: int = _BATCH_SIZE_DEFAULT,
    project_name: str = "",
) -> AnchorReceipt | None:
    # BLOCKING-3: Insert a 'pending' receipt *before* submitting to the
    # provider.  If the provider submission succeeds but the subsequent
    # update transaction fails, the pending receipt is already persisted
    # and can be retried — the external anchor is never permanently lost.
    pending_receipt_id = uuid.uuid4()

    # Step 1: Lock, select batch, compute anchor, insert pending receipt.
    with mgr.transaction() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(%s)", [_ANCHORING_LOCK_ID])
        last_seq = latest_confirmed_seq(conn)
        rows = conn.execute(
            "SELECT global_seq, canonical_envelope, signature "
            "FROM events WHERE global_seq > %s ORDER BY global_seq LIMIT %s",
            [last_seq, batch_size],
        ).fetchall()
        if not rows:
            return None

        last_global_seq = rows[-1]["global_seq"]
        target_env = rows[-1]["canonical_envelope"]
        target_sig = rows[-1]["signature"]
        if target_env is None or target_sig is None:
            return None

        chain_head_hash = hashlib.sha256(
            bytes(target_env) + bytes(target_sig)
        ).digest()
        anchor_value = compute_content_anchor(
            chain_head_hash=chain_head_hash,
            project_name=project_name,
            target_global_seq=last_global_seq,
            envelope_version=_DEFAULT_ENVELOPE_VERSION,
            hash_algorithm=_DEFAULT_HASH_ALGORITHM,
        )

        pending_receipt = AnchorReceipt(
            receipt_id=pending_receipt_id,
            provider=getattr(provider, "name", "unknown"),
            merkle_root=anchor_value,
            status=AnchorStatus.PENDING,
            submitted_at=_now_utc(),
            target_global_seq=last_global_seq,
            project_name=project_name,
            envelope_version=_DEFAULT_ENVELOPE_VERSION,
            hash_algorithm=_DEFAULT_HASH_ALGORITHM,
        )
        # create_anchor_receipt may return a different receipt_id if a
        # conflict occurred (e.g. a stale pending/retryable row from a
        # previous crashed run).  Use the persisted receipt_id for updates.
        persisted = create_anchor_receipt(conn, pending_receipt)
        pending_receipt_id = persisted.receipt_id

    # Step 2: Submit to the provider (outside the transaction).
    try:
        receipt = provider.submit(anchor_value)
        receipt = dataclasses.replace(
            receipt,
            receipt_id=pending_receipt_id,
            target_global_seq=last_global_seq,
            project_name=project_name,
            envelope_version=_DEFAULT_ENVELOPE_VERSION,
            hash_algorithm=_DEFAULT_HASH_ALGORITHM,
        )
    except RegistaError:
        raise
    except Exception as e:
        # Step 3a: Provider failed — update the pending receipt to retryable.
        # Increment the existing failure_count rather than resetting to 1,
        # so a retryable receipt that already failed N times retains its
        # count and can eventually exhaust max_failures.
        existing_failure_count = persisted.failure_count
        with mgr.transaction() as conn:
            update_anchor_receipt(
                conn,
                pending_receipt_id,
                status=AnchorStatus.RETRYABLE,
                failure_count=existing_failure_count + 1,
                last_error=str(e)[:500],
            )
        log.error(
            "anchoring.submit_failed",
            error=str(e),
            provider=getattr(provider, "name", "unknown"),
        )
        return AnchorReceipt(
            receipt_id=pending_receipt_id,
            provider=getattr(provider, "name", "unknown"),
            merkle_root=anchor_value,
            status=AnchorStatus.RETRYABLE,
            submitted_at=_now_utc(),
            target_global_seq=last_global_seq,
            failure_count=1,
            last_error=str(e)[:500],
            project_name=project_name,
            envelope_version=_DEFAULT_ENVELOPE_VERSION,
            hash_algorithm=_DEFAULT_HASH_ALGORITHM,
        )

    # Step 3b: Provider succeeded — update the pending receipt with the result.
    with mgr.transaction() as conn:
        update_anchor_receipt(
            conn,
            pending_receipt_id,
            status=receipt.status,
            receipt_bytes=receipt.receipt_bytes,
            confirmed_at=receipt.confirmed_at,
        )
    log.info(
        "anchoring.receipt_created",
        receipt_id=str(receipt.receipt_id),
        provider=receipt.provider,
        status=receipt.status,
        last_global_seq=last_global_seq,
    )
    return receipt


def upgrade_pending_anchors(
    conn: Any,
    provider: AnchorProvider,
    *,
    max_iterations: int = 100,
) -> int:
    rows = conn.execute(
        "SELECT * FROM anchor_receipts WHERE provider = %s AND status = 'pending' "
        "ORDER BY submitted_at LIMIT %s",
        [provider.name, max_iterations],
    ).fetchall()
    upgraded = 0
    for row in rows:
        receipt = _row_to_receipt(row)
        updated = provider.upgrade(receipt)
        if updated.status != receipt.status:
            fields: dict[str, Any] = {"status": updated.status}
            if updated.receipt_bytes != receipt.receipt_bytes:
                fields["receipt_bytes"] = updated.receipt_bytes
            if updated.confirmed_at != receipt.confirmed_at:
                fields["confirmed_at"] = updated.confirmed_at
            update_anchor_receipt(conn, receipt.receipt_id, **fields)
            if updated.status == AnchorStatus.CONFIRMED:
                upgraded += 1
                log.info(
                    "anchoring.receipt_upgraded",
                    receipt_id=str(updated.receipt_id),
                    provider=updated.provider,
                )
    return upgraded


def retry_failed_anchors(
    mgr: Any,
    provider: AnchorProvider,
    *,
    max_iterations: int = 100,
    max_failures: int = 5,
) -> int:
    with mgr.transaction() as conn:
        conn.execute("SELECT pg_advisory_xact_lock(%s)", [_ANCHORING_LOCK_ID])
        rows = conn.execute(
            "SELECT * FROM anchor_receipts "
            "WHERE provider = %s AND status = 'retryable' "
            "AND failure_count < %s "
            "ORDER BY submitted_at LIMIT %s",
            [provider.name, max_failures, max_iterations],
        ).fetchall()

    if not rows:
        return 0

    retried = 0
    for row in rows:
        receipt = _row_to_receipt(row)
        try:
            new_receipt = provider.submit(receipt.merkle_root)
            with mgr.transaction() as conn:
                update_anchor_receipt(
                    conn,
                    receipt.receipt_id,
                    status=new_receipt.status,
                    receipt_bytes=new_receipt.receipt_bytes,
                    confirmed_at=new_receipt.confirmed_at,
                    failure_count=0,
                    last_error=None,
                )
            retried += 1
            log.info(
                "anchoring.retry_succeeded",
                receipt_id=str(receipt.receipt_id),
                provider=receipt.provider,
            )
        except Exception as e:
            new_count = receipt.failure_count + 1
            new_status = (
                AnchorStatus.FAILED if new_count >= max_failures
                else AnchorStatus.RETRYABLE
            )
            with mgr.transaction() as conn:
                update_anchor_receipt(
                    conn,
                    receipt.receipt_id,
                    status=new_status,
                    failure_count=new_count,
                    last_error=str(e)[:500],
                )
            log.error(
                "anchoring.retry_failed",
                error=str(e),
                receipt_id=str(receipt.receipt_id),
            )
    return retried
