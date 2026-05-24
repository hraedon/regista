from __future__ import annotations

import hashlib
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class TSAConfig:
    tsa_url: str
    tsa_cert_path: str | None = None
    batch_size: int = 1000
    interval_seconds: float = 3600.0
    hash_algorithm: str = "sha256"


@dataclass(frozen=True)
class TimestampBatch:
    batch_id: uuid.UUID
    event_ids: list[uuid.UUID]
    merkle_root: bytes
    tsa_token: bytes | None
    tsa_timestamp: datetime | None
    submitted_at: datetime | None
    confirmed_at: datetime | None
    status: str  # pending | confirmed | failed
    error_message: str | None = None

    def to_dict(self) -> dict:
        return {
            "batch_id": str(self.batch_id),
            "event_ids": [str(e) for e in self.event_ids],
            "merkle_root": self.merkle_root.hex(),
            "tsa_token": self.tsa_token.hex() if self.tsa_token else None,
            "tsa_timestamp": self.tsa_timestamp.isoformat() if self.tsa_timestamp else None,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "confirmed_at": self.confirmed_at.isoformat() if self.confirmed_at else None,
            "status": self.status,
            "error_message": self.error_message,
        }


def _hash_pair(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(left + right).digest()


def compute_merkle_root(event_ids: list[uuid.UUID]) -> bytes:
    if not event_ids:
        raise ValueError("event_ids must not be empty")
    sorted_ids = sorted(event_ids, key=lambda u: u.bytes)
    hashes = [hashlib.sha256(u.bytes).digest() for u in sorted_ids]
    while len(hashes) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(hashes), 2):
            left = hashes[i]
            right = hashes[i + 1] if i + 1 < len(hashes) else left
            next_level.append(_hash_pair(left, right))
        hashes = next_level
    return hashes[0]


def merkle_proof(event_ids: list[uuid.UUID], target: uuid.UUID) -> list[tuple[int, bytes]]:
    sorted_ids = sorted(event_ids, key=lambda u: u.bytes)
    try:
        target_idx = sorted_ids.index(target)
    except ValueError:
        raise ValueError("target not in event_ids")
    hashes = [hashlib.sha256(u.bytes).digest() for u in sorted_ids]
    proof: list[tuple[int, bytes]] = []
    index = target_idx
    while len(hashes) > 1:
        next_level: list[bytes] = []
        for i in range(0, len(hashes), 2):
            left = hashes[i]
            right = hashes[i + 1] if i + 1 < len(hashes) else left
            if i == index or i + 1 == index:
                sibling = right if index == i else left
                proof.append((0 if index == i else 1, sibling))
                index = i // 2
            next_level.append(_hash_pair(left, right))
        hashes = next_level
    return proof


def verify_merkle_proof(root: bytes, target: uuid.UUID, proof: list[tuple[int, bytes]]) -> bool:
    current = hashlib.sha256(target.bytes).digest()
    for direction, sibling in proof:
        if direction == 0:
            current = _hash_pair(current, sibling)
        else:
            current = _hash_pair(sibling, current)
    return current == root


def _build_tsr(data: bytes, config: TSAConfig) -> bytes:
    algo_oid = b"\x06\x08\x60\x86\x48\x01\x65\x03\x04\x02\x01"
    digest = hashlib.sha256(data).digest()
    algo_seq = b"\x30\x0d" + algo_oid + b"\x05\x00"
    digest_oct = b"\x04\x20" + digest
    mi_seq = b"\x30" + bytes([len(algo_seq) + len(digest_oct)]) + algo_seq + digest_oct
    req_info = b"\x30" + bytes([len(mi_seq) + 3]) + b"\x02\x01\x01" + mi_seq
    cert_req = b"\x01\x01\xff"
    total_len = len(req_info) + 3 + len(cert_req)
    return b"\x30" + bytes([total_len]) + req_info + b"\xa0\x03" + cert_req


def submit_to_tsa(data: bytes, config: TSAConfig) -> bytes:
    tsr = _build_tsr(data, config)
    req = urllib.request.Request(
        config.tsa_url,
        data=tsr,
        headers={"Content-Type": "application/timestamp-query"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        if resp.status != 200:
            from ._errors import ErrorCode, SubstrateError

            raise SubstrateError(
                ErrorCode.TSA_SUBMISSION_FAILED,
                f"TSA returned HTTP {resp.status}",
            )
        return resp.read()


def verify_tsa_token(token: bytes, data: bytes, config: TSAConfig) -> bool:
    if not token or len(token) < 16:
        return False
    digest = hashlib.sha256(data).digest()
    idx = 0
    while idx < len(token) - len(digest):
        if token[idx : idx + len(digest)] == digest:
            return True
        idx += 1
    return False


def trigger_timestamping(conn, config: TSAConfig) -> TimestampBatch | None:
    import structlog

    log = structlog.get_logger()
    row = conn.execute(
        "SELECT MAX(last_event_seq) AS max_seq FROM work_items_current"
    ).fetchone()
    max_seq = row["max_seq"] or 0

    batch_row = conn.execute(
        "SELECT MAX(last_event_seq) AS max_seq FROM tsp_batches WHERE status = 'confirmed'"
    ).fetchone()
    last_confirmed_seq = batch_row["max_seq"] or 0

    if last_confirmed_seq >= max_seq:
        return None

    start_seq = last_confirmed_seq + 1
    rows = conn.execute(
        "SELECT event_id, event_seq, timestamp FROM events "
        "WHERE event_seq >= %s ORDER BY event_seq LIMIT %s",
        [start_seq, config.batch_size],
    ).fetchall()
    if not rows:
        return None

    event_ids = [r["event_id"] for r in rows]
    merkle_root = compute_merkle_root(event_ids)
    first_event_seq = rows[0]["event_seq"]
    last_event_seq = rows[-1]["event_seq"]
    first_event_at = rows[0]["timestamp"]
    last_event_at = rows[-1]["timestamp"]

    batch_id = uuid.uuid4()
    conn.execute(
        "INSERT INTO tsp_batches "
        "(batch_id, merkle_root, first_event_seq, last_event_seq, "
        "first_event_at, last_event_at, event_count, status, submitted_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now())",
        [
            batch_id,
            merkle_root,
            first_event_seq,
            last_event_seq,
            first_event_at,
            last_event_at,
            len(rows),
            "pending",
        ],
    )
    log.info(
        "timestamping.batch_created",
        batch_id=str(batch_id),
        event_count=len(rows),
        first_seq=first_event_seq,
        last_seq=last_event_seq,
    )

    try:
        token = submit_to_tsa(merkle_root, config)
        conn.execute(
            "UPDATE tsp_batches SET status = 'confirmed', tsa_token = %s, confirmed_at = now() "
            "WHERE batch_id = %s",
            [token, batch_id],
        )
        return TimestampBatch(
            batch_id=batch_id,
            event_ids=event_ids,
            merkle_root=merkle_root,
            tsa_token=token,
            tsa_timestamp=datetime.now(),
            submitted_at=datetime.now(),
            confirmed_at=datetime.now(),
            status="confirmed",
        )
    except Exception as e:
        conn.execute(
            "UPDATE tsp_batches SET status = 'failed', error_message = %s WHERE batch_id = %s",
            [str(e)[:500], batch_id],
        )
        log.error("timestamping.tsa_failed", batch_id=str(batch_id), error=str(e))
        return TimestampBatch(
            batch_id=batch_id,
            event_ids=event_ids,
            merkle_root=merkle_root,
            tsa_token=None,
            tsa_timestamp=None,
            submitted_at=datetime.now(),
            confirmed_at=None,
            status="failed",
            error_message=str(e)[:500],
        )


def _rehydrate_event_ids(conn, first_seq: int, last_seq: int) -> list[uuid.UUID]:
    if first_seq > last_seq:
        return []
    rows = conn.execute(
        "SELECT event_id FROM events "
        "WHERE event_seq >= %s AND event_seq <= %s ORDER BY event_seq",
        [first_seq, last_seq],
    ).fetchall()
    return [r["event_id"] for r in rows]


def list_batches(conn, status: str | None = None) -> list[TimestampBatch]:
    if status:
        rows = conn.execute(
            "SELECT * FROM tsp_batches WHERE status = %s ORDER BY created_at DESC",
            [status],
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM tsp_batches ORDER BY created_at DESC"
        ).fetchall()
    result: list[TimestampBatch] = []
    for r in rows:
        event_ids = _rehydrate_event_ids(
            conn, r["first_event_seq"], r["last_event_seq"]
        )
        result.append(
            TimestampBatch(
                batch_id=r["batch_id"],
                event_ids=event_ids,
                merkle_root=bytes(r["merkle_root"]),
                tsa_token=bytes(r["tsa_token"]) if r["tsa_token"] else None,
                tsa_timestamp=r["tsa_timestamp"],
                submitted_at=r["submitted_at"],
                confirmed_at=r["confirmed_at"],
                status=r["status"],
                error_message=r["error_message"],
            )
        )
    return result
