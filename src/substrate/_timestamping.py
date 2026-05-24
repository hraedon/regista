from __future__ import annotations

import hashlib
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


def submit_to_tsa(data: bytes, config: TSAConfig) -> bytes:
    raise NotImplementedError("submit_to_tsa requires cryptography dependencies")


def verify_tsa_token(token: bytes, data: bytes, config: TSAConfig) -> bool:
    raise NotImplementedError("verify_tsa_token requires cryptography dependencies")


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
        result.append(
            TimestampBatch(
                batch_id=r["batch_id"],
                event_ids=[],
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
