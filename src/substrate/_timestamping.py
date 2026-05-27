from __future__ import annotations

import hashlib
import hmac as _hmac
import os
import urllib.request
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

_SUPPORTED_HASH_ALGOS = {"sha256", "sha384", "sha512"}


def _hash_data(data: bytes, algo: str) -> bytes:
    if algo not in _SUPPORTED_HASH_ALGOS:
        raise ValueError(f"Unsupported hash algorithm: {algo!r}")
    return hashlib.new(algo, data).digest()


def _require_asn1crypto():
    try:
        import asn1crypto.cms
        import asn1crypto.tsp  # noqa: F401
    except ImportError as e:
        from ._errors import ErrorCode, SubstrateError

        raise SubstrateError(
            ErrorCode.TSA_SUBMISSION_FAILED,
            "RFC 3161 timestamping requires asn1crypto: pip install substrate[timestamping]",
        ) from e


@dataclass(frozen=True)
class TSAConfig:
    tsa_url: str
    tsa_cert_path: str | None = None
    """Path to a trusted TSA certificate (PEM or DER).

    RESERVED FOR FUTURE USE — this field is accepted so that existing
    configurations are not broken, but it is not currently read by any
    substrate code.  Full TSA-signature verification against a configured
    trust anchor is tracked in BC-229 and has not yet been implemented.
    Setting this field has no security effect in the current release.
    """
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


def _build_tsr(data: bytes, config: TSAConfig, nonce: int | None = None) -> bytes:
    # Produces a DER-encoded RFC 3161 TimeStampReq via asn1crypto. Honors
    # config.hash_algorithm and always includes a nonce for replay protection.
    _require_asn1crypto()
    from asn1crypto import tsp

    digest = _hash_data(data, config.hash_algorithm)
    if nonce is None:
        nonce = int.from_bytes(os.urandom(8), "big")
    request = tsp.TimeStampReq(
        {
            "version": "v1",
            "message_imprint": tsp.MessageImprint(
                {
                    "hash_algorithm": {"algorithm": config.hash_algorithm},
                    "hashed_message": digest,
                }
            ),
            "nonce": nonce,
            "cert_req": True,
        }
    )
    return request.dump()


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
        return resp.read(1_000_000)


def _parse_tst_info(token: bytes):
    # Accepts either a full TimeStampResp (status + timeStampToken) or just the
    # timeStampToken (a CMS ContentInfo). Returns the parsed TSTInfo or raises.
    from asn1crypto import cms, tsp

    try:
        resp = tsp.TimeStampResp.load(token)
        status = int(resp["status"]["status"])
        if status not in (0, 1):  # granted / grantedWithMods
            raise ValueError(f"TSA status {status}")
        ci = resp["time_stamp_token"]
    except Exception:
        ci = cms.ContentInfo.load(token)
    if ci["content_type"].native != "signed_data":
        raise ValueError("Token is not CMS signed-data")
    encap = ci["content"]["encap_content_info"]
    if encap["content_type"].native != "tst_info":
        raise ValueError("Encapsulated content is not TSTInfo")
    content = encap["content"]
    # asn1crypto returns this as a ParsableOctetString; .parsed gives the
    # already-decoded TSTInfo. Fall back to raw bytes for defensive parsing.
    parsed = getattr(content, "parsed", None)
    if isinstance(parsed, tsp.TSTInfo):
        return parsed
    return tsp.TSTInfo.load(bytes(content))


def verify_tsa_token(token: bytes, data: bytes, config: TSAConfig) -> bool:
    # Cryptographic verification of the RFC 3161 message imprint embedded in
    # the TSA response. Parses the CMS/PKCS#7 envelope, extracts TSTInfo, and
    # constant-time-compares the embedded hash to a fresh hash of `data` using
    # the algorithm declared by the TSA.
    #
    # Note: this does NOT verify the TSA's signature on the token or validate
    # the TSA certificate chain. Full signature/chain validation is tracked
    # separately and requires a configured trust anchor (see BC-229).
    if not token:
        return False
    _require_asn1crypto()
    try:
        tst_info = _parse_tst_info(token)
        imprint = tst_info["message_imprint"]
        algo_name = imprint["hash_algorithm"]["algorithm"].native
        if algo_name not in _SUPPORTED_HASH_ALGOS:
            return False
        expected = _hash_data(data, algo_name)
        return _hmac.compare_digest(bytes(imprint["hashed_message"]), expected)
    except Exception:
        import structlog
        structlog.get_logger().warning(
            "timestamping.verify_tsa_token_failed",
            exc_info=True,
        )
        return False


def trigger_timestamping(conn, config: TSAConfig) -> TimestampBatch | None:
    import structlog

    log = structlog.get_logger()
    batch_row = conn.execute(
        "SELECT MAX(last_global_seq) AS max_seq FROM tsp_batches WHERE status = 'confirmed'"
    ).fetchone()
    last_confirmed_seq = batch_row["max_seq"] or 0

    rows = conn.execute(
        "SELECT event_id, global_seq, timestamp FROM events "
        "WHERE global_seq > %s ORDER BY global_seq LIMIT %s",
        [last_confirmed_seq, config.batch_size],
    ).fetchall()
    if not rows:
        return None

    event_ids = [r["event_id"] for r in rows]
    merkle_root = compute_merkle_root(event_ids)
    first_global_seq = rows[0]["global_seq"]
    last_global_seq = rows[-1]["global_seq"]
    first_event_at = rows[0]["timestamp"]
    last_event_at = rows[-1]["timestamp"]

    batch_id = uuid.uuid4()
    conn.execute(
        "INSERT INTO tsp_batches "
        "(batch_id, merkle_root, first_global_seq, last_global_seq, "
        "first_event_at, last_event_at, event_count, status, submitted_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now())",
        [
            batch_id,
            merkle_root,
            first_global_seq,
            last_global_seq,
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
        first_seq=first_global_seq,
        last_seq=last_global_seq,
    )

    now_utc = datetime.now(UTC)
    try:
        token = submit_to_tsa(merkle_root, config)
        confirmed_at = datetime.now(UTC)
        # Derive tsa_timestamp from the token's TSTInfo gen_time when possible.
        tsa_timestamp: datetime | None = None
        try:
            tsa_timestamp = _parse_tst_info(token)["gen_time"].native
            if tsa_timestamp is not None and tsa_timestamp.tzinfo is None:
                tsa_timestamp = tsa_timestamp.replace(tzinfo=UTC)
        except Exception:
            import structlog
            structlog.get_logger().warning(
                "timestamping.tsa_token_gen_time_parse_failed",
                exc_info=True,
            )
            tsa_timestamp = confirmed_at
        conn.execute(
            "UPDATE tsp_batches SET status = 'confirmed', "
            "tsa_token = %s, tsa_timestamp = %s, confirmed_at = now() "
            "WHERE batch_id = %s",
            [token, tsa_timestamp, batch_id],
        )
        return TimestampBatch(
            batch_id=batch_id,
            event_ids=event_ids,
            merkle_root=merkle_root,
            tsa_token=token,
            tsa_timestamp=tsa_timestamp,
            submitted_at=now_utc,
            confirmed_at=confirmed_at,
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
            submitted_at=now_utc,
            confirmed_at=None,
            status="failed",
            error_message=str(e)[:500],
        )


def _rehydrate_event_ids(conn, first_global_seq: int, last_global_seq: int) -> list[uuid.UUID]:
    if first_global_seq > last_global_seq:
        return []
    rows = conn.execute(
        "SELECT event_id FROM events "
        "WHERE global_seq >= %s AND global_seq <= %s ORDER BY global_seq",
        [first_global_seq, last_global_seq],
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
            conn, r["first_global_seq"], r["last_global_seq"]
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
