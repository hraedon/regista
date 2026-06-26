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
        from ._errors import ErrorCode, RegistaError

        raise RegistaError(
            ErrorCode.TSA_SUBMISSION_FAILED,
            "RFC 3161 timestamping requires asn1crypto: pip install regista[timestamping]",
        ) from e


@dataclass(frozen=True)
class TSAConfig:
    tsa_url: str
    tsa_cert_path: str | None = None
    """Path to a trusted TSA certificate (PEM or DER).

    When set, ``verify_tsa_token`` will verify the CMS signature on the
    TSA token against this certificate (the trust anchor).  The signer's
    certificate in the token must either *be* this certificate or chain
    to it via a single intermediate.
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
            from ._errors import ErrorCode, RegistaError

            raise RegistaError(
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


def _load_trust_anchor(cert_path: str):
    """Load a trust-anchor certificate from *cert_path* (PEM or DER).

    Returns an ``asn1crypto.x509.Certificate``.
    """
    from asn1crypto import pem, x509

    raw = open(cert_path, "rb").read()
    if pem.detect(raw):
        _, _, der = pem.unarmor(raw)
    else:
        der = raw
    return x509.Certificate.load(der)


def verify_tsa_signature(
    token: bytes,
    trust_anchor,
) -> tuple[bool, str]:
    """Verify the CMS signature on an RFC 3161 TSA token.

    Parameters
    ----------
    token:
        Raw TSA response bytes (TimeStampResp or ContentInfo).
    trust_anchor:
        An ``asn1crypto.x509.Certificate`` to trust as the TSA root.

    Returns
    -------
    (ok, detail)
        *ok* is ``True`` when the signature is valid and the signer
        chains to *trust_anchor*.  *detail* describes the failure reason
        when *ok* is ``False``.
    """
    try:
        ci = _extract_content_info(token)
        signed_data = ci["content"]
        signers = signed_data["signer_infos"]
        if len(signers) == 0:
            return False, "No signer info in CMS SignedData"
        if len(signers) > 1:
            return False, f"Expected 1 signer, got {len(signers)}"

        signer = signers[0]
        signer_cert = _find_signer_cert(signed_data, signer)
        if signer_cert is None:
            return False, "Signer certificate not found in token"

        # Verify the signer's certificate chains to the trust anchor
        chain_ok, chain_detail = _verify_cert_chain(signer_cert, signed_data, trust_anchor)
        if not chain_ok:
            return False, f"Certificate chain validation failed: {chain_detail}"

        # Verify the CMS signature (over signed attributes or content digest)
        sig_ok, sig_detail = _verify_cms_signature(signer, signed_data, signer_cert)
        if not sig_ok:
            return False, f"CMS signature verification failed: {sig_detail}"

        return True, "TSA signature verified against trust anchor"
    except Exception as exc:
        return False, f"TSA signature verification error: {exc}"


def _extract_content_info(token: bytes):
    """Parse a TSA token into a CMS ContentInfo, handling TimeStampResp wrapping."""
    from asn1crypto import cms, tsp

    try:
        resp = tsp.TimeStampResp.load(token)
        status = int(resp["status"]["status"])
        if status not in (0, 1):
            raise ValueError(f"TSA status {status}")
        return resp["time_stamp_token"]
    except Exception:
        return cms.ContentInfo.load(token)


def _find_signer_cert(signed_data, signer):
    """Locate the signer's certificate in the SignedData certificates bag."""
    from asn1crypto import cms

    sid = signer["sid"]
    certs = signed_data["certificates"]
    sid = signer["sid"]

    for cert_choice in certs:
        if cert_choice.name == "certificate":
            cert = cert_choice.chosen
            if isinstance(sid, cms.IssuerAndSerialNumber):
                if (
                    cert.issuer == sid["issuer"]
                    and cert.serial_number == sid["serial_number"]
                ):
                    return cert
            else:
                # SubjectKeyIdentifier — compare raw bytes
                try:
                    ext = cert.key_identifier_value
                    if ext and bytes(ext) == bytes(sid):
                        return cert
                except Exception:
                    pass

    # Fallback: if only one certificate, assume it's the signer
    real_certs = [c.chosen for c in certs if c.name == "certificate"]
    if len(real_certs) == 1:
        return real_certs[0]
    return None


def _verify_cert_chain(signer_cert, signed_data, trust_anchor) -> tuple[bool, str]:
    """Verify that *signer_cert* chains to *trust_anchor*.

    Supports a direct match (signer == anchor) or a single-intermediate chain.
    """
    # Direct match: signer IS the trust anchor
    if (
        signer_cert.subject == trust_anchor.subject
        and signer_cert.serial_number == trust_anchor.serial_number
    ):
        try:
            _verify_cert_signature(signer_cert, trust_anchor)
            return True, "Direct match with trust anchor"
        except Exception as exc:
            return False, f"Signer cert signature invalid: {exc}"

    # Try single-intermediate chain: signer <- intermediate, intermediate <- anchor
    certs = signed_data["certificates"]
    intermediates = [
        c.chosen for c in certs if c.name == "certificate" and c.chosen is not signer_cert
    ]

    for inter in intermediates:
        if (
            inter.subject == trust_anchor.subject
            and inter.serial_number == trust_anchor.serial_number
        ):
            try:
                _verify_cert_signature(signer_cert, inter)
                return True, "Signer chains to trust anchor via intermediate"
            except Exception:
                continue

    return False, "Signer certificate does not chain to trust anchor"


def _verify_cert_signature(child_cert, parent_cert) -> None:
    """Verify that *parent_cert* signed *child_cert*.

    Uses the ``cryptography`` library for the actual RSA/ECDSA verification.
    Raises on failure.
    """
    from cryptography import x509 as crypto_x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    parent_crypto = crypto_x509.load_der_x509_certificate(parent_cert.dump())
    child_crypto = crypto_x509.load_der_x509_certificate(child_cert.dump())

    parent_pub = parent_crypto.public_key()
    signature = child_crypto.signature
    tbs_der = child_crypto.tbs_certificate_bytes

    # Determine hash algorithm from the signature OID
    sig_oid = child_crypto.signature_algorithm_oid
    sig_oid_str = sig_oid.dotted_string

    # RSA OIDs: 1.2.840.113549.1.1.11 (sha256RSA), .12 (sha384RSA), .13 (sha512RSA)
    # ECDSA OIDs: 1.2.840.10045.4.3.2 (ecdsa-with-SHA256), .3 (SHA384), .4 (SHA512)
    if sig_oid_str in ("1.2.840.113549.1.1.11",):
        parent_pub.verify(signature, tbs_der, padding.PKCS1v15(), hashes.SHA256())
    elif sig_oid_str in ("1.2.840.113549.1.1.12",):
        parent_pub.verify(signature, tbs_der, padding.PKCS1v15(), hashes.SHA384())
    elif sig_oid_str in ("1.2.840.113549.1.1.13",):
        parent_pub.verify(signature, tbs_der, padding.PKCS1v15(), hashes.SHA512())
    elif sig_oid_str in ("1.2.840.10045.4.3.2",):
        parent_pub.verify(signature, tbs_der, ec.ECDSA(hashes.SHA256()))
    elif sig_oid_str in ("1.2.840.10045.4.3.3",):
        parent_pub.verify(signature, tbs_der, ec.ECDSA(hashes.SHA384()))
    elif sig_oid_str in ("1.2.840.10045.4.3.4",):
        parent_pub.verify(signature, tbs_der, ec.ECDSA(hashes.SHA512()))
    else:
        raise ValueError(f"Unsupported cert signature OID: {sig_oid_str}")


def _verify_cms_signature(signer, signed_data, signer_cert) -> tuple[bool, str]:
    """Verify the PKCS#7 signature in *signer* against *signer_cert*."""
    sig_algo = signer["signature_algorithm"]
    signature_bytes = bytes(signer["signature"])
    signed_attrs = signer["signed_attrs"]

    # RFC 3852: when signed_attrs are present, the signature is over the
    # DER encoding of the signed attributes (with the IMPLICIT [0] tag).
    if signed_attrs is not None and len(signed_attrs) > 0:
        # Re-encode with IMPLICIT tag set as required by CMS
        data_to_verify = signed_attrs.untag().dump()
    else:
        # No signed attrs — signature over the encapsulated content digest
        encap = signed_data["encap_content_info"]["content"]
        data_to_verify = bytes(encap) if encap else b""

    # Dispatch verification based on algorithm
    algo_name = sig_algo["algorithm"].native

    try:
        from cryptography import x509 as crypto_x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, padding

        crypto_cert = crypto_x509.load_der_x509_certificate(signer_cert.dump())
        crypto_pub = crypto_cert.public_key()

        # Determine hash from OID
        sig_oid = crypto_cert.signature_algorithm_oid.dotted_string
        hash_map = {
            "1.2.840.113549.1.1.11": hashes.SHA256,
            "1.2.840.113549.1.1.12": hashes.SHA384,
            "1.2.840.113549.1.1.13": hashes.SHA512,
            "1.2.840.10045.4.3.2": hashes.SHA256,
            "1.2.840.10045.4.3.3": hashes.SHA384,
            "1.2.840.10045.4.3.4": hashes.SHA512,
        }
        hash_cls = hash_map.get(sig_oid, hashes.SHA256)()

        if "rsa" in algo_name.lower():
            if "pss" in algo_name.lower():
                crypto_pub.verify(
                    signature_bytes, data_to_verify,
                    padding.PSS(mgf=padding.MGF1(hash_cls), salt_length=padding.PSS.MAX_LENGTH),
                    hash_cls,
                )
            else:
                crypto_pub.verify(signature_bytes, data_to_verify, padding.PKCS1v15(), hash_cls)
        elif "ecdsa" in algo_name.lower() or "ec" in algo_name.lower():
            crypto_pub.verify(signature_bytes, data_to_verify, ec.ECDSA(hash_cls))
        else:
            return False, f"Unsupported signature algorithm: {algo_name}"

        return True, "CMS signature valid"
    except Exception as exc:
        return False, f"Signature verification failed: {exc}"


def verify_tsa_token(token: bytes, data: bytes, config: TSAConfig) -> bool:
    """Cryptographic verification of an RFC 3161 TSA token.

    Checks the message imprint hash and, when ``config.tsa_cert_path`` is
    set, verifies the CMS signature against the trust anchor.
    """
    ok, _detail = verify_tsa_token_full(token, data, config)
    return ok


def verify_tsa_token_full(
    token: bytes, data: bytes, config: TSAConfig
) -> tuple[bool, str]:
    """Full verification of an RFC 3161 TSA token.

    Returns ``(ok, detail)`` where *detail* describes the failure reason
    or the verification method on success.
    """
    if not token:
        return False, "Empty token"
    _require_asn1crypto()
    try:
        tst_info = _parse_tst_info(token)
        imprint = tst_info["message_imprint"]
        algo_name = imprint["hash_algorithm"]["algorithm"].native
        if algo_name not in _SUPPORTED_HASH_ALGOS:
            return False, f"Unsupported hash algorithm: {algo_name}"
        expected = _hash_data(data, algo_name)
        if not _hmac.compare_digest(bytes(imprint["hashed_message"]), expected):
            return False, "Message imprint mismatch"

        # When a trust anchor is configured, also verify the CMS signature
        if config.tsa_cert_path:
            trust_anchor = _load_trust_anchor(config.tsa_cert_path)
            sig_ok, sig_detail = verify_tsa_signature(token, trust_anchor)
            if not sig_ok:
                return False, sig_detail
            return True, f"Imprint OK; {sig_detail}"

        return True, "Imprint verified (no trust anchor — signature not checked)"
    except Exception:
        import structlog
        structlog.get_logger().warning(
            "timestamping.verify_tsa_token_failed",
            exc_info=True,
        )
        return False, "Verification failed with exception"


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
