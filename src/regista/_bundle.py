from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import structlog

from ._anchoring import AnchorReceipt, compute_content_anchor
from ._archive_segments import _verify_global_chain, _verify_work_item_chains
from ._connection import ConnectionManager
from ._errors import ErrorCode, RegistaError
from ._signing_scheme import get_scheme, resolve_hash_function
from ._types import Event

log = structlog.get_logger()

# v2 adds the principal public-key registry to the bundle so event signatures
# on asymmetric schemes are verified offline (signer binding). v1 bundles are
# still accepted; their signature check is reported as skipped.
_BUNDLE_FORMAT_VERSION = 2
_SUPPORTED_FORMAT_VERSIONS = frozenset({1, 2})

# Output names that imply a compressed/archive container. An audit bundle is a
# canonical JSON document; writing plain JSON under one of these names hands an
# auditor a file that `tar -xzf` / `unzip` rejects as corrupt (WI-210).
_ARCHIVE_OUTPUT_SUFFIXES = (
    ".tar.gz",
    ".tar.bz2",
    ".tar.xz",
    ".tar.zst",
    ".tgz",
    ".tbz2",
    ".txz",
    ".tar",
    ".zip",
    ".gz",
    ".bz2",
    ".xz",
    ".zst",
    ".7z",
    ".rar",
)


def _reject_archive_output_name(output_path: str | Path) -> None:
    name = Path(output_path).name.lower()
    for suffix in _ARCHIVE_OUTPUT_SUFFIXES:
        if name.endswith(suffix):
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"Output name {Path(output_path).name!r} implies a compressed "
                f"archive ({suffix}), but an audit bundle is a canonical JSON "
                f"document; use a .json name (e.g. 'bundle.json').",
            )


@dataclass(frozen=True)
class BundleVerificationReport:
    verified: bool
    event_count: int
    anchor_receipt_count: int
    segment_count: int
    global_chain_ok: bool
    global_chain_error: str | None = None
    work_item_chain_ok: bool = True
    work_item_chain_error: str | None = None
    anchor_verifications: list[dict] = field(default_factory=list)
    segment_chain_ok: bool = True
    segment_chain_error: str | None = None
    bundle_hash_ok: bool = True
    bundle_hash_error: str | None = None
    signatures_verified: int = 0
    signatures_unverifiable: int = 0
    signature_check: str = "enforced"
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verified": self.verified,
            "event_count": self.event_count,
            "anchor_receipt_count": self.anchor_receipt_count,
            "segment_count": self.segment_count,
            "global_chain_ok": self.global_chain_ok,
            "global_chain_error": self.global_chain_error,
            "work_item_chain_ok": self.work_item_chain_ok,
            "work_item_chain_error": self.work_item_chain_error,
            "anchor_verifications": self.anchor_verifications,
            "segment_chain_ok": self.segment_chain_ok,
            "segment_chain_error": self.segment_chain_error,
            "bundle_hash_ok": self.bundle_hash_ok,
            "bundle_hash_error": self.bundle_hash_error,
            "signatures_verified": self.signatures_verified,
            "signatures_unverifiable": self.signatures_unverifiable,
            "signature_check": self.signature_check,
            "errors": self.errors,
        }


def export_audit_bundle(
    mgr: ConnectionManager,
    project_name: str,
    output_path: str | Path,
    *,
    since_seq: int | None = None,
) -> dict:
    _reject_archive_output_name(output_path)
    with mgr.transaction() as conn:
        if since_seq is not None:
            rows = conn.execute(
                "SELECT event_id, work_item_id, entity_kind, entity_id, hash_alg, "
                "event_seq, global_seq, actor_id, actor_kind, "
                "actor_metadata, key_id, workflow_name, workflow_version, "
                "timestamp, transition, payload, payload_canonical_hash, signature, "
                "canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, "
                "prev_global_event_hash "
                "FROM events WHERE global_seq > %s ORDER BY global_seq",
                [since_seq],
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT event_id, work_item_id, entity_kind, entity_id, hash_alg, "
                "event_seq, global_seq, actor_id, actor_kind, "
                "actor_metadata, key_id, workflow_name, workflow_version, "
                "timestamp, transition, payload, payload_canonical_hash, signature, "
                "canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, "
                "prev_global_event_hash "
                "FROM events ORDER BY global_seq"
            ).fetchall()

        events = [_row_to_event_dict(r) for r in rows]

        # Optional sections come from tables that may predate their migration
        # (older stores). ONLY a missing table is tolerated — and it is
        # recorded in the manifest so the auditor sees the bundle's scope.
        # Any other failure aborts the export: an audit bundle that silently
        # omits anchor receipts or public keys would still "verify" while
        # proving less than the auditor believes (fail closed).
        anchor_receipts, receipts_available = _read_optional_section(
            conn,
            "anchor_receipts",
            lambda c: _list_receipts_dicts(c),
        )
        public_keys, registry_available = _read_optional_section(
            conn,
            "principal_keys",
            lambda c: _list_principal_key_dicts(c),
        )

        segments: list[dict] = []
        segments_available = True
        try:
            from ._archive_segments import list_segments

            segments = list_segments(mgr, limit=10_000)
        except Exception as exc:
            if not _is_undefined_table(exc):
                raise
            segments_available = False
            log.warning("bundle.segments_table_absent", error=str(exc))

        exported_at = datetime.now(UTC)
        manifest = {
            "project": project_name,
            "exported_at": exported_at.isoformat(),
            "event_count": len(events),
            "anchor_receipt_count": len(anchor_receipts),
            "segment_count": len(segments),
            "public_key_count": len(public_keys),
            "anchor_receipts_available": receipts_available,
            "segments_available": segments_available,
            "principal_key_registry": "present" if registry_available else "absent",
            "format_version": _BUNDLE_FORMAT_VERSION,
            "since_seq": since_seq,
        }

        bundle: dict = {
            "manifest": manifest,
            "events": events,
            "anchor_receipts": anchor_receipts,
            "segments": segments,
            "public_keys": public_keys,
        }

        bundle_bytes = _canonical_bundle_bytes(bundle)
        bundle_hash = hashlib.sha256(bundle_bytes).hexdigest()
        manifest["bundle_hash"] = f"sha256:{bundle_hash}"
        bundle["manifest"] = manifest

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(bundle, sort_keys=True, separators=(",", ":"), default=str),
            encoding="utf-8",
        )

        log.info(
            "bundle.exported",
            project=project_name,
            event_count=len(events),
            anchor_receipt_count=len(anchor_receipts),
            segment_count=len(segments),
            public_key_count=len(public_keys),
            output_path=str(output),
        )

        return {
            "output_path": str(output),
            "event_count": len(events),
            "anchor_receipt_count": len(anchor_receipts),
            "segment_count": len(segments),
            "public_key_count": len(public_keys),
            "bundle_hash": manifest["bundle_hash"],
        }


def _is_undefined_table(exc: Exception) -> bool:
    try:
        from psycopg import errors as pg_errors
    except ImportError:
        return False
    return isinstance(exc, pg_errors.UndefinedTable)


def _read_optional_section(
    conn, table_name: str, reader
) -> tuple[list[dict], bool]:
    """Read an optional bundle section under a savepoint.

    Returns ``(rows, available)``. A missing table (store predates the
    migration) yields ``([], False)``; any other error propagates. The
    savepoint keeps an UndefinedTable from aborting the outer transaction.
    """
    conn.execute("SAVEPOINT bundle_section")
    try:
        rows = reader(conn)
    except Exception as exc:
        conn.execute("ROLLBACK TO SAVEPOINT bundle_section")
        if not _is_undefined_table(exc):
            raise
        log.warning("bundle.section_table_absent", table=table_name)
        return [], False
    else:
        conn.execute("RELEASE SAVEPOINT bundle_section")
        return rows, True


def _list_receipts_dicts(conn) -> list[dict]:
    from ._anchoring import list_anchor_receipts

    return [r.to_dict() for r in list_anchor_receipts(conn, limit=10_000)]


def _list_principal_key_dicts(conn) -> list[dict]:
    from ._principal_keys import list_principal_keys_for_conn

    return [k.to_dict() for k in list_principal_keys_for_conn(conn)]


def verify_audit_bundle_offline(bundle_path: str | Path) -> BundleVerificationReport:
    path = Path(bundle_path)
    if not path.is_file():
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Bundle file not found: {bundle_path}",
        )

    raw = path.read_bytes()
    if len(raw) > 512 * 1024 * 1024:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Bundle file too large ({len(raw)} bytes, max 512 MB)",
        )

    try:
        bundle = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Bundle is not valid JSON: {exc}",
        ) from exc

    manifest = bundle.get("manifest", {})
    events_data = bundle.get("events", [])
    anchor_receipts_data = bundle.get("anchor_receipts", [])
    segments_data = bundle.get("segments", [])

    errors: list[str] = []
    anchor_verifications: list[dict] = []

    stored_hash = manifest.get("bundle_hash", "")
    recomputed_hash = f"sha256:{hashlib.sha256(_canonical_bundle_bytes(bundle)).hexdigest()}"
    bundle_hash_ok = _hmac.compare_digest(stored_hash, recomputed_hash)
    bundle_hash_error = None if bundle_hash_ok else (
        "Bundle hash mismatch: stored hash does not match recomputed hash"
    )
    if not bundle_hash_ok:
        errors.append(bundle_hash_error or "")

    fmt_version = manifest.get("format_version")
    if fmt_version not in _SUPPORTED_FORMAT_VERSIONS:
        errors.append(
            f"Unsupported bundle format_version: {fmt_version}, "
            f"supported: {sorted(_SUPPORTED_FORMAT_VERSIONS)}"
        )

    events: list[Event] = []
    for i, ed in enumerate(events_data):
        try:
            events.append(Event.from_dict(ed))
        except Exception as exc:
            errors.append(f"Failed to parse event {i}: {exc}")

    events.sort(key=lambda e: e.global_seq if e.global_seq is not None else float("inf"))

    ok_global, err_global, _tail = _verify_global_chain(events)
    ok_wi, err_wi = _verify_work_item_chains(events)

    if not ok_global:
        errors.append(f"Global chain error: {err_global}")
    if not ok_wi:
        errors.append(f"Work-item chain error: {err_wi}")

    for rd in anchor_receipts_data:
        try:
            receipt = AnchorReceipt.from_dict(rd)
        except Exception as exc:
            errors.append(f"Failed to parse anchor receipt: {exc}")
            continue

        result = _verify_anchor_offline(receipt, events)
        anchor_verifications.append(result)
        if not result["verified"]:
            if result["error"]:
                errors.append(
                    f"Anchor {result['receipt_id']} verification failed: {result['error']}"
                )

    seg_chain_ok = True
    seg_chain_error: str | None = None
    if segments_data:
        seg_chain_ok, seg_chain_error = _verify_segment_chain_offline(segments_data, events)
        if not seg_chain_ok:
            errors.append(f"Segment chain error: {seg_chain_error}")

    if fmt_version == 1 and "public_keys" not in bundle:
        # v1 bundles carry no key registry; skipping is reported, not hidden.
        signature_check = "skipped_v1_bundle"
        sigs_verified = 0
        sigs_unverifiable = 0
    else:
        signature_check = "enforced"
        sigs_verified, sigs_unverifiable, sig_errors = _verify_event_signatures(
            events, bundle.get("public_keys", [])
        )
        errors.extend(sig_errors)
        if sigs_verified == 0 and len(events) > 0:
            signature_check = "enforced_none_verified"

    verified = (
        bundle_hash_ok
        and ok_global
        and ok_wi
        and all(av["verified"] for av in anchor_verifications)
        and seg_chain_ok
        and len(errors) == 0
    )

    return BundleVerificationReport(
        verified=verified,
        event_count=len(events),
        anchor_receipt_count=len(anchor_receipts_data),
        segment_count=len(segments_data),
        global_chain_ok=ok_global,
        global_chain_error=err_global if not ok_global else None,
        work_item_chain_ok=ok_wi,
        work_item_chain_error=err_wi if not ok_wi else None,
        anchor_verifications=anchor_verifications,
        segment_chain_ok=seg_chain_ok,
        segment_chain_error=seg_chain_error,
        bundle_hash_ok=bundle_hash_ok,
        bundle_hash_error=bundle_hash_error,
        signatures_verified=sigs_verified,
        signatures_unverifiable=sigs_unverifiable,
        signature_check=signature_check,
        errors=errors,
    )


def _verify_event_signatures(
    events: list[Event], public_keys_data: list[dict]
) -> tuple[int, int, list[str]]:
    """Verify event signatures offline against the bundled key registry.

    Asymmetric-scheme events (e.g. ed25519) are verified against the
    principal public-key registry exported in the bundle, including the
    principal↔signer binding (key.principal_id must equal event.actor_id,
    mirroring ``verify_principal_binding``) and the key's validity window.

    Symmetric-scheme events (hmac-*) are counted as unverifiable: verifying
    an HMAC requires the secret, which is deliberately never exported. An
    unknown scheme fails closed.

    Returns ``(verified_count, unverifiable_count, errors)``.
    """
    keys_by_id: dict[str, dict] = {}
    errors: list[str] = []

    for kd in public_keys_data:
        try:
            entry = {
                "key_id": kd["key_id"],
                "principal_id": kd["principal_id"],
                "scheme": kd["scheme"],
                "public_key": bytes.fromhex(kd["public_key"]),
                "status": kd.get("status", "active"),
                "valid_from": (
                    datetime.fromisoformat(kd["valid_from"])
                    if kd.get("valid_from")
                    else None
                ),
                "valid_to": (
                    datetime.fromisoformat(kd["valid_to"])
                    if kd.get("valid_to")
                    else None
                ),
                "revoked_at": (
                    datetime.fromisoformat(kd["revoked_at"])
                    if kd.get("revoked_at")
                    else None
                ),
            }
        except (KeyError, ValueError, TypeError) as exc:
            errors.append(f"Malformed public-key entry in bundle: {exc}")
            continue
        keys_by_id[entry["key_id"]] = entry

    verified_count = 0
    unverifiable_count = 0

    for evt in events:
        label = f"event {evt.event_id} (global_seq={evt.global_seq})"

        try:
            scheme = get_scheme(evt.scheme_id)
        except RegistaError:
            errors.append(
                f"Unknown signing scheme {evt.scheme_id!r} at {label} (fail closed)"
            )
            continue

        if not getattr(scheme, "is_asymmetric", False):
            unverifiable_count += 1
            continue

        if evt.canonical_envelope is None or evt.signature is None:
            errors.append(f"Missing canonical_envelope or signature at {label}")
            continue

        key = keys_by_id.get(evt.key_id)
        if key is None:
            errors.append(
                f"No public key for key_id {evt.key_id!r} in bundle registry at {label}"
            )
            continue

        if key["scheme"] != evt.scheme_id:
            errors.append(
                f"Key scheme mismatch at {label}: key {evt.key_id!r} is "
                f"{key['scheme']!r}, event claims {evt.scheme_id!r}"
            )
            continue

        if key["principal_id"] != evt.actor_id:
            errors.append(
                f"Actor-signer mismatch at {label}: actor_id={evt.actor_id!r} "
                f"but key {evt.key_id!r} is bound to {key['principal_id']!r}"
            )
            continue

        try:
            if key["valid_from"] is not None and evt.timestamp < key["valid_from"]:
                errors.append(
                    f"Event signed before key validity at {label}: "
                    f"timestamp={evt.timestamp.isoformat()}, "
                    f"valid_from={key['valid_from'].isoformat()}"
                )
                continue
            boundary = key["revoked_at"] or key["valid_to"]
            if boundary is not None and evt.timestamp > boundary:
                errors.append(
                    f"Event signed after key revocation/expiry at {label}: "
                    f"timestamp={evt.timestamp.isoformat()}, "
                    f"boundary={boundary.isoformat()}"
                )
                continue
        except TypeError as exc:
            errors.append(f"Key validity comparison failed at {label}: {exc}")
            continue

        if not scheme.verify(
            bytes(evt.canonical_envelope),
            bytes(evt.signature),
            bytes(evt.payload_canonical_hash),
            key["public_key"],
            hash_alg=evt.hash_alg or "sha-256",
        ):
            errors.append(f"Signature verification failed at {label}")
            continue

        verified_count += 1

    return verified_count, unverifiable_count, errors


def _verify_anchor_offline(
    receipt: AnchorReceipt, events: list[Event]
) -> dict:
    receipt_id = str(receipt.receipt_id)

    if receipt.target_global_seq is None:
        return {
            "receipt_id": receipt_id,
            "verified": False,
            "error": "receipt has no target_global_seq",
        }
    if receipt.project_name is None or receipt.envelope_version is None:
        return {
            "receipt_id": receipt_id,
            "verified": False,
            "error": "receipt missing binding fields (project_name or envelope_version)",
        }
    if receipt.hash_algorithm is None:
        return {
            "receipt_id": receipt_id,
            "verified": False,
            "error": "receipt missing hash_algorithm",
        }

    target_seq = receipt.target_global_seq

    min_seq = min(
        (e.global_seq for e in events if e.global_seq is not None),
        default=None,
    )
    if min_seq is not None and target_seq < min_seq:
        return {
            "receipt_id": receipt_id,
            "verified": True,
            "skipped": True,
            "error": None,
        }

    candidate_events = [
        e for e in events
        if e.global_seq is not None and e.global_seq <= target_seq
    ]

    if not candidate_events:
        return {
            "receipt_id": receipt_id,
            "verified": False,
            "error": f"no events at or before target_global_seq={target_seq}",
        }

    by_prev: dict[str, list[Event]] = {}
    genesis_events: list[Event] = []
    for evt in candidate_events:
        prev = evt.prev_global_event_hash
        if prev is None:
            genesis_events.append(evt)
        else:
            key = bytes(prev).hex()
            by_prev.setdefault(key, []).append(evt)

    if not genesis_events:
        return {
            "receipt_id": receipt_id,
            "verified": False,
            "error": "no genesis event found in bundle events",
        }

    current: Event | None = genesis_events[0]
    chain_head_hash: bytes | None = None
    prev_chain_head_hash: bytes | None = None
    visited: set[uuid.UUID] = set()
    found_target = False

    while current is not None:
        if current.event_id in visited:
            return {
                "receipt_id": receipt_id,
                "verified": False,
                "error": "cycle detected in global chain",
            }
        visited.add(current.event_id)

        env = current.canonical_envelope
        sig = current.signature
        if env is None or sig is None:
            return {
                "receipt_id": receipt_id,
                "verified": False,
                "error": f"event {current.event_id} missing canonical_envelope or signature",
            }

        env_bytes = bytes(env)
        sig_bytes = bytes(sig)

        stored_pch = current.payload_canonical_hash
        if stored_pch is not None and len(stored_pch) > 0:
            event_hash_alg = current.hash_alg or "sha-256"
            hash_fn = resolve_hash_function(event_hash_alg)
            recomputed_pch = hash_fn(env_bytes).digest()
            if not _hmac.compare_digest(recomputed_pch, bytes(stored_pch)):
                return {
                    "receipt_id": receipt_id,
                    "verified": False,
                    "error": (
                        f"payload_canonical_hash mismatch at event {current.event_id}"
                    ),
                }

        chain_head_hash = hashlib.sha256(env_bytes + sig_bytes).digest()

        if prev_chain_head_hash is not None:
            prev_global_hash = current.prev_global_event_hash
            if prev_global_hash is None:
                return {
                    "receipt_id": receipt_id,
                    "verified": False,
                    "error": f"event {current.event_id} has null prev_global_event_hash",
                }
            if not _hmac.compare_digest(prev_chain_head_hash, bytes(prev_global_hash)):
                return {
                    "receipt_id": receipt_id,
                    "verified": False,
                    "error": (
                        f"chain link mismatch at event {current.event_id}: "
                        f"prev_global_event_hash does not match predecessor"
                    ),
                }

        if current.global_seq == target_seq:
            found_target = True
            break

        prev_chain_head_hash = chain_head_hash
        successors = by_prev.get(chain_head_hash.hex(), [])
        if len(successors) != 1:
            break
        current = successors[0]

    if not found_target or chain_head_hash is None:
        return {
            "receipt_id": receipt_id,
            "verified": False,
            "error": f"target_global_seq={target_seq} not found in chain",
        }

    expected_anchor = compute_content_anchor(
        chain_head_hash=chain_head_hash,
        project_name=receipt.project_name,
        target_global_seq=target_seq,
        envelope_version=receipt.envelope_version,
        hash_algorithm=receipt.hash_algorithm,
    )

    verified = _hmac.compare_digest(expected_anchor, receipt.merkle_root)
    return {
        "receipt_id": receipt_id,
        "verified": verified,
        "error": None if verified else (
            f"merkle_root mismatch: recomputed={expected_anchor.hex()}, "
            f"stored={receipt.merkle_root.hex()}"
        ),
    }


def _verify_segment_chain_offline(
    segments: list[dict], events: list[Event]
) -> tuple[bool, str | None]:
    if len(segments) <= 1:
        return True, None

    sorted_segs = sorted(segments, key=lambda s: s.get("first_global_seq", 0))

    for i in range(1, len(sorted_segs)):
        prev_seg = sorted_segs[i - 1]
        curr_seg = sorted_segs[i]

        prev_head_hash = prev_seg.get("head_hash")
        curr_first_prev_hash = curr_seg.get("first_event_prev_hash")

        if prev_head_hash is None:
            continue
        if curr_first_prev_hash is None:
            return False, (
                f"segment {curr_seg.get('segment_id', '?')} has no "
                f"first_event_prev_hash but is not the first segment"
            )

        if curr_first_prev_hash != prev_head_hash:
            return False, (
                f"segment chain broken between segment "
                f"{prev_seg.get('segment_id', '?')} and "
                f"{curr_seg.get('segment_id', '?')}: "
                f"head_hash={prev_head_hash}, "
                f"first_event_prev_hash={curr_first_prev_hash}"
            )

    return True, None


def _row_to_event_dict(row: dict) -> dict:
    pch = row["payload_canonical_hash"]
    sig = row["signature"]
    if pch is None or sig is None:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Event {row['event_id']} has null payload_canonical_hash or signature",
        )
    d = {
        "event_id": str(row["event_id"]),
        "work_item_id": str(row["work_item_id"]),
        "event_seq": row["event_seq"],
        "actor_id": row["actor_id"],
        "actor_kind": row["actor_kind"],
        "actor_metadata": row["actor_metadata"] if row["actor_metadata"] else None,
        "key_id": row["key_id"],
        "workflow_name": row["workflow_name"],
        "workflow_version": row["workflow_version"],
        "timestamp": row["timestamp"].isoformat() if row["timestamp"] else None,
        "transition": row["transition"],
        "payload": row["payload"] if row["payload"] else None,
        "payload_canonical_hash": bytes(pch).hex(),
        "signature": bytes(sig).hex(),
        "entity_kind": row.get("entity_kind") or "work_item",
        "entity_id": str(row["entity_id"]) if row.get("entity_id") else str(row["work_item_id"]),
        "hash_alg": row.get("hash_alg") or "sha-256",
    }

    env = row.get("canonical_envelope")
    if env is not None:
        d["canonical_envelope"] = bytes(env).hex()

    obo = row.get("on_behalf_of")
    if obo is not None:
        d["on_behalf_of"] = obo

    d["scheme_id"] = row.get("scheme_id") or "hmac-sha256"

    peh = row.get("prev_event_hash")
    if peh is not None:
        d["prev_event_hash"] = bytes(peh).hex()

    gs = row.get("global_seq")
    if gs is not None:
        d["global_seq"] = gs

    pgdh = row.get("prev_global_event_hash")
    if pgdh is not None:
        d["prev_global_event_hash"] = bytes(pgdh).hex()

    return d


def _canonical_bundle_bytes(bundle: dict) -> bytes:
    manifest = dict(bundle.get("manifest", {}))
    manifest.pop("bundle_hash", None)

    canonical = {
        "manifest": manifest,
        "events": bundle.get("events", []),
        "anchor_receipts": bundle.get("anchor_receipts", []),
        "segments": bundle.get("segments", []),
    }
    # v1 bundles have no public_keys section; including the key only when
    # present keeps v1 hashes recomputable by a v2 verifier.
    if "public_keys" in bundle:
        canonical["public_keys"] = bundle.get("public_keys", [])
    return json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
