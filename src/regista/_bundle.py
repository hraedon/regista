from __future__ import annotations

import hashlib
import hmac as _hmac
import json
import os
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from ._anchoring import AnchorReceipt, compute_content_anchor
from ._archive_segments import (
    _hash_event,
    _segment_chain_links,
    _verify_global_chain,
    _verify_work_item_chains,
)
from ._connection import ConnectionManager, DictConn
from ._errors import ErrorCode, RegistaError
from ._signing_scheme import get_scheme, resolve_hash_function
from ._types import Event
from ._verification import (
    DEFAULT_POLICY,
    Backend,
    BundleKeyResolver,
    EventRow,
    verify_event_strict,
)

log = structlog.get_logger()

# v2 adds the principal public-key registry to the bundle so event signatures
# on asymmetric schemes are verified offline (signer binding). v1 bundles are
# still accepted; their signature check is reported as skipped.
_BUNDLE_FORMAT_VERSION = 2
_SUPPORTED_FORMAT_VERSIONS = frozenset({1, 2})

# One cap, shared by export and verify (WI-240). An export larger than what
# the offline verifier accepts is unverifiable by the tool that exists to
# verify it, so export refuses to write past this size rather than exit 0.
MAX_BUNDLE_BYTES = 512 * 1024 * 1024

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
    anchor_verifications: list[dict[str, Any]] = field(default_factory=list)
    segment_chain_ok: bool = True
    segment_chain_error: str | None = None
    bundle_hash_ok: bool = True
    bundle_hash_error: str | None = None
    signatures_verified: int = 0
    signatures_unverifiable: int = 0
    signature_check: str = "enforced"
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
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


_EVENT_COLUMNS = (
    "event_id, work_item_id, entity_kind, entity_id, hash_alg, "
    "event_seq, global_seq, actor_id, actor_kind, "
    "actor_metadata, key_id, workflow_name, workflow_version, "
    "timestamp, transition, payload, payload_canonical_hash, signature, "
    "canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, "
    "prev_global_event_hash"
)


def _slice_receipts_to_verifiable(
    anchor_receipts: list[dict[str, Any]],
    *,
    since_seq: int | None,
    max_exported_seq: int | None,
) -> tuple[list[dict[str, Any]], int]:
    """Keep only anchor receipts the exported bundle can actually verify.

    An anchor receipt is verified offline by re-walking the global chain from
    the **genesis event** to the receipt's ``target_global_seq``
    (:func:`_verify_anchor_offline`), so a receipt is provable only in a
    bundle whose events cover that full prefix:

    * A prefix export (``since_seq`` unset or 0) proves receipts with
      ``target_global_seq <= max_exported_seq``. Receipts targeting beyond
      the exported range are excluded — shipping them would make the bundle
      fail verification for events it does not contain.
    * A mid-chain chunk (``since_seq > 0``) contains no genesis, so it can
      prove **no** receipt; all are excluded and the exclusion is counted.
      This is an inherent limit of the full-prefix anchor design (Plan 023
      retires it at M4); the receipts remain in the store and verifiable in
      a prefix bundle.

    Receipts with a null ``target_global_seq`` are kept in prefix exports:
    they are data defects the verifier must report, not quietly drop.
    Returns ``(kept, excluded_count)``.
    """
    if since_seq is not None and since_seq > 0:
        return [], len(anchor_receipts)
    if max_exported_seq is None:
        # No events exported — no prefix to prove anything against.
        return [], len(anchor_receipts)
    kept = [
        r
        for r in anchor_receipts
        if r.get("target_global_seq") is None
        or r["target_global_seq"] <= max_exported_seq
    ]
    return kept, len(anchor_receipts) - len(kept)


def _slice_segments_to_window(
    segments: list[dict[str, Any]],
    min_exported_seq: int | None,
    max_exported_seq: int | None,
) -> tuple[list[dict[str, Any]], int]:
    """Keep segments overlapping the exported ``global_seq`` window.

    A chunk that ships segments wholly outside its event range overclaims
    scope (WI-240 review F5). The window is contiguous, so only leading and
    trailing segments drop; the slice preserves the order of the kept
    segments, and the offline inter-segment linkage walk
    (:func:`_verify_segment_chain_offline`) compares adjacent kept segments
    in that order. Segments with unknown bounds are kept: the slice must never
    silently discard what it cannot classify. (Review N6: no such row can come
    from the store — migration 039 declares ``first_global_seq``,
    ``last_global_seq``, ``head_hash`` and ``event_count`` NOT NULL with
    CHECKs for ``event_count > 0`` and ``first_global_seq <= last_global_seq``,
    and ``seal_segment`` never inserts without events. The branch guards
    hand-built and tampered bundles only, which
    ``_verify_segment_chain_offline`` then rejects.) Returns
    ``(kept, excluded_count)``.
    """
    if min_exported_seq is None or max_exported_seq is None:
        return segments, 0
    kept: list[dict[str, Any]] = []
    for seg in segments:
        first = seg.get("first_global_seq")
        last = seg.get("last_global_seq")
        if first is None or last is None:
            kept.append(seg)
            continue
        if last < min_exported_seq or first > max_exported_seq:
            continue
        kept.append(seg)
    return kept, len(segments) - len(kept)


def export_audit_bundle(
    mgr: ConnectionManager,
    project_name: str,
    output_path: str | Path,
    *,
    since_seq: int | None = None,
    until_seq: int | None = None,
) -> dict[str, Any]:
    _reject_archive_output_name(output_path)
    if until_seq is not None and since_seq is not None and until_seq <= since_seq:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Empty export range: until_seq ({until_seq}) must be greater "
            f"than since_seq ({since_seq}).",
        )
    with mgr.transaction() as conn:
        clauses: list[str] = []
        params: list[int] = []
        if since_seq is not None:
            clauses.append("global_seq > %s")
            params.append(since_seq)
        if until_seq is not None:
            clauses.append("global_seq <= %s")
            params.append(until_seq)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = conn.execute(
            f"SELECT {_EVENT_COLUMNS} FROM events{where} ORDER BY global_seq",
            params,
        ).fetchall()

        events = [_row_to_event_dict(r) for r in rows]

        # A window that selects nothing produces a bundle that proves nothing
        # — and "verifies" trivially. Reporting success for it is the exact
        # defect class this function exists to fix (WI-240 review F1): in the
        # chunking workflow a single bad boundary would silently lose events.
        if not events:
            detail = (
                "the store has no events"
                if since_seq is None and until_seq is None
                else f"window since_seq={since_seq} until_seq={until_seq} "
                "selected no events"
            )
            raise RegistaError(
                ErrorCode.INVALID_ARGUMENT,
                f"Refusing to export an empty bundle: {detail}. "
                "Nothing was written.",
            )

        # Optional sections come from tables that may predate their migration
        # (older stores). ONLY a missing table is tolerated — and it is
        # recorded in the manifest so the auditor sees the bundle's scope.
        # Any other failure aborts the export: an audit bundle that silently
        # omits anchor receipts or public keys would still "verify" while
        # proving less than the auditor believes (fail closed).
        # Receipts are fetched oldest-target-first so the bounded fetch holds
        # exactly the receipts a prefix bundle can prove, and counted so the
        # manifest's exclusion accounting is exhaustive (review F4).
        conn.execute("SAVEPOINT bundle_receipts")
        try:
            receipts_total_row = conn.execute(
                "SELECT COUNT(*) AS n FROM anchor_receipts"
            ).fetchone()
            receipts_total = int(receipts_total_row["n"]) if receipts_total_row else 0
            anchor_receipts = _list_receipts_dicts(conn)
        except Exception as exc:
            conn.execute("ROLLBACK TO SAVEPOINT bundle_receipts")
            if not _is_undefined_table(exc):
                raise
            log.warning("bundle.section_table_absent", table="anchor_receipts")
            anchor_receipts, receipts_total, receipts_available = [], 0, False
        else:
            conn.execute("RELEASE SAVEPOINT bundle_receipts")
            receipts_available = True
        public_keys, registry_available = _read_optional_section(
            conn,
            "principal_keys",
            lambda c: _list_principal_key_dicts(c),
        )

        segments: list[dict[str, Any]] = []
        segments_available = True
        try:
            from ._archive_segments import list_segments

            segments = list_segments(mgr, limit=10_000)
        except Exception as exc:
            if not _is_undefined_table(exc):
                raise
            segments_available = False
            log.warning("bundle.segments_table_absent", error=str(exc))

    # File assembly, the size gate and self-verification run outside the
    # transaction: none of it reads the store, and an 800 MiB serialization
    # should not hold a connection open (WI-240).
    seqs = [e["global_seq"] for e in events if e.get("global_seq") is not None]
    max_exported_seq = max(seqs) if seqs else None
    min_exported_seq = min(seqs) if seqs else None
    anchor_receipts, _ = _slice_receipts_to_verifiable(
        anchor_receipts, since_seq=since_seq, max_exported_seq=max_exported_seq
    )
    # Exclusion accounting is against the STORE total, not the bounded fetch,
    # so the manifest never claims an exhaustive accounting it did not do
    # (review F4).
    receipts_excluded = receipts_total - len(anchor_receipts)
    segments, segments_excluded = _slice_segments_to_window(
        segments, min_exported_seq, max_exported_seq
    )

    exported_at = datetime.now(UTC)
    manifest = {
        "project": project_name,
        "exported_at": exported_at.isoformat(),
        "event_count": len(events),
        "anchor_receipt_count": len(anchor_receipts),
        "segment_count": len(segments),
        "public_key_count": len(public_keys),
        "anchor_receipts_available": receipts_available,
        "anchor_receipts_excluded": receipts_excluded,
        "segments_available": segments_available,
        "segments_excluded": segments_excluded,
        "principal_key_registry": "present" if registry_available else "absent",
        "format_version": _BUNDLE_FORMAT_VERSION,
        "since_seq": since_seq,
        "until_seq": until_seq,
    }

    bundle: dict[str, Any] = {
        "manifest": manifest,
        "events": events,
        "anchor_receipts": anchor_receipts,
        "segments": segments,
        "public_keys": public_keys,
    }

    bundle_bytes = _canonical_bundle_bytes(bundle)
    bundle_hash = hashlib.sha256(bundle_bytes).hexdigest()
    del bundle_bytes  # ~800 MiB at the motivating scale; don't hold two copies
    manifest["bundle_hash"] = f"sha256:{bundle_hash}"
    bundle["manifest"] = manifest

    serialized = json.dumps(
        bundle, sort_keys=True, separators=(",", ":"), default=str
    ).encode("utf-8")
    if len(serialized) > MAX_BUNDLE_BYTES:
        raise RegistaError(
            ErrorCode.BUNDLE_UNVERIFIABLE,
            f"Refusing to write an unverifiable bundle: {len(serialized)} bytes "
            f"exceeds the offline verifier's {MAX_BUNDLE_BYTES}-byte cap "
            f"({len(events)} events, global_seq "
            f"{min_exported_seq}..{max_exported_seq}). Chunk the export with "
            "--since-seq/--until-seq; nothing was written.",
        )

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    # Write-then-rename so a killed process cannot leave a plausible-looking
    # partial bundle at the destination (review F8). If write_bytes itself
    # dies mid-write, unlink the .partial temp file — only the partial, never
    # the real destination (WI-249).
    tmp_output = output.with_name(output.name + ".partial")
    try:
        tmp_output.write_bytes(serialized)
    except BaseException:
        if tmp_output.exists():
            tmp_output.unlink()
        raise
    os.replace(tmp_output, output)

    # An export is done when the artifact it wrote is verifiable, not when
    # the write returns (WI-240). Two failure classes are deliberately
    # distinct: a defect EXPORT introduced (the artifact does not hash-match
    # what was serialized) fails the export, artifact left for inspection;
    # a defect of the STORE faithfully preserved (e.g. ed25519 events whose
    # key registry predates its migration) must not block the only archival
    # path a degraded store has — it is reported, loudly, in the result and
    # the log, and `bundle verify` remains the enforcement point.
    report = verify_audit_bundle_offline(output)
    if not report.bundle_hash_ok:
        raise RegistaError(
            ErrorCode.BUNDLE_WRITE_CORRUPT,
            f"Exported artifact does not match what was serialized "
            f"(bundle hash mismatch); artifact left at {output} for "
            f"inspection: {report.bundle_hash_error}",
        )
    if not report.verified:
        log.warning(
            "bundle.exported_with_verification_errors",
            output_path=str(output),
            errors=report.errors[:5],
        )

    log.info(
        "bundle.exported",
        project=project_name,
        event_count=len(events),
        anchor_receipt_count=len(anchor_receipts),
        anchor_receipts_excluded=receipts_excluded,
        segment_count=len(segments),
        public_key_count=len(public_keys),
        bundle_bytes=len(serialized),
        self_verified=report.verified,
        output_path=str(output),
    )

    return {
        "output_path": str(output),
        "event_count": len(events),
        "anchor_receipt_count": len(anchor_receipts),
        "anchor_receipts_excluded": receipts_excluded,
        "segment_count": len(segments),
        "segments_excluded": segments_excluded,
        "public_key_count": len(public_keys),
        "bundle_hash": manifest["bundle_hash"],
        "bundle_bytes": len(serialized),
        "since_seq": since_seq,
        "until_seq": until_seq,
        "self_verification": {
            "verified": report.verified,
            "signatures_verified": report.signatures_verified,
            "signatures_unverifiable": report.signatures_unverifiable,
            "signature_check": report.signature_check,
            "errors": report.errors[:5],
        },
    }


def _is_undefined_table(exc: Exception) -> bool:
    try:
        from psycopg import errors as pg_errors
    except ImportError:
        return False
    return isinstance(exc, pg_errors.UndefinedTable)


def _read_optional_section(
    conn: DictConn, table_name: str, reader: Callable[[DictConn], list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]], bool]:
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


def _list_receipts_dicts(conn: DictConn) -> list[dict[str, Any]]:
    from ._anchoring import list_anchor_receipts

    return [
        r.to_dict()
        for r in list_anchor_receipts(conn, limit=10_000, order="target_seq")
    ]


def _list_principal_key_dicts(conn: DictConn) -> list[dict[str, Any]]:
    from ._principal_keys import list_principal_keys_for_conn

    return [k.to_dict() for k in list_principal_keys_for_conn(conn)]


# Manifest count key -> the bundle section it declares the size of. Every
# count the exporter writes into the manifest is listed here; a count with no
# section to compare against would be an unchecked claim (WI-255).
_MANIFEST_COUNT_SECTIONS = (
    ("event_count", "events"),
    ("anchor_receipt_count", "anchor_receipts"),
    ("segment_count", "segments"),
    ("public_key_count", "public_keys"),
)


def _verify_manifest_counts(
    manifest: dict[str, Any], bundle: dict[str, Any], fmt_version: Any
) -> list[str]:
    """Check every count the manifest declares against the section it describes.

    The manifest is the auditor-facing summary of the bundle, but nothing used
    to compare it to the document it summarises: the report's ``event_count``
    is taken from the parsed section, so deleting the tail event and leaving
    ``manifest.event_count`` alone was silently normalised away and the bundle
    still verified (WI-255). The bundle hash is unkeyed and therefore
    attacker-recomputable, so this check does not make the artifact
    unforgeable — it makes it internally inconsistent to remove a record
    without also rewriting the claim about how many records there are.

    A count present but not an integer is a malformed claim and fails closed.
    An ABSENT count is version-gated (review N2): a v2 manifest is always
    written with all four counts, so one missing from a v2 bundle is tamper
    evidence — dropping the key would otherwise be a way to opt out of the
    check. v1 bundles predate the key registry and carry no
    ``public_key_count``, so for them a missing count declares nothing and is
    skipped. Returns a list of error strings (empty when every declared count
    agrees).
    """
    errors: list[str] = []
    for key, section in _MANIFEST_COUNT_SECTIONS:
        if key not in manifest:
            if fmt_version == 2:
                errors.append(
                    f"Manifest count missing: format_version 2 always declares "
                    f"{key!r}, so its absence is not a bundle this exporter wrote "
                    f"(section '{section}' holds "
                    f"{len(bundle.get(section) or [])} record(s))"
                )
            continue
        declared = manifest[key]
        actual = len(bundle.get(section) or [])
        if isinstance(declared, bool) or not isinstance(declared, int):
            errors.append(
                f"Manifest count mismatch: manifest.{key}={declared!r} is not an "
                f"integer (section '{section}' holds {actual} record(s))"
            )
            continue
        if declared != actual:
            errors.append(
                f"Manifest count mismatch: manifest.{key}={declared} but section "
                f"'{section}' holds {actual} record(s)"
            )
    return errors


def verify_audit_bundle_offline(bundle_path: str | Path) -> BundleVerificationReport:
    path = Path(bundle_path)
    if not path.is_file():
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Bundle file not found: {bundle_path}",
        )

    raw = path.read_bytes()
    if len(raw) > MAX_BUNDLE_BYTES:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"Bundle file too large ({len(raw)} bytes, max {MAX_BUNDLE_BYTES})",
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
    anchor_verifications: list[dict[str, Any]] = []

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

    errors.extend(_verify_manifest_counts(manifest, bundle, fmt_version))

    events: list[Event] = []
    for i, ed in enumerate(events_data):
        try:
            events.append(Event.from_dict(ed))
        except Exception as exc:
            errors.append(f"Failed to parse event {i}: {exc}")

    events.sort(key=lambda e: e.global_seq if e.global_seq is not None else float("inf"))

    # An event-free bundle proves nothing and verifies trivially — the empty
    # global chain is vacuously valid and there is nothing left to fail. The
    # exporter refuses to write one for exactly that reason (WI-240), so a
    # bundle with no events is not an artifact this tool produced: it is what
    # is left after someone wipes one and zeroes the counts. Reject it rather
    # than answer "verified" to a document that makes no claim (review N5).
    if not events_data:
        errors.append(
            "Bundle contains no events: export refuses to write an empty "
            "bundle, so an event-free bundle proves nothing and cannot verify"
        )

    errors.extend(_verify_declared_window(manifest, events))

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
        seg_chain_ok, seg_chain_error = _verify_segment_chain_offline(
            segments_data,
            events,
            since_seq=manifest.get("since_seq"),
            until_seq=manifest.get("until_seq"),
        )
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

    # WI-267: `signatures_verified > 0` is part of the verdict. A bundle in
    # which every signature was unverifiable used to report verified=True
    # provided `errors` was empty — "nothing was checked" was being reported as
    # "everything checks out", which is exactly the silent-pass shape S1 exists
    # to make structurally impossible. Note this means an HMAC-only bundle is
    # NOT `verified`: the secret is deliberately never exported, so such a
    # bundle proves internal consistency and nothing cryptographic. Splitting
    # the verdict into internally-consistent / authenticated-to-an-external-root
    # is S3/S5 and is deliberately not attempted here.
    verified = (
        bundle_hash_ok
        and ok_global
        and ok_wi
        and all(av["verified"] for av in anchor_verifications)
        and seg_chain_ok
        and len(errors) == 0
        and sigs_verified > 0
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
    events: list[Event], public_keys_data: list[dict[str, Any]]
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
    keys_by_id: dict[str, dict[str, Any]] = {}
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
    resolver = BundleKeyResolver(keys_by_id)

    for evt in events:
        label = f"event {evt.event_id} (global_seq={evt.global_seq})"

        key = keys_by_id.get(evt.key_id)
        if key is None:
            # WI-267 / S2-interim: whether this event needs an asymmetric check
            # is decided from key metadata, not from the row's self-declared
            # scheme_id. With no registry entry there is no metadata, so a row
            # claiming a symmetric scheme can no longer excuse itself — an
            # event whose key the bundle does not carry is unverifiable.
            try:
                claimed = get_scheme(evt.scheme_id)
            except RegistaError:
                errors.append(
                    f"Unknown signing scheme {evt.scheme_id!r} at {label} (fail closed)"
                )
                continue
            if getattr(claimed, "is_asymmetric", False):
                errors.append(
                    f"No public key for key_id {evt.key_id!r} in bundle registry at {label}"
                )
            else:
                unverifiable_count += 1
            continue

        key_scheme = key["scheme"]
        try:
            scheme = get_scheme(key_scheme)
        except RegistaError:
            errors.append(
                f"Unknown signing scheme {key_scheme!r} for key {evt.key_id!r} "
                f"at {label} (fail closed)"
            )
            continue

        if not getattr(scheme, "is_asymmetric", False):
            # Verifying an HMAC requires the secret, which is deliberately never
            # exported. Unverifiable, and it must not count towards `verified`.
            unverifiable_count += 1
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

        # WI-267: this used to be a second, independent verifier that called
        # scheme.verify() on the stored envelope and never reconciled the row —
        # the audit's defect in its purest form. It now delegates to the one
        # primitive, so a bundle whose event records were rewritten under intact
        # envelopes no longer verifies.
        result = verify_event_strict(
            EventRow.from_event(evt, backend=Backend.BUNDLE),
            keys=resolver,
            policy=DEFAULT_POLICY,
        )
        if not result.accepted:
            errors.append(f"Signature verification failed at {label}: {result.summary()}")
            continue

        verified_count += 1

    return verified_count, unverifiable_count, errors


def _verify_anchor_offline(
    receipt: AnchorReceipt, events: list[Event]
) -> dict[str, Any]:
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


def _as_seq_bound(value: Any) -> int | None:
    """Return *value* as a seq bound, or ``None`` when it is not one."""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _window_is_impossible(since_seq: Any, until_seq: Any) -> str | None:
    """Describe why a declared export window could not have been produced.

    ``export_audit_bundle`` refuses ``until_seq <= since_seq`` outright and
    refuses any window that selects no events, and ``global_seq`` is 1-based —
    so a non-positive ``until_seq``, a negative ``since_seq`` or an inverted
    pair cannot appear in a bundle this exporter wrote. A manifest carrying
    one is tamper evidence, and it is the shape a tamperer reaches for,
    because the window is what gates the segment checks. Returns the reason,
    or ``None`` when the declared window is a shape an export could produce.
    """
    since = _as_seq_bound(since_seq)
    until = _as_seq_bound(until_seq)
    if since_seq is not None and since is None:
        return f"since_seq={since_seq!r} is not an integer"
    if until_seq is not None and until is None:
        return f"until_seq={until_seq!r} is not an integer"
    if until is not None and until <= 0:
        return (
            f"until_seq={until} selects no events (global_seq is 1-based); "
            f"export refuses such a window"
        )
    if since is not None and since < 0:
        return f"since_seq={since} is negative"
    if since is not None and until is not None and since >= until:
        return (
            f"since_seq={since} is not below until_seq={until}; export refuses "
            f"an empty range"
        )
    return None


def _exported_window(
    since_seq: Any, until_seq: Any
) -> tuple[int | None, int | None]:
    """Translate the manifest's export window into inclusive seq bounds.

    ``since_seq`` is exclusive on the export side (``global_seq > since_seq``)
    and ``until_seq`` inclusive, so the exported window is
    ``[since_seq + 1, until_seq]``. ``None`` on either side means unbounded.

    Anything that is not a bound an export could have produced ALSO reads as
    unbounded, which is the strict direction: an unbounded side subjects MORE
    segments to the full checks, so a manifest cannot buy itself leniency by
    declaring nonsense. That covers non-integers and — the case the first cut
    of this fix got wrong (review B1) — integer nonsense: ``until_seq = 0``
    would otherwise be honoured as a real upper bound, and since every segment
    has ``last_global_seq > 0`` it skipped EVERY segment check in the bundle,
    reopening both WI-254 and WI-255 with a one-key manifest edit. Negative
    and inverted windows did the same. ``_window_is_impossible`` reports these
    as errors in their own right; this function only has to make sure the
    segment gate does not act on them.
    """
    if _window_is_impossible(since_seq, until_seq) is not None:
        return None, None
    since = _as_seq_bound(since_seq)
    return (since + 1 if since is not None else None), _as_seq_bound(until_seq)


def _verify_declared_window(
    manifest: dict[str, Any], events: list[Event]
) -> list[str]:
    """Check the manifest's declared window against the events it shipped.

    Two claims are settled here. First, the window must be a shape an export
    could have produced at all (see ``_window_is_impossible``). Second — the
    cheap anchor the first cut of this fix left out (review N1) — every event
    must lie INSIDE the declared window. A real export guarantees this by
    construction: the event query is filtered by the same bounds. So a
    tamperer who invents a window to disclaim completeness for a segment (the
    residual documented on ``_verify_segment_record_offline``) has to delete
    the out-of-window events too, rather than just editing one manifest key.
    """
    since_seq = manifest.get("since_seq")
    until_seq = manifest.get("until_seq")

    reason = _window_is_impossible(since_seq, until_seq)
    if reason is not None:
        return [
            f"Manifest window is not one this exporter could have written: "
            f"{reason} (since_seq={since_seq!r}, until_seq={until_seq!r})"
        ]

    seqs = [e.global_seq for e in events if e.global_seq is not None]
    if not seqs:
        return []
    lo, hi = _exported_window(since_seq, until_seq)
    errors: list[str] = []
    if lo is not None and min(seqs) < lo:
        errors.append(
            f"Bundle holds an event at global_seq {min(seqs)}, below the "
            f"declared window (since_seq={since_seq})"
        )
    if hi is not None and max(seqs) > hi:
        errors.append(
            f"Bundle holds an event at global_seq {max(seqs)}, above the "
            f"declared window (until_seq={until_seq})"
        )
    return errors


# Segment-record field -> the key carrying the same fact in the signed
# ``segment_sealed`` payload. Confirmed against a live seal event: the sealer
# writes all of these into the payload it signs (``seal_segment``), so a
# tamperer who edits the record has to forge a signature to keep the two
# agreeing. ``seal_event_id`` is reconciled separately (it is the seal event's
# OWN event_id, not a payload key); ``archived`` and ``created_at`` have no
# payload counterpart — see ``_reconcile_segment_with_seal``.
_SEAL_RECONCILED_FIELDS = (
    "first_global_seq",
    "last_global_seq",
    "event_count",
    "head_hash",
    "first_event_prev_hash",
    "first_event_id",
    "last_event_id",
    "work_item_ids",
    "min_timestamp",
    "max_timestamp",
    "archive_path",
)

_TIMESTAMP_SEAL_FIELDS = frozenset({"min_timestamp", "max_timestamp"})


def _seal_payload_of(evt: Event) -> dict[str, Any] | None:
    """Return the ``segment_sealed`` payload carried by *evt*'s SIGNED envelope.

    The payload is read out of ``canonical_envelope`` — the exact bytes the
    sealer signed and the bytes the global hash chain commits to
    (``_hash_event`` is ``sha256(canonical_envelope + signature)``) — and NOT
    out of the event's top-level ``payload`` field, which no check binds to
    anything. Reading the wrong one would make the reconciliation below as
    forgeable as the record it is meant to anchor.
    """
    env_bytes = evt.canonical_envelope
    if env_bytes is None:
        return None
    try:
        envelope = json.loads(bytes(env_bytes))
    except (ValueError, TypeError):
        return None
    if not isinstance(envelope, dict):
        return None
    if envelope.get("transition") != "segment_sealed":
        return None
    payload = envelope.get("payload")
    if not isinstance(payload, dict) or "segment_id" not in payload:
        return None
    return payload


def _index_seal_events(
    events: list[Event], events_by_seq: dict[int, Event]
) -> tuple[dict[str, tuple[Event, dict[str, Any]]], set[str]]:
    """Index the bundle's signed seal events by the segment they seal.

    Returns ``(by_segment_id, ambiguous_ids)``. A segment claimed by two seal
    events is ambiguous and fails closed rather than letting a verifier pick
    the convenient one.

    A seal event is only accepted as an anchor if it is CHAIN-LINKED: its
    ``prev_global_event_hash`` must match an event present in the bundle,
    unless it is the lowest-``global_seq`` event there (the one event a
    windowed chunk may legitimately start from). Without that, a tamperer
    could delete a real seal event and inject a forged one carrying whatever
    payload the doctored record needs: a free-floating event chains from
    nothing, so ``_verify_global_chain`` accepts it as a bridge fragment,
    whereas an injected event that DOES chain from a present predecessor forks
    that predecessor and is already rejected. (Precondition, same as
    ``_segment_chain_links``: a store whose events have been moved to
    ``events_archive`` can have genuine gaps, so a real seal event may look
    unlinked — see WI-259.)
    """
    by_segment: dict[str, tuple[Event, dict[str, Any]]] = {}
    ambiguous: set[str] = set()
    min_seq = min(events_by_seq) if events_by_seq else None
    present_hashes = {
        h.hex() for h in (_hash_event(e) for e in events) if h is not None
    }

    for evt in events:
        if evt.entity_kind != "segment":
            continue
        payload = _seal_payload_of(evt)
        if payload is None:
            continue
        if evt.global_seq != min_seq:
            prev = evt.prev_global_event_hash
            if prev is None or bytes(prev).hex() not in present_hashes:
                continue
        seg_id = str(payload["segment_id"])
        if seg_id in by_segment:
            ambiguous.add(seg_id)
            continue
        by_segment[seg_id] = (evt, payload)
    return by_segment, ambiguous


def _seal_values_agree(name: str, record_value: Any, seal_value: Any) -> bool:
    if name == "work_item_ids":
        return sorted(str(w) for w in (record_value or [])) == sorted(
            str(w) for w in (seal_value or [])
        )
    if name in _TIMESTAMP_SEAL_FIELDS and record_value != seal_value:
        # Compare instants, not spellings: the record's timestamps round-trip
        # through the database while the payload's are the event's own
        # isoformat, so an identical instant could differ in representation.
        try:
            return datetime.fromisoformat(str(record_value)) == datetime.fromisoformat(
                str(seal_value)
            )
        except (TypeError, ValueError):
            return False
    return bool(record_value == seal_value)


def _reconcile_segment_with_seal(
    seg: dict[str, Any], seal_event: Event, payload: dict[str, Any]
) -> tuple[bool, str | None]:
    """Reconcile a segment RECORD against its own signed ``segment_sealed`` event.

    Everything else in this module checks the record against the bundle's
    EVENTS. That leaves the record's own fields anchored only where an event
    happens to mirror them, and it makes the ``event_count`` check circular:
    membership is computed from the record's ``work_item_ids``, so editing
    both together kept them agreeing (Sol round-2 finding 1, attacks (a) and
    (b)). The seal event closes the circle. Its payload is the sealer's signed
    statement of what the segment is, it travels in the bundle as an ordinary
    event, and its envelope is committed by the global hash chain — so a
    tamperer must forge a signature, not edit a JSON field.

    Reconciled (all confirmed present in a live seal payload):
    ``first_global_seq``, ``last_global_seq``, ``event_count``, ``head_hash``,
    ``first_event_prev_hash``, ``first_event_id``, ``last_event_id``,
    ``work_item_ids``, ``min_timestamp``, ``max_timestamp``, ``archive_path``,
    plus ``segment_id`` (implicit — it is the lookup key) and
    ``seal_event_id`` (against the seal event's own ``event_id``).

    NOT anchored, because the seal payload does not carry them and cannot:

    * ``archived`` — flipped by archival AFTER the segment is sealed, so no
      value signed at seal time could be authoritative.
    * ``created_at`` — the row's insert timestamp, written alongside the seal
      rather than inside it.

    Both are row lifecycle metadata that no verification step consumes; a
    tamperer can rewrite them and nothing here objects. Stated rather than
    silently skipped.
    """
    seg_id = seg.get("segment_id", "?")

    declared_seal_id = seg.get("seal_event_id")
    if declared_seal_id is not None and str(declared_seal_id) != str(
        seal_event.event_id
    ):
        return False, (
            f"segment {seg_id} names seal_event_id={declared_seal_id} but the "
            f"segment_sealed event that seals it is {seal_event.event_id}"
        )

    for name in _SEAL_RECONCILED_FIELDS:
        if name not in payload:
            continue
        if not _seal_values_agree(name, seg.get(name), payload[name]):
            return False, (
                f"segment {seg_id} record disagrees with its signed "
                f"segment_sealed event on {name}: record={seg.get(name)!r}, "
                f"seal={payload[name]!r}"
            )
    return True, None


def _count_segment_events(
    seg: dict[str, Any], events: list[Event], first: int, last: int
) -> int:
    """Count the bundle's events that belong to *seg*.

    A segment is NOT simply "every event in ``[first, last]``": sealing selects
    the events of work items that have reached a terminal state, so events of
    other work items can be interleaved inside the segment's seq range and are
    not members of it (see ``seal_segment``). The segment record carries the
    ``work_item_ids`` it sealed, which is the same membership key the store
    uses, so membership is ``work_item_id in seg.work_item_ids`` bounded by the
    segment's own declared range. A record with no ``work_item_ids`` (an older
    row) falls back to the seq range excluding seal events, mirroring
    ``verify_segment``'s fallback when a segment carries no ``event_ids``.

    CIRCULARITY. ``work_item_ids`` is part of the record being checked, so
    this count agrees with ``event_count`` whenever a tamperer edits BOTH
    (Sol round-2 attack (b): unrelated work_item_ids + ``event_count`` 0).
    It is exact when the record is honest and it still catches a single-field
    edit, but it is not an anchor. ``_segment_count_band`` supplies the
    non-circular bound, and ``_reconcile_segment_with_seal`` the signed one.
    """
    wi_ids = {str(w) for w in (seg.get("work_item_ids") or [])}
    count = 0
    for evt in events:
        gseq = evt.global_seq
        if gseq is None or gseq < first or gseq > last:
            continue
        if wi_ids:
            if str(evt.work_item_id) in wi_ids:
                count += 1
        elif evt.entity_kind != "segment":
            count += 1
    return count


def _segment_count_band(
    events: list[Event], first: int, last: int
) -> int:
    """Upper bound on a segment's event count that the record cannot move.

    A segment's members are a SUBSET of the non-seal events in its own seq
    range (sealing may skip interleaved work items, so the range can hold more
    than the segment does — but never fewer). Counting the range without
    consulting ``work_item_ids`` gives a bound no field of the record can
    influence, which is what makes it worth having next to the exact count.
    """
    return sum(
        1
        for evt in events
        if evt.global_seq is not None
        and first <= evt.global_seq <= last
        and evt.entity_kind != "segment"
    )


def _verify_segment_record_offline(
    seg: dict[str, Any],
    events: list[Event],
    events_by_seq: dict[int, Event],
    lo: int | None,
    hi: int | None,
    seals: dict[str, tuple[Event, dict[str, Any]]],
    ambiguous_seals: set[str],
) -> tuple[bool, str | None]:
    """Validate one segment record against the bundle.

    Three independent anchors, because each covers what the others cannot:

    1. **The signed seal event** (``_reconcile_segment_with_seal``). The
       sealer's ``segment_sealed`` payload states what the segment is, and it
       is committed by the global hash chain, so it anchors the record's own
       fields — including the ones no event mirrors. This is the only anchor
       that is not circular, and it is what closes Sol round-2 finding 1.
    2. **The boundary events.** ``head_hash`` must be the hash of the event at
       ``last_global_seq``, and the event at ``first_global_seq`` must be the
       record's ``first_event_id`` with the record's ``first_event_prev_hash``.
       Anchoring BOTH ends is what makes a boundary edit fail even when the
       seal event is out of window: moving ``first_global_seq`` to 0 (Sol
       attack (a)) lands on no event at all, and moving it onto a real event
       lands on the wrong ``event_id``.
    3. **The count band.** ``1 <= event_count <=`` the non-seal events in the
       range — bounds that no field of the record can move — alongside the
       exact (circular) membership count.

    WINDOWED EXPORTS (WI-240/WI-249). A chunked export keeps every segment
    that OVERLAPS the window, so a kept segment may be only partly inside it.
    Each anchor is gated on what the window actually contains:

    * ``last_global_seq <= hi`` — the tail event is in-window, so the
      ``head_hash`` anchor applies. A low-side cut does not remove it.
    * ``first_global_seq >= lo`` — the first event is in-window, so the
      first-boundary anchor applies.
    * both — the whole segment is in-window, so the counts are claims the
      bundle can settle and must.
    * The seal event is reconciled whenever it is IN the bundle, whatever the
      window does, and is REQUIRED when the bundle declares no upper bound
      (``hi is None``): the seal's ``global_seq`` is always above the
      segment's ``last_global_seq``, so an unbounded export must contain it.

    What remains unverifiable, stated rather than skipped:

    * A bundle that declares a window ending before a segment's
      ``last_global_seq`` disclaims completeness for that segment. A tamperer
      who rewrites a full export's manifest into such a window buys the
      leniency that goes with it — including, when the declared ``until_seq``
      is at or below where the seal event sits, the chance to delete that seal
      event and lose anchor 1. Anchors 2 and 3 still apply to whatever stays
      in range, so the surviving move is narrow (understating a segment's
      ``work_item_ids`` and ``event_count`` together). This is the inherent
      limit of an unkeyed bundle hash, and the reason the manifest's
      ``since_seq``/``until_seq`` belong in the auditor's chunk plan.
    * ``archived`` and ``created_at`` are not in the seal payload and cannot
      be — see ``_reconcile_segment_with_seal``.
    * For an HMAC-signed store the seal event's SIGNATURE cannot be checked
      offline (the secret is deliberately never exported), so anchor 1 rests
      on the hash chain: rewriting a seal event's envelope changes its hash
      and breaks whatever chains from it. An ed25519 store additionally gets
      the signature verified by ``_verify_event_signatures``.
    * If a segment's events have been moved to ``events_archive`` they are
      missing from the bundle, and these checks fail closed — the same
      precondition ``_segment_chain_links`` documents for gap events (WI-259).
    """
    seg_id = str(seg.get("segment_id", "?"))
    first = seg["first_global_seq"]
    last = seg["last_global_seq"]

    if seg_id in ambiguous_seals:
        return False, (
            f"segment {seg_id} is claimed by more than one segment_sealed "
            f"event — its record cannot be anchored (fail closed)"
        )
    seal = seals.get(seg_id)
    if seal is not None:
        ok, err = _reconcile_segment_with_seal(seg, seal[0], seal[1])
        if not ok:
            return False, err
    elif hi is None:
        return False, (
            f"segment {seg_id} has no chain-linked segment_sealed event in the "
            f"bundle, which declares no upper window bound — a seal always "
            f"follows the segment it seals, so an unbounded export contains it "
            f"(fail closed)"
        )

    if hi is not None and last > hi:
        # Upper-truncated by the export window: the boundary/count anchors
        # below describe events the chunk deliberately excludes.
        return True, None

    head_hash = seg.get("head_hash")
    if head_hash is None:
        return False, (
            f"segment {seg_id} has no head_hash but its terminal event "
            f"(global_seq {last}) is inside the exported window"
        )
    try:
        stored_head = bytes.fromhex(head_hash)
    except (TypeError, ValueError):
        return False, f"segment {seg_id} has a malformed head_hash: {head_hash!r}"

    tail = events_by_seq.get(last)
    if tail is None:
        return False, (
            f"segment {seg_id} claims last_global_seq={last} but the bundle "
            f"holds no event at that global_seq — its head_hash anchors "
            f"nothing (fail closed)"
        )
    recomputed_head = _hash_event(tail)
    if recomputed_head is None:
        return False, (
            f"segment {seg_id}: event at last_global_seq={last} is missing "
            f"canonical_envelope or signature, so head_hash cannot be checked"
        )
    if not _hmac.compare_digest(recomputed_head, stored_head):
        return False, (
            f"segment {seg_id} head_hash does not match the event at "
            f"last_global_seq={last}: stored={head_hash}, "
            f"recomputed={recomputed_head.hex()}"
        )

    if lo is not None and first < lo:
        # Lower-truncated: the tail anchor applied, the first-boundary and
        # count anchors describe events outside the chunk.
        return True, None

    head = events_by_seq.get(first)
    if head is None:
        return False, (
            f"segment {seg_id} claims first_global_seq={first} but the bundle "
            f"holds no event at that global_seq (fail closed)"
        )
    declared_first_id = seg.get("first_event_id")
    if declared_first_id is not None and str(declared_first_id) != str(head.event_id):
        return False, (
            f"segment {seg_id} names first_event_id={declared_first_id} but the "
            f"event at first_global_seq={first} is {head.event_id}"
        )
    declared_first_prev = seg.get("first_event_prev_hash")
    actual_first_prev = (
        bytes(head.prev_global_event_hash).hex()
        if head.prev_global_event_hash is not None
        else None
    )
    if declared_first_prev != actual_first_prev:
        return False, (
            f"segment {seg_id} declares first_event_prev_hash="
            f"{declared_first_prev!r} but the event at first_global_seq={first} "
            f"chains from {actual_first_prev!r}"
        )

    declared_count = seg.get("event_count")
    # Non-circular band first: these bounds cannot be moved by editing the
    # record, so they hold even when work_item_ids has been rewritten to make
    # the exact count agree with itself.
    if not isinstance(declared_count, int) or isinstance(declared_count, bool):
        return False, (
            f"segment {seg_id} declares a non-integer event_count="
            f"{declared_count!r}"
        )
    if declared_count < 1:
        return False, (
            f"segment {seg_id} declares event_count={declared_count}; a sealed "
            f"segment always holds at least one event"
        )
    range_count = _segment_count_band(events, first, last)
    if declared_count > range_count:
        return False, (
            f"segment {seg_id} declares event_count={declared_count} but its "
            f"range global_seq [{first}, {last}] holds only {range_count} "
            f"non-seal event(s) in the bundle"
        )

    actual_count = _count_segment_events(seg, events, first, last)
    if declared_count != actual_count:
        return False, (
            f"segment {seg_id} declares event_count={declared_count} but the "
            f"bundle holds {actual_count} of its event(s) in global_seq "
            f"[{first}, {last}]"
        )

    return True, None


def _verify_segment_chain_offline(
    segments: list[dict[str, Any]],
    events: list[Event],
    *,
    since_seq: Any = None,
    until_seq: Any = None,
) -> tuple[bool, str | None]:
    # Fail closed on malformed segments: a segment with no first_global_seq
    # cannot be placed in the chain, and silently sorting it first (the
    # default 0) would let a corrupt segment masquerade as the chain start.
    # last_global_seq is equally load-bearing now — it is where the segment's
    # head_hash is anchored (WI-254) — so an absent or nonsensical boundary is
    # a refusal, not a skipped check.
    for seg in segments:
        seg_id = seg.get("segment_id", "?")
        first = seg.get("first_global_seq")
        last = seg.get("last_global_seq")
        if first is None:
            return False, (
                f"segment {seg_id} has no first_global_seq "
                f"— cannot order it in the segment chain (fail closed)"
            )
        if last is None:
            return False, (
                f"segment {seg_id} has no last_global_seq — its head_hash "
                f"cannot be anchored to an event (fail closed)"
            )
        if (
            isinstance(first, bool)
            or isinstance(last, bool)
            or not isinstance(first, int)
            or not isinstance(last, int)
        ):
            return False, (
                f"segment {seg_id} has non-integer bounds "
                f"(first_global_seq={first!r}, last_global_seq={last!r})"
            )
        if first > last:
            return False, (
                f"segment {seg_id} has first_global_seq={first} greater than "
                f"last_global_seq={last}"
            )

    sorted_segs = sorted(segments, key=lambda s: s["first_global_seq"])

    # Segments partition the chain: they must not overlap. An overlap would
    # let two records claim the same events (and the same tail), which the
    # per-record checks below would then both "confirm".
    for i in range(1, len(sorted_segs)):
        prev_last = sorted_segs[i - 1]["last_global_seq"]
        curr_first = sorted_segs[i]["first_global_seq"]
        if curr_first <= prev_last:
            return False, (
                f"segments {sorted_segs[i - 1].get('segment_id', '?')} "
                f"[..{prev_last}] and {sorted_segs[i].get('segment_id', '?')} "
                f"[{curr_first}..] overlap — segment ranges must be disjoint "
                f"and monotonic"
            )

    # Events indexed by global_seq so the inter-segment gap can be sliced
    # without re-scanning the whole list for every consecutive pair.
    events_by_seq = sorted(
        (e for e in events if e.global_seq is not None),
        key=lambda e: e.global_seq if e.global_seq is not None else 0,
    )
    events_at_seq: dict[int, Event] = {
        e.global_seq: e for e in events_by_seq if e.global_seq is not None
    }

    # Every segment record — including the terminal one and a sole segment,
    # which the chain walk below never reaches as a predecessor (WI-254).
    lo, hi = _exported_window(since_seq, until_seq)
    seals, ambiguous_seals = _index_seal_events(events, events_at_seq)
    for seg in sorted_segs:
        ok, err = _verify_segment_record_offline(
            seg, events, events_at_seq, lo, hi, seals, ambiguous_seals
        )
        if not ok:
            return False, err

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

        # Consecutive segments are not adjacent in the global chain: the seal
        # event of the earlier segment (and any other events created between
        # the two seals) sits between them. Walk the chain through those
        # intermediate events instead of comparing the boundary hashes
        # directly (WI-249).
        prev_last = prev_seg.get("last_global_seq")
        curr_first = curr_seg.get("first_global_seq")
        if prev_last is not None and curr_first is not None:
            intermediate = [
                e for e in events_by_seq
                if prev_last < e.global_seq < curr_first
            ]
        else:
            intermediate = []

        try:
            prev_head_bytes = bytes.fromhex(prev_head_hash)
            curr_first_bytes = bytes.fromhex(curr_first_prev_hash)
        except ValueError:
            return False, (
                f"segment chain broken between segment "
                f"{prev_seg.get('segment_id', '?')} and "
                f"{curr_seg.get('segment_id', '?')}: "
                f"malformed boundary hash"
            )

        if _segment_chain_links(
            prev_head_bytes, curr_first_bytes, intermediate
        ):
            continue

        return False, (
            f"segment chain broken between segment "
            f"{prev_seg.get('segment_id', '?')} and "
            f"{curr_seg.get('segment_id', '?')}: "
            f"head_hash={prev_head_hash}, "
            f"first_event_prev_hash={curr_first_prev_hash}"
        )

    return True, None


def _row_to_event_dict(row: dict[str, Any]) -> dict[str, Any]:
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
        # `is not None`, not truthiness: an empty object is a *signed value*
        # distinct from null (JCS emits `{}` vs `null`), so collapsing it would
        # make the exported row disagree with the envelope that signed it.
        "actor_metadata": (
            row["actor_metadata"] if row["actor_metadata"] is not None else None
        ),
        "key_id": row["key_id"],
        "workflow_name": row["workflow_name"],
        "workflow_version": row["workflow_version"],
        "timestamp": row["timestamp"].isoformat() if row["timestamp"] else None,
        "transition": row["transition"],
        "payload": row["payload"] if row["payload"] is not None else None,
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


def _canonical_bundle_bytes(bundle: dict[str, Any]) -> bytes:
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
