from __future__ import annotations

import base64
import binascii
import hashlib
import hmac as _hmac
import json
import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from ._connection import ConnectionManager, DictConn
from ._errors import ErrorCode, RegistaError
from ._signing_scheme import get_scheme
from ._types import Event
from ._v6_referents import BundleReferents
from ._verification import (
    DEFAULT_POLICY,
    Applicability,
    Backend,
    BundleKeyResolver,
    EventRow,
    VerificationPolicy,
    verify_event_strict,
)

log = structlog.get_logger()

# v2 adds the principal public-key registry to the bundle so event signatures
# on asymmetric schemes are verified offline (signer binding). v1 bundles are
# still accepted; their signature check is reported as skipped.
#
# P1.4 (BUNDLE-V3.md §8) deleted the anchor-receipt, segment and
# window/manifest-count machinery: zero anchor_receipts and zero
# event_segments existed estate-wide, and bundle v3 (P3.3) replaces the
# unkeyed bundle hash with a signed statement. This module is the retained
# interim export/verify path until P3.3 lands.
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
    global_chain_ok: bool
    global_chain_error: str | None = None
    work_item_chain_ok: bool = True
    work_item_chain_error: str | None = None
    bundle_hash_ok: bool = True
    bundle_hash_error: str | None = None
    signatures_verified: int = 0
    signatures_unverifiable: int = 0
    signature_check: str = "enforced"
    errors: list[str] = field(default_factory=list)
    #: Why each unverifiable signature was unverifiable. A count with no reason is
    #: how "nothing was checked" gets read as "everything checks out"; the two v6
    #: cases that land here (an unpinned bootstrap event, a referent outside a
    #: windowed scope) are both things an auditor must be able to read off the
    #: report rather than reproduce.
    unverifiable_details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verified": self.verified,
            "event_count": self.event_count,
            "global_chain_ok": self.global_chain_ok,
            "global_chain_error": self.global_chain_error,
            "work_item_chain_ok": self.work_item_chain_ok,
            "work_item_chain_error": self.work_item_chain_error,
            "bundle_hash_ok": self.bundle_hash_ok,
            "bundle_hash_error": self.bundle_hash_error,
            "signatures_verified": self.signatures_verified,
            "signatures_unverifiable": self.signatures_unverifiable,
            "signature_check": self.signature_check,
            "errors": self.errors,
            "unverifiable_details": self.unverifiable_details,
        }


_EVENT_COLUMNS = (
    "event_id, work_item_id, entity_kind, entity_id, hash_alg, "
    "event_seq, global_seq, actor_id, actor_kind, "
    "actor_metadata, key_id, workflow_name, workflow_version, "
    "timestamp, transition, payload, payload_canonical_hash, signature, "
    "canonical_envelope, on_behalf_of, scheme_id, prev_event_hash, "
    "prev_global_event_hash"
)


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

        # The optional section comes from a table that may predate its
        # migration (older stores). ONLY a missing table is tolerated — and it
        # is recorded in the manifest so the auditor sees the bundle's scope.
        # Any other failure aborts the export: an audit bundle that silently
        # omits public keys would still "verify" while proving less than the
        # auditor believes (fail closed).
        public_keys, registry_available = _read_optional_section(
            conn,
            "principal_keys",
            lambda c: _list_principal_key_dicts(c),
        )

    # File assembly, the size gate and self-verification run outside the
    # transaction: none of it reads the store, and an 800 MiB serialization
    # should not hold a connection open (WI-240).
    seqs = [e["global_seq"] for e in events if e.get("global_seq") is not None]
    max_exported_seq = max(seqs) if seqs else None
    min_exported_seq = min(seqs) if seqs else None

    exported_at = datetime.now(UTC)
    manifest = {
        "project": project_name,
        "exported_at": exported_at.isoformat(),
        "event_count": len(events),
        "public_key_count": len(public_keys),
        "principal_key_registry": "present" if registry_available else "absent",
        "format_version": _BUNDLE_FORMAT_VERSION,
        "since_seq": since_seq,
        "until_seq": until_seq,
    }

    bundle: dict[str, Any] = {
        "manifest": manifest,
        "events": events,
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
        public_key_count=len(public_keys),
        bundle_bytes=len(serialized),
        self_verified=report.verified,
        output_path=str(output),
    )

    return {
        "output_path": str(output),
        "event_count": len(events),
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
            "unverifiable_details": report.unverifiable_details[:5],
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


def _list_principal_key_dicts(conn: DictConn) -> list[dict[str, Any]]:
    from ._principal_keys import list_principal_keys_for_conn

    return [k.to_dict() for k in list_principal_keys_for_conn(conn)]


def verify_audit_bundle_offline(
    bundle_path: str | Path,
    *,
    policy: VerificationPolicy | None = None,
) -> BundleVerificationReport:
    """Verify a bundle offline. No network, no store, no fetch (§8.4).

    ``policy`` carries the caller's out-of-band pins — the trust domain, the cutover
    checkpoint hash, the project instance. They are the difference between "this
    artifact is internally consistent" and "this artifact chains to a root I named",
    and they cannot come from the artifact: a bundle that supplied its own pin would
    be vouching for itself. ``None`` means no pin was supplied, and the report then
    says so per event (``unbound_properties`` names ``external_trust_pin``) rather
    than quietly grading the bundle as if it had one.
    """

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

    errors: list[str] = []

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

    ok_global, err_global, _tail = _verify_global_chain(events)
    ok_wi, err_wi = _verify_work_item_chains(events)

    if not ok_global:
        errors.append(f"Global chain error: {err_global}")
    if not ok_wi:
        errors.append(f"Work-item chain error: {err_wi}")

    if fmt_version == 1 and "public_keys" not in bundle:
        # v1 bundles carry no key registry; skipping is reported, not hidden.
        signature_check = "skipped_v1_bundle"
        sigs_verified = 0
        sigs_unverifiable = 0
        sigs_unverifiable_details: list[str] = []
    else:
        signature_check = "enforced"
        sigs_verified, sigs_unverifiable, sig_errors, sigs_unverifiable_details = (
            _verify_event_signatures(
            events,
            bundle.get("public_keys", []),
            manifest=manifest,
            policy=policy or DEFAULT_POLICY,
            )
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
        and len(errors) == 0
        and sigs_verified > 0
    )

    return BundleVerificationReport(
        verified=verified,
        event_count=len(events),
        global_chain_ok=ok_global,
        global_chain_error=err_global if not ok_global else None,
        work_item_chain_ok=ok_wi,
        work_item_chain_error=err_wi if not ok_wi else None,
        bundle_hash_ok=bundle_hash_ok,
        bundle_hash_error=bundle_hash_error,
        signatures_verified=sigs_verified,
        signatures_unverifiable=sigs_unverifiable,
        signature_check=signature_check,
        errors=errors,
        unverifiable_details=sigs_unverifiable_details,
    )


def _key_evidence_from_v6_payloads(events: list[Event]) -> dict[str, dict[str, Any]]:
    """Key material carried by the bundle's own v6 acceptance payloads (WI-296).

    ``TRUST-DOMAIN.md`` §5.8 repeats ``public_key`` inside every
    ``regista.key-acceptance`` object, and ``RECONCILIATION.md`` Resolution 1 repeats
    it inside every ``bootstrap_key_acceptance``, and both say why: "It makes a
    project bundle self-sufficient for key material without making it self-sufficient
    for *trust*: the bytes are present, the authority to believe them comes from the
    externally pinned root via ``trust_event_hash``."

    So this is not a fallback and not a second key resolver — it reads the **signed
    envelope** of an event the bundle already carries. The alternative WI-296 offered
    (``write_genesis`` seeding a ``principal_keys`` row from the same object) was
    rejected on the item: a projection row that exists *because* a verifier needs it
    is precisely §5.9 rule 1's forbidden coupling.

    The entries produced carry no validity window and no revocation state, because
    the acceptance payload declares none. That is why an operator-registered entry
    wins where both exist: it knows strictly more.
    """

    from ._verification import (
        V6EnvelopeError,
        parse_v6_envelope_strict,
    )

    evidence: dict[str, dict[str, Any]] = {}
    for evt in events:
        if evt.canonical_envelope is None:
            continue
        try:
            envelope = parse_v6_envelope_strict(bytes(evt.canonical_envelope))
        except (V6EnvelopeError, TypeError, ValueError):
            continue
        payload = envelope["payload"]
        if not isinstance(payload, Mapping):
            continue
        candidates: list[Mapping[str, Any]] = []
        if payload.get("type") == "regista.key-acceptance":
            candidates.append(payload)
        embedded = payload.get("bootstrap_key_acceptance")
        if isinstance(embedded, Mapping):
            candidates.append(embedded)
        for acceptance in candidates:
            key_id = acceptance.get("key_id")
            principal_id = acceptance.get("principal_id")
            public_key = acceptance.get("public_key")
            if not (
                isinstance(key_id, str)
                and isinstance(principal_id, str)
                and isinstance(public_key, str)
            ):
                continue
            try:
                material = base64.b64decode(public_key, validate=True)
            except (ValueError, binascii.Error):
                continue
            if len(material) != 32:
                continue
            evidence.setdefault(
                key_id,
                {
                    "key_id": key_id,
                    "principal_id": principal_id,
                    # The scheme is ed25519 by construction: a v6 envelope's
                    # `signing.scheme_id` is validated to it, and the acceptance's
                    # own `scheme_id` is cross-checked at write time
                    # (`_genesis._require_bootstrap_acceptance`).
                    "scheme": "ed25519",
                    "public_key": material,
                    "status": "active",
                    "valid_from": None,
                    "valid_to": None,
                    "revoked_at": None,
                },
            )
    return evidence


def _verify_event_signatures(
    events: list[Event],
    public_keys_data: list[dict[str, Any]],
    *,
    manifest: Mapping[str, Any] | None = None,
    policy: VerificationPolicy | None = None,
) -> tuple[int, int, list[str], list[str]]:
    """Verify event signatures offline against the bundled key registry.

    Asymmetric-scheme events (e.g. ed25519) are verified against the
    principal public-key registry exported in the bundle, including the
    principal↔signer binding (key.principal_id must equal event.actor_id,
    mirroring ``verify_principal_binding``) and the key's validity window.

    Symmetric-scheme events (hmac-*) are counted as unverifiable: verifying
    an HMAC requires the secret, which is deliberately never exported. An
    unknown scheme fails closed.

    Returns ``(verified_count, unverifiable_count, errors, unverifiable_details)``.
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

    # WI-296's genesis key-evidence half, taking the BUNDLE route rather than
    # seeding `principal_keys` from the genesis payload. §5.8 repeats `public_key`
    # inside the acceptance object **on purpose** — "it makes a project bundle
    # self-sufficient for key material without making it self-sufficient for
    # trust" — so a bundle that carries a v6 acceptance already carries the bytes,
    # and reading them from there is not a fallback: it is the signed artifact.
    # Seeding the projection instead would put a row in `principal_keys`
    # specifically so a verifier could find it, which §5.9 rule 1 forbids and
    # §5.11's last row calls the S6 defect.
    #
    # The registry still wins where both exist: an operator-registered entry
    # carries a validity window and a status that the payload does not.
    for key_id, entry in _key_evidence_from_v6_payloads(events).items():
        keys_by_id.setdefault(key_id, entry)

    verified_count = 0
    unverifiable_count = 0
    errors_unverifiable: list[str] = []
    resolver = BundleKeyResolver(keys_by_id)
    # No credential section is passed because bundle v2 has none to pass: WI-289/P3.3
    # adds `sections.action_delegation_credentials` in v3, and until then a delegated
    # event here is *unverifiable* from bundle evidence rather than invalid
    # (BUNDLE-V3.md §9 item 6). `from_bundle`'s default states that, and it is a
    # different state from an empty v3 section — see its docstring.
    referents = BundleReferents.from_bundle(manifest or {}, events)
    effective_policy = policy or DEFAULT_POLICY

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
            referents=referents,
            policy=effective_policy,
        )
        if result.applicability is Applicability.INVALID:
            errors.append(f"Signature verification failed at {label}: {result.summary()}")
            continue
        if not result.accepted:
            # UNVERIFIABLE is an evidentiary gap, not a defect of the artifact, and
            # the two must not be collapsed — the operator response is completely
            # different. Two cases reach here on a healthy v6 bundle and both are
            # honest: a bootstrap event whose authority is external and unpinned
            # (RECONCILIATION.md Resolution 1), and a referent outside a
            # `contiguous-range` window (§9 criterion 15). Both are counted, and the
            # reason travels with the count instead of being dropped.
            unverifiable_count += 1
            errors_unverifiable.append(f"{label}: {result.summary()}")
            continue

        verified_count += 1

    return verified_count, unverifiable_count, errors, errors_unverifiable
# ---------------------------------------------------------------------------
# Chain verification over bundle events.
#
# Relocated from _archive_segments.py when P1.4 deleted that module: these
# walk the global and per-entity hash chains of the events actually present
# in a bundle, which is retained interim-verify behavior — not segment
# machinery. The unused anchor_hash parameter (segment-only) was dropped in
# the move.
# ---------------------------------------------------------------------------


def _hash_event(event: Event) -> bytes | None:
    """The chain head hash this event contributes, in ITS OWN version's formula.

    Delegates to :func:`regista._signing.compute_chain_head_hash`, which is where the
    formula lives for the whole tree. This function used to hand-copy the version
    dispatch, which made it the **fifth** copy — and the copies have a history:
    mutation M20 reverted this one to the legacy formula and the suite stayed green
    (NOTES-P17 finding 15), and ``_in_memory_replay`` carried the legacy formula in
    both its chain walks, which made a healthy in-memory v6 epoch report five chain
    breaks (finding 16). Finding 16 centralised the formula; this is that
    centralisation finishing the job it started, found by the phase-4 ceremony.

    ``None`` when the event carries no bytes to chain on — a bundle may legitimately
    contain pre-002 rows, and "no envelope" is not "a zero hash".
    """

    if event.canonical_envelope is None or event.signature is None:
        return None
    from ._signing import compute_chain_head_hash

    return compute_chain_head_hash(
        bytes(event.canonical_envelope), bytes(event.signature)
    )


def _verify_global_chain(
    events: list[Event],
) -> tuple[bool, str, Event | None]:
    """Verify the global hash chain within *events*.

    The chain must contain an entry point: an event whose
    ``prev_global_event_hash`` is ``None`` (the global genesis) or one whose
    predecessor lies outside the set (a *bridge point* — a windowed export's
    chunk legitimately starts mid-chain, so its first event links from an
    event the bundle does not carry).

    Returns ``(ok, error, tail)`` where *tail* is the event with the highest
    ``global_seq`` among all chain-fragment tails (or ``None`` if empty).
    """
    if not events:
        return True, "", None

    link_map: dict[str, list[Event]] = {}
    event_hashes: set[bytes] = set()
    for evt in events:
        head = _hash_event(evt)
        if head is not None:
            event_hashes.add(head)
        prev = evt.prev_global_event_hash
        prev_hex = bytes(prev).hex() if prev is not None else ""
        link_map.setdefault(prev_hex, []).append(evt)

    entry_points: list[Event] = []
    for evt in events:
        prev = evt.prev_global_event_hash
        if prev is None:
            entry_points.append(evt)
        elif bytes(prev) not in event_hashes:
            entry_points.append(evt)

    if not entry_points:
        return False, "no chain entry points found (no genesis or bridge events)", None

    visited: set[uuid.UUID] = set()
    tails: list[Event] = []

    for entry in entry_points:
        current: Event | None = entry
        while current is not None:
            if current.event_id in visited:
                break
            visited.add(current.event_id)
            head = _hash_event(current)
            if head is None:
                return (
                    False,
                    f"event {current.event_id} missing canonical_envelope or signature",
                    None,
                )
            successors = link_map.get(head.hex(), [])
            if not successors:
                tails.append(current)
                break
            if len(successors) > 1:
                return False, f"fork detected at event {current.event_id}", None
            current = successors[0]

    if len(visited) != len(events):
        unvisited = [e for e in events if e.event_id not in visited]
        return (
            False,
            f"{len(unvisited)} event(s) not reachable from any entry point",
            None,
        )

    tails.sort(key=lambda e: e.global_seq or 0, reverse=True)
    return True, "", tails[0] if tails else None


def _verify_work_item_chains(events: list[Event]) -> tuple[bool, str]:
    from collections import defaultdict

    by_entity: dict[tuple[str, uuid.UUID], list[Event]] = defaultdict(list)
    for evt in events:
        entity_key = (evt.entity_kind, evt.effective_entity_id)
        by_entity[entity_key].append(evt)

    for (ek, eid), entity_events in by_entity.items():
        entity_events.sort(key=lambda e: e.event_seq)

        entity_event_hashes: set[bytes] = set()
        for evt in entity_events:
            head = _hash_event(evt)
            if head is not None:
                entity_event_hashes.add(head)

        prev_hash: bytes | None = None
        for i, evt in enumerate(entity_events):
            if i == 0:
                if evt.prev_event_hash is not None:
                    if bytes(evt.prev_event_hash) in entity_event_hashes:
                        return False, (
                            f"first event for {ek}/{eid} references an event "
                            f"within the slice — slice is incomplete"
                        )
            else:
                if evt.prev_event_hash is None:
                    return False, (
                        f"event {evt.event_id} (seq {evt.event_seq}) "
                        f"for {ek}/{eid} has null prev_event_hash"
                    )
                if prev_hash is not None:
                    if not _hmac.compare_digest(prev_hash, bytes(evt.prev_event_hash)):
                        return False, (
                            f"hash chain mismatch for {ek}/{eid} at seq {evt.event_seq}"
                        )
            head = _hash_event(evt)
            prev_hash = head

    return True, ""


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
