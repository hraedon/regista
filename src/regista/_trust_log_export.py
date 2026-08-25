"""The published trust-log export — WI-337 (`TRUST-DOMAIN.md` §4.2/§4.3, §5.4 step 5).

What this closes
----------------
`BUNDLE-V3.md`'s Phase-C note states the gap in one sentence: the chain-to-root walk for
a **non-root** project key crosses from the project chain into the trust log (writer →
project acceptance → project genesis bootstrap → trust-log enrolment → pinned root), and
"every trust-log verifier in the tree — ``verify_trust_log_chain``, ``resolve_enrolled_key``,
``load_published_checkpoint`` — is **store-backed**, and §8.4 forbids the offline verifier
from fetching." So `externally_authenticated` was unreachable for a PROJECT bundle, and
§5.4 step 5's "re-fetch the publication through an independent checkout and verify" needed
database credentials — an auditor holding only the publication repository could not
establish the current root set at all.

This module publishes the log itself as a §4.2 artifact: a canonical (RFC 8785 JCS),
root-threshold-signed document carrying **the signed event bytes of every trust-log event**
plus the durable possession-challenge records the replay consumes. It is deliberately NOT a
governance-state *extract*, and the difference is the whole security argument:

    An extract asserts "the current roots are X at threshold k". A verifier consuming it
    must believe that assertion, so the assertion's signature is the only thing standing
    between the auditor and a lie — and the signature is checked against the very set the
    document asserts. That is the circularity WI-330 had to remove from the checkpoint
    path (`_estate_catalog.verify_published_checkpoint`), and re-introducing it one layer
    down would be the same defect with a new name.

    An export of the **events** asserts nothing. The current root set is *derived* by
    replaying the events from the auditor's out-of-band-pinned genesis document, under the
    same verified walk the live store uses. Rotations are proven by their own root-signed
    ``trust_root_rotated`` payloads; a forged rotation needs the genesis roots' private
    keys. The artifact's own ``root_signatures`` are then checked against that *derived*
    set — they prove the publication is currently endorsed, and they are never the source
    of the authority they are checked against.

Offline == online, by construction, not by parallel implementation
------------------------------------------------------------------
There is exactly one verified trust-log walk (WI-303) and this module does not add a
second. ``_trust_log_writer.verify_trust_log_chain`` was widened to read its material
through :class:`~regista._trust_log_writer.TrustLogMaterial`, which names the two reads it
performs (the event rows, and a possession-challenge record by id).
``_StoreMaterial`` answers them from PostgreSQL exactly as before;
:class:`OfflineTrustLogMaterial` answers them from this artifact. The authority semantics —
threshold, rotation, registrar liveness, enrolment-before-use, revocation — are the *same
code* in both cases. A parallel offline replay would drift, and the drift would be in
authority semantics, which is the worst possible place for it.

What the offline replay does NOT reproduce, stated so nobody infers it
----------------------------------------------------------------------
1. **Row/envelope reconciliation is vacuous offline, by construction.**
   ``_reconcile_row`` compares twelve database columns against the signed envelope; its job
   is to catch a tampered *row* beside an intact envelope. An export carries no second copy
   — only ``canonical_envelope`` and ``signature`` — so :class:`OfflineTrustLogMaterial`
   synthesises the row from the envelope and the comparison passes trivially. Nothing is
   lost: the property the check defends (the row and the signed bytes agree) is provided
   here by there being no row. This is named rather than hidden.
2. **A published export can be a truncated PREFIX of the log and still replay cleanly** —
   a prefix of a hash chain is a valid hash chain. Truncation is the one attack the
   artifact's own structure cannot refute, because "this is the whole log" is a claim about
   a set, exactly like `_estate_catalog`'s completeness claim. It is therefore checked
   against something outside the artifact: :func:`verify_trust_log_export` takes an
   ``expect_head`` pin (exact head + count, from direct exchange) and a ``must_cover`` pin
   (a ``min_trust_log_checkpoint`` head the export must be able to reach), and the
   verification report carries ``tail_truncation_undetectable`` whenever no exact head pin
   was supplied — ``must_cover`` raises the floor (it refuses a prefix that does not even
   reach the checkpoint) but does NOT make truncation ABOVE the checkpoint detectable, so a
   ``must_cover``-only export still carries the flag. A consumer that wants a top verdict
   must supply an exact ``expect_head``; see
   ``_bundle._trust_log_export_material``, which requires the §4.6 policy's
   ``min_trust_log_checkpoint`` before any project key is treated as externally pinned.
3. **Authority is evaluated at the export's head**, exactly as `verify-catalog` evaluates it
   at the log's current head (WI-330 FR3-2). Point-in-time authority is still not
   implementable — ``verify_trust_log_chain`` takes no upper bound and
   ``effective_from_checkpoint_seq`` is parsed but never consulted — so a rotation appended
   after publication makes a historically valid export fail an ``expect_head`` pin rather
   than being silently reinterpreted.

Byte contract
-------------
Signed core = the document minus ``{root_signatures, countersignatures, anchors}``,
canonicalised with JCS. Each root signature covers::

    b"regista.trust-log-export.v1\\x00" || uint64be(len(core)) || core

and ``trust_log_export_digest`` is ``sha256`` over those framed bytes — the same shape as
the genesis, checkpoint and estate-catalog documents, produced by the same helpers rather
than a parallel scheme.

``events`` is an ARRAY and JCS does not sort arrays, so its order is inside the signed
bytes. The parser requires that order to be **exact chain order** (genesis first, each
element the ``previous_project_event_hash`` successor of the last), so the publication
bytes for a given log are reproducible and an out-of-order array is a refusal rather than
a document two honest publishers would render differently.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, NoReturn

from ._errors import ErrorCode, RegistaError
from ._jcs import canonicalize
from ._signing import compute_v6_event_hash
from ._trust_domain import (
    derive_governance_mode,
    genesis_document_digest,
    parse_trust_genesis,
    verify_trust_genesis,
)
from ._trust_log import PRINCIPAL_KEY_ENROLLED, PRINCIPAL_KEY_ROTATED
from ._trust_log_writer import (
    TrustLogMaterial,
    VerifiedChain,
    chain_order,
    trust_log_material,
    verify_trust_log_chain,
)

TRUST_LOG_EXPORT_TYPE: Final[str] = "regista.trust-log-export"
TRUST_LOG_EXPORT_VERSION: Final[int] = 1
TRUST_LOG_EXPORT_DOMAIN: Final[bytes] = b"regista.trust-log-export.v1\x00"

#: Excluded from the signed core, for the same reason everywhere else in §4.3: a signature
#: cannot cover itself, and later countersignatures/anchors are additive records.
SIGNATURE_SECTIONS: Final[frozenset[str]] = frozenset(
    {"root_signatures", "countersignatures", "anchors"}
)

#: The signed core's closed key set. ``events`` and ``possession_challenges`` are the
#: evidence; every other member is a *claim* that the replay independently re-derives and
#: this module refuses on disagreement.
CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "type",
        "version",
        "trust_domain_id",
        "trust_domain_core_digest",
        "genesis_document_digest",
        "trust_log",
        "root_governance",
        "active_root_fingerprints",
        "events",
        "possession_challenges",
        "prev_commit",
        "created_at",
    }
)

EXPORT_KEYS: Final[frozenset[str]] = CORE_KEYS | SIGNATURE_SECTIONS

_TRUST_LOG_KEYS: Final[frozenset[str]] = frozenset(
    {"project_instance_id", "event_count", "genesis_event_hash", "head_event_hash"}
)
_GOVERNANCE_KEYS: Final[frozenset[str]] = frozenset({"mode", "threshold", "signer_count"})
_ROOT_SIGNATURE_KEYS: Final[frozenset[str]] = frozenset(
    {"signer_id", "fingerprint", "signature"}
)
_EVENT_KEYS: Final[frozenset[str]] = frozenset({"canonical_envelope", "signature"})

#: The durable possession-challenge record, exactly the columns
#: ``_trust_log_writer._verify_possession_evidence`` and ``_possession_challenge_from_row``
#: read. The key set is closed so an artifact cannot smuggle an extra field past the
#: signature into a future reader.
_CHALLENGE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "challenge_id",
        "operation_id",
        "operation_digest",
        "project",
        "principal_id",
        "fingerprint",
        "scheme",
        "verifier_nonce",
        "issued_at",
        "expires_at",
        "used",
        "kind",
        "trust_domain_id",
        "enrollment_request_digest",
        "proof_signature",
    }
)

_DIGEST_RE: Final[re.Pattern[str]] = re.compile(r"^sha256:[0-9a-f]{64}$")
_FINGERPRINT_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9-]+:sha256:[0-9a-f]{64}$")
_GIT_COMMIT_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")
_UUID_RE: Final[re.Pattern[str]] = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
#: Exactly six fractional digits — ``strptime('%f')`` accepts one to six, which was
#: WI-330 defect N-b. The publication bytes must not have two renderings.
_TIMESTAMP_RE: Final[re.Pattern[str]] = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)
_TIMESTAMP_STRPTIME: Final[str] = "%Y-%m-%dT%H:%M:%S.%fZ"
_ED25519_SIGNATURE_LEN: Final[int] = 64


# ---------------------------------------------------------------------------
# Refusals. Every one carries a machine-readable ``reason``; no path warns.
# ---------------------------------------------------------------------------


def _schema(message: str, reason: str, **detail: Any) -> NoReturn:
    raise RegistaError(
        ErrorCode.TRUST_LOG_EXPORT_SCHEMA_INVALID, message, {"reason": reason, **detail}
    )


def _unverified(message: str, reason: str, **detail: Any) -> NoReturn:
    raise RegistaError(
        ErrorCode.TRUST_LOG_EXPORT_UNVERIFIED, message, {"reason": reason, **detail}
    )


def _require(condition: bool, message: str, reason: str, **detail: Any) -> None:
    if not condition:
        _schema(message, reason, **detail)


def _require_object(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _schema(f"{path} must be a JSON object", "not_an_object", path=path)
    return value


def _require_keys(value: object, expected: frozenset[str], path: str) -> Mapping[str, Any]:
    obj = _require_object(value, path)
    unknown = sorted(set(obj) - expected)
    missing = sorted(expected - set(obj))
    if unknown or missing:
        _schema(
            f"{path} does not carry exactly its defined key set",
            "closed_key_set_violated",
            path=path,
            unknown=unknown,
            missing=missing,
        )
    return obj


def _require_str(value: object, path: str) -> str:
    if not isinstance(value, str) or not value:
        _schema(f"{path} must be a non-empty string", "not_a_string", path=path)
    return value


def _require_pattern(value: object, pattern: re.Pattern[str], path: str, what: str) -> str:
    text = _require_str(value, path)
    if not pattern.match(text):
        _schema(f"{path} must be {what}", "malformed_value", path=path, value=text)
    return text


def _require_int(value: object, path: str, *, minimum: int) -> int:
    # ``type(value) is int`` so ``True`` is not silently an integer.
    if type(value) is not int:
        _schema(f"{path} must be an integer", "not_an_integer", path=path)
    if value < minimum:
        _schema(
            f"{path} must be >= {minimum}",
            "integer_out_of_range",
            path=path,
            value=value,
            minimum=minimum,
        )
    return value


def _require_list(value: object, path: str) -> Sequence[Any]:
    if not isinstance(value, list):
        _schema(f"{path} must be a JSON array", "not_an_array", path=path)
    return value


def _require_timestamp(value: object, path: str) -> str:
    text = _require_str(value, path)
    if not _TIMESTAMP_RE.match(text):
        _schema(
            f"{path} must be YYYY-MM-DDTHH:MM:SS.ffffffZ with exactly six fractional "
            "digits",
            "malformed_timestamp",
            path=path,
            value=text,
        )
    try:
        datetime.strptime(text, _TIMESTAMP_STRPTIME)
    except ValueError:
        _schema(f"{path} is not a real timestamp", "malformed_timestamp", path=path)
    return text


def _require_b64(value: object, path: str, *, exact_len: int | None = None) -> bytes:
    text = _require_str(value, path)
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, binascii.Error):
        _schema(f"{path} is not valid base64", "malformed_base64", path=path)
    if exact_len is not None and len(raw) != exact_len:
        _schema(
            f"{path} must decode to exactly {exact_len} bytes, got {len(raw)}",
            "signature_length_invalid",
            path=path,
        )
    return raw


# ---------------------------------------------------------------------------
# Byte contract
# ---------------------------------------------------------------------------


def trust_log_export_core(document: Mapping[str, Any]) -> dict[str, Any]:
    """The signed core: the document minus its signature sections."""

    return {k: v for k, v in document.items() if k not in SIGNATURE_SECTIONS}


def trust_log_export_canonical_core(document: Mapping[str, Any]) -> bytes:
    return canonicalize(trust_log_export_core(document))


def trust_log_export_signature_input(document: Mapping[str, Any]) -> bytes:
    """``DOMAIN || uint64be(len(core)) || core`` — §4.3's one framing."""

    body = trust_log_export_canonical_core(document)
    return TRUST_LOG_EXPORT_DOMAIN + struct.pack(">Q", len(body)) + body


def trust_log_export_digest(document: Mapping[str, Any]) -> str:
    """The out-of-band-comparable digest, over the FRAMED signing input."""

    return "sha256:" + hashlib.sha256(trust_log_export_signature_input(document)).hexdigest()


# ---------------------------------------------------------------------------
# Parsed shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExportedEvent:
    """One trust-log event, carried as the two byte strings its hash covers."""

    canonical_envelope: bytes
    signature: bytes

    @property
    def event_hash(self) -> str:
        return "sha256:" + compute_v6_event_hash(self.canonical_envelope, self.signature).hex()

    def as_document_member(self) -> dict[str, str]:
        return {
            "canonical_envelope": base64.b64encode(self.canonical_envelope).decode("ascii"),
            "signature": base64.b64encode(self.signature).decode("ascii"),
        }


@dataclass(frozen=True)
class ExportGovernance:
    mode: str
    threshold: int
    signer_count: int


@dataclass(frozen=True)
class ExportRootSignature:
    signer_id: str
    fingerprint: str
    signature: bytes


@dataclass(frozen=True)
class TrustLogExport:
    """A strictly-parsed export. Every field here is still a CLAIM until verified."""

    trust_domain_id: str
    trust_domain_core_digest: str
    genesis_document_digest: str
    project_instance_id: str
    event_count: int
    genesis_event_hash: str
    head_event_hash: str
    root_governance: ExportGovernance
    active_root_fingerprints: tuple[str, ...]
    events: tuple[ExportedEvent, ...]
    possession_challenges: tuple[Mapping[str, Any], ...]
    prev_commit: str | None
    created_at: str
    root_signatures: tuple[ExportRootSignature, ...]


def _parse_governance(value: object, path: str) -> ExportGovernance:
    obj = _require_keys(value, _GOVERNANCE_KEYS, path)
    mode = _require_str(obj["mode"], f"{path}.mode")
    threshold = _require_int(obj["threshold"], f"{path}.threshold", minimum=1)
    signer_count = _require_int(obj["signer_count"], f"{path}.signer_count", minimum=1)
    _require(
        threshold <= signer_count,
        f"{path}.threshold exceeds signer_count",
        "threshold_exceeds_signer_count",
        threshold=threshold,
        signer_count=signer_count,
    )
    derived = derive_governance_mode(threshold, signer_count)
    _require(
        mode == derived,
        f"{path}.mode {mode!r} disagrees with the mode derived from "
        f"{threshold}-of-{signer_count} ({derived!r})",
        "governance_mode_mismatch",
        declared=mode,
        derived=derived,
    )
    return ExportGovernance(mode=mode, threshold=threshold, signer_count=signer_count)


def _parse_root_signatures(value: object, path: str) -> tuple[ExportRootSignature, ...]:
    entries = _require_list(value, path)
    parsed: list[ExportRootSignature] = []
    seen: set[str] = set()
    for index, raw in enumerate(entries):
        item = _require_keys(raw, _ROOT_SIGNATURE_KEYS, f"{path}[{index}]")
        fingerprint = _require_pattern(
            item["fingerprint"],
            _FINGERPRINT_RE,
            f"{path}[{index}].fingerprint",
            "<scheme>:sha256:<64 lowercase hex>",
        )
        _require(
            fingerprint not in seen,
            f"{path} repeats {fingerprint}; k-of-n counts DISTINCT signers",
            "duplicate_root_signature",
            fingerprint=fingerprint,
        )
        seen.add(fingerprint)
        parsed.append(
            ExportRootSignature(
                signer_id=_require_str(item["signer_id"], f"{path}[{index}].signer_id"),
                fingerprint=fingerprint,
                signature=_require_b64(
                    item["signature"],
                    f"{path}[{index}].signature",
                    exact_len=_ED25519_SIGNATURE_LEN,
                ),
            )
        )
    return tuple(parsed)


def _parse_challenge(value: object, path: str) -> Mapping[str, Any]:
    obj = _require_keys(value, _CHALLENGE_KEYS, path)
    _require_pattern(obj["challenge_id"], _UUID_RE, f"{path}.challenge_id", "a lowercase UUID")
    for field_name in ("operation_id", "operation_digest", "project", "principal_id", "scheme"):
        _require_str(obj[field_name], f"{path}.{field_name}")
    _require_pattern(
        obj["fingerprint"],
        _FINGERPRINT_RE,
        f"{path}.fingerprint",
        "<scheme>:sha256:<64 lowercase hex>",
    )
    _require_str(obj["verifier_nonce"], f"{path}.verifier_nonce")
    _require_str(obj["enrollment_request_digest"], f"{path}.enrollment_request_digest")
    _require_timestamp(obj["issued_at"], f"{path}.issued_at")
    _require_timestamp(obj["expires_at"], f"{path}.expires_at")
    _require_pattern(
        obj["trust_domain_id"], _UUID_RE, f"{path}.trust_domain_id", "a lowercase UUID"
    )
    _require(
        obj["used"] is True,
        f"{path}.used must be true: an unconsumed challenge is not evidence",
        "challenge_not_consumed",
        challenge_id=obj["challenge_id"],
    )
    _require(
        obj["kind"] == "possession",
        f"{path}.kind must be 'possession'",
        "challenge_kind_unsupported",
        kind=obj["kind"],
    )
    _require_b64(obj["proof_signature"], f"{path}.proof_signature")
    return obj


def parse_trust_log_export(
    document: Mapping[str, Any], *, for_signing: bool = False
) -> TrustLogExport:
    """THE strict parser. Closed key sets everywhere; no field is optional.

    ``for_signing=True`` tolerates absent/empty signature sections, so the builder can
    hand its own output through this function before anyone has signed it — a builder
    that can emit something its own verifier rejects is a defect generator.
    """

    raw = _require_object(document, "document")
    present = dict(raw)
    if for_signing:
        for section in SIGNATURE_SECTIONS:
            present.setdefault(section, [])
    obj = _require_keys(present, EXPORT_KEYS, "document")

    _require(
        obj["type"] == TRUST_LOG_EXPORT_TYPE,
        f"document.type must be {TRUST_LOG_EXPORT_TYPE!r}",
        "wrong_type",
        type=obj["type"],
    )
    _require(
        obj["version"] == TRUST_LOG_EXPORT_VERSION,
        f"document.version must be {TRUST_LOG_EXPORT_VERSION}",
        "wrong_version",
        version=obj["version"],
    )

    trust_domain_id = _require_pattern(
        obj["trust_domain_id"], _UUID_RE, "document.trust_domain_id", "a lowercase UUID"
    )
    core_digest = _require_pattern(
        obj["trust_domain_core_digest"],
        _DIGEST_RE,
        "document.trust_domain_core_digest",
        "sha256:<64 lowercase hex>",
    )
    genesis_digest = _require_pattern(
        obj["genesis_document_digest"],
        _DIGEST_RE,
        "document.genesis_document_digest",
        "sha256:<64 lowercase hex>",
    )

    log = _require_keys(obj["trust_log"], _TRUST_LOG_KEYS, "document.trust_log")
    project_instance_id = _require_pattern(
        log["project_instance_id"],
        _UUID_RE,
        "document.trust_log.project_instance_id",
        "a lowercase UUID",
    )
    event_count = _require_int(log["event_count"], "document.trust_log.event_count", minimum=1)
    genesis_event_hash = _require_pattern(
        log["genesis_event_hash"],
        _DIGEST_RE,
        "document.trust_log.genesis_event_hash",
        "sha256:<64 lowercase hex>",
    )
    head_event_hash = _require_pattern(
        log["head_event_hash"],
        _DIGEST_RE,
        "document.trust_log.head_event_hash",
        "sha256:<64 lowercase hex>",
    )

    governance = _parse_governance(obj["root_governance"], "document.root_governance")

    actives_raw = _require_list(
        obj["active_root_fingerprints"], "document.active_root_fingerprints"
    )
    actives: list[str] = []
    for index, item in enumerate(actives_raw):
        actives.append(
            _require_pattern(
                item,
                _FINGERPRINT_RE,
                f"document.active_root_fingerprints[{index}]",
                "<scheme>:sha256:<64 lowercase hex>",
            )
        )
    _require(
        bool(actives),
        "document.active_root_fingerprints must not be empty",
        "active_roots_empty",
    )
    _require(
        len(set(actives)) == len(actives),
        "document.active_root_fingerprints repeats a fingerprint",
        "duplicate_active_root",
    )
    _require(
        actives == sorted(actives),
        "document.active_root_fingerprints must be sorted ascending; an unsorted list "
        "is a hand-edited document",
        "active_roots_unsorted",
    )
    _require(
        governance.signer_count == len(actives),
        "document.root_governance.signer_count contradicts the number of active roots; "
        "governance is not free to invent a denominator",
        "signer_count_contradicts_active_roots",
        signer_count=governance.signer_count,
        actives=len(actives),
    )

    event_items = _require_list(obj["events"], "document.events")
    _require(bool(event_items), "document.events must not be empty", "events_empty")
    events: list[ExportedEvent] = []
    for index, item in enumerate(event_items):
        path = f"document.events[{index}]"
        record = _require_keys(item, _EVENT_KEYS, path)
        events.append(
            ExportedEvent(
                canonical_envelope=_require_b64(
                    record["canonical_envelope"], f"{path}.canonical_envelope"
                ),
                signature=_require_b64(
                    record["signature"], f"{path}.signature", exact_len=_ED25519_SIGNATURE_LEN
                ),
            )
        )
    hashes = [event.event_hash for event in events]
    _require(
        len(set(hashes)) == len(hashes),
        "document.events repeats an event; the export is a set of distinct events",
        "duplicate_event",
    )
    _require(
        event_count == len(events),
        "document.trust_log.event_count disagrees with the number of carried events",
        "event_count_contradicts_events",
        declared=event_count,
        carried=len(events),
    )

    challenge_items = _require_list(
        obj["possession_challenges"], "document.possession_challenges"
    )
    challenges: list[Mapping[str, Any]] = []
    for index, item in enumerate(challenge_items):
        challenges.append(_parse_challenge(item, f"document.possession_challenges[{index}]"))
    challenge_ids = [str(entry["challenge_id"]) for entry in challenges]
    _require(
        len(set(challenge_ids)) == len(challenge_ids),
        "document.possession_challenges repeats a challenge_id",
        "duplicate_possession_challenge",
    )
    _require(
        challenge_ids == sorted(challenge_ids),
        "document.possession_challenges must be sorted by challenge_id; the publication "
        "bytes must have exactly one rendering",
        "possession_challenges_unsorted",
    )

    prev_commit = obj["prev_commit"]
    if prev_commit is not None:
        prev_commit = _require_pattern(
            prev_commit, _GIT_COMMIT_RE, "document.prev_commit", "a 40-hex git commit sha"
        )
    created_at = _require_timestamp(obj["created_at"], "document.created_at")

    root_signatures = _parse_root_signatures(obj["root_signatures"], "document.root_signatures")
    if not for_signing:
        _require(
            bool(root_signatures),
            "document.root_signatures is empty: an unsigned export authorises nothing",
            "root_signatures_absent",
        )
    for section in ("countersignatures", "anchors"):
        _require(
            _require_list(obj[section], f"document.{section}") == [],
            f"document.{section} must be [] — later attestations are separate immutable "
            "records under attestations/<subject-digest>/<ordinal>.json (§4.3 rule 3)",
            "inline_attestations_unsupported",
            section=section,
        )

    return TrustLogExport(
        trust_domain_id=trust_domain_id,
        trust_domain_core_digest=core_digest,
        genesis_document_digest=genesis_digest,
        project_instance_id=project_instance_id,
        event_count=event_count,
        genesis_event_hash=genesis_event_hash,
        head_event_hash=head_event_hash,
        root_governance=governance,
        active_root_fingerprints=tuple(actives),
        events=tuple(events),
        possession_challenges=tuple(challenges),
        prev_commit=prev_commit,
        created_at=created_at,
        root_signatures=root_signatures,
    )


# ---------------------------------------------------------------------------
# Offline material — the WI-337 half of the TrustLogMaterial extraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OfflineTrustLogMaterial(TrustLogMaterial):
    """The published artifact, answering the two reads the verified walk performs.

    The rows are **synthesised from the signed envelopes**: an export carries no database
    columns, so ``_reconcile_row``'s row-vs-envelope comparison is satisfied by
    construction (see this module's docstring, point 1). Every field below is read out of
    the strict-parsed envelope, never out of a caller-supplied duplicate, so there is no
    channel by which a claim could disagree with the bytes it accompanies.
    """

    events: tuple[ExportedEvent, ...]
    challenges: Mapping[str, Mapping[str, Any]]

    def rows(self) -> list[dict[str, Any]]:
        from ._signing import compute_v6_payload_canonical_hash
        from ._verification import parse_v6_envelope_strict

        rows: list[dict[str, Any]] = []
        for event in self.events:
            try:
                envelope = parse_v6_envelope_strict(event.canonical_envelope)
            except Exception as exc:
                _schema(
                    "a carried trust-log event is not a parseable v6 envelope",
                    "event_envelope_unparseable",
                    event_hash=event.event_hash,
                    detail=str(exc),
                )
            chain = envelope["chain"]
            rows.append(
                {
                    "event_id": str(envelope["event_id"]),
                    "event_seq": int(envelope["entity_seq"]),
                    "entity_kind": envelope["entity"]["kind"],
                    "entity_id": str(envelope["entity"]["id"]),
                    "actor_id": envelope["actor"]["principal_id"],
                    "actor_kind": envelope["actor"]["kind"],
                    "actor_metadata": envelope["actor"]["metadata"],
                    "transition": envelope["transition"],
                    "payload": envelope["payload"],
                    "timestamp": _occurred_at(envelope),
                    "payload_canonical_hash": compute_v6_payload_canonical_hash(
                        event.canonical_envelope
                    ),
                    "canonical_envelope": event.canonical_envelope,
                    "signature": event.signature,
                    "scheme_id": envelope["signing"]["scheme_id"],
                    "hash_alg": chain["hash_algorithm"],
                    "prev_event_hash": _hash_bytes(chain["previous_entity_event_hash"]),
                    "prev_global_event_hash": _hash_bytes(chain["previous_project_event_hash"]),
                    "key_id": envelope["signing"]["key_id"],
                }
            )
        return rows

    def lifecycle_challenge(self, challenge_id: str) -> Mapping[str, Any] | None:
        return self.challenges.get(challenge_id)

    def describe(self) -> str:
        return f"published trust-log export ({len(self.events)} events)"


def _occurred_at(envelope: Mapping[str, Any]) -> datetime:
    # The store path derives the row's ``timestamp`` column from the same envelope member
    # through this exact helper, so the offline row cannot differ by construction.
    from ._trust_log_writer import _envelope_occurred_at

    return _envelope_occurred_at(envelope)


def _hash_bytes(value: Any) -> bytes | None:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return None
    try:
        raw = bytes.fromhex(value.removeprefix("sha256:"))
    except (TypeError, ValueError):
        return None
    return raw if len(raw) == 32 else None


def offline_material(export: TrustLogExport) -> OfflineTrustLogMaterial:
    return OfflineTrustLogMaterial(
        events=export.events,
        challenges={str(entry["challenge_id"]): entry for entry in export.possession_challenges},
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustLogExportVerification:
    """What a verified export establishes — every field DERIVED, none of it believed."""

    trust_domain_id: str
    trust_domain_core_digest: str
    genesis_document_digest: str
    project_instance_id: str
    #: Head and count as the REPLAY reached them, reconciled against the document's claims.
    head_event_hash: str
    genesis_event_hash: str
    event_count: int
    #: The current root set, derived by replaying the carried events from the pinned
    #: genesis. This is the authority; ``active_root_fingerprints`` is only a restatement.
    root_signer_fingerprints: tuple[str, ...]
    root_threshold: int
    root_governance_mode: str
    #: Fingerprints whose signature over this artifact verified against the derived set.
    verified_root_signatures: tuple[str, ...]
    document_digest: str
    #: True when neither an exact head pin nor a must-cover pin was supplied — the export
    #: could be a prefix of the real log and nothing here can reveal it.
    tail_truncation_undetectable: bool
    head_pin_checked: bool
    covered_checkpoint_head: str | None
    #: ``(principal_id, key_id)`` pairs the replay reports as REVOKED, and the hashes of
    #: the enrolment/rotation events that introduced them.
    revoked_key_introductions: tuple[str, ...]
    #: The exact events the replay walked, in chain order. Held on the verification
    #: object so :func:`export_referents` reads what WAS verified rather than re-reading
    #: a document a caller could have swapped underneath it.
    walked_events: tuple[ExportedEvent, ...]
    chain: VerifiedChain

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust_domain_id": self.trust_domain_id,
            "trust_domain_core_digest": self.trust_domain_core_digest,
            "genesis_document_digest": self.genesis_document_digest,
            "project_instance_id": self.project_instance_id,
            "head_event_hash": self.head_event_hash,
            "genesis_event_hash": self.genesis_event_hash,
            "event_count": self.event_count,
            "root_signer_fingerprints": list(self.root_signer_fingerprints),
            "root_threshold": self.root_threshold,
            "root_governance_mode": self.root_governance_mode,
            "verified_root_signatures": list(self.verified_root_signatures),
            "document_digest": self.document_digest,
            "tail_truncation_undetectable": self.tail_truncation_undetectable,
            "head_pin_checked": self.head_pin_checked,
            "covered_checkpoint_head": self.covered_checkpoint_head,
            "revoked_key_introductions": list(self.revoked_key_introductions),
        }


def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        from nacl.exceptions import BadSignatureError
        from nacl.signing import VerifyKey
    except ImportError as exc:  # pragma: no cover - packaging failure
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            "PyNaCl is required to verify a trust-log export's root signatures",
        ) from exc
    try:
        VerifyKey(public_key).verify(message, signature)
    except (BadSignatureError, ValueError):
        return False
    return True


def verify_trust_log_export(
    document: Mapping[str, Any],
    *,
    genesis_document: Mapping[str, Any],
    file_bytes: bytes | None = None,
    expect_digest: str | None = None,
    expect_head: tuple[str, int] | None = None,
    must_cover: Mapping[str, Any] | None = None,
    require_signatures: bool = True,
) -> TrustLogExportVerification:
    """Verify a published trust-log export, fail-closed, offline, in one order.

    The order is load-bearing and mirrors ``_estate_catalog.verify_published_checkpoint``:
    identity before cryptography, derivation before comparison, and the document's own
    claims reconciled against the derivation last.

    1. The **genesis document is verified on its own terms** — this function is public and
       must not assume its caller did. An under-signed genesis is refused here.
    2. Strict parse; if ``file_bytes`` is given, they must be *exactly* the canonical JCS
       bytes of what parsed. A publication file with different bytes is a different
       document even when it deserialises the same.
    3. **Identity, before any signature is checked.** ``trust_domain_id``,
       ``trust_domain_core_digest`` and ``genesis_document_digest`` must equal the pinned
       genesis's, and ``trust_log.project_instance_id`` must equal the genesis's
       ``trust_log.project_instance_id``. This is the cross-domain-laundering gate: an
       export from another estate cannot be presented against this pin, however well
       signed it is in its own domain.
    4. **Replay.** The carried events are walked by ``verify_trust_log_chain`` — the one
       verified walk — rooted at the pinned genesis. Chain linkage, per-event envelope
       signatures, root thresholds on every root-authorised payload, registrar liveness,
       possession evidence and enrolment-before-use are all checked there, by the same
       code the live store uses. This is what derives the current root set.
    5. **Reconcile the claims.** ``trust_log.head_event_hash`` / ``genesis_event_hash`` /
       ``event_count``, ``root_governance`` and ``active_root_fingerprints`` must EQUAL
       what the replay reached. A restatement that disagrees is a false claim inside
       signed bytes.
    6. **Root threshold over the artifact**, against the DERIVED set and threshold. A
       signature by a fingerprint the replay does not show as a current root is refused
       even when the document lists it (that is WI-330's removed-root attack, one layer
       down); the count must reach the derived threshold.
    7. **Truncation pins.** ``expect_head`` (exact) and ``must_cover`` (a
       ``min_trust_log_checkpoint``-shaped head the export must reach) are the only
       defences against a published PREFIX, because a prefix replays cleanly. No exact head
       pin supplied → ``tail_truncation_undetectable`` (``must_cover`` raises the floor but
       does not make truncation above the checkpoint detectable, so a ``must_cover``-only
       export still carries the flag; only an exact ``expect_head`` clears it).
    """

    # --- 1. the pin's own root ------------------------------------------------------
    verify_trust_genesis(genesis_document)
    genesis = parse_trust_genesis(genesis_document)

    # --- 2. shape and bytes ---------------------------------------------------------
    parsed = parse_trust_log_export(document, for_signing=not require_signatures)
    if file_bytes is not None:
        if canonicalize(dict(document)) != file_bytes:
            _schema(
                "the export file is not the canonical JCS serialisation of its own "
                "content; §4.4 publishes canonical bytes and only canonical bytes",
                "not_canonical_publication_bytes",
            )

    digest = trust_log_export_digest(document)
    if expect_digest is not None and digest != expect_digest:
        _unverified(
            "the export digest does not match the one obtained by direct exchange; this "
            "is the substitution the publication channel exists to expose (§4.1)",
            "export_digest_mismatch",
            computed=digest,
            expected=expect_digest,
        )

    # --- 3. identity, before cryptography -------------------------------------------
    if parsed.trust_domain_id != genesis.trust_domain_id:
        _unverified(
            "the export names a different trust domain than the pinned genesis",
            "trust_domain_mismatch",
            export=parsed.trust_domain_id,
            genesis=genesis.trust_domain_id,
        )
    if parsed.trust_domain_core_digest != genesis.trust_domain_core_digest:
        _unverified(
            "the export's trust_domain_core_digest is not the pinned genesis's",
            "trust_domain_core_digest_mismatch",
            export=parsed.trust_domain_core_digest,
            genesis=genesis.trust_domain_core_digest,
        )
    pinned_genesis_digest = genesis_document_digest(genesis_document)
    if parsed.genesis_document_digest != pinned_genesis_digest:
        _unverified(
            "the export was produced against a different genesis document than the one "
            "pinned; the whole authority chain hangs off that document",
            "genesis_document_digest_mismatch",
            export=parsed.genesis_document_digest,
            pinned=pinned_genesis_digest,
        )
    if parsed.project_instance_id != str(genesis.trust_log.project_instance_id):
        _unverified(
            "the export names a different trust-log project than the pinned genesis's "
            "trust_log.project_instance_id",
            "trust_log_project_mismatch",
            export=parsed.project_instance_id,
            genesis=str(genesis.trust_log.project_instance_id),
        )

    # --- 4. the one verified walk, over the carried events --------------------------
    material = offline_material(parsed)
    chain = verify_trust_log_chain(material, genesis_document)

    # The walk orders by predecessor link and refuses gaps, cycles and unreachable
    # events; requiring the ARRAY to be in that same order is what makes the publication
    # bytes reproducible for a given log rather than one of n! renderings.
    replayed_hashes = [
        "sha256:"
        + compute_v6_event_hash(
            bytes(row["canonical_envelope"]), bytes(row["signature"])
        ).hex()
        for row in chain_order(material.rows())
    ]
    carried_hashes = [event.event_hash for event in parsed.events]
    if replayed_hashes != carried_hashes:
        _schema(
            "document.events is not in chain order (genesis first, each element the "
            "predecessor-link successor of the last); the publication bytes for a given "
            "log must have exactly one rendering",
            "events_not_in_chain_order",
        )

    # --- 5. the document's claims, reconciled against the derivation ------------------
    if chain.head_event_hash != parsed.head_event_hash:
        _unverified(
            "the export's declared head is not the head its own events replay to",
            "head_contradicts_replay",
            declared=parsed.head_event_hash,
            replayed=chain.head_event_hash,
        )
    if chain.state.genesis_event_hash != parsed.genesis_event_hash:
        _unverified(
            "the export's declared genesis_event_hash is not the one its own events "
            "replay to",
            "genesis_event_hash_contradicts_replay",
            declared=parsed.genesis_event_hash,
            replayed=chain.state.genesis_event_hash,
        )
    if chain.event_count != parsed.event_count:
        _unverified(
            "the export's declared event_count is not the number the replay walked",
            "event_count_contradicts_replay",
            declared=parsed.event_count,
            replayed=chain.event_count,
        )
    if str(chain.state.identity.project_instance_id) != parsed.project_instance_id:
        _unverified(
            "the replayed trust-log identity is not the project the export declares",
            "replayed_identity_mismatch",
            declared=parsed.project_instance_id,
            replayed=str(chain.state.identity.project_instance_id),
        )

    derived_fingerprints = tuple(sorted(chain.state.governance.signer_fingerprints))
    derived_threshold = int(chain.state.governance.threshold)
    if parsed.active_root_fingerprints != derived_fingerprints:
        _unverified(
            "the export's active_root_fingerprints contradict the set its own events "
            "replay to; the log is the authority and the restatement is only a claim",
            "actives_contradict_replay",
            declared=list(parsed.active_root_fingerprints),
            replayed=list(derived_fingerprints),
        )
    if parsed.root_governance.threshold != derived_threshold:
        _unverified(
            "the export's restated threshold contradicts the replayed governance",
            "threshold_contradicts_replay",
            declared=parsed.root_governance.threshold,
            replayed=derived_threshold,
        )
    if parsed.root_governance.mode != chain.state.governance.mode:
        _unverified(
            "the export's restated governance mode contradicts the replayed governance",
            "governance_mode_contradicts_replay",
            declared=parsed.root_governance.mode,
            replayed=chain.state.governance.mode,
        )
    # A threshold may never decrease (WI-280 / `validate_governance_transition`). The
    # replay enforces that across rotations; this is the same rule against the pinned
    # genesis, so a log that somehow replayed to a weaker root than the auditor pinned
    # is refused rather than reported.
    if derived_threshold < int(genesis.initial_governance.threshold):
        _unverified(
            "the replayed root threshold is lower than the pinned genesis's; the "
            "threshold is monotone non-decreasing",
            "root_threshold_lowered",
            replayed=derived_threshold,
            genesis=int(genesis.initial_governance.threshold),
        )

    # --- 6. root threshold over the artifact, against the DERIVED authority ----------
    verified: list[str] = []
    if require_signatures or parsed.root_signatures:
        message = trust_log_export_signature_input(document)
        genesis_signer_ids = {
            signer.fingerprint: signer.signer_id for signer in genesis.signers
        }
        for entry in parsed.root_signatures:
            if entry.fingerprint not in derived_fingerprints:
                _unverified(
                    "an export root signature is by a key the replayed log does not show "
                    "as a current root; a root removed by a rotation cannot re-authorise "
                    "the log that records its removal",
                    "root_signer_not_active",
                    fingerprint=entry.fingerprint,
                    active=list(derived_fingerprints),
                )
            public_key = chain.state.root_public_keys.get(entry.fingerprint)
            if public_key is None:
                _unverified(
                    "no public key for an active root fingerprint is available from the "
                    "pinned genesis or the replayed rotations; there is deliberately no "
                    "operator channel for root public keys",
                    "root_public_key_unavailable",
                    fingerprint=entry.fingerprint,
                )
            declared_id = genesis_signer_ids.get(entry.fingerprint)
            if declared_id is not None and declared_id != entry.signer_id:
                _unverified(
                    "an export root signature names a signer_id the genesis does not give "
                    "that fingerprint",
                    "root_signer_id_mismatch",
                    fingerprint=entry.fingerprint,
                    declared=entry.signer_id,
                    genesis=declared_id,
                )
            if not _verify_ed25519(public_key, message, entry.signature):
                _unverified(
                    "an export root signature does not verify over the signed core",
                    "root_signature_invalid",
                    fingerprint=entry.fingerprint,
                )
            verified.append(entry.fingerprint)

    if require_signatures and len(verified) < derived_threshold:
        _unverified(
            "the export did not reach the root threshold derived from the replayed log",
            "root_threshold_not_met",
            verified=len(verified),
            threshold=derived_threshold,
        )

    # --- 7. truncation pins ----------------------------------------------------------
    head_pin_checked = False
    if expect_head is not None:
        expected_head, expected_count = expect_head
        if chain.head_event_hash != expected_head or chain.event_count != expected_count:
            _unverified(
                "the export's replayed head/count contradicts the head pinned out of "
                "band; a published PREFIX of the log replays cleanly, so this pin is the "
                "only thing that can detect one",
                "head_pin_contradicted",
                replayed_head=chain.head_event_hash,
                replayed_count=chain.event_count,
                pinned_head=expected_head,
                pinned_count=expected_count,
            )
        head_pin_checked = True

    covered: str | None = None
    if must_cover is not None:
        wanted = must_cover.get("head_event_hash")
        if not isinstance(wanted, str) or not _DIGEST_RE.match(wanted):
            _schema(
                "the supplied min_trust_log_checkpoint has no usable head_event_hash",
                "must_cover_malformed",
                value=repr(wanted),
            )
        if wanted not in set(replayed_hashes):
            _unverified(
                "the export does not reach the trust-log checkpoint head the auditor "
                "pinned; a log truncated before a pinned checkpoint hides every event "
                "after it, which is exactly how a rotation or a revocation is concealed",
                "pinned_checkpoint_not_covered",
                pinned_head=wanted,
                replayed_head=chain.head_event_hash,
                event_count=chain.event_count,
            )
        covered = wanted

    revoked_introductions = _revoked_key_introductions(chain)

    return TrustLogExportVerification(
        trust_domain_id=parsed.trust_domain_id,
        trust_domain_core_digest=parsed.trust_domain_core_digest,
        genesis_document_digest=parsed.genesis_document_digest,
        project_instance_id=parsed.project_instance_id,
        head_event_hash=chain.head_event_hash,
        genesis_event_hash=chain.state.genesis_event_hash,
        event_count=chain.event_count,
        root_signer_fingerprints=derived_fingerprints,
        root_threshold=derived_threshold,
        root_governance_mode=chain.state.governance.mode,
        verified_root_signatures=tuple(verified),
        document_digest=digest,
        # WI-350 (Daybreak Blue): truncation is undetectable UNLESS an exact head+count
        # pin was checked. A `must_cover` checkpoint only RAISES THE FLOOR — it proves the
        # export reaches AT LEAST that historical event (and its own check above refuses a
        # prefix below the checkpoint) — but truncation ABOVE the checkpoint stays
        # undetectable, so a STALE checkpoint cannot clear this flag. Only an exact
        # `expect_head` (matched head AND count) defeats truncation; `must_cover` must NOT.
        tail_truncation_undetectable=(not head_pin_checked),
        head_pin_checked=head_pin_checked,
        covered_checkpoint_head=covered,
        revoked_key_introductions=revoked_introductions,
        walked_events=parsed.events,
        chain=chain,
    )


def _revoked_key_introductions(chain: VerifiedChain) -> tuple[str, ...]:
    """Hashes of enrolment/rotation events introducing a key the replay shows REVOKED.

    A revoked key is not merely superseded: ``principal_key_revoked`` with reason
    ``compromised`` is the estate saying the key's signatures may be forgeries. A
    consumer must not treat such an introduction as authenticating anything, so the
    hashes are named here and :func:`export_referents` withholds them.

    Supersession is deliberately NOT included. After an A→B rotation, events A signed
    *before* the rotation are still validly authenticated, and the project side already
    windows acceptance revocation by chain position (§5.10 step 4). Excluding superseded
    introductions would make every rotation retroactively unauthenticate history.
    """

    revoked_pairs = {
        pair for pair, status in chain.state.principal_key_status.items() if status == "revoked"
    }
    hashes: list[str] = []
    for record in chain.verified:
        if record.transition not in (PRINCIPAL_KEY_ENROLLED, PRINCIPAL_KEY_ROTATED):
            continue
        principal_id = record.payload.get("principal_id")
        # §5.5/§5.6 put the key material at the payload's TOP level (`key_id`,
        # `public_key`, `fingerprint`, `scheme_id`); `_parse_key_material` reads it from
        # there and `_remember_principal_key` keys the replayed status by
        # `(principal_id, key.key_id)`. Reading a nested `payload["key"]` object would
        # match nothing and silently withhold nothing, which is the direction that fails
        # OPEN — so the lookup is by the same key the status map is built from.
        key_id = record.payload.get("key_id")
        if (str(principal_id), str(key_id)) in revoked_pairs:
            hashes.append(record.event_hash)
    return tuple(sorted(hashes))


def export_referents(
    verification: TrustLogExportVerification,
) -> dict[str, Any]:
    """The verified trust-log events, indexed by v6 event hash, as presented material.

    Only events the replay in :func:`verify_trust_log_export` *walked* appear here, and
    introductions of a revoked key are withheld (see :func:`_revoked_key_introductions`).
    Nothing that failed verification is ever offered: this is the whole difference between
    WI-337 and the Phase-C round-1 defect, where caller-supplied trust-log referents were
    indexed without their signatures or ancestry ever being checked.
    """

    from ._v6_referents import referent_from_bytes

    withheld = set(verification.revoked_key_introductions)
    indexed: dict[str, Any] = {}
    for record in verification.walked_events:
        referent = referent_from_bytes(record.canonical_envelope, record.signature)
        if referent is None:
            continue
        if referent.event_hash in withheld:
            continue
        indexed[referent.event_hash] = referent
    return indexed


# ---------------------------------------------------------------------------
# Build and sign
# ---------------------------------------------------------------------------


def build_trust_log_export(
    source: Any,
    *,
    genesis_document: Mapping[str, Any],
    created_at: str,
    prev_commit: str | None = None,
) -> dict[str, Any]:
    """Build the exact canonical publication content from a live trust-log store.

    ``source`` is a live ``DictConn`` (or any :class:`TrustLogMaterial`). The build runs
    the verified walk FIRST and derives every declared field from it, so the artifact can
    never declare a head, count or governance the log does not have. It touches no private
    key — signing is a separate, offline step (§4.4's separation) — and it never writes.
    """

    material = trust_log_material(source)
    chain = verify_trust_log_chain(material, genesis_document)
    genesis = parse_trust_genesis(genesis_document)

    ordered = chain_order(material.rows())
    events = [
        ExportedEvent(
            canonical_envelope=bytes(row["canonical_envelope"]),
            signature=bytes(row["signature"]),
        )
        for row in ordered
    ]

    challenges: dict[str, Mapping[str, Any]] = {}
    for row in ordered:
        if row["transition"] not in (PRINCIPAL_KEY_ENROLLED, PRINCIPAL_KEY_ROTATED):
            continue
        payload = row["payload"]
        proof = payload.get("possession_proof") if isinstance(payload, Mapping) else None
        challenge_id = proof.get("challenge_id") if isinstance(proof, Mapping) else None
        if not isinstance(challenge_id, str):
            _unverified(
                "a lifecycle event carries no possession challenge id, so its evidence "
                "cannot be exported",
                "possession_challenge_id_absent",
                transition=str(row["transition"]),
            )
        record = material.lifecycle_challenge(challenge_id)
        if record is None:
            _unverified(
                "the durable possession challenge behind a lifecycle event is not "
                "available from the source, so the export would not replay",
                "possession_challenge_unavailable",
                challenge_id=challenge_id,
            )
        challenges[challenge_id] = _challenge_document(record)

    document: dict[str, Any] = {
        "type": TRUST_LOG_EXPORT_TYPE,
        "version": TRUST_LOG_EXPORT_VERSION,
        "trust_domain_id": str(genesis.trust_domain_id),
        "trust_domain_core_digest": str(genesis.trust_domain_core_digest),
        "genesis_document_digest": genesis_document_digest(genesis_document),
        "trust_log": {
            "project_instance_id": str(chain.state.identity.project_instance_id),
            "event_count": chain.event_count,
            "genesis_event_hash": chain.state.genesis_event_hash,
            "head_event_hash": chain.head_event_hash,
        },
        "root_governance": {
            "mode": chain.state.governance.mode,
            "threshold": int(chain.state.governance.threshold),
            "signer_count": int(chain.state.governance.signer_count),
        },
        "active_root_fingerprints": sorted(chain.state.governance.signer_fingerprints),
        "events": [event.as_document_member() for event in events],
        "possession_challenges": [challenges[cid] for cid in sorted(challenges)],
        "prev_commit": prev_commit,
        "created_at": _require_timestamp(created_at, "created_at"),
    }

    # Never emit something this module's own verifier rejects (the same discipline §4.4
    # requires of `publish`, and `_estate_catalog.build_estate_catalog` of itself).
    verify_trust_log_export(
        document, genesis_document=genesis_document, require_signatures=False
    )
    return document


def _challenge_document(row: Mapping[str, Any]) -> dict[str, Any]:
    """Render a stored challenge row as JSON-safe, canonicalisable members."""

    from ._trust_log_writer import _challenge_timestamp

    issued_at, _ = _challenge_timestamp(row["issued_at"], "issued_at")
    expires_at, _ = _challenge_timestamp(row["expires_at"], "expires_at")
    proof_signature = row.get("proof_signature")
    if not isinstance(proof_signature, str) or not proof_signature:
        _unverified(
            "a consumed possession challenge has no stored proof signature; without it "
            "the export cannot carry the evidence the replay checks",
            "possession_proof_evidence_missing",
            challenge_id=str(row.get("challenge_id")),
        )
    return {
        "challenge_id": str(row["challenge_id"]),
        "operation_id": str(row["operation_id"]),
        "operation_digest": str(row["operation_digest"]),
        "project": str(row["project"]),
        "principal_id": str(row["principal_id"]),
        "fingerprint": str(row["fingerprint"]),
        "scheme": str(row["scheme"]),
        "verifier_nonce": str(row["verifier_nonce"]),
        "enrollment_request_digest": str(row["enrollment_request_digest"]),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "used": bool(row["used"]),
        "kind": str(row["kind"]),
        "trust_domain_id": str(row["trust_domain_id"]),
        "proof_signature": proof_signature,
    }


def sign_trust_log_export(
    document: Mapping[str, Any],
    *,
    seed: bytes,
    signer_id: str,
    fingerprint: str,
) -> dict[str, Any]:
    """Append ONE detached root signature. Returns a new document; never mutates.

    Separate from the build so the airgapped k-of-n leg works the way §4.4 requires: the
    building host holds no private key, and each root signs the *same* canonical core on
    its own machine.
    """

    from ._signing_scheme import Ed25519Scheme

    parsed = parse_trust_log_export(document, for_signing=True)
    for entry in parsed.root_signatures:
        if entry.fingerprint == fingerprint:
            _unverified(
                "this fingerprint has already signed the export; k-of-n counts DISTINCT "
                "signers and re-signing does not advance it",
                "duplicate_root_signature",
                fingerprint=fingerprint,
            )
    message = trust_log_export_signature_input(document)
    signature, _digest = Ed25519Scheme().sign(message, seed)
    out = dict(document)
    out["root_signatures"] = [
        *(
            {
                "signer_id": entry.signer_id,
                "fingerprint": entry.fingerprint,
                "signature": base64.b64encode(entry.signature).decode("ascii"),
            }
            for entry in parsed.root_signatures
        ),
        {
            "signer_id": signer_id,
            "fingerprint": fingerprint,
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    ]
    out.setdefault("countersignatures", [])
    out.setdefault("anchors", [])
    return out


__all__ = [
    "CORE_KEYS",
    "EXPORT_KEYS",
    "SIGNATURE_SECTIONS",
    "TRUST_LOG_EXPORT_DOMAIN",
    "TRUST_LOG_EXPORT_TYPE",
    "TRUST_LOG_EXPORT_VERSION",
    "ExportGovernance",
    "ExportRootSignature",
    "ExportedEvent",
    "OfflineTrustLogMaterial",
    "TrustLogExport",
    "TrustLogExportVerification",
    "build_trust_log_export",
    "export_referents",
    "offline_material",
    "parse_trust_log_export",
    "sign_trust_log_export",
    "trust_log_export_canonical_core",
    "trust_log_export_core",
    "trust_log_export_digest",
    "trust_log_export_signature_input",
    "verify_trust_log_export",
]
