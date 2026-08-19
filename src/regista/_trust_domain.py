"""Trust-domain genesis document: contract, derivation, verification (P2.1, contracts half).

Normative sources, in precedence order:

* ``docs/0.6.0/RECONCILIATION.md`` — Resolution 4 (wire mode spellings ``co_signed`` /
  ``solo`` / ``solo_effective``, underscores everywhere) and Resolution 1 (bootstrap
  positions, consumed by P2.2, not here).
* ``docs/0.6.0/TRUST-DOMAIN.md`` §3 as overlay-corrected by **WI-280**
  (``ARCHITECTURE-FINAL.md`` §3 decision 1): ``threshold`` and ``signer_count`` are **not**
  in ``binding_core`` and **not** inputs to the ``trust_domain_id`` derivation. Governance
  is a monotone signed log inside the domain; a verifier rejects any threshold decrease
  no matter who signed it.
* ``docs/0.6.0/TRUST-DOMAIN.md`` §9 "Conformance criteria", Genesis items 1-6
  (item 6's bundle-renderer half lands with P3.3; the mode-derivation half is here).

Scope note (contract/ceremony split, ``IMPLEMENTATION-PLAN.md`` P2.1): this module is the
contracts/code half, testable entirely against test trust roots. The owner-executed
production ceremony, §4 publication (P2.4), §5 trust-log event replay (P2.2) and §2
principal grammar (P2.3) are all out of scope here. The governance-transition primitive
at the bottom is designed for P2.2's log replay to consume.

Derivation (§3.3)::

    core_bytes   = JCS(binding_core)
    core_digest  = SHA256(b"regista.trust-genesis.core.v1\\x00" || uint64be(len(core_bytes))
                          || core_bytes)
    trust_domain_core_digest = "sha256:" + lowercase_hex(core_digest)
    trust_domain_id = UUIDv5(NAMESPACE_OID, "regista.trust-domain:" + lowercase_hex)

Signature input (§3.5)::

    document_core = document MINUS {"signatures", "countersignatures", "anchors"}
    sig_bytes     = JCS(document_core)
    input         = b"regista.trust-genesis.v1\\x00" || uint64be(len(sig_bytes)) || sig_bytes

Every signer signs the same bytes; ``document_core`` includes the stated digest and id, so
signers commit to the derivation and a verifier recomputes both and rejects disagreement.

Fail-closed posture: unknown fields are rejected at every level; a signature entry that
does not verify, or whose signer is not in ``binding_core.signers``, makes the whole
document invalid — never "bad signature ignored", because silently dropping a bad
signature is how a k-of-n check becomes a 1-of-n check (§3.4).

``declared_mode`` / ``declared_holder`` are **unverified operator claims**
(OPERATOR-FORGERY R1); every surface here that carries them labels them as declared and
unverified. ``attestation`` is null/reserved in 0.6.0.

**WI-292 (decided 2026-08-17)**: custody declarations are NOT in ``binding_core.signers[]``.
They live in a mandatory top-level ``initial_custody`` array, keyed by signer fingerprint,
exactly one entry per signer, sorted by fingerprint ascending. The block is inside
``document_core``, so every root signature covers it — an edit changes **neither** the digest
**nor** the id, but invalidates **every** genesis signature (§9 criterion 4 (ii)). An
unverified operator claim has no business inside the cryptographic identifier: it buys no
security and makes every honest correction cost a full epoch. Post-genesis corrections are
threshold-authorized trust-log events (P2.2's catalogue), which is why nothing here mutates
custody.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
import uuid as _uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, NoReturn

from ._errors import ErrorCode, RegistaError
from ._jcs import canonicalize
from ._principal_keys import _compute_fingerprint

# ---------------------------------------------------------------------------
# Frozen byte-level constants (must match tests/vectors/v6/manifest.json)
# ---------------------------------------------------------------------------

TRUST_GENESIS_CORE_DOMAIN = b"regista.trust-genesis.core.v1\x00"
TRUST_GENESIS_SIGNING_DOMAIN = b"regista.trust-genesis.v1\x00"
TRUST_DOMAIN_ID_NAMESPACE_PREFIX = "regista.trust-domain:"

TRUST_GENESIS_TYPE = "regista.trust-genesis"
TRUST_GENESIS_CORE_TYPE = "regista.trust-genesis.core"
TRUST_GENESIS_VERSION = 1

# Wire mode values — RECONCILIATION.md Resolution 4: underscores, everywhere.
MODE_CO_SIGNED = "co_signed"
MODE_SOLO = "solo"
MODE_SOLO_EFFECTIVE = "solo_effective"
_MODES = frozenset({MODE_CO_SIGNED, MODE_SOLO, MODE_SOLO_EFFECTIVE})

# The three sections excluded from BOTH binding_core and sig_bytes (§3.5) —
# addable later with no epoch change and no signature invalidation.
_SIGNATURE_EXCLUDED_SECTIONS = frozenset({"signatures", "countersignatures", "anchors"})

# Closed sets from §3.2. Widening any of these is a spec change, not a patch.
_CUSTODY_DECLARED_MODES = frozenset(
    {"offline-airgapped", "offline-host", "online-vault", "unspecified"}
)
_SIGNER_SCHEME_IDS = frozenset({"ed25519"})
_PUBLICATION_KINDS = frozenset({"git"})
_PUBLICATION_BOOTSTRAPS = frozenset({"direct-exchange"})
_ANCHOR_KINDS = frozenset({"rfc3161", "opentimestamps", "git-tag", "other"})
# `over` is restricted so a countersignature/anchor can never be retargeted at a
# mutable part of the document (§3.5).
_OVER_VALUES = frozenset({"trust_domain_core_digest"})

_TOP_LEVEL_KEYS = frozenset(
    {
        "type",
        "version",
        "binding_core",
        "initial_custody",
        "initial_governance",
        "trust_domain_core_digest",
        "trust_domain_id",
        "trust_log",
        "publication",
        "signatures",
        "countersignatures",
        "anchors",
    }
)
# WI-280: binding_core carries NO governance fields.
_BINDING_CORE_KEYS = frozenset({"type", "version", "signers", "created_at", "nonce"})
# WI-292: signers carry cryptographic identity only; custody moved to initial_custody.
_SIGNER_KEYS = frozenset({"signer_id", "scheme_id", "public_key", "fingerprint"})
_CUSTODY_ENTRY_KEYS = frozenset(
    {"fingerprint", "declared_mode", "declared_holder", "attestation"}
)
_GOVERNANCE_KEYS = frozenset({"mode", "threshold", "signer_count"})
_TRUST_LOG_KEYS = frozenset(
    {"project_instance_id", "project_name_hint", "initial_head_event_hash"}
)
_PUBLICATION_KEYS = frozenset({"kind", "url", "path", "bootstrap"})
_SIGNATURE_KEYS = frozenset({"signer_id", "fingerprint", "scheme_id", "signed_at", "signature"})
_COUNTERSIGNATURE_KEYS = frozenset(
    {"custodian_id", "scheme_id", "fingerprint", "over", "signature", "signed_at", "statement"}
)
_ANCHOR_KEYS = frozenset({"kind", "over", "obtained_at", "evidence"})

_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_FINGERPRINT_RE = re.compile(r"[a-z0-9-]+:sha256:[0-9a-f]{64}")
# §3.2: nonce is 64 lowercase hex chars (32 bytes of ceremony entropy).
_NONCE_RE = re.compile(r"[0-9a-f]{64}")
# Microsecond-precision UTC "Z" lexical form used throughout the genesis document.
_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
_TIMESTAMP_STRPTIME = "%Y-%m-%dT%H:%M:%S.%fZ"
_TIMESTAMP_WHAT = "a microsecond-precision UTC Z timestamp (YYYY-MM-DDTHH:MM:SS.ffffffZ)"

_ED25519_PUBLIC_KEY_LEN = 32
_ED25519_SIGNATURE_LEN = 64


# ---------------------------------------------------------------------------
# Failure helper — every rejection is a RegistaError with a machine-readable
# `reason` in detail, so callers and tests can assert the *named* failure.
# ---------------------------------------------------------------------------


def _fail(code: ErrorCode, message: str, reason: str, **detail: Any) -> NoReturn:
    raise RegistaError(code, message, {"reason": reason, **detail})


def _require(
    condition: bool, code: ErrorCode, message: str, reason: str, **detail: Any
) -> None:
    if not condition:
        _fail(code, message, reason, **detail)


def _require_keys(value: Any, expected: frozenset[str], path: str) -> None:
    _require(
        isinstance(value, dict),
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path} must be an object",
        "not_an_object",
        path=path,
    )
    actual = frozenset(value)
    unknown = sorted(actual - expected)
    missing = sorted(expected - actual)
    _require(
        not unknown and not missing,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path} keys must be exactly {sorted(expected)!r}; "
        f"unknown={unknown!r} missing={missing!r}",
        "unknown_or_missing_field",
        path=path,
        unknown=unknown,
        missing=missing,
    )


def _require_string(value: Any, path: str, *, non_empty: bool = True) -> str:
    _require(
        isinstance(value, str),
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path} must be a string",
        "not_a_string",
        path=path,
    )
    if non_empty:
        _require(
            bool(value.strip()),
            ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
            f"{path} must be non-empty",
            "empty_string",
            path=path,
        )
    return str(value)


def _require_int(value: Any, path: str) -> int:
    _require(
        isinstance(value, int) and not isinstance(value, bool),
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path} must be an integer",
        "not_an_integer",
        path=path,
    )
    return int(value)


def _require_pattern(value: Any, pattern: re.Pattern[str], path: str, what: str) -> str:
    text = _require_string(value, path)
    _require(
        pattern.fullmatch(text) is not None,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path} must be {what}",
        "malformed_value",
        path=path,
    )
    return text


def require_genesis_timestamp(value: Any, path: str) -> str:
    """Validate a genesis-document timestamp: microsecond-precision UTC ``Z``, real instant.

    Public (in a private module) because the offline signing helper must apply the
    *verifier's* rule at production time: a tool that mints an artifact its own
    verifier rejects has failed at the only moment the ceremony can still be fixed.
    The lexical check is the §3.2 form; the calendar check rejects lexically-valid
    impossibilities like ``2026-02-30T00:00:00.000000Z``.
    """
    text = _require_pattern(value, _TIMESTAMP_RE, path, _TIMESTAMP_WHAT)
    try:
        datetime.strptime(text, _TIMESTAMP_STRPTIME)
    except ValueError as exc:
        raise RegistaError(
            ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
            f"{path} must name a real calendar instant",
            {"reason": "impossible_timestamp", "path": path},
        ) from exc
    return text


def _require_uuid(value: Any, path: str) -> str:
    text = _require_string(value, path)
    try:
        parsed = _uuid.UUID(text)
    except (ValueError, TypeError) as exc:
        raise RegistaError(
            ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
            f"{path} must be a canonical UUID string",
            {"reason": "malformed_uuid", "path": path},
        ) from exc
    _require(
        str(parsed) == text,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path} must use lowercase canonical UUID text",
        "non_canonical_uuid",
        path=path,
    )
    return text


def _require_base64(value: Any, path: str, *, expected_len: int) -> bytes:
    text = _require_string(value, path)
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RegistaError(
            ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
            f"{path} must be standard base64",
            {"reason": "malformed_base64", "path": path},
        ) from exc
    _require(
        len(raw) == expected_len,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path} must decode to exactly {expected_len} bytes, got {len(raw)}",
        "wrong_key_length" if expected_len == _ED25519_PUBLIC_KEY_LEN else "wrong_signature_length",
        path=path,
    )
    # Canonical round-trip: exactly one base64 spelling per byte string, so the
    # signed bytes admit no aliasing.
    _require(
        base64.b64encode(raw).decode("ascii") == text,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path} must be canonical (padded, no alternate alphabet) base64",
        "non_canonical_base64",
        path=path,
    )
    return raw


def _require_json_object(value: Mapping[str, Any], path: str) -> None:
    """Require a mapping to be JSON-native throughout: string keys, and values drawn
    only from object/array/string/number/bool/null."""
    for key, item in value.items():
        _require(
            isinstance(key, str) and bool(key),
            ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
            f"{path} keys must be non-empty strings",
            "non_string_key",
            path=path,
        )
        _require_json_value(item, f"{path}.{key}")


def _require_json_value(value: Any, path: str) -> None:
    if isinstance(value, dict):
        _require_json_object(value, path)
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _require_json_value(item, f"{path}[{i}]")
        return
    _require(
        value is None or isinstance(value, str | bool | int | float),
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path} must be a JSON value (object, array, string, number, boolean or null)",
        "not_a_json_value",
        path=path,
        type=type(value).__name__,
    )
    # json.load happily produces inf/nan (e.g. from a literal 1e400), but neither
    # is a JSON number (RFC 8785 requires finite), and either would break JCS
    # canonicalization of any future full-document digest over this material.
    if isinstance(value, float):
        _require(
            value == value and value not in (float("inf"), float("-inf")),
            ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
            f"{path} must be a finite JSON number",
            "non_finite_number",
            path=path,
        )


def _require_base64_text(value: Any, path: str, *, expected_len: int) -> str:
    """Same validation as :func:`_require_base64`, returning the canonical text —
    for fields carried through as their wire spelling rather than as bytes."""
    _require_base64(value, path, expected_len=expected_len)
    return str(value)


# ---------------------------------------------------------------------------
# Derivation (§3.3) — deliberately shape-agnostic over the binding_core mapping,
# so it reproduces the committed Gate 0 vector byte-for-byte.
# ---------------------------------------------------------------------------


def derive_core_digest(binding_core: Mapping[str, Any]) -> str:
    """``"sha256:" + hex(SHA256(domain || uint64be(len(core_bytes)) || core_bytes))``."""
    core_bytes = canonicalize(dict(binding_core))
    framed = TRUST_GENESIS_CORE_DOMAIN + struct.pack(">Q", len(core_bytes)) + core_bytes
    return "sha256:" + hashlib.sha256(framed).hexdigest()


def derive_trust_domain_id(core_digest: str) -> str:
    """UUIDv5(NAMESPACE_OID, "regista.trust-domain:" + <64 lowercase hex>)."""
    _require_pattern(
        core_digest, _DIGEST_RE, "core_digest", "sha256:<64 lowercase hex characters>"
    )
    hex_part = core_digest.removeprefix("sha256:")
    return str(_uuid.uuid5(_uuid.NAMESPACE_OID, TRUST_DOMAIN_ID_NAMESPACE_PREFIX + hex_part))


def genesis_document_core(document: Mapping[str, Any]) -> dict[str, Any]:
    """The genesis object minus {signatures, countersignatures, anchors} (§3.5)."""
    _require(
        isinstance(document, Mapping),
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        "genesis document must be an object",
        "not_an_object",
        path="document",
    )
    return {k: v for k, v in document.items() if k not in _SIGNATURE_EXCLUDED_SECTIONS}


def genesis_signature_input(document: Mapping[str, Any]) -> bytes:
    """``domain || uint64be(len(sig_bytes)) || sig_bytes`` over JCS(document_core).

    Every signer signs these same bytes, independently and in any order (§3.5).
    """
    sig_bytes = canonicalize(genesis_document_core(document))
    return TRUST_GENESIS_SIGNING_DOMAIN + struct.pack(">Q", len(sig_bytes)) + sig_bytes


def genesis_document_digest(document: Mapping[str, Any]) -> str:
    """``sha256:`` + hex of JCS over the **complete published** genesis document.

    The A-prime (owner-approved, Fable-adjudicated) digest: the digest a trust_domain_established
    payload restates covers the exact bytes an operator publishes — the whole
    document including ``signatures``/``countersignatures``/``anchors`` — computed
    once here and reused by the payload builder, the bootstrap validator and the
    verifier so the three can never disagree.
    """
    return "sha256:" + hashlib.sha256(canonicalize(document)).hexdigest()


# ---------------------------------------------------------------------------
# Governance mode derivation (§3.4 table)
# ---------------------------------------------------------------------------


def derive_governance_mode(threshold: int, signer_count: int) -> str:
    """Derive the required mode from replayed ``threshold``/``signer_count``.

    The mode is a *derived, restated* value: a document whose stated mode disagrees
    with this function is INVALID, not mislabelled (§3.4). ``solo_effective`` exists
    to close the theater hole where an estate lists several fingerprints, sets
    threshold 1, and calls itself co-signed.
    """
    _require(
        isinstance(threshold, int) and not isinstance(threshold, bool),
        ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID,
        "threshold must be an integer",
        "not_an_integer",
        path="threshold",
    )
    _require(
        isinstance(signer_count, int) and not isinstance(signer_count, bool),
        ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID,
        "signer_count must be an integer",
        "not_an_integer",
        path="signer_count",
    )
    _require(
        threshold >= 1,
        ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID,
        f"threshold must be >= 1, got {threshold}",
        "threshold_below_one",
        threshold=threshold,
    )
    _require(
        threshold <= signer_count,
        ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID,
        f"threshold {threshold} exceeds signer_count {signer_count}",
        "threshold_exceeds_signer_count",
        threshold=threshold,
        signer_count=signer_count,
    )
    if signer_count == 1:
        return MODE_SOLO
    if threshold == 1:
        return MODE_SOLO_EFFECTIVE
    return MODE_CO_SIGNED


# ---------------------------------------------------------------------------
# Typed model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CustodyDeclaration:
    """One ``initial_custody`` entry (WI-292): unverified operator claims about where a
    genesis signer's key is kept, keyed by that signer's fingerprint.

    Signed genesis state, not identity — it is inside ``document_core`` and outside
    ``binding_core``. ``attestation`` is reserved (must be null in 0.6.0); when it lands
    it is what closes OPERATOR-FORGERY R1.
    """

    fingerprint: str
    declared_mode: str
    declared_holder: str
    attestation: None = None


@dataclass(frozen=True)
class GenesisSigner:
    """Cryptographic identity only (WI-292) — this is what the derivation commits to."""

    signer_id: str
    scheme_id: str
    public_key: bytes
    fingerprint: str


@dataclass(frozen=True)
class InitialGovernance:
    mode: str
    threshold: int
    signer_count: int


@dataclass(frozen=True)
class TrustLogBlock:
    project_instance_id: str
    project_name_hint: str
    initial_head_event_hash: str | None


@dataclass(frozen=True)
class PublicationBlock:
    kind: str
    url: str
    path: str
    bootstrap: str


@dataclass(frozen=True)
class GenesisSignature:
    signer_id: str
    fingerprint: str
    scheme_id: str
    signed_at: str  # actor claim; not ordered, not trusted, not used (§3.4)
    signature: bytes


@dataclass(frozen=True)
class Countersignature:
    """Present in the artifact; 0.6.0 verifies none of it — reported present_unverified."""

    custodian_id: str
    scheme_id: str
    fingerprint: str
    over: str
    signature: str
    signed_at: str
    statement: str


@dataclass(frozen=True)
class Anchor:
    """Present in the artifact; 0.6.0 verifies none of it — reported present_unverified."""

    kind: str
    over: str
    obtained_at: str
    evidence: Mapping[str, Any]


@dataclass(frozen=True)
class TrustGenesisDocument:
    binding_core_type: str
    binding_core_version: int
    signers: tuple[GenesisSigner, ...]
    created_at: str
    nonce: str
    initial_custody: tuple[CustodyDeclaration, ...]
    initial_governance: InitialGovernance
    trust_domain_core_digest: str
    trust_domain_id: str
    trust_log: TrustLogBlock
    publication: PublicationBlock
    signatures: tuple[GenesisSignature, ...]
    countersignatures: tuple[Countersignature, ...]
    anchors: tuple[Anchor, ...]

    def signer_by_fingerprint(self, fingerprint: str) -> GenesisSigner | None:
        for signer in self.signers:
            if signer.fingerprint == fingerprint:
                return signer
        return None

    def custody_by_fingerprint(self, fingerprint: str) -> CustodyDeclaration | None:
        """The declared (unverified) custody for a signer. Never ``None`` for a signer
        of a *parsed* document — the 1:1 rule is enforced at parse time (WI-292)."""
        for declaration in self.initial_custody:
            if declaration.fingerprint == fingerprint:
                return declaration
        return None


# ---------------------------------------------------------------------------
# Strict parsing — unknown fields rejected at every level, fail closed.
# ---------------------------------------------------------------------------


def _parse_signer(entry: Any, path: str) -> GenesisSigner:
    _require_keys(entry, _SIGNER_KEYS, path)
    signer_id = _require_string(entry["signer_id"], f"{path}.signer_id")
    scheme_id = _require_string(entry["scheme_id"], f"{path}.scheme_id")
    _require(
        scheme_id in _SIGNER_SCHEME_IDS,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path}.scheme_id must be one of {sorted(_SIGNER_SCHEME_IDS)!r}",
        "unsupported_scheme",
        path=f"{path}.scheme_id",
    )
    public_key = _require_base64(
        entry["public_key"], f"{path}.public_key", expected_len=_ED25519_PUBLIC_KEY_LEN
    )
    fingerprint = _require_pattern(
        entry["fingerprint"],
        _FINGERPRINT_RE,
        f"{path}.fingerprint",
        "<scheme_id>:sha256:<64 lowercase hex>",
    )
    # Fingerprint equality is key-material equality (§3.2). A stated fingerprint
    # that disagrees with the recomputation is invalid, not corrected.
    recomputed = _compute_fingerprint(public_key, scheme_id)
    _require(
        fingerprint == recomputed,
        ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID,
        f"{path}.fingerprint does not match the recomputed fingerprint of public_key",
        "fingerprint_mismatch",
        path=f"{path}.fingerprint",
        stated=fingerprint,
        recomputed=recomputed,
    )
    return GenesisSigner(
        signer_id=signer_id,
        scheme_id=scheme_id,
        public_key=public_key,
        fingerprint=fingerprint,
    )


def _parse_custody_declaration(entry: Any, path: str) -> CustodyDeclaration:
    """Parse one ``initial_custody`` entry (WI-292). The value rules are unchanged from
    the pre-WI-292 ``signers[].custody`` block; only the location and the fingerprint key
    are new."""
    _require_keys(entry, _CUSTODY_ENTRY_KEYS, path)
    fingerprint = _require_pattern(
        entry["fingerprint"],
        _FINGERPRINT_RE,
        f"{path}.fingerprint",
        "<scheme_id>:sha256:<64 lowercase hex>",
    )
    declared_mode = _require_string(entry["declared_mode"], f"{path}.declared_mode")
    _require(
        declared_mode in _CUSTODY_DECLARED_MODES,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path}.declared_mode must be one of {sorted(_CUSTODY_DECLARED_MODES)!r}",
        "unknown_custody_mode",
        path=f"{path}.declared_mode",
    )
    declared_holder = _require_string(entry["declared_holder"], f"{path}.declared_holder")
    _require(
        entry["attestation"] is None,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path}.attestation is reserved and must be null in 0.6.0",
        "attestation_not_null",
        path=f"{path}.attestation",
    )
    return CustodyDeclaration(
        fingerprint=fingerprint,
        declared_mode=declared_mode,
        declared_holder=declared_holder,
    )


def _parse_signature_entry(entry: Any, path: str) -> GenesisSignature:
    _require_keys(entry, _SIGNATURE_KEYS, path)
    return GenesisSignature(
        signer_id=_require_string(entry["signer_id"], f"{path}.signer_id"),
        fingerprint=_require_pattern(
            entry["fingerprint"],
            _FINGERPRINT_RE,
            f"{path}.fingerprint",
            "<scheme_id>:sha256:<64 lowercase hex>",
        ),
        scheme_id=_require_string(entry["scheme_id"], f"{path}.scheme_id"),
        signed_at=require_genesis_timestamp(entry["signed_at"], f"{path}.signed_at"),
        signature=_require_base64(
            entry["signature"], f"{path}.signature", expected_len=_ED25519_SIGNATURE_LEN
        ),
    )


def _parse_countersignature(entry: Any, path: str) -> Countersignature:
    """Parse a countersignature. 0.6.0 verifies no countersignature cryptographically
    (§3.5) — but its *shape* is contract, and ``present_unverified`` over a garbage
    entry is a report that says "there is something here" about a field that is not a
    countersignature at all. Every field is therefore held to its stated format; only
    the signature *check* is deferred, never the parse."""
    _require_keys(entry, _COUNTERSIGNATURE_KEYS, path)
    over = _require_string(entry["over"], f"{path}.over")
    _require(
        over in _OVER_VALUES,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f'{path}.over must be "trust_domain_core_digest"',
        "invalid_over_target",
        path=f"{path}.over",
    )
    scheme_id = _require_string(entry["scheme_id"], f"{path}.scheme_id")
    # Closed set, like binding_core.signers: 0.6.0 produces no countersignatures, so
    # widening this later breaks no existing artifact, whereas accepting an unknown
    # scheme now means the eventual verifier inherits entries it cannot check.
    _require(
        scheme_id in _SIGNER_SCHEME_IDS,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path}.scheme_id must be one of {sorted(_SIGNER_SCHEME_IDS)!r}",
        "unsupported_scheme",
        path=f"{path}.scheme_id",
    )
    fingerprint = _require_pattern(
        entry["fingerprint"],
        _FINGERPRINT_RE,
        f"{path}.fingerprint",
        "<scheme_id>:sha256:<64 lowercase hex>",
    )
    # The fingerprint names the scheme in its own prefix; disagreement means one of
    # the two is wrong and there is no rule for choosing which.
    _require(
        fingerprint.split(":", 1)[0] == scheme_id,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path}.fingerprint scheme prefix must equal {path}.scheme_id",
        "fingerprint_scheme_mismatch",
        path=f"{path}.fingerprint",
        scheme_id=scheme_id,
    )
    return Countersignature(
        custodian_id=_require_string(entry["custodian_id"], f"{path}.custodian_id"),
        scheme_id=scheme_id,
        fingerprint=fingerprint,
        over=over,
        # Canonical base64 of an Ed25519-length signature: a value that cannot be a
        # signature is rejected now rather than at whatever future release verifies it.
        signature=_require_base64_text(
            entry["signature"], f"{path}.signature", expected_len=_ED25519_SIGNATURE_LEN
        ),
        signed_at=require_genesis_timestamp(entry["signed_at"], f"{path}.signed_at"),
        statement=_require_string(entry["statement"], f"{path}.statement"),
    )


def _parse_anchor(entry: Any, path: str) -> Anchor:
    _require_keys(entry, _ANCHOR_KEYS, path)
    kind = _require_string(entry["kind"], f"{path}.kind")
    _require(
        kind in _ANCHOR_KINDS,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path}.kind must be one of {sorted(_ANCHOR_KINDS)!r}",
        "unknown_anchor_kind",
        path=f"{path}.kind",
    )
    over = _require_string(entry["over"], f"{path}.over")
    _require(
        over in _OVER_VALUES,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f'{path}.over must be "trust_domain_core_digest"',
        "invalid_over_target",
        path=f"{path}.over",
    )
    evidence = entry["evidence"]
    _require(
        isinstance(evidence, dict),
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"{path}.evidence must be an object",
        "not_an_object",
        path=f"{path}.evidence",
    )
    # `evidence` is deliberately free-form (the shape depends on the anchoring
    # provider), but it must still be a JSON object: string keys, JSON values. An
    # anchor carrying something that cannot be serialised back out is not evidence
    # of anything.
    _require_json_object(evidence, f"{path}.evidence")
    return Anchor(
        kind=kind,
        over=over,
        obtained_at=require_genesis_timestamp(entry["obtained_at"], f"{path}.obtained_at"),
        evidence=evidence,
    )


def parse_trust_genesis(
    document: Mapping[str, Any], *, for_signing: bool = False
) -> TrustGenesisDocument:
    """Strictly parse a genesis document; fail closed with named reasons.

    Validates structure (unknown fields rejected at every level), §3.4 governance
    rules, and recomputes the §3.3 derivation, rejecting disagreement with the stated
    ``trust_domain_core_digest`` / ``trust_domain_id``. Does **not** perform Ed25519
    verification — that is :func:`verify_trust_genesis`.

    With ``for_signing=True`` the three signature-excluded sections
    (``signatures``, ``countersignatures``, ``anchors``) may be absent — the offline
    signing helper reads a document that has not been signed yet. When present they
    are validated exactly as in verification mode.
    """
    _require(
        isinstance(document, dict),
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        "genesis document must be an object",
        "not_an_object",
        path="document",
    )
    if for_signing:
        # The excluded sections are optional at signing time; normalize to empty.
        working = dict(document)
        for section in _SIGNATURE_EXCLUDED_SECTIONS:
            working.setdefault(section, [])
        document = working
    _require_keys(document, _TOP_LEVEL_KEYS, "document")
    _require(
        document["type"] == TRUST_GENESIS_TYPE,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f'document.type must be "{TRUST_GENESIS_TYPE}"',
        "wrong_type",
        path="document.type",
    )
    _require(
        _require_int(document["version"], "document.version") == TRUST_GENESIS_VERSION,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"document.version must be integer {TRUST_GENESIS_VERSION}",
        "wrong_version",
        path="document.version",
    )

    # --- binding_core (stable genesis identity; WI-280: no governance inside) ---
    binding_core = document["binding_core"]
    _require_keys(binding_core, _BINDING_CORE_KEYS, "binding_core")
    _require(
        binding_core["type"] == TRUST_GENESIS_CORE_TYPE,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f'binding_core.type must be "{TRUST_GENESIS_CORE_TYPE}"',
        "wrong_type",
        path="binding_core.type",
    )
    _require(
        _require_int(binding_core["version"], "binding_core.version") == TRUST_GENESIS_VERSION,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"binding_core.version must be integer {TRUST_GENESIS_VERSION}",
        "wrong_version",
        path="binding_core.version",
    )
    created_at = require_genesis_timestamp(binding_core["created_at"], "binding_core.created_at")
    nonce = _require_pattern(
        binding_core["nonce"], _NONCE_RE, "binding_core.nonce", "64 lowercase hex characters"
    )
    signers_raw = binding_core["signers"]
    _require(
        isinstance(signers_raw, list) and len(signers_raw) >= 1,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        "binding_core.signers must be a non-empty array",
        "signers_not_a_list",
        path="binding_core.signers",
    )
    signers = tuple(
        _parse_signer(entry, f"binding_core.signers[{i}]") for i, entry in enumerate(signers_raw)
    )
    fingerprints = [s.fingerprint for s in signers]
    # Pairwise distinct: two entries with the same key material is invalid, not
    # co_signed (§3.4).
    _require(
        len(set(fingerprints)) == len(fingerprints),
        ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID,
        "binding_core.signers fingerprints must be pairwise distinct",
        "duplicate_signer_fingerprint",
        path="binding_core.signers",
    )
    # Sorted ascending, enforced — never silently sorted — so the digest is
    # independent of authoring order (§3.4).
    _require(
        fingerprints == sorted(fingerprints),
        ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID,
        "binding_core.signers must be sorted by fingerprint ascending",
        "signers_not_sorted",
        path="binding_core.signers",
    )
    signer_ids = [s.signer_id for s in signers]
    _require(
        len(set(signer_ids)) == len(signer_ids),
        ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID,
        "binding_core.signers signer_id values must be pairwise distinct",
        "duplicate_signer_id",
        path="binding_core.signers",
    )

    # --- initial_custody (signed genesis state; NOT in binding_core, WI-292) ---
    # Mandatory, even when every declared mode is "unspecified": an estate that declines
    # to declare says so in the artifact, and absence is not a permitted third state. The
    # 1:1 correspondence with the signer set is what makes "custody unknown" unreachable
    # for a valid document — a verifier either has a declaration for a signer or the
    # document is invalid.
    custody_raw = document["initial_custody"]
    _require(
        isinstance(custody_raw, list),
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        "initial_custody must be an array",
        "custody_not_a_list",
        path="initial_custody",
    )
    initial_custody = tuple(
        _parse_custody_declaration(entry, f"initial_custody[{i}]")
        for i, entry in enumerate(custody_raw)
    )
    custody_fingerprints = [c.fingerprint for c in initial_custody]
    _require(
        len(set(custody_fingerprints)) == len(custody_fingerprints),
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        "initial_custody fingerprints must be pairwise distinct",
        "duplicate_custody_fingerprint",
        path="initial_custody",
    )
    # Sorted ascending, enforced and never silently sorted — same rule as the signer
    # list, same reason: a canonical order is a diffable order.
    _require(
        custody_fingerprints == sorted(custody_fingerprints),
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        "initial_custody must be sorted by fingerprint ascending",
        "custody_not_sorted",
        path="initial_custody",
    )
    signer_fingerprint_set = {s.fingerprint for s in signers}
    extraneous = sorted(set(custody_fingerprints) - signer_fingerprint_set)
    _require(
        not extraneous,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"initial_custody names {len(extraneous)} fingerprint(s) that are not genesis signers",
        "custody_unknown_signer",
        path="initial_custody",
        fingerprints=extraneous,
    )
    missing = sorted(signer_fingerprint_set - set(custody_fingerprints))
    _require(
        not missing,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"initial_custody is missing an entry for {len(missing)} genesis signer(s)",
        "custody_missing_signer",
        path="initial_custody",
        fingerprints=missing,
    )

    # --- initial_governance (signed genesis state; NOT in binding_core, WI-280) ---
    governance_raw = document["initial_governance"]
    _require_keys(governance_raw, _GOVERNANCE_KEYS, "initial_governance")
    threshold = _require_int(governance_raw["threshold"], "initial_governance.threshold")
    signer_count = _require_int(governance_raw["signer_count"], "initial_governance.signer_count")
    stated_mode = _require_string(governance_raw["mode"], "initial_governance.mode")
    _require(
        signer_count == len(signers),
        ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID,
        f"initial_governance.signer_count {signer_count} != len(signers) {len(signers)}",
        "signer_count_mismatch",
        signer_count=signer_count,
        signers=len(signers),
    )
    derived_mode = derive_governance_mode(threshold, signer_count)
    _require(
        stated_mode in _MODES,
        ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID,
        f"initial_governance.mode must be one of {sorted(_MODES)!r} (Resolution 4 spellings)",
        "unknown_mode",
        stated=stated_mode,
    )
    # The mode is derived and restated; disagreement is INVALID, not mislabelled
    # (§3.4). threshold:1 with three signers is solo_effective, never co_signed.
    _require(
        stated_mode == derived_mode,
        ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID,
        f"initial_governance.mode {stated_mode!r} disagrees with the mode derived from "
        f"threshold={threshold}, signer_count={signer_count}: {derived_mode!r}",
        "mode_threshold_disagreement",
        stated=stated_mode,
        derived=derived_mode,
        threshold=threshold,
        signer_count=signer_count,
    )

    # --- stated derivation values, recomputed and compared (§3.3/§3.5) ---
    stated_digest = _require_pattern(
        document["trust_domain_core_digest"],
        _DIGEST_RE,
        "trust_domain_core_digest",
        "sha256:<64 lowercase hex characters>",
    )
    stated_id = _require_uuid(document["trust_domain_id"], "trust_domain_id")
    recomputed_digest = derive_core_digest(binding_core)
    _require(
        stated_digest == recomputed_digest,
        ErrorCode.TRUST_GENESIS_DERIVATION_MISMATCH,
        "trust_domain_core_digest disagrees with the digest recomputed from binding_core",
        "core_digest_mismatch",
        stated=stated_digest,
        recomputed=recomputed_digest,
    )
    recomputed_id = derive_trust_domain_id(recomputed_digest)
    _require(
        stated_id == recomputed_id,
        ErrorCode.TRUST_GENESIS_DERIVATION_MISMATCH,
        "trust_domain_id disagrees with the id recomputed from trust_domain_core_digest",
        "trust_domain_id_mismatch",
        stated=stated_id,
        recomputed=recomputed_id,
    )

    # --- trust_log / publication ---
    trust_log_raw = document["trust_log"]
    _require_keys(trust_log_raw, _TRUST_LOG_KEYS, "trust_log")
    head = trust_log_raw["initial_head_event_hash"]
    _require(
        head is None,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        "trust_log.initial_head_event_hash must be null on a v1 trust genesis: the "
        "genesis event hash is unknown until the event is written and is pinned later "
        "by the checkpoint (§4.3), not by the genesis document",
        "genesis_head_must_be_null",
        head=head,
    )
    trust_log = TrustLogBlock(
        project_instance_id=_require_uuid(
            trust_log_raw["project_instance_id"], "trust_log.project_instance_id"
        ),
        project_name_hint=_require_string(
            trust_log_raw["project_name_hint"], "trust_log.project_name_hint"
        ),
        initial_head_event_hash=None,
    )
    publication_raw = document["publication"]
    _require_keys(publication_raw, _PUBLICATION_KEYS, "publication")
    pub_kind = _require_string(publication_raw["kind"], "publication.kind")
    _require(
        pub_kind in _PUBLICATION_KINDS,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"publication.kind must be one of {sorted(_PUBLICATION_KINDS)!r}",
        "unknown_publication_kind",
        path="publication.kind",
    )
    pub_bootstrap = _require_string(publication_raw["bootstrap"], "publication.bootstrap")
    _require(
        pub_bootstrap in _PUBLICATION_BOOTSTRAPS,
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        f"publication.bootstrap must be one of {sorted(_PUBLICATION_BOOTSTRAPS)!r}",
        "unknown_publication_bootstrap",
        path="publication.bootstrap",
    )
    publication = PublicationBlock(
        kind=pub_kind,
        url=_require_string(publication_raw["url"], "publication.url"),
        path=_require_string(publication_raw["path"], "publication.path"),
        bootstrap=pub_bootstrap,
    )

    # --- signature sections (structural only here; crypto in verify) ---
    signatures_raw = document["signatures"]
    _require(
        isinstance(signatures_raw, list),
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        "signatures must be an array",
        "signatures_not_a_list",
        path="signatures",
    )
    signatures = tuple(
        _parse_signature_entry(entry, f"signatures[{i}]")
        for i, entry in enumerate(signatures_raw)
    )
    countersignatures_raw = document["countersignatures"]
    _require(
        isinstance(countersignatures_raw, list),
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        "countersignatures must be an array",
        "countersignatures_not_a_list",
        path="countersignatures",
    )
    countersignatures = tuple(
        _parse_countersignature(entry, f"countersignatures[{i}]")
        for i, entry in enumerate(countersignatures_raw)
    )
    anchors_raw = document["anchors"]
    _require(
        isinstance(anchors_raw, list),
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        "anchors must be an array",
        "anchors_not_a_list",
        path="anchors",
    )
    anchors = tuple(_parse_anchor(entry, f"anchors[{i}]") for i, entry in enumerate(anchors_raw))

    return TrustGenesisDocument(
        binding_core_type=str(binding_core["type"]),
        binding_core_version=int(binding_core["version"]),
        signers=signers,
        created_at=created_at,
        nonce=nonce,
        initial_custody=initial_custody,
        initial_governance=InitialGovernance(
            mode=stated_mode, threshold=threshold, signer_count=signer_count
        ),
        trust_domain_core_digest=stated_digest,
        trust_domain_id=stated_id,
        trust_log=trust_log,
        publication=publication,
        signatures=signatures,
        countersignatures=countersignatures,
        anchors=anchors,
    )


# ---------------------------------------------------------------------------
# Verification (§3.5, §3.6)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RootGovernance:
    """§3.6 emitted state. ``independence`` is the literal ``"unverifiable"`` in 0.6.0
    (OPERATOR-FORGERY R2) and no code path sets anything else. ``custody_declared``
    values are unverified operator claims (R1) — hence ``custody_verified`` is always
    ``False`` here."""

    mode: str
    threshold: int
    signer_count: int
    signatures_seen: int
    signer_fingerprints_verified: tuple[str, ...]
    independence: str = "unverifiable"
    custody_declared: tuple[str, ...] = ()
    custody_verified: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "threshold": self.threshold,
            "signer_count": self.signer_count,
            "signatures_seen": self.signatures_seen,
            "signer_fingerprints_verified": list(self.signer_fingerprints_verified),
            "independence": self.independence,
            "custody_declared": list(self.custody_declared),
            "custody_verified": self.custody_verified,
        }


@dataclass(frozen=True)
class TrustGenesisVerification:
    """Successful verification report. Invalid documents never produce one of these —
    :func:`verify_trust_genesis` raises instead (fail closed)."""

    trust_domain_id: str
    trust_domain_core_digest: str
    root_governance: RootGovernance
    signatures_verified: int
    extra_signatures: int
    # 0.6.0 produces and verifies neither countersignatures nor anchors; they are
    # reported as present_unverified (§3.5).
    countersignatures_status: str  # "absent" | "present_unverified"
    countersignature_count: int
    anchors_status: str  # "absent" | "present_unverified"
    anchor_count: int
    # Unverified operator claims (OPERATOR-FORGERY R1); the field name carries the label.
    custody_declared_holders_unverified: tuple[str, ...] = field(default=())

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust_domain_id": self.trust_domain_id,
            "trust_domain_core_digest": self.trust_domain_core_digest,
            "root_governance": self.root_governance.to_dict(),
            "signatures_verified": self.signatures_verified,
            "extra_signatures": self.extra_signatures,
            "countersignatures": self.countersignatures_status,
            "countersignature_count": self.countersignature_count,
            "anchors": self.anchors_status,
            "anchor_count": self.anchor_count,
            "custody_declared_holders_unverified": list(
                self.custody_declared_holders_unverified
            ),
        }


def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        import nacl.exceptions
        import nacl.signing
    except ImportError as exc:  # pragma: no cover - extras always present in CI
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            "trust-genesis verification requires PyNaCl: pip install regista[ed25519]",
        ) from exc
    try:
        nacl.signing.VerifyKey(public_key).verify(message, signature)
    except (nacl.exceptions.BadSignatureError, ValueError, TypeError):
        return False
    return True


def verify_trust_genesis(document: Mapping[str, Any]) -> TrustGenesisVerification:
    """Full genesis verification (§3.5/§3.6): parse strictly, recompute the derivation,
    verify every signature entry, and require >= threshold distinct verified signers.

    Any entry that does not verify, or whose signer is not in ``binding_core.signers``,
    makes the document INVALID — never "bad signature ignored" (§3.4). Extra valid
    signatures beyond the threshold are permitted and reported. Raises
    :class:`RegistaError` on any invalidity; returns a report only for a valid document.
    """
    parsed = parse_trust_genesis(document)
    sig_input = genesis_signature_input(document)

    verified_fingerprints: list[str] = []
    for i, entry in enumerate(parsed.signatures):
        path = f"signatures[{i}]"
        signer = parsed.signer_by_fingerprint(entry.fingerprint)
        _require(
            signer is not None,
            ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID,
            f"{path}.fingerprint is not a genesis signer",
            "unknown_signer",
            path=path,
            fingerprint=entry.fingerprint,
        )
        assert signer is not None  # narrowed by _require above
        _require(
            entry.signer_id == signer.signer_id,
            ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID,
            f"{path}.signer_id {entry.signer_id!r} does not match the genesis signer "
            f"{signer.signer_id!r} for this fingerprint",
            "signer_id_mismatch",
            path=path,
        )
        _require(
            entry.scheme_id == signer.scheme_id,
            ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID,
            f"{path}.scheme_id {entry.scheme_id!r} does not match the genesis signer's "
            f"scheme {signer.scheme_id!r}",
            "scheme_mismatch",
            path=path,
        )
        # Two entries by the same signer cannot raise the distinct-signer count; a
        # duplicate is a malformed ceremony artifact and fails closed.
        _require(
            entry.fingerprint not in verified_fingerprints,
            ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID,
            f"{path} duplicates an earlier signature by the same signer",
            "duplicate_signature_entry",
            path=path,
            fingerprint=entry.fingerprint,
        )
        _require(
            _verify_ed25519(signer.public_key, sig_input, entry.signature),
            ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID,
            f"{path} does not verify over the genesis signature input",
            "bad_signature",
            path=path,
            fingerprint=entry.fingerprint,
        )
        verified_fingerprints.append(entry.fingerprint)

    threshold = parsed.initial_governance.threshold
    _require(
        len(verified_fingerprints) >= threshold,
        ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID,
        f"{len(verified_fingerprints)} verified signature(s); threshold is {threshold}",
        "threshold_not_met",
        verified=len(verified_fingerprints),
        threshold=threshold,
    )

    governance = RootGovernance(
        mode=parsed.initial_governance.mode,
        threshold=threshold,
        signer_count=parsed.initial_governance.signer_count,
        signatures_seen=len(verified_fingerprints),
        signer_fingerprints_verified=tuple(verified_fingerprints),
        # WI-292: read from initial_custody, in binding_core signer order (both are
        # sorted by fingerprint, and the 1:1 rule makes the lookup total).
        custody_declared=tuple(_custody_for(parsed, s).declared_mode for s in parsed.signers),
    )
    return TrustGenesisVerification(
        trust_domain_id=parsed.trust_domain_id,
        trust_domain_core_digest=parsed.trust_domain_core_digest,
        root_governance=governance,
        signatures_verified=len(verified_fingerprints),
        extra_signatures=max(0, len(verified_fingerprints) - threshold),
        countersignatures_status=(
            "present_unverified" if parsed.countersignatures else "absent"
        ),
        countersignature_count=len(parsed.countersignatures),
        anchors_status="present_unverified" if parsed.anchors else "absent",
        anchor_count=len(parsed.anchors),
        custody_declared_holders_unverified=tuple(
            _custody_for(parsed, s).declared_holder for s in parsed.signers
        ),
    )


def _custody_for(parsed: TrustGenesisDocument, signer: GenesisSigner) -> CustodyDeclaration:
    """The declared custody for a signer of an already-parsed document.

    Total by construction: :func:`parse_trust_genesis` rejects any document whose
    ``initial_custody`` is not in exact 1:1 correspondence with the signer set, so a
    missing declaration here is an internal invariant break, not a document defect.
    """
    declaration = parsed.custody_by_fingerprint(signer.fingerprint)
    assert declaration is not None, (
        f"parsed document has no initial_custody entry for signer {signer.signer_id}"
    )
    return declaration


# ---------------------------------------------------------------------------
# Governance monotonicity primitive (WI-280) — standalone, for P2.2's log replay
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GovernanceState:
    """A replayed governance state: the current threshold and the current signer set,
    identified by fingerprint. ``signer_count`` is always ``len(signer_fingerprints)``."""

    threshold: int
    signer_fingerprints: tuple[str, ...]

    @property
    def signer_count(self) -> int:
        return len(self.signer_fingerprints)

    @property
    def mode(self) -> str:
        return derive_governance_mode(self.threshold, self.signer_count)


@dataclass(frozen=True)
class GovernanceTransition:
    """A validated transition. ``authorization_threshold`` is the threshold active
    immediately **before** the transition — the number of detached root signatures by
    *current* signers that P2.2's replay must find on the transition event (§3.6 rule 5).
    This function validates the structural/monotonicity rules only; it does not (and
    cannot) check signatures."""

    old: GovernanceState
    new: GovernanceState
    authorization_threshold: int
    new_mode: str


def _validate_governance_state(state: GovernanceState, path: str) -> None:
    fingerprints = list(state.signer_fingerprints)
    _require(
        len(fingerprints) >= 1,
        ErrorCode.TRUST_GOVERNANCE_TRANSITION_INVALID,
        f"{path} must have at least one signer",
        "empty_signer_set",
        path=path,
    )
    for i, fp in enumerate(fingerprints):
        _require(
            isinstance(fp, str) and _FINGERPRINT_RE.fullmatch(fp) is not None,
            ErrorCode.TRUST_GOVERNANCE_TRANSITION_INVALID,
            f"{path}.signer_fingerprints[{i}] must be <scheme_id>:sha256:<64 lowercase hex>",
            "malformed_fingerprint",
            path=f"{path}.signer_fingerprints[{i}]",
        )
    _require(
        len(set(fingerprints)) == len(fingerprints),
        ErrorCode.TRUST_GOVERNANCE_TRANSITION_INVALID,
        f"{path} signer fingerprints must be pairwise distinct",
        "duplicate_signer_fingerprint",
        path=path,
    )
    _require(
        isinstance(state.threshold, int)
        and not isinstance(state.threshold, bool)
        and state.threshold >= 1,
        ErrorCode.TRUST_GOVERNANCE_TRANSITION_INVALID,
        f"{path}.threshold must be an integer >= 1",
        "threshold_below_one",
        path=path,
    )
    _require(
        state.threshold <= state.signer_count,
        ErrorCode.TRUST_GOVERNANCE_TRANSITION_INVALID,
        f"{path}.threshold {state.threshold} exceeds signer_count {state.signer_count}",
        "threshold_exceeds_signer_count",
        path=path,
    )


def validate_governance_transition(
    current: GovernanceState, proposed: GovernanceState
) -> GovernanceTransition:
    """Validate a proposed governance transition under the WI-280 monotone-log rules.

    * **The threshold may never decrease.** Rejected regardless of who signed the
      transition — by design this function takes no signer identity at all, so no
      authorization argument can make a decrease valid. Downgrade is structurally
      impossible, not merely expensive.
    * **Signers may be replaced at the current threshold** — a compromised co-signer
      key is removable. The returned ``authorization_threshold`` (== the *current*
      threshold) is the number of detached signatures by current signers that P2.2's
      replay must verify on the transition event.
    * The resulting set must have pairwise-distinct fingerprints, and the proposed
      threshold must fit the proposed set (``1 <= threshold <= signer_count``).
    """
    _validate_governance_state(current, "current")
    _validate_governance_state(proposed, "proposed")
    _require(
        proposed.threshold >= current.threshold,
        ErrorCode.TRUST_GOVERNANCE_TRANSITION_INVALID,
        f"threshold may never decrease: current {current.threshold}, "
        f"proposed {proposed.threshold} (rejected no matter who signed it)",
        "threshold_decrease",
        current=current.threshold,
        proposed=proposed.threshold,
    )
    return GovernanceTransition(
        old=current,
        new=proposed,
        authorization_threshold=current.threshold,
        new_mode=derive_governance_mode(proposed.threshold, proposed.signer_count),
    )


__all__: Sequence[str] = [
    "MODE_CO_SIGNED",
    "MODE_SOLO",
    "MODE_SOLO_EFFECTIVE",
    "TRUST_GENESIS_CORE_DOMAIN",
    "TRUST_GENESIS_SIGNING_DOMAIN",
    "Anchor",
    "Countersignature",
    "CustodyDeclaration",
    "GenesisSignature",
    "GenesisSigner",
    "GovernanceState",
    "GovernanceTransition",
    "InitialGovernance",
    "PublicationBlock",
    "RootGovernance",
    "TrustGenesisDocument",
    "TrustGenesisVerification",
    "TrustLogBlock",
    "derive_core_digest",
    "derive_governance_mode",
    "derive_trust_domain_id",
    "genesis_document_core",
    "genesis_signature_input",
    "parse_trust_genesis",
    "validate_governance_transition",
    "verify_trust_genesis",
]
