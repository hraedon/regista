"""WI-330: the signed estate cutover catalog (``TRUST-DOMAIN.md`` §4.3).

The catalog is the only artifact that says a cutover ceremony *finished*
(``CUTOVER-CLASSIFICATION.md``:588). One document, one entry per project, and each
entry binds three facts that no single store can produce alone:

* the **frozen legacy** head hash and event count (``EPOCH-RESET.md``:200 — the legacy
  population is retained read-only, so these are the last measurements taken before
  the freeze and they can never be re-derived from the new store);
* the event that **opened the new epoch** for that project; and
* the **new epoch head** the project was at when the ceremony closed.

Binding them in one signed document is what makes a *dropped project* detectable: an
operator who quietly omits one project's checkpoint produces a catalog an auditor
holding a prior copy can contradict (``CUTOVER-CLASSIFICATION.md``:562-565).

Byte contract, frozen by ``tests/vectors/v6/estate-catalog.json``::

    core   = document minus {root_signatures, countersignatures, anchors}
    c      = JCS(core)
    input  = b"regista.estate-catalog.v1\\x00" || uint64be(len(c)) || c
    digest = "sha256:" + hex(sha256(input))

The document's ``root_signatures`` each cover ``input``. That is §4.3's "same framing"
sentence applied literally, and it is the same shape ``_genesis_open``'s trust-log
checkpoint already implements (``_checkpoint_signature_input``).

Judgment calls this module makes, because §4.3 under-specifies them
--------------------------------------------------------------------

1. **Signing authority is direct root threshold**, so the document carries
   ``root_signatures: [{signer_id, fingerprint, signature}]`` and **no** ``signer``
   block. §4.3's JSON skeleton shows ``"signer": {}`` and a scalar ``"signature"``,
   but the AMENDED rule 1 immediately below it (``RECONCILIATION.md`` collisions 19,
   21, 22) supersedes the skeleton: "a **direct root-threshold** authorisation does
   **not** invent a principal id for the root — it uses ``root_signatures: []`` ...
   and leaves ``signer`` absent". §4.3 permits producer-policy-style documents to be
   signed "under an explicitly scoped authority that the genesis grants"; this module
   does **not** implement that alternative for the catalog, because no ratified
   document names a scoped authority for it and inventing one would create a second,
   weaker path to the artifact that says the ceremony finished. A registrar-signed
   catalog is therefore a named refusal, not a warning.
2. **``trust_log_checkpoint_digest`` is a plain SHA-256 over the published
   checkpoint's exact canonical bytes** — the same value
   ``_genesis_open.TrustLogCheckpoint.document_digest`` computes and that every
   project's ``bootstrap_key_acceptance.trust_log_checkpoint.document_digest``
   already binds. §4.3 names the field but not its construction; reusing the existing
   one makes the catalog and the project genesis events cross-checkable instead of
   binding the same checkpoint two incomparable ways.
3. **``cutover_event_hash`` is the event that opened the project's new epoch** — under
   ``EPOCH-RESET.md`` §5 the fresh schema's first event is ``project_initialized``, so
   that event *is* the project's cutover event. §4.3's field name comes from the
   in-place cutover model, where a ``project_cryptographic_epoch_started`` event sits
   in the same chain as the legacy population; the fresh-schema runbook has no such
   event and the epoch-opening genesis is its only analog. It stays distinct from
   ``new_epoch_head_event_hash``, which advances as the new chain grows.
4. **``sum(scheme_counts.values()) == legacy_event_count``** is enforced. §4.3 does not
   say so, but the frozen vector satisfies it (800 + 200 == 1000), the two numbers
   describe the same population, and a catalog whose own two counts disagree is not
   evidence about anything. Prefer the stricter reading.
5. **``catalog_kind: project_heads``** (§4.3 rule 4) is **not** implemented. Its
   project entries would carry no legacy binding, so it is a different entry shape
   with no frozen vector, and rule 4 states it is explicitly not a release gate. It is
   a named refusal here rather than a shape this module guesses at.
6. **``catalog_status: "partial"`` is present only on a partial catalog.**
   ``RECONCILIATION.md``:682-684 requires a partial catalog to say
   ``catalog_status: partial`` and treats it as ceremony failure. The frozen vector has
   no such key, so absence is the complete claim and presence is the partial one —
   which keeps byte conformance intact while making the distinction visible. The field
   sits inside the signed core, so an operator cannot strip it after signing. The
   expected estate is **operator-supplied** (a ``regista.estate-manifest/v1`` document);
   nothing here hardcodes 26 projects.

Where authority comes from, and why it is not the genesis document alone
-----------------------------------------------------------------------

The set of keys that may sign a catalog is the **verified published trust-log
checkpoint's** ``active_root_fingerprints``, not the genesis document's signer list.
Genesis names the *initial* roots; §5.4/WI-280 let a rotation replace signers and raise
the threshold without moving ``trust_domain_id``. Verifying against genesis alone gets
both directions wrong: a **removed** root's signature still verifies, and a
**rotated-in** root is refused. So verification requires the checkpoint, reconciles the
catalog's restated ``root_governance`` against it, and takes the threshold from it.

Public keys are still needed to check a signature, and a checkpoint carries only
fingerprints. They come from the genesis document plus operator-supplied
``--root-public-key`` files; each supplied key is accepted only if
``sha256(public_key)`` matches a fingerprint the **signed** checkpoint authorises, so
the operator supplies bytes, never authority. That is the same out-of-band exchange
§4.5 step 1 already requires of the root fingerprints themselves.

Everything fails closed. Unknown top-level keys are a rejection; a file whose bytes are
not exact canonical JCS is a rejection; a signature by a fingerprint the verified
checkpoint does not authorise is a rejection rather than a dropped signature; and absent
evidence — no genesis, no checkpoint, no expected-estate manifest — is a named refusal,
never a silent pass. In particular there is no verdict that means "I could not check the
checkpoint but everything else looked fine".

What the signed artifact does NOT carry
---------------------------------------

Provenance labels for the frozen-legacy numbers (``operator_recorded`` / ``measured`` /
``operator_recorded_and_measured``) live in the **command's report**, not in the
document: adding a field would change the canonical bytes and break the frozen vector.
A reader of a published catalog therefore cannot tell from the artifact alone whether a
``legacy_*`` value was re-measured or transcribed from the §2.4 record. The build-time
cross-check (and its refusal on disagreement) is what stands behind those numbers.
"""

from __future__ import annotations

import hashlib
import re
import struct
import uuid as _uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, NoReturn

from ._errors import ErrorCode, RegistaError
from ._jcs import canonicalize

# ---------------------------------------------------------------------------
# Frozen constants (TRUST-DOMAIN.md §4.3; tools/make_v6_vectors.py:89)
# ---------------------------------------------------------------------------

ESTATE_CATALOG_TYPE: Final[str] = "regista.estate-catalog"
ESTATE_CATALOG_VERSION: Final[int] = 1
ESTATE_CATALOG_DOMAIN: Final[bytes] = b"regista.estate-catalog.v1\x00"

CATALOG_KIND_CUTOVER: Final[str] = "cutover"
#: Judgment call 5: ``project_heads`` is deliberately absent.
SUPPORTED_CATALOG_KINDS: Final[frozenset[str]] = frozenset({CATALOG_KIND_CUTOVER})

#: The operator-authored *measurements* input, NOT the catalog document. §5.4 of the
#: suite runbook forbids hand-authoring catalog JSON; the frozen legacy numbers it
#: requires were recorded by §2.4 before the legacy schema went read-only, so they
#: have to enter the tool from somewhere.
CATALOG_INPUTS_TYPE: Final[str] = "regista.estate-catalog-inputs"
CATALOG_INPUTS_VERSION: Final[int] = 1

#: The operator's expected estate: which projects a COMPLETE catalog must cover.
#: ``TRUST-DOMAIN.md``:807 says "one document, all 26 project checkpoints", but 26 is
#: this estate's current count, not a contract — so the list is supplied, never
#: hardcoded (``RECONCILIATION.md``:682-684 fix, WI-330 review F4).
ESTATE_MANIFEST_TYPE: Final[str] = "regista.estate-manifest"
ESTATE_MANIFEST_VERSION: Final[int] = 1

#: Sections excluded from the signed core: a signature cannot be inside the bytes it
#: signs (§3.5's rule, applied to §4.3 documents by ``_genesis_open`` already).
SIGNATURE_SECTIONS: Final[frozenset[str]] = frozenset(
    {"root_signatures", "countersignatures", "anchors"}
)

CORE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "type",
        "version",
        "trust_domain_id",
        "trust_domain_core_digest",
        "root_governance",
        "catalog_kind",
        "projects",
        "trust_log_checkpoint_digest",
        "prev_commit",
        "created_at",
    }
)

#: ``RECONCILIATION.md``:682-684: "A partial catalog says ``catalog_status: partial``
#: and is ceremony failure, not success."
CATALOG_STATUS_PARTIAL: Final[str] = "partial"

#: Keys a catalog MAY carry but need not. ``catalog_status`` is here and not in
#: :data:`CORE_KEYS` for a byte reason: the frozen vector
#: (``tests/vectors/v6/estate-catalog.json``) has no such key, so making it mandatory
#: would change the canonical bytes of every catalog and break conformance. Absence is
#: therefore the *complete* claim and presence is the *partial* one. It is still inside
#: the signed core (it is not a signature section), so it cannot be stripped after
#: signing without invalidating every signature.
OPTIONAL_CORE_KEYS: Final[frozenset[str]] = frozenset({"catalog_status"})

CATALOG_KEYS: Final[frozenset[str]] = CORE_KEYS | SIGNATURE_SECTIONS
_ALLOWED_KEYS: Final[frozenset[str]] = CATALOG_KEYS | OPTIONAL_CORE_KEYS

_PROJECT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "project_instance_id",
        "project_name_hint",
        "cutover_event_hash",
        "legacy_head_event_hash",
        "legacy_event_count",
        "scheme_counts",
        "new_epoch_head_event_hash",
    }
)
_GOVERNANCE_KEYS: Final[frozenset[str]] = frozenset({"mode", "threshold", "signer_count"})
_ROOT_SIGNATURE_KEYS: Final[frozenset[str]] = frozenset(
    {"signer_id", "fingerprint", "signature"}
)

_INPUTS_KEYS: Final[frozenset[str]] = frozenset({"type", "version", "projects"})
_INPUTS_PROJECT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "project",
        "project_name_hint",
        "legacy_project",
        "legacy_head_event_hash",
        "legacy_event_count",
        "scheme_counts",
        "expected_new_epoch_head_event_hash",
        "expected_new_epoch_event_count",
    }
)
_INPUTS_LEGACY_FACT_KEYS: Final[tuple[str, ...]] = (
    "legacy_head_event_hash",
    "legacy_event_count",
    "scheme_counts",
)
#: ``ARCHITECTURE-0.6.0.md``:802-810 — "Confirm the head/count equal the approved
#: preflight result." Mandatory, not optional: the whole point is that the tool cannot
#: be the only witness to the number it signs (WI-330 review F1).
_INPUTS_PREFLIGHT_KEYS: Final[tuple[str, ...]] = (
    "expected_new_epoch_head_event_hash",
    "expected_new_epoch_event_count",
)

_MANIFEST_KEYS: Final[frozenset[str]] = frozenset(
    {"type", "version", "trust_domain_id", "project_instance_ids"}
)

_DIGEST_RE: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}")
_FINGERPRINT_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9-]+:sha256:[0-9a-f]{64}")
_GIT_COMMIT_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}")
_SCHEME_ID_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_PROJECT_NAME_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
#: EXACTLY six fractional digits. ``datetime.strptime("%f")`` accepts one to six, so
#: ``...T12:00:00.1Z`` used to pass a check whose own error message promised
#: microsecond precision. Same pattern as ``_trust_log.py``:251 and
#: ``_principal_alias.py``:85 (WI-330 review N-b). The frozen vector uses ``.000000Z``,
#: so byte conformance is unaffected.
_TIMESTAMP_RE: Final[re.Pattern[str]] = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z"
)
_TIMESTAMP_STRPTIME: Final[str] = "%Y-%m-%dT%H:%M:%S.%fZ"
_ED25519_SIGNATURE_LEN: Final[int] = 64


# ---------------------------------------------------------------------------
# Refusals. Two codes, because the operator's next action differs: a SCHEMA
# refusal means "the document is malformed, rebuild it"; an UNVERIFIED refusal
# means "the document is well-formed and its claims did not hold up".
# ---------------------------------------------------------------------------


def _schema(message: str, reason: str, **detail: Any) -> NoReturn:
    raise RegistaError(
        ErrorCode.ESTATE_CATALOG_SCHEMA_INVALID, message, {"reason": reason, **detail}
    )


def _unverified(message: str, reason: str, **detail: Any) -> NoReturn:
    raise RegistaError(
        ErrorCode.ESTATE_CATALOG_UNVERIFIED, message, {"reason": reason, **detail}
    )


def _require(condition: bool, message: str, reason: str, **detail: Any) -> None:
    if not condition:
        _schema(message, reason, **detail)


def _require_object(value: Any, path: str) -> None:
    _require(
        isinstance(value, Mapping), f"{path} must be a JSON object", "not_an_object", path=path
    )


def _require_keys(value: Any, expected: frozenset[str], path: str) -> Mapping[str, Any]:
    _require_object(value, path)
    assert isinstance(value, Mapping)
    present = set(value)
    unknown = sorted(present - expected)
    missing = sorted(expected - present)
    if unknown or missing:
        _schema(
            f"{path} has unknown or missing fields",
            "closed_key_set_violated",
            path=path,
            unknown=unknown,
            missing=missing,
        )
    return value


def _require_str(value: Any, path: str) -> str:
    _require(
        isinstance(value, str) and bool(value),
        f"{path} must be a non-empty string",
        "not_a_string",
        path=path,
    )
    assert isinstance(value, str)
    return value


def _require_pattern(value: Any, pattern: re.Pattern[str], path: str, what: str) -> str:
    text = _require_str(value, path)
    _require(
        pattern.fullmatch(text) is not None,
        f"{path} must be {what}",
        "malformed_value",
        path=path,
    )
    return text


def _require_int(value: Any, path: str, *, minimum: int) -> int:
    # `type(...) is not int` rather than isinstance: bool is an int subclass, and
    # `true` in a count field is a malformed document, not the number 1.
    _require(type(value) is int, f"{path} must be an integer", "not_an_integer", path=path)
    assert isinstance(value, int)
    _require(
        value >= minimum,
        f"{path} must be >= {minimum}, got {value}",
        "integer_out_of_range",
        path=path,
        value=value,
    )
    return value


def _require_uuid(value: Any, path: str) -> str:
    text = _require_str(value, path)
    try:
        parsed = _uuid.UUID(text)
    except ValueError:
        _schema(f"{path} must be a UUID", "not_a_uuid", path=path)
    _require(
        str(parsed) == text,
        f"{path} must be the canonical lowercase hyphenated UUID form",
        "uuid_not_canonical",
        path=path,
    )
    return text


def _require_timestamp(value: Any, path: str) -> str:
    text = _require_str(value, path)
    # The regex FIRST, and it is what makes the check match its own error message:
    # `strptime`'s %f accepts one to six fractional digits, so `.1Z` satisfied
    # strptime while contradicting the promise of microsecond precision.
    if _TIMESTAMP_RE.fullmatch(text) is None:
        _schema(
            f"{path} must be a microsecond-precision UTC Z timestamp with EXACTLY six "
            "fractional digits (YYYY-MM-DDTHH:MM:SS.ffffffZ)",
            "malformed_timestamp",
            path=path,
        )
    try:
        datetime.strptime(text, _TIMESTAMP_STRPTIME)
    except ValueError:
        _schema(
            f"{path} is not a real instant even though its shape is right",
            "malformed_timestamp",
            path=path,
        )
    return text


def _require_scheme_counts(value: Any, path: str) -> dict[str, int]:
    _require_object(value, path)
    assert isinstance(value, Mapping)
    _require(bool(value), f"{path} must be non-empty", "empty_object", path=path)
    counts: dict[str, int] = {}
    for scheme, count in value.items():
        _require_pattern(scheme, _SCHEME_ID_RE, f"{path} key {scheme!r}", "a scheme id")
        counts[scheme] = _require_int(count, f"{path}.{scheme}", minimum=0)
    return counts


# ---------------------------------------------------------------------------
# Byte contract
# ---------------------------------------------------------------------------


def estate_catalog_core(document: Mapping[str, Any]) -> dict[str, Any]:
    """The document as its root signatures see it (signature sections removed)."""
    return {key: value for key, value in document.items() if key not in SIGNATURE_SECTIONS}


def estate_catalog_canonical_core(document: Mapping[str, Any]) -> bytes:
    """``JCS(core)`` — the vector's ``canonical_bytes``."""
    return canonicalize(estate_catalog_core(document))


def estate_catalog_signature_input(document: Mapping[str, Any]) -> bytes:
    """Domain-separated, length-framed bytes each root signature covers (§4.3)."""
    body = estate_catalog_canonical_core(document)
    return ESTATE_CATALOG_DOMAIN + struct.pack(">Q", len(body)) + body


def estate_catalog_digest(document: Mapping[str, Any]) -> str:
    """The vector's ``estate_catalog_digest``: sha256 over the framed signature input."""
    return "sha256:" + hashlib.sha256(estate_catalog_signature_input(document)).hexdigest()


# ---------------------------------------------------------------------------
# Typed model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CatalogProject:
    """One ``projects[]`` entry: the legacy population bound to the new epoch."""

    project_instance_id: str
    project_name_hint: str
    cutover_event_hash: str
    legacy_head_event_hash: str
    legacy_event_count: int
    scheme_counts: Mapping[str, int]
    new_epoch_head_event_hash: str

    def as_document_member(self) -> dict[str, Any]:
        return {
            "project_instance_id": self.project_instance_id,
            "project_name_hint": self.project_name_hint,
            "cutover_event_hash": self.cutover_event_hash,
            "legacy_head_event_hash": self.legacy_head_event_hash,
            "legacy_event_count": self.legacy_event_count,
            "scheme_counts": dict(self.scheme_counts),
            "new_epoch_head_event_hash": self.new_epoch_head_event_hash,
        }


@dataclass(frozen=True)
class CatalogGovernance:
    mode: str
    threshold: int
    signer_count: int


@dataclass(frozen=True)
class CatalogRootSignature:
    signer_id: str
    fingerprint: str
    signature: bytes


@dataclass(frozen=True)
class EstateCatalog:
    """A strictly parsed catalog document."""

    trust_domain_id: str
    trust_domain_core_digest: str
    root_governance: CatalogGovernance
    catalog_kind: str
    projects: tuple[CatalogProject, ...]
    trust_log_checkpoint_digest: str
    prev_commit: str | None
    created_at: str
    root_signatures: tuple[CatalogRootSignature, ...]
    #: ``None`` is the document's COMPLETE claim (the field is absent);
    #: ``"partial"`` is its self-declared ceremony failure.
    catalog_status: str | None


@dataclass(frozen=True)
class VerifiedCheckpoint:
    """A published §4.3 trust-log checkpoint that has been authenticated offline.

    This is what supplies the authority a catalog is checked against: the threshold and
    the ``active_root_fingerprints`` at checkpoint time, both inside its signed core.
    """

    checkpoint_seq: int
    document_digest: str
    trust_domain_id: str
    trust_domain_core_digest: str
    governance: CatalogGovernance
    active_root_fingerprints: tuple[str, ...]
    signatures_verified: int
    verified_fingerprints: tuple[str, ...]
    trust_log_head_event_hash: str
    trust_log_event_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_seq": self.checkpoint_seq,
            "document_digest": self.document_digest,
            "trust_domain_id": self.trust_domain_id,
            "governance": {
                "mode": self.governance.mode,
                "threshold": self.governance.threshold,
                "signer_count": self.governance.signer_count,
            },
            "active_root_fingerprints": list(self.active_root_fingerprints),
            "signatures_verified": self.signatures_verified,
            "trust_log_head_event_hash": self.trust_log_head_event_hash,
            "trust_log_event_count": self.trust_log_event_count,
        }


@dataclass(frozen=True)
class EstateCatalogVerification:
    """What a verifier established, and what it explicitly did not.

    ``verdict`` is ``"VALID"`` only for a catalog that is authenticated AND complete
    against the operator's expected-estate manifest. A self-declared partial catalog
    verifies cryptographically and still returns ``"PARTIAL"``, because
    ``RECONCILIATION.md``:682-684 makes a partial catalog a ceremony *failure* — the
    caller must not be able to treat it as success by reading only the signature count.
    """

    verdict: str
    trust_domain_id: str
    trust_domain_core_digest: str
    catalog_kind: str
    estate_catalog_digest: str
    project_count: int
    root_governance: CatalogGovernance
    signatures_verified: int
    verified_fingerprints: tuple[str, ...]
    extra_signatures: int
    trust_log_checkpoint_digest: str
    digest_pin_status: str
    project_name_hints: tuple[str, ...]
    catalog_status: str
    completeness: str
    missing_project_instance_ids: tuple[str, ...]
    checkpoint: VerifiedCheckpoint

    @property
    def complete(self) -> bool:
        return self.verdict == "VALID"

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "trust_domain_id": self.trust_domain_id,
            "trust_domain_core_digest": self.trust_domain_core_digest,
            "catalog_kind": self.catalog_kind,
            "estate_catalog_digest": self.estate_catalog_digest,
            "project_count": self.project_count,
            "root_governance": {
                "mode": self.root_governance.mode,
                "threshold": self.root_governance.threshold,
                "signer_count": self.root_governance.signer_count,
            },
            "signatures_verified": self.signatures_verified,
            "verified_fingerprints": list(self.verified_fingerprints),
            "extra_signatures": self.extra_signatures,
            "trust_log_checkpoint_digest": self.trust_log_checkpoint_digest,
            "digest_pin_status": self.digest_pin_status,
            "project_name_hints": list(self.project_name_hints),
            "catalog_status": self.catalog_status,
            "completeness": self.completeness,
            "missing_project_instance_ids": list(self.missing_project_instance_ids),
            "checkpoint": self.checkpoint.to_dict(),
        }


# ---------------------------------------------------------------------------
# Strict parsing
# ---------------------------------------------------------------------------


def _parse_governance(value: Any, path: str) -> CatalogGovernance:
    from ._trust_domain import derive_governance_mode

    raw = _require_keys(value, _GOVERNANCE_KEYS, path)
    threshold = _require_int(raw["threshold"], f"{path}.threshold", minimum=1)
    signer_count = _require_int(raw["signer_count"], f"{path}.signer_count", minimum=1)
    mode = _require_str(raw["mode"], f"{path}.mode")
    _require(
        threshold <= signer_count,
        f"{path}.threshold {threshold} exceeds signer_count {signer_count}",
        "threshold_exceeds_signer_count",
        path=path,
    )
    # §3.4: the mode is DERIVED and merely restated. A document that labels itself
    # co_signed on threshold 1 is invalid, not mislabelled.
    expected = derive_governance_mode(threshold, signer_count)
    _require(
        mode == expected,
        f"{path}.mode is {mode!r} but threshold {threshold} of {signer_count} derives "
        f"{expected!r}",
        "governance_mode_mismatch",
        path=path,
        stated=mode,
        derived=expected,
    )
    return CatalogGovernance(mode=mode, threshold=threshold, signer_count=signer_count)


def _parse_project(value: Any, path: str) -> CatalogProject:
    raw = _require_keys(value, _PROJECT_KEYS, path)
    digest_what = "sha256:<64 lowercase hex characters>"
    legacy_count = _require_int(raw["legacy_event_count"], f"{path}.legacy_event_count", minimum=1)
    scheme_counts = _require_scheme_counts(raw["scheme_counts"], f"{path}.scheme_counts")
    # Judgment call 4: the two numbers describe one population.
    total = sum(scheme_counts.values())
    _require(
        total == legacy_count,
        f"{path}.scheme_counts sum to {total} but legacy_event_count is {legacy_count}; "
        "the two describe the same frozen population and cannot disagree",
        "scheme_counts_do_not_sum_to_event_count",
        path=path,
        scheme_total=total,
        legacy_event_count=legacy_count,
    )
    return CatalogProject(
        project_instance_id=_require_uuid(
            raw["project_instance_id"], f"{path}.project_instance_id"
        ),
        project_name_hint=_require_pattern(
            raw["project_name_hint"],
            _PROJECT_NAME_RE,
            f"{path}.project_name_hint",
            "a backend-safe project name",
        ),
        cutover_event_hash=_require_pattern(
            raw["cutover_event_hash"], _DIGEST_RE, f"{path}.cutover_event_hash", digest_what
        ),
        legacy_head_event_hash=_require_pattern(
            raw["legacy_head_event_hash"],
            _DIGEST_RE,
            f"{path}.legacy_head_event_hash",
            digest_what,
        ),
        legacy_event_count=legacy_count,
        scheme_counts=scheme_counts,
        new_epoch_head_event_hash=_require_pattern(
            raw["new_epoch_head_event_hash"],
            _DIGEST_RE,
            f"{path}.new_epoch_head_event_hash",
            digest_what,
        ),
    )


def _parse_root_signatures(value: Any, path: str) -> tuple[CatalogRootSignature, ...]:
    import base64
    import binascii

    _require(isinstance(value, list), f"{path} must be an array", "not_an_array", path=path)
    assert isinstance(value, list)
    out: list[CatalogRootSignature] = []
    for index, entry in enumerate(value):
        item = f"{path}[{index}]"
        raw = _require_keys(entry, _ROOT_SIGNATURE_KEYS, item)
        encoded = _require_str(raw["signature"], f"{item}.signature")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            _schema(
                f"{item}.signature must be base64", "malformed_base64", path=f"{item}.signature"
            )
        _require(
            len(decoded) == _ED25519_SIGNATURE_LEN,
            f"{item}.signature must decode to {_ED25519_SIGNATURE_LEN} bytes, got "
            f"{len(decoded)}",
            "signature_length_invalid",
            path=f"{item}.signature",
        )
        out.append(
            CatalogRootSignature(
                signer_id=_require_str(raw["signer_id"], f"{item}.signer_id"),
                fingerprint=_require_pattern(
                    raw["fingerprint"],
                    _FINGERPRINT_RE,
                    f"{item}.fingerprint",
                    "<scheme_id>:sha256:<64 lowercase hex>",
                ),
                signature=decoded,
            )
        )
    fingerprints = [entry.fingerprint for entry in out]
    _require(
        len(set(fingerprints)) == len(fingerprints),
        f"{path} entries must have pairwise-distinct fingerprints: two entries by the "
        "same signer cannot raise the distinct-signer count",
        "duplicate_root_signature",
        path=path,
    )
    return tuple(out)


def parse_estate_catalog(
    document: Mapping[str, Any], *, for_signing: bool = False
) -> EstateCatalog:
    """Strictly parse a catalog document. Unknown fields are refused at every level.

    ``for_signing=True`` accepts a document whose signature sections are absent or
    empty — the shape the builder produces and the shape the frozen vector's ``input``
    document has. A *published* catalog (``for_signing=False``) must carry all three
    sections and at least one root signature.
    """
    _require(
        isinstance(document, Mapping),
        "the catalog must be a JSON object",
        "not_an_object",
        path="<document>",
    )
    present = set(document)
    required = CORE_KEYS if for_signing else CATALOG_KEYS
    unknown = sorted(present - _ALLOWED_KEYS)
    missing = sorted(required - present)
    if unknown or missing:
        _schema(
            "the catalog has unknown or missing fields",
            "closed_key_set_violated",
            path="<document>",
            unknown=unknown,
            missing=missing,
        )

    # ``catalog_status`` is optional, and when present it may say exactly one thing.
    # An unrecognised value would otherwise let a catalog carry a status a verifier
    # silently ignores while it reads as meaningful to a human.
    catalog_status: str | None = None
    if "catalog_status" in document:
        catalog_status = _require_str(document["catalog_status"], "catalog_status")
        _require(
            catalog_status == CATALOG_STATUS_PARTIAL,
            f"catalog_status may only be {CATALOG_STATUS_PARTIAL!r} when present; a "
            "COMPLETE catalog OMITS the field (RECONCILIATION.md:682-684, and the "
            "frozen vector carries no such key)",
            "catalog_status_invalid",
            path="catalog_status",
            catalog_status=catalog_status,
        )

    _require(
        document["type"] == ESTATE_CATALOG_TYPE,
        f"type must be {ESTATE_CATALOG_TYPE!r}",
        "wrong_type",
        path="type",
        type=document["type"],
    )
    _require(
        type(document["version"]) is int and document["version"] == ESTATE_CATALOG_VERSION,
        f"version must be the integer {ESTATE_CATALOG_VERSION}",
        "wrong_version",
        path="version",
        version=document["version"],
    )
    catalog_kind = _require_str(document["catalog_kind"], "catalog_kind")
    _require(
        catalog_kind in SUPPORTED_CATALOG_KINDS,
        f"catalog_kind {catalog_kind!r} is not implemented; this build produces and "
        f"verifies only {sorted(SUPPORTED_CATALOG_KINDS)!r}. §4.3 rule 4's "
        "project_heads catalog has a different projects[] shape, no frozen vector and "
        "is explicitly not a release gate — it is refused rather than guessed at.",
        "catalog_kind_unsupported",
        path="catalog_kind",
        catalog_kind=catalog_kind,
    )

    projects_raw = document["projects"]
    _require(
        isinstance(projects_raw, list), "projects must be an array", "not_an_array", path="projects"
    )
    assert isinstance(projects_raw, list)
    _require(
        bool(projects_raw),
        "projects must be non-empty: a catalog covering no project asserts nothing, "
        "and a partial catalog is a failed ceremony (CUTOVER-CLASSIFICATION.md:588)",
        "projects_empty",
        path="projects",
    )
    projects = tuple(
        _parse_project(entry, f"projects[{index}]") for index, entry in enumerate(projects_raw)
    )
    instance_ids = [entry.project_instance_id for entry in projects]
    _require(
        len(set(instance_ids)) == len(instance_ids),
        "projects[] entries must have pairwise-distinct project_instance_id: two "
        "entries for one project would make the catalog's own claim ambiguous",
        "duplicate_project_instance_id",
        path="projects",
    )
    hints = [entry.project_name_hint for entry in projects]
    _require(
        len(set(hints)) == len(hints),
        "projects[] entries must have pairwise-distinct project_name_hint",
        "duplicate_project_name_hint",
        path="projects",
    )

    prev_commit = document["prev_commit"]
    if prev_commit is not None:
        _require_pattern(
            prev_commit, _GIT_COMMIT_RE, "prev_commit", "null or a full lowercase 40-hex git commit"
        )

    signatures: tuple[CatalogRootSignature, ...] = ()
    if "root_signatures" in document:
        signatures = _parse_root_signatures(document["root_signatures"], "root_signatures")
    if not for_signing:
        # §4.3 AMENDED rule 3: countersignatures and anchors become separate immutable
        # attestation records. Inline ones are refused rather than reported unverified,
        # matching the checkpoint's rule in `_genesis_open`.
        for section in ("countersignatures", "anchors"):
            _require(
                document[section] == [],
                f"{section} must be [] — later attestations are new immutable records "
                "under attestations/<subject-digest>/<ordinal>.json (§4.3 rule 3), not "
                "fields appended to a published catalog",
                "inline_attestations_unsupported",
                path=section,
            )
        _require(
            bool(signatures),
            "a published catalog must carry at least one root signature",
            "root_signatures_absent",
            path="root_signatures",
        )

    return EstateCatalog(
        trust_domain_id=_require_uuid(document["trust_domain_id"], "trust_domain_id"),
        trust_domain_core_digest=_require_pattern(
            document["trust_domain_core_digest"],
            _DIGEST_RE,
            "trust_domain_core_digest",
            "sha256:<64 lowercase hex characters>",
        ),
        root_governance=_parse_governance(document["root_governance"], "root_governance"),
        catalog_kind=catalog_kind,
        projects=projects,
        trust_log_checkpoint_digest=_require_pattern(
            document["trust_log_checkpoint_digest"],
            _DIGEST_RE,
            "trust_log_checkpoint_digest",
            "sha256:<64 lowercase hex characters>",
        ),
        prev_commit=prev_commit,
        created_at=_require_timestamp(document["created_at"], "created_at"),
        root_signatures=signatures,
        catalog_status=catalog_status,
    )


# ---------------------------------------------------------------------------
# Building (assembly only; the store reads live in the CLI)
# ---------------------------------------------------------------------------


def build_estate_catalog(
    *,
    trust_domain_id: str,
    trust_domain_core_digest: str,
    root_governance: Mapping[str, Any],
    projects: Sequence[CatalogProject],
    trust_log_checkpoint_digest: str,
    created_at: str,
    prev_commit: str | None = None,
    catalog_kind: str = CATALOG_KIND_CUTOVER,
    catalog_status: str | None = None,
) -> dict[str, Any]:
    """Assemble an unsigned catalog document and validate it before returning.

    ``projects`` is ordered by ``project_name_hint`` so two runs over the same estate
    produce the same bytes regardless of the order the operator listed them in. JCS
    does not sort arrays, so an unstable order would make an otherwise-identical
    re-run a different document with a different digest.

    ``catalog_status`` is ``None`` for a complete catalog — the key is then **omitted**,
    which is what keeps the frozen vector's bytes reproducible — and
    ``"partial"`` for a catalog that does not cover the whole expected estate.
    """
    document: dict[str, Any] = {
        "type": ESTATE_CATALOG_TYPE,
        "version": ESTATE_CATALOG_VERSION,
        "trust_domain_id": trust_domain_id,
        "trust_domain_core_digest": trust_domain_core_digest,
        "root_governance": {
            "mode": root_governance["mode"],
            "threshold": root_governance["threshold"],
            "signer_count": root_governance["signer_count"],
        },
        "catalog_kind": catalog_kind,
        "projects": [
            entry.as_document_member()
            for entry in sorted(projects, key=lambda item: item.project_name_hint)
        ],
        "trust_log_checkpoint_digest": trust_log_checkpoint_digest,
        "prev_commit": prev_commit,
        "created_at": created_at,
        "root_signatures": [],
        "countersignatures": [],
        "anchors": [],
    }
    if catalog_status is not None:
        document["catalog_status"] = catalog_status
    # Never hand back a document this module's own verifier would reject.
    parse_estate_catalog(document, for_signing=True)
    return document


def parse_estate_manifest(raw: Any) -> tuple[str, tuple[str, ...]]:
    """Parse the operator's expected-estate manifest. Returns (trust_domain_id, ids).

    ``TRUST-DOMAIN.md``:807 says a cutover catalog is "one document, all 26 project
    checkpoints". 26 is this estate's current project count, not a contract — so the
    expected set is supplied and bound to a trust domain, and nothing here hardcodes a
    number. Without it there is no fact against which "complete" could be checked, and
    a verifier that assumes completeness is exactly the dropped-project hole the
    catalog exists to close (``CUTOVER-CLASSIFICATION.md``:562-565).
    """
    outer = _require_keys(raw, _MANIFEST_KEYS, "<manifest>")
    _require(
        outer["type"] == ESTATE_MANIFEST_TYPE,
        f"the expected-estate manifest type must be {ESTATE_MANIFEST_TYPE!r}",
        "wrong_manifest_type",
        path="type",
        type=outer["type"],
    )
    _require(
        type(outer["version"]) is int and outer["version"] == ESTATE_MANIFEST_VERSION,
        f"the expected-estate manifest version must be the integer "
        f"{ESTATE_MANIFEST_VERSION}",
        "wrong_manifest_version",
        path="version",
    )
    trust_domain_id = _require_uuid(outer["trust_domain_id"], "trust_domain_id")
    ids_raw = outer["project_instance_ids"]
    _require(
        isinstance(ids_raw, list) and bool(ids_raw),
        "project_instance_ids must be a non-empty array: an empty expected estate "
        "would make every catalog vacuously complete",
        "manifest_projects_empty",
        path="project_instance_ids",
    )
    assert isinstance(ids_raw, list)
    ids = tuple(
        _require_uuid(value, f"project_instance_ids[{index}]")
        for index, value in enumerate(ids_raw)
    )
    _require(
        len(set(ids)) == len(ids),
        "project_instance_ids must be pairwise distinct",
        "duplicate_manifest_project_instance_id",
        path="project_instance_ids",
    )
    return trust_domain_id, ids


def sign_estate_catalog(
    document: Mapping[str, Any], *, seed: bytes, signer_id: str, fingerprint: str
) -> dict[str, Any]:
    """Append one detached root signature over ``estate_catalog_signature_input``.

    Returns a new document; the input is not mutated. Re-signing with a fingerprint the
    document already carries is refused — silently replacing it would turn a k-of-n
    ceremony into a 1-of-n one.
    """
    import base64

    import nacl.signing

    parsed = parse_estate_catalog(document, for_signing=True)
    if any(entry.fingerprint == fingerprint for entry in parsed.root_signatures):
        _unverified(
            f"the catalog already carries a root signature by {fingerprint}",
            "duplicate_root_signature",
            fingerprint=fingerprint,
        )
    signature = nacl.signing.SigningKey(seed).sign(estate_catalog_signature_input(document))
    signed = dict(document)
    signed["root_signatures"] = [
        *list(document.get("root_signatures") or []),
        {
            "signer_id": signer_id,
            "fingerprint": fingerprint,
            "signature": base64.b64encode(signature.signature).decode("ascii"),
        },
    ]
    signed.setdefault("countersignatures", [])
    signed.setdefault("anchors", [])
    return signed


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        import nacl.exceptions
        import nacl.signing
    except ImportError as exc:  # pragma: no cover - extras always present in CI
        raise RegistaError(
            ErrorCode.KEY_LOAD_ERROR,
            "estate-catalog verification requires PyNaCl: pip install regista[ed25519]",
        ) from exc
    try:
        nacl.signing.VerifyKey(public_key).verify(message, signature)
    except (nacl.exceptions.BadSignatureError, ValueError, TypeError):
        return False
    return True


def resolve_root_public_keys(
    genesis_document: Mapping[str, Any],
    additional_public_keys: Sequence[bytes] = (),
) -> dict[str, bytes]:
    """Fingerprint -> raw Ed25519 public key, from genesis plus operator-supplied keys.

    A checkpoint authorises *fingerprints*; checking a signature needs *bytes*. Genesis
    carries the initial roots' bytes, but a root rotated in after genesis appears in no
    document an offline verifier holds — so its public key has to be supplied. That is
    safe because a supplied key is only ever consulted through its fingerprint, and the
    fingerprint must appear in the SIGNED checkpoint's ``active_root_fingerprints``:
    the operator supplies bytes, never authority. §4.5 step 1 already requires the root
    fingerprints to be obtained by direct exchange; this is the same exchange.
    """
    from ._principal_keys import _compute_fingerprint
    from ._trust_domain import parse_trust_genesis

    genesis = parse_trust_genesis(genesis_document)
    keys: dict[str, bytes] = {
        signer.fingerprint: signer.public_key for signer in genesis.signers
    }
    for index, raw in enumerate(additional_public_keys):
        _require(
            isinstance(raw, bytes) and len(raw) == 32,
            f"additional root public key {index} must be 32 raw Ed25519 bytes",
            "root_public_key_malformed",
            index=index,
        )
        fingerprint = _compute_fingerprint(raw, "ed25519")
        existing = keys.get(fingerprint)
        if existing is not None and existing != raw:
            # Cannot happen for Ed25519 (the fingerprint IS sha256 of these bytes), but
            # asserting it means a future scheme change cannot silently replace a
            # genesis key with operator-supplied bytes under the same label.
            _unverified(
                f"additional root public key {index} collides with a different key "
                f"already known for fingerprint {fingerprint}",
                "root_public_key_collision",
                fingerprint=fingerprint,
            )
        keys[fingerprint] = raw
    return keys


def verify_published_checkpoint(
    checkpoint_bytes: bytes,
    *,
    genesis_document: Mapping[str, Any],
    additional_root_public_keys: Sequence[bytes] = (),
) -> VerifiedCheckpoint:
    """Authenticate a published §4.3 trust-log checkpoint OFFLINE, fail-closed.

    This is ``_genesis_open.load_published_checkpoint``'s model with the live trust log
    removed: same closed key set, same canonical-bytes rule, same signature input, same
    "signer must be in the current root set" and "threshold must be met" refusals — but
    the key material comes from :func:`resolve_root_public_keys` instead of a chain
    walk, because runbook §5.4 step 5 runs from an independent checkout with no
    database. The shape constants and the framing are IMPORTED from ``_genesis_open``
    rather than re-declared: a second copy of a signed document's key set is a second
    copy that can drift.

    What is deliberately NOT claimed: this proves the checkpoint is internally coherent
    and threshold-signed by keys its own ``active_root_fingerprints`` authorise. It does
    not prove the checkpoint describes the real trust log — that needs the log, and it
    is what ``genesis init`` does at ceremony time.
    """
    import base64
    import binascii
    import json as _json

    from ._genesis_open import (
        _CHECKPOINT_GOVERNANCE_KEYS,
        _CHECKPOINT_KEYS,
        _CHECKPOINT_LOG_KEYS,
        TRUST_CHECKPOINT_TYPE,
        _checkpoint_signature_input,
    )

    try:
        raw = _json.loads(checkpoint_bytes.decode("utf-8"))
    except (ValueError, UnicodeError) as exc:
        _schema(
            f"the presented trust-log checkpoint is not valid JSON: {exc}",
            "checkpoint_file_invalid_json",
        )
    _require_object(raw, "<checkpoint>")
    assert isinstance(raw, Mapping)
    _require_keys(raw, _CHECKPOINT_KEYS, "<checkpoint>")
    _require(
        raw["type"] == TRUST_CHECKPOINT_TYPE,
        f"the checkpoint type must be {TRUST_CHECKPOINT_TYPE!r}",
        "checkpoint_wrong_type",
        path="type",
        type=raw["type"],
    )
    _require(
        type(raw["version"]) is int and raw["version"] == 1,
        "the checkpoint version must be the integer 1",
        "checkpoint_wrong_version",
        path="version",
    )
    canonical = canonicalize(dict(raw))
    if checkpoint_bytes != canonical:
        _schema(
            "the published checkpoint file is not exact canonical JCS bytes",
            "checkpoint_not_canonical_publication_bytes",
            file_len=len(checkpoint_bytes),
            canonical_len=len(canonical),
        )

    checkpoint_seq = _require_int(raw["checkpoint_seq"], "checkpoint_seq", minimum=1)
    trust_domain_id = _require_uuid(raw["trust_domain_id"], "trust_domain_id")
    core_digest = _require_pattern(
        raw["trust_domain_core_digest"],
        _DIGEST_RE,
        "trust_domain_core_digest",
        "sha256:<64 lowercase hex characters>",
    )
    _require_timestamp(raw["created_at"], "created_at")
    if raw["prev_checkpoint_digest"] is not None:
        _require_pattern(
            raw["prev_checkpoint_digest"],
            _DIGEST_RE,
            "prev_checkpoint_digest",
            "null or sha256:<64 lowercase hex characters>",
        )
    if raw["prev_commit"] is not None:
        _require_pattern(
            raw["prev_commit"],
            _GIT_COMMIT_RE,
            "prev_commit",
            "null or a full lowercase 40-hex git commit",
        )
    for section in ("countersignatures", "anchors"):
        _require(
            raw[section] == [],
            f"checkpoint {section} must be [] — 0.6.0 verifies none of it and §4.3 "
            "rule 3 makes later attestations separate immutable records",
            "checkpoint_inline_attestations_unsupported",
            path=section,
        )

    log = _require_keys(raw["trust_log"], _CHECKPOINT_LOG_KEYS, "trust_log")
    _require_uuid(log["project_instance_id"], "trust_log.project_instance_id")
    log_event_count = _require_int(log["event_count"], "trust_log.event_count", minimum=1)
    _require_int(log["max_global_seq"], "trust_log.max_global_seq", minimum=1)
    _require_pattern(
        log["genesis_event_hash"],
        _DIGEST_RE,
        "trust_log.genesis_event_hash",
        "sha256:<64 lowercase hex characters>",
    )
    head = _require_pattern(
        log["head_event_hash"],
        _DIGEST_RE,
        "trust_log.head_event_hash",
        "sha256:<64 lowercase hex characters>",
    )

    governance = _parse_governance(raw["root_governance"], "root_governance")
    _require_keys(raw["root_governance"], _CHECKPOINT_GOVERNANCE_KEYS, "root_governance")
    actives_raw = raw["active_root_fingerprints"]
    _require(
        isinstance(actives_raw, list) and bool(actives_raw),
        "active_root_fingerprints must be a non-empty array",
        "checkpoint_active_roots_empty",
        path="active_root_fingerprints",
    )
    assert isinstance(actives_raw, list)
    actives = tuple(
        _require_pattern(
            value,
            _FINGERPRINT_RE,
            f"active_root_fingerprints[{index}]",
            "<scheme_id>:sha256:<64 lowercase hex>",
        )
        for index, value in enumerate(actives_raw)
    )
    _require(
        len(set(actives)) == len(actives),
        "active_root_fingerprints must be pairwise distinct",
        "checkpoint_duplicate_active_root",
        path="active_root_fingerprints",
    )
    _require(
        list(actives) == sorted(actives),
        "active_root_fingerprints must be sorted ascending, as the publisher writes "
        "them; an unsorted list is a hand-edited document",
        "checkpoint_active_roots_unsorted",
        path="active_root_fingerprints",
    )
    # The invented-governance hole (WI-330 review F2): a checkpoint could claim
    # signer_count 99 beside two fingerprints and nothing compared the two.
    _require(
        governance.signer_count == len(actives),
        f"root_governance.signer_count is {governance.signer_count} but "
        f"{len(actives)} active_root_fingerprints are listed; the checkpoint "
        "contradicts itself",
        "checkpoint_signer_count_contradicts_active_roots",
        signer_count=governance.signer_count,
        active_roots=len(actives),
    )

    # Identity BEFORE cryptography: a checkpoint describing another trust domain is not
    # evidence about this one whoever signed it, and saying so is more useful than
    # "no public key for that fingerprint" — which is what a cross-domain checkpoint
    # would otherwise produce, since the other domain's roots are not in this genesis.
    from ._trust_domain import parse_trust_genesis

    genesis = parse_trust_genesis(genesis_document)
    for field_name, stated, actual in (
        ("trust_domain_id", trust_domain_id, str(genesis.trust_domain_id)),
        ("trust_domain_core_digest", core_digest, genesis.trust_domain_core_digest),
    ):
        if stated != actual:
            _unverified(
                f"the checkpoint's {field_name} is {stated!r} but the pinned genesis "
                f"document's is {actual!r}",
                "checkpoint_trust_domain_mismatch",
                field=field_name,
                stated=stated,
                actual=actual,
            )
    _require(
        governance.threshold >= genesis.initial_governance.threshold,
        f"the checkpoint states threshold {governance.threshold} but the pinned "
        f"genesis threshold is {genesis.initial_governance.threshold}; the root "
        "threshold is monotone non-decreasing (WI-280)",
        "checkpoint_root_threshold_lowered",
        stated=governance.threshold,
        genesis_threshold=genesis.initial_governance.threshold,
    )

    public_keys = resolve_root_public_keys(genesis_document, additional_root_public_keys)
    message = _checkpoint_signature_input(raw)
    signatures = raw["root_signatures"]
    _require(
        isinstance(signatures, list) and bool(signatures),
        "the checkpoint carries no root_signatures; registrar checkpoint authority "
        "remains deferred (P2.4), so an unsigned checkpoint is not evidence",
        "checkpoint_root_signatures_absent",
        path="root_signatures",
    )
    assert isinstance(signatures, list)
    verified: list[str] = []
    for index, entry in enumerate(signatures):
        path = f"root_signatures[{index}]"
        item = _require_keys(entry, _ROOT_SIGNATURE_KEYS, path)
        _require_str(item["signer_id"], f"{path}.signer_id")
        fingerprint = _require_pattern(
            item["fingerprint"],
            _FINGERPRINT_RE,
            f"{path}.fingerprint",
            "<scheme_id>:sha256:<64 lowercase hex>",
        )
        _require(
            fingerprint not in verified,
            f"{path} repeats a fingerprint already counted; two entries by one signer "
            "cannot raise the distinct-signer count",
            "checkpoint_duplicate_root_signature",
            path=path,
        )
        try:
            signature = base64.b64decode(_require_str(item["signature"], f"{path}.signature"),
                                         validate=True)
        except (binascii.Error, ValueError):
            _schema(
                f"{path}.signature must be base64",
                "checkpoint_signature_malformed",
                path=path,
            )
        _require(
            len(signature) == _ED25519_SIGNATURE_LEN,
            f"{path}.signature must decode to {_ED25519_SIGNATURE_LEN} bytes",
            "checkpoint_signature_malformed",
            path=path,
        )
        if fingerprint not in actives:
            _unverified(
                f"{path}.fingerprint is not in the checkpoint's own "
                "active_root_fingerprints; a checkpoint signed by a key it does not "
                "itself declare active is not evidence about the root set",
                "checkpoint_root_signer_not_active",
                path=path,
                fingerprint=fingerprint,
            )
        key = public_keys.get(fingerprint)
        if key is None:
            _unverified(
                f"{path}.fingerprint has no public key in the presented material; "
                "supply it out of band (--root-public-key) rather than skipping the "
                "signature",
                "checkpoint_root_public_key_unavailable",
                path=path,
                fingerprint=fingerprint,
            )
        if not _verify_ed25519(key, message, signature):
            _unverified(
                f"{path} does not verify over the trust-checkpoint signature input",
                "checkpoint_root_signature_invalid",
                path=path,
                fingerprint=fingerprint,
            )
        verified.append(fingerprint)
    if len(verified) < governance.threshold:
        _unverified(
            f"{len(verified)} verified checkpoint root signature(s); the checkpoint's "
            f"threshold is {governance.threshold}",
            "checkpoint_root_threshold_not_met",
            verified=len(verified),
            threshold=governance.threshold,
        )

    return VerifiedCheckpoint(
        checkpoint_seq=checkpoint_seq,
        document_digest="sha256:" + hashlib.sha256(canonical).hexdigest(),
        trust_domain_id=trust_domain_id,
        trust_domain_core_digest=core_digest,
        governance=governance,
        active_root_fingerprints=actives,
        signatures_verified=len(verified),
        verified_fingerprints=tuple(verified),
        trust_log_head_event_hash=head,
        trust_log_event_count=log_event_count,
    )


def verify_estate_catalog(
    document: Mapping[str, Any],
    *,
    genesis_document: Mapping[str, Any],
    trust_log_checkpoint_bytes: bytes,
    expected_estate: Any,
    file_bytes: bytes | None = None,
    expect_digest: str | None = None,
    additional_root_public_keys: Sequence[bytes] = (),
) -> EstateCatalogVerification:
    """Verify a published estate catalog. Fail-closed: every refusal is named.

    Three pieces of evidence are REQUIRED, because runbook §5.4 step 5 asks for
    "signatures, catalog fields, and referenced heads" and none of them can be checked
    without all three:

    * ``genesis_document`` — the operator's pinned, out-of-band trust genesis. Fully
      threshold-verified first (an unverified genesis is not a source of anything), and
      the origin of the initial roots' public key bytes.
    * ``trust_log_checkpoint_bytes`` — the published checkpoint the catalog binds. It is
      parsed, canonical-form-checked and **signature-verified**
      (:func:`verify_published_checkpoint`), and it is what supplies the authorised
      signer set and the threshold. Comparing only its sha256 (as this function once
      did) accepted arbitrary bytes as "matched" and let an invented
      ``signer_count`` pass.
    * ``expected_estate`` — the ``regista.estate-manifest/v1`` document naming which
      projects a complete catalog must cover. Without it "complete" is unfalsifiable,
      and a dropped project is exactly the attack the catalog exists to expose.

    There is no degraded mode. A caller that cannot present all three gets a named
    refusal, not a qualified VALID.

    The returned verdict is ``"VALID"`` only for an authenticated AND complete catalog;
    an authenticated catalog that declares itself ``catalog_status: partial`` returns
    ``"PARTIAL"``, which ``RECONCILIATION.md``:682-684 defines as ceremony failure.
    """
    from ._trust_domain import parse_trust_genesis, verify_trust_genesis

    parsed = parse_estate_catalog(document)

    if file_bytes is not None:
        canonical = canonicalize(dict(document))
        if file_bytes != canonical:
            _schema(
                "the published catalog file is not exact canonical JCS bytes",
                "not_canonical_publication_bytes",
                file_len=len(file_bytes),
                canonical_len=len(canonical),
            )

    # The genesis must itself hold up before anything derived from it is treated as
    # authority. `verify_trust_genesis` raises on anything short of VALID — including a
    # signature count below the genesis threshold (`threshold_not_met`) — so the
    # refusal is delegated to it rather than re-implemented here.
    verify_trust_genesis(genesis_document)
    genesis = parse_trust_genesis(genesis_document)

    for field_name, stated, actual in (
        ("trust_domain_id", parsed.trust_domain_id, str(genesis.trust_domain_id)),
        (
            "trust_domain_core_digest",
            parsed.trust_domain_core_digest,
            genesis.trust_domain_core_digest,
        ),
    ):
        if stated != actual:
            _unverified(
                f"the catalog's {field_name} is {stated!r} but the pinned genesis "
                f"document's is {actual!r}; a catalog about another trust domain is not "
                "evidence about this one",
                "trust_domain_mismatch",
                field=field_name,
                stated=stated,
                actual=actual,
            )

    # The checkpoint, AUTHENTICATED. Everything about root authority below comes from
    # here rather than from the genesis signer list: genesis names the INITIAL roots,
    # and §5.4/WI-280 rotations change the set. Verifying against genesis alone let a
    # removed root keep signing and refused a rotated-in one (review F3).
    checkpoint = verify_published_checkpoint(
        trust_log_checkpoint_bytes,
        genesis_document=genesis_document,
        additional_root_public_keys=additional_root_public_keys,
    )
    if checkpoint.document_digest != parsed.trust_log_checkpoint_digest:
        _unverified(
            f"the presented trust-log checkpoint digests to "
            f"{checkpoint.document_digest} but the catalog binds "
            f"{parsed.trust_log_checkpoint_digest}",
            "trust_log_checkpoint_digest_mismatch",
            expected=parsed.trust_log_checkpoint_digest,
            actual=checkpoint.document_digest,
        )
    # The catalog RESTATES the checkpoint's governance; a restatement that disagrees is
    # invalid rather than mislabelled (the §3.4 rule, applied across the two artifacts).
    if parsed.root_governance != checkpoint.governance:
        _unverified(
            "the catalog's root_governance disagrees with the verified checkpoint's",
            "root_governance_contradicts_checkpoint",
            catalog={
                "mode": parsed.root_governance.mode,
                "threshold": parsed.root_governance.threshold,
                "signer_count": parsed.root_governance.signer_count,
            },
            checkpoint={
                "mode": checkpoint.governance.mode,
                "threshold": checkpoint.governance.threshold,
                "signer_count": checkpoint.governance.signer_count,
            },
        )

    public_keys = resolve_root_public_keys(genesis_document, additional_root_public_keys)
    message = estate_catalog_signature_input(document)
    verified: list[str] = []
    for index, entry in enumerate(parsed.root_signatures):
        path = f"root_signatures[{index}]"
        if entry.fingerprint not in checkpoint.active_root_fingerprints:
            _unverified(
                f"{path}.fingerprint is not in the verified checkpoint's "
                "active_root_fingerprints; a root removed by a rotation cannot sign a "
                "catalog, and its signature is refused rather than dropped",
                "root_signer_not_active",
                path=path,
                fingerprint=entry.fingerprint,
                active_root_fingerprints=list(checkpoint.active_root_fingerprints),
            )
        key = public_keys.get(entry.fingerprint)
        if key is None:
            _unverified(
                f"{path}.fingerprint is authorised by the checkpoint but no public key "
                "for it was presented, so the signature cannot be checked; supply it "
                "out of band (--root-public-key) rather than skipping the signature",
                "root_public_key_unavailable",
                path=path,
                fingerprint=entry.fingerprint,
            )
        signer = genesis.signer_by_fingerprint(entry.fingerprint)
        if signer is not None and signer.signer_id != entry.signer_id:
            _unverified(
                f"{path}.signer_id is {entry.signer_id!r} but the genesis names "
                f"{signer.signer_id!r} for that fingerprint",
                "root_signer_id_mismatch",
                path=path,
                stated=entry.signer_id,
                actual=signer.signer_id,
            )
        if not _verify_ed25519(key, message, entry.signature):
            _unverified(
                f"{path} does not verify over the estate-catalog signature input",
                "root_signature_invalid",
                path=path,
                fingerprint=entry.fingerprint,
            )
        verified.append(entry.fingerprint)

    threshold = checkpoint.governance.threshold
    if len(verified) < threshold:
        _unverified(
            f"{len(verified)} verified root signature(s); the verified checkpoint's "
            f"threshold is {threshold}",
            "root_threshold_not_met",
            verified=len(verified),
            threshold=threshold,
        )

    digest = estate_catalog_digest(document)
    digest_pin_status = "not_pinned"
    if expect_digest is not None:
        _require_pattern(
            expect_digest, _DIGEST_RE, "--expect-digest", "sha256:<64 lowercase hex characters>"
        )
        if expect_digest != digest:
            _unverified(
                f"the catalog's estate_catalog_digest is {digest} but the out-of-band "
                f"pin is {expect_digest}; a substituted catalog is exactly what pinning "
                "exists to expose",
                "estate_catalog_digest_mismatch",
                expected=expect_digest,
                actual=digest,
            )
        digest_pin_status = "matched"

    # Completeness (review F4). The manifest is REQUIRED: "complete" is a claim about
    # a set the catalog cannot describe on its own.
    manifest_domain, expected_ids = parse_estate_manifest(expected_estate)
    if manifest_domain != parsed.trust_domain_id:
        _unverified(
            f"the expected-estate manifest is for trust domain {manifest_domain!r} but "
            f"the catalog is for {parsed.trust_domain_id!r}",
            "expected_estate_trust_domain_mismatch",
            manifest=manifest_domain,
            catalog=parsed.trust_domain_id,
        )
    present_ids = {entry.project_instance_id for entry in parsed.projects}
    unexpected = sorted(present_ids - set(expected_ids))
    if unexpected:
        _unverified(
            "the catalog lists project_instance_id(s) that are not in the expected "
            "estate; that is not an incomplete ceremony, it is a catalog about a "
            "different estate",
            "catalog_project_not_in_expected_estate",
            unexpected=unexpected,
        )
    missing = tuple(sorted(set(expected_ids) - present_ids))
    if parsed.catalog_status is None and missing:
        # It claims completeness (no catalog_status) and is not complete. That is a
        # false claim inside signed bytes, so it is a refusal rather than a downgrade.
        _unverified(
            f"the catalog omits catalog_status — claiming a COMPLETE estate — but "
            f"{len(missing)} expected project(s) are absent from projects[]. "
            "RECONCILIATION.md:682-684 requires a partial catalog to say so.",
            "catalog_completeness_contradicted",
            missing_project_instance_ids=list(missing),
        )
    if parsed.catalog_status == CATALOG_STATUS_PARTIAL and not missing:
        _unverified(
            "the catalog declares catalog_status: partial but covers the whole expected "
            "estate; a false partial claim is as misleading as a false complete one",
            "catalog_partial_claim_contradicted",
        )

    verdict = "VALID" if parsed.catalog_status is None else "PARTIAL"
    return EstateCatalogVerification(
        verdict=verdict,
        trust_domain_id=parsed.trust_domain_id,
        trust_domain_core_digest=parsed.trust_domain_core_digest,
        catalog_kind=parsed.catalog_kind,
        estate_catalog_digest=digest,
        project_count=len(parsed.projects),
        root_governance=parsed.root_governance,
        signatures_verified=len(verified),
        verified_fingerprints=tuple(verified),
        extra_signatures=max(0, len(verified) - threshold),
        trust_log_checkpoint_digest=parsed.trust_log_checkpoint_digest,
        digest_pin_status=digest_pin_status,
        project_name_hints=tuple(entry.project_name_hint for entry in parsed.projects),
        catalog_status=parsed.catalog_status or "complete",
        completeness="complete" if not missing else "partial",
        missing_project_instance_ids=missing,
        checkpoint=checkpoint,
    )


# ---------------------------------------------------------------------------
# Operator inputs (the frozen legacy measurements §2.4 told them to record)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CatalogProjectInputs:
    """One project's operator-supplied half of a catalog entry."""

    project: str
    project_name_hint: str
    legacy_project: str | None
    legacy_head_event_hash: str | None
    legacy_event_count: int | None
    scheme_counts: Mapping[str, int] | None
    #: The approved preflight result for the NEW epoch
    #: (``ARCHITECTURE-0.6.0.md``:802-810). Mandatory: the tool must not be the only
    #: witness to the head and count it signs.
    expected_new_epoch_head_event_hash: str
    expected_new_epoch_event_count: int

    @property
    def has_recorded_legacy_facts(self) -> bool:
        return self.legacy_head_event_hash is not None


def parse_catalog_inputs(raw: Any) -> tuple[CatalogProjectInputs, ...]:
    """Parse the ``--projects`` measurements file. Closed key sets throughout.

    Why this file exists rather than store reads for everything: the runbook freezes
    the legacy schema and records its head hash, event count and scheme counts
    (§2.4) *before* anything is repointed, and those measurements are then kept
    outside the repository. They cannot be re-derived from the new store, and the
    frozen one may no longer be reachable from wherever the ceremony runs. Supplying
    ``legacy_project`` makes them re-measurable, and then they are cross-checked
    rather than trusted.
    """
    outer = _require_keys(raw, _INPUTS_KEYS, "<inputs>")
    _require(
        outer["type"] == CATALOG_INPUTS_TYPE,
        f"the inputs file type must be {CATALOG_INPUTS_TYPE!r}",
        "wrong_inputs_type",
        path="type",
        type=outer["type"],
    )
    _require(
        type(outer["version"]) is int and outer["version"] == CATALOG_INPUTS_VERSION,
        f"the inputs file version must be the integer {CATALOG_INPUTS_VERSION}",
        "wrong_inputs_version",
        path="version",
    )
    entries = outer["projects"]
    _require(
        isinstance(entries, list) and bool(entries),
        "the inputs file must carry a non-empty projects array",
        "inputs_projects_empty",
        path="projects",
    )
    assert isinstance(entries, list)

    out: list[CatalogProjectInputs] = []
    for index, entry in enumerate(entries):
        path = f"projects[{index}]"
        _require_object(entry, path)
        assert isinstance(entry, Mapping)
        unknown = sorted(set(entry) - _INPUTS_PROJECT_KEYS)
        _require(
            not unknown,
            f"{path} has unknown fields",
            "closed_key_set_violated",
            path=path,
            unknown=unknown,
        )
        _require(
            "project" in entry,
            f"{path}.project is required: it names the NEW v6 schema whose epoch this "
            "entry describes",
            "inputs_project_absent",
            path=path,
        )
        project = _require_pattern(
            entry["project"], _PROJECT_NAME_RE, f"{path}.project", "a backend-safe project name"
        )
        hint = (
            _require_pattern(
                entry["project_name_hint"],
                _PROJECT_NAME_RE,
                f"{path}.project_name_hint",
                "a backend-safe project name",
            )
            if entry.get("project_name_hint") is not None
            else project
        )
        legacy_project = (
            _require_pattern(
                entry["legacy_project"],
                _PROJECT_NAME_RE,
                f"{path}.legacy_project",
                "a backend-safe project name",
            )
            if entry.get("legacy_project") is not None
            else None
        )
        recorded = [key for key in _INPUTS_LEGACY_FACT_KEYS if entry.get(key) is not None]
        _require(
            legacy_project is not None or len(recorded) == len(_INPUTS_LEGACY_FACT_KEYS),
            f"{path} must supply either legacy_project (to MEASURE the frozen store) or "
            f"all of {list(_INPUTS_LEGACY_FACT_KEYS)} (the §2.4 recorded measurements). "
            "The legacy binding is the whole point of a cutover catalog and is never "
            "defaulted.",
            "inputs_legacy_facts_incomplete",
            path=path,
            present=recorded,
        )
        _require(
            len(recorded) in (0, len(_INPUTS_LEGACY_FACT_KEYS)),
            f"{path} supplies only part of the recorded legacy measurements "
            f"{list(_INPUTS_LEGACY_FACT_KEYS)}; a partial record cannot be "
            "cross-checked and is refused rather than half-used",
            "inputs_legacy_facts_partial",
            path=path,
            present=recorded,
        )
        legacy_head = (
            _require_pattern(
                entry["legacy_head_event_hash"],
                _DIGEST_RE,
                f"{path}.legacy_head_event_hash",
                "sha256:<64 lowercase hex characters>",
            )
            if recorded
            else None
        )
        legacy_count = (
            _require_int(entry["legacy_event_count"], f"{path}.legacy_event_count", minimum=1)
            if recorded
            else None
        )
        scheme_counts = (
            _require_scheme_counts(entry["scheme_counts"], f"{path}.scheme_counts")
            if recorded
            else None
        )
        _require(
            legacy_project != project,
            f"{path}.legacy_project is the same schema as {path}.project; the frozen "
            "legacy store and the clean v6 store are distinct schemas under EPOCH-RESET",
            "inputs_legacy_project_is_target",
            path=path,
        )
        # ARCHITECTURE-0.6.0.md:802-810 — "Confirm the head/count equal the approved
        # preflight result." Mandatory, and refused when absent rather than defaulted:
        # the point is that the command is not the only witness to the numbers it signs
        # (WI-330 review F1), so an operator who cannot state them has not run the
        # preflight the ceremony is gated on.
        preflight_missing = [key for key in _INPUTS_PREFLIGHT_KEYS if entry.get(key) is None]
        _require(
            not preflight_missing,
            f"{path} must supply {list(_INPUTS_PREFLIGHT_KEYS)} — the approved preflight "
            "head and count for the NEW epoch. They are cross-checked against the store "
            "and the catalog is not signed if they disagree.",
            "inputs_preflight_absent",
            path=path,
            missing=preflight_missing,
        )
        expected_head = _require_pattern(
            entry["expected_new_epoch_head_event_hash"],
            _DIGEST_RE,
            f"{path}.expected_new_epoch_head_event_hash",
            "sha256:<64 lowercase hex characters>",
        )
        expected_count = _require_int(
            entry["expected_new_epoch_event_count"],
            f"{path}.expected_new_epoch_event_count",
            minimum=1,
        )
        out.append(
            CatalogProjectInputs(
                project=project,
                project_name_hint=hint,
                legacy_project=legacy_project,
                legacy_head_event_hash=legacy_head,
                legacy_event_count=legacy_count,
                scheme_counts=scheme_counts,
                expected_new_epoch_head_event_hash=expected_head,
                expected_new_epoch_event_count=expected_count,
            )
        )

    projects = [entry.project for entry in out]
    _require(
        len(set(projects)) == len(projects),
        "the inputs file lists the same project twice",
        "duplicate_input_project",
        path="projects",
    )
    hints = [entry.project_name_hint for entry in out]
    _require(
        len(set(hints)) == len(hints),
        "the inputs file lists the same project_name_hint twice",
        "duplicate_input_project_name_hint",
        path="projects",
    )
    return tuple(out)


# ---------------------------------------------------------------------------
# Store measurement
# ---------------------------------------------------------------------------


#: Columns needed to recompute an event's chain-link contribution. Deliberately the
#: SIGNED bytes plus the signature and nothing else: every other column is derived, and
#: a derived column is exactly what a forger edits.
_CHAIN_EVIDENCE_COLUMNS: Final[str] = (
    "event_id, global_seq, transition, canonical_envelope, signature"
)


def _chain_head_hash_from_row(row: Mapping[str, Any], *, path: str) -> str:
    """``compute_chain_head_hash`` over one event row's signed bytes.

    Delegated, never re-implemented: ``_signing.compute_chain_head_hash`` is
    version-aware (v6 uses the domain-separated framing, v1-v5 the legacy
    concatenation) and its own docstring records two bugs caused by hand-copies.
    """
    from ._signing import compute_chain_head_hash

    envelope = row.get("canonical_envelope")
    signature = row.get("signature")
    if envelope is None or signature is None:
        _unverified(
            f"{path} has no canonical_envelope/signature, so its chain contribution "
            "cannot be recomputed and no head may be derived from it",
            "event_bytes_unavailable",
            path=path,
        )
    return "sha256:" + compute_chain_head_hash(bytes(envelope), bytes(signature)).hex()


def _require_chain_evidence(conn: Any, *, project: str, what: str) -> None:
    from ._genesis import _relation_exists

    for relation in ("events", "event_chain_head"):
        if not _relation_exists(conn, relation):
            _unverified(
                f"{what} {project!r} has no {relation} relation, so its head cannot be "
                "recomputed from event bytes",
                "store_not_measurable",
                project=project,
                relation=relation,
            )


def _head_row(conn: Any) -> Mapping[str, Any] | None:
    from psycopg.sql import SQL

    row: Mapping[str, Any] | None = conn.execute(
        SQL(
            f"SELECT {_CHAIN_EVIDENCE_COLUMNS} FROM events "
            "ORDER BY global_seq DESC LIMIT 1"
        )
    ).fetchone()
    return row


def _posture_head(conn: Any) -> tuple[str | None, Any]:
    from psycopg.sql import SQL

    row = conn.execute(
        SQL("SELECT head_hash, head_event_id FROM event_chain_head WHERE id = TRUE")
    ).fetchone()
    if row is None or row["head_hash"] is None:
        return None, None
    return "sha256:" + bytes(row["head_hash"]).hex(), row["head_event_id"]


@dataclass(frozen=True)
class LegacyMeasurement:
    head_event_hash: str
    event_count: int
    scheme_counts: Mapping[str, int]


def measure_frozen_legacy(conn: Any, *, project: str) -> LegacyMeasurement:
    """Measure a frozen legacy store, RECOMPUTING its head from event bytes.

    The head is not read from ``event_chain_head``. It is recomputed with
    :func:`~regista._signing.compute_chain_head_hash` over the max-``global_seq``
    event's signed bytes — which is exactly what the writer stored there
    (``_event_store.py``:1164 → ``_advance_global_chain_head``) — and the posture row is
    then treated as a *claim to be checked*, not as the measurement. A reviewer forged
    ``event_chain_head.head_hash`` with the events left intact and this function
    happily signed the forgery (WI-330 review F1); ``ARCHITECTURE-0.6.0.md``:802-810 is
    explicit that "the signed event, not the mutable posture row, tells future verifiers
    where strict v6 rules begin".

    Recomputation is O(1), not O(events): the stored global head IS the last event's own
    chain-link hash, so no walk is needed to reproduce it.

    ``event_count`` and ``scheme_counts`` are still aggregate reads over ``events`` —
    they have no signed counterpart to recompute against — but they are bound to each
    other by the ``sum(scheme_counts) == legacy_event_count`` rule the catalog parser
    enforces, and (when the operator recorded them) to the §2.4 record by the caller's
    cross-check.
    """
    from psycopg.sql import SQL

    from ._genesis import _count_rows

    _require_chain_evidence(conn, project=project, what="legacy schema")
    row = _head_row(conn)
    if row is None:
        _unverified(
            f"legacy schema {project!r} holds no events, so there is no frozen "
            "population for a cutover catalog to bind",
            "legacy_store_empty",
            project=project,
        )
    recomputed = _chain_head_hash_from_row(row, path="legacy max(global_seq) event")
    stated, stated_event_id = _posture_head(conn)
    if stated is None:
        _unverified(
            f"legacy schema {project!r} has events but no event_chain_head row; the "
            "store is internally inconsistent and is not measured",
            "legacy_head_row_absent",
            project=project,
        )
    if stated != recomputed:
        _unverified(
            f"legacy schema {project!r} claims head {stated} but recomputing the "
            f"max(global_seq) event's chain contribution from its signed bytes yields "
            f"{recomputed}; the posture row has been edited or the log has been "
            "truncated, and neither is signed over",
            "legacy_head_row_contradicts_events",
            project=project,
            stated=stated,
            recomputed=recomputed,
        )
    if stated_event_id is not None and str(stated_event_id) != str(row["event_id"]):
        _unverified(
            f"legacy schema {project!r} names head_event_id {stated_event_id} but the "
            f"max(global_seq) event is {row['event_id']}",
            "legacy_head_event_id_contradicts_events",
            project=project,
        )
    count = _count_rows(conn, "events")
    scheme_rows = conn.execute(
        SQL("SELECT scheme_id, COUNT(*) AS n FROM events GROUP BY scheme_id")
    ).fetchall()
    # A NULL scheme_id collapses to the literal bucket name "unset" rather than being
    # dropped. Dropping it would let rows vanish from scheme_counts while
    # legacy_event_count still counted them, and the parser's
    # sum(scheme_counts) == legacy_event_count rule would then FAIL — so the collapse is
    # what keeps that check honest instead of turning a NULL into a silent undercount.
    # "unset" cannot collide with a real scheme id: `_SCHEME_ID_RE` admits it, so a
    # store genuinely holding scheme_id='unset' rows would merge with the NULLs, which
    # is visible in the artifact rather than hidden (no such scheme exists in regista).
    counts = {(row["scheme_id"] or "unset"): int(row["n"]) for row in scheme_rows}
    return LegacyMeasurement(
        head_event_hash=recomputed,
        event_count=count,
        scheme_counts=counts,
    )


@dataclass(frozen=True)
class NewEpochMeasurement:
    """The new epoch as recomputed from its own signed events."""

    project_instance_id: str
    trust_domain_id: str
    cutover_event_hash: str
    new_epoch_head_event_hash: str
    event_count: int


def measure_new_epoch(conn: Any, *, project: str) -> NewEpochMeasurement:
    """Derive the opened v6 store's catalog facts from its SIGNED events.

    Judgment call 3: ``cutover_event_hash`` is the epoch-opening event's hash — under
    EPOCH-RESET the fresh schema's ``project_initialized`` IS the event that opened the
    epoch.

    Every value returned is recomputed from event bytes and then compared with the
    mutable posture rows, which are treated as claims:

    * the head is ``compute_chain_head_hash`` over the max-``global_seq`` event, checked
      against ``event_chain_head.head_hash`` **and** ``head_event_id``;
    * the cutover hash is the same construction over the min-``global_seq`` event,
      checked against ``project_identity.genesis_event_hash``;
    * ``project_instance_id`` and ``trust_domain_id`` come from inside the genesis
      event's signed envelope, checked against ``project_identity``'s columns.

    A reviewer forged ``event_chain_head`` and ``project_identity`` with the events left
    intact and the previous version of this function signed the forged values (WI-330
    review F1). Each disagreement is now a distinct named refusal, because the
    operator's next action differs: a contradicted head means the log was truncated or
    the row was edited; a contradicted identity means the schema is not the project it
    says it is.
    """
    from psycopg.sql import SQL

    from ._genesis import _count_rows
    from ._v6_writer import read_project_identity

    _require_chain_evidence(conn, project=project, what="project")
    identity = read_project_identity(conn)
    if identity is None:
        _unverified(
            f"project {project!r} has not opened a v6 epoch (no project_identity row); "
            "run `regista genesis init` before cataloguing it",
            "new_epoch_not_opened",
            project=project,
        )

    head_row = _head_row(conn)
    if head_row is None:
        _unverified(
            f"project {project!r} has a project_identity row but no events; the store "
            "is inconsistent and is not catalogued",
            "new_epoch_events_absent",
            project=project,
        )
    recomputed_head = _chain_head_hash_from_row(head_row, path="max(global_seq) event")
    stated_head, stated_head_event_id = _posture_head(conn)
    if stated_head is None:
        _unverified(
            f"project {project!r} has events but no event_chain_head row",
            "new_epoch_head_absent",
            project=project,
        )
    if stated_head != recomputed_head:
        _unverified(
            f"project {project!r} claims head {stated_head} but recomputing the "
            f"max(global_seq) event's chain contribution from its signed bytes yields "
            f"{recomputed_head}; the posture row is not evidence and the catalog is not "
            "signed over it",
            "new_epoch_head_row_contradicts_events",
            project=project,
            stated=stated_head,
            recomputed=recomputed_head,
        )
    if stated_head_event_id is not None and str(stated_head_event_id) != str(
        head_row["event_id"]
    ):
        _unverified(
            f"project {project!r} names head_event_id {stated_head_event_id} but the "
            f"max(global_seq) event is {head_row['event_id']}",
            "new_epoch_head_event_id_contradicts_events",
            project=project,
        )

    genesis_row = conn.execute(
        SQL(
            f"SELECT {_CHAIN_EVIDENCE_COLUMNS} FROM events "
            "ORDER BY global_seq ASC LIMIT 1"
        )
    ).fetchone()
    if genesis_row is None:  # pragma: no cover - _head_row already proved events exist
        _unverified(
            f"project {project!r} has no first event to derive its cutover hash from",
            "new_epoch_events_absent",
            project=project,
        )
    recomputed_cutover = _chain_head_hash_from_row(
        genesis_row, path="min(global_seq) event"
    )
    stated_cutover = "sha256:" + identity.genesis_event_hash.hex()
    if stated_cutover != recomputed_cutover:
        _unverified(
            f"project {project!r} claims genesis_event_hash {stated_cutover} but "
            f"recomputing the first event's hash from its signed bytes yields "
            f"{recomputed_cutover}",
            "genesis_event_hash_row_contradicts_events",
            project=project,
            stated=stated_cutover,
            recomputed=recomputed_cutover,
        )
    if str(genesis_row["event_id"]) != str(identity.genesis_event_id):
        _unverified(
            f"project {project!r} names genesis_event_id {identity.genesis_event_id} "
            f"but its first event is {genesis_row['event_id']}",
            "genesis_event_id_contradicts_events",
            project=project,
        )

    # Identity from INSIDE the signed genesis envelope, not from the projection row.
    from ._verification import V6EnvelopeError, parse_v6_envelope_strict

    try:
        envelope = parse_v6_envelope_strict(bytes(genesis_row["canonical_envelope"]))
    except (V6EnvelopeError, TypeError, ValueError) as exc:
        _unverified(
            f"project {project!r}'s first event is not a parseable v6 envelope, so its "
            f"identity cannot be derived from signed bytes: {exc}",
            "genesis_envelope_unparseable",
            project=project,
        )
    signed_instance_id = str(envelope.get("project_instance_id"))
    signed_domain_id = str(envelope.get("trust_domain_id"))
    for field_name, signed_value, row_value in (
        ("project_instance_id", signed_instance_id, str(identity.project_instance_id)),
        ("trust_domain_id", signed_domain_id, str(identity.trust_domain_id)),
    ):
        if signed_value != row_value:
            _unverified(
                f"project {project!r}'s project_identity.{field_name} is {row_value!r} "
                f"but its signed genesis envelope says {signed_value!r}",
                "project_identity_contradicts_genesis_envelope",
                project=project,
                field=field_name,
                row=row_value,
                signed=signed_value,
            )

    return NewEpochMeasurement(
        project_instance_id=_require_uuid(signed_instance_id, "genesis.project_instance_id"),
        trust_domain_id=_require_uuid(signed_domain_id, "genesis.trust_domain_id"),
        cutover_event_hash=recomputed_cutover,
        new_epoch_head_event_hash=recomputed_head,
        event_count=_count_rows(conn, "events"),
    )


__all__ = [
    "CATALOG_INPUTS_TYPE",
    "CATALOG_INPUTS_VERSION",
    "CATALOG_KEYS",
    "CATALOG_KIND_CUTOVER",
    "CATALOG_STATUS_PARTIAL",
    "CORE_KEYS",
    "ESTATE_CATALOG_DOMAIN",
    "ESTATE_CATALOG_TYPE",
    "ESTATE_CATALOG_VERSION",
    "ESTATE_MANIFEST_TYPE",
    "ESTATE_MANIFEST_VERSION",
    "OPTIONAL_CORE_KEYS",
    "SIGNATURE_SECTIONS",
    "SUPPORTED_CATALOG_KINDS",
    "CatalogGovernance",
    "CatalogProject",
    "CatalogProjectInputs",
    "CatalogRootSignature",
    "EstateCatalog",
    "EstateCatalogVerification",
    "LegacyMeasurement",
    "NewEpochMeasurement",
    "VerifiedCheckpoint",
    "build_estate_catalog",
    "estate_catalog_canonical_core",
    "estate_catalog_core",
    "estate_catalog_digest",
    "estate_catalog_signature_input",
    "measure_frozen_legacy",
    "measure_new_epoch",
    "parse_catalog_inputs",
    "parse_estate_catalog",
    "parse_estate_manifest",
    "resolve_root_public_keys",
    "sign_estate_catalog",
    "verify_estate_catalog",
    "verify_published_checkpoint",
]
