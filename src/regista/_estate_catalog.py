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

Everything else fails closed: unknown top-level keys are a rejection, a document whose
file bytes are not exact canonical JCS is a rejection, a signature by a key the
presented genesis never committed to is a rejection, and absent evidence (no genesis
document, no checkpoint to compare) is a named refusal rather than a skipped check.
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
CATALOG_KEYS: Final[frozenset[str]] = CORE_KEYS | SIGNATURE_SECTIONS

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
    }
)
_INPUTS_LEGACY_FACT_KEYS: Final[tuple[str, ...]] = (
    "legacy_head_event_hash",
    "legacy_event_count",
    "scheme_counts",
)

_DIGEST_RE: Final[re.Pattern[str]] = re.compile(r"sha256:[0-9a-f]{64}")
_FINGERPRINT_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9-]+:sha256:[0-9a-f]{64}")
_GIT_COMMIT_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-f]{40}")
_SCHEME_ID_RE: Final[re.Pattern[str]] = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_PROJECT_NAME_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,62}")
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
    try:
        datetime.strptime(text, _TIMESTAMP_STRPTIME)
    except ValueError:
        _schema(
            f"{path} must be a microsecond-precision UTC Z timestamp "
            "(YYYY-MM-DDTHH:MM:SS.ffffffZ)",
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


@dataclass(frozen=True)
class EstateCatalogVerification:
    """What a verifier established, and what it explicitly did not."""

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
    trust_log_checkpoint_status: str
    trust_log_checkpoint_digest: str
    digest_pin_status: str
    project_name_hints: tuple[str, ...]

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
            "trust_log_checkpoint_status": self.trust_log_checkpoint_status,
            "trust_log_checkpoint_digest": self.trust_log_checkpoint_digest,
            "digest_pin_status": self.digest_pin_status,
            "project_name_hints": list(self.project_name_hints),
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
    if for_signing:
        unknown = sorted(present - CATALOG_KEYS)
        missing = sorted(CORE_KEYS - present)
        if unknown or missing:
            _schema(
                "the catalog core has unknown or missing fields",
                "closed_key_set_violated",
                path="<document>",
                unknown=unknown,
                missing=missing,
            )
    else:
        _require_keys(document, CATALOG_KEYS, "<document>")

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
) -> dict[str, Any]:
    """Assemble an unsigned catalog document and validate it before returning.

    ``projects`` is ordered by ``project_name_hint`` so two runs over the same estate
    produce the same bytes regardless of the order the operator listed them in. JCS
    does not sort arrays, so an unstable order would make an otherwise-identical
    re-run a different document with a different digest.
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
    # Never hand back a document this module's own verifier would reject.
    parse_estate_catalog(document, for_signing=True)
    return document


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


def verify_estate_catalog(
    document: Mapping[str, Any],
    *,
    genesis_document: Mapping[str, Any],
    file_bytes: bytes | None = None,
    expect_digest: str | None = None,
    trust_log_checkpoint_bytes: bytes | None = None,
) -> EstateCatalogVerification:
    """Verify a published estate catalog. Fail-closed: every refusal is named.

    ``genesis_document`` is the operator's pinned, out-of-band trust genesis. It is
    fully threshold-verified first — an unverified genesis is not a source of root
    public keys — and then supplies the *only* keys a catalog signature may verify
    under. A signature by a fingerprint the genesis never committed to is a refusal,
    not a dropped signature: silently ignoring one turns a k-of-n check into 1-of-n.

    ``file_bytes``, when given, must equal the canonical JCS bytes of the document.
    ``TRUST-DOMAIN.md`` §4.4 requires publications to be canonical JCS; a file that
    merely *parses* to the right document can carry unsigned whitespace or key
    reordering that an auditor comparing files by digest would see as a difference.

    ``trust_log_checkpoint_bytes`` is the published checkpoint document's exact bytes.
    Absent, the checkpoint binding is reported ``not_presented`` — explicitly, never a
    silent skip.
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

    # The genesis must itself hold up before its signers are treated as authority: an
    # unverified genesis is not a source of root public keys. `verify_trust_genesis`
    # raises on anything short of VALID — including a signature count below the
    # genesis threshold (`threshold_not_met`) — so the refusal is delegated to it
    # rather than re-implemented here, which is how the two stay in agreement.
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

    # WI-280: the threshold is monotone non-decreasing across root rotations, so a
    # catalog may state a HIGHER threshold than genesis (the domain rotated) but never
    # a lower one. A catalog that lowers its own bar is refused whoever signed it.
    genesis_threshold = genesis.initial_governance.threshold
    if parsed.root_governance.threshold < genesis_threshold:
        _unverified(
            f"the catalog states threshold {parsed.root_governance.threshold} but the "
            f"pinned genesis threshold is {genesis_threshold}; the root threshold is "
            "monotone non-decreasing (WI-280) and a document may not lower its own bar",
            "root_threshold_lowered",
            stated=parsed.root_governance.threshold,
            genesis_threshold=genesis_threshold,
        )

    message = estate_catalog_signature_input(document)
    known = {signer.fingerprint: signer for signer in genesis.signers}
    verified: list[str] = []
    for index, entry in enumerate(parsed.root_signatures):
        path = f"root_signatures[{index}]"
        signer = known.get(entry.fingerprint)
        if signer is None:
            _unverified(
                f"{path}.fingerprint is not a signer the pinned genesis committed to; "
                "no public key was presented for it, so the signature cannot be checked "
                "and is refused rather than dropped",
                "root_signer_not_presented",
                path=path,
                fingerprint=entry.fingerprint,
            )
        if signer.signer_id != entry.signer_id:
            _unverified(
                f"{path}.signer_id is {entry.signer_id!r} but the genesis names "
                f"{signer.signer_id!r} for that fingerprint",
                "root_signer_id_mismatch",
                path=path,
                stated=entry.signer_id,
                actual=signer.signer_id,
            )
        if not _verify_ed25519(signer.public_key, message, entry.signature):
            _unverified(
                f"{path} does not verify over the estate-catalog signature input",
                "root_signature_invalid",
                path=path,
                fingerprint=entry.fingerprint,
            )
        verified.append(entry.fingerprint)

    threshold = parsed.root_governance.threshold
    if len(verified) < threshold:
        _unverified(
            f"{len(verified)} verified root signature(s); the catalog's stated threshold "
            f"is {threshold}",
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

    checkpoint_status = "not_presented"
    if trust_log_checkpoint_bytes is not None:
        observed = "sha256:" + hashlib.sha256(trust_log_checkpoint_bytes).hexdigest()
        if observed != parsed.trust_log_checkpoint_digest:
            _unverified(
                f"the presented trust-log checkpoint digests to {observed} but the "
                f"catalog binds {parsed.trust_log_checkpoint_digest}",
                "trust_log_checkpoint_digest_mismatch",
                expected=parsed.trust_log_checkpoint_digest,
                actual=observed,
            )
        checkpoint_status = "matched"

    return EstateCatalogVerification(
        verdict="VALID",
        trust_domain_id=parsed.trust_domain_id,
        trust_domain_core_digest=parsed.trust_domain_core_digest,
        catalog_kind=parsed.catalog_kind,
        estate_catalog_digest=digest,
        project_count=len(parsed.projects),
        root_governance=parsed.root_governance,
        signatures_verified=len(verified),
        verified_fingerprints=tuple(verified),
        extra_signatures=max(0, len(verified) - threshold),
        trust_log_checkpoint_status=checkpoint_status,
        trust_log_checkpoint_digest=parsed.trust_log_checkpoint_digest,
        digest_pin_status=digest_pin_status,
        project_name_hints=tuple(entry.project_name_hint for entry in parsed.projects),
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
        out.append(
            CatalogProjectInputs(
                project=project,
                project_name_hint=hint,
                legacy_project=legacy_project,
                legacy_head_event_hash=legacy_head,
                legacy_event_count=legacy_count,
                scheme_counts=scheme_counts,
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


@dataclass(frozen=True)
class LegacyMeasurement:
    head_event_hash: str
    event_count: int
    scheme_counts: Mapping[str, int]


def measure_frozen_legacy(conn: Any, *, project: str) -> LegacyMeasurement:
    """Measure a frozen legacy store's head, count and scheme counts, read-only.

    Refuses by name when the schema has no chain head to read, which is what an
    operator pointing ``legacy_project`` at the wrong schema actually sees. A legacy
    store predating the ``event_chain_head`` baseline cannot be measured here; omit
    ``legacy_project`` and supply the §2.4 recorded numbers instead.
    """
    from psycopg.sql import SQL

    from ._genesis import _count_rows, _relation_exists

    for relation in ("events", "event_chain_head"):
        if not _relation_exists(conn, relation):
            _unverified(
                f"legacy schema {project!r} has no {relation} relation, so its frozen "
                "head cannot be measured here; omit legacy_project and supply the §2.4 "
                "recorded legacy_head_event_hash/legacy_event_count/scheme_counts",
                "legacy_store_not_measurable",
                project=project,
                relation=relation,
            )
    head_row = conn.execute(
        SQL("SELECT head_hash FROM event_chain_head WHERE id = TRUE")
    ).fetchone()
    if head_row is None or head_row["head_hash"] is None:
        _unverified(
            f"legacy schema {project!r} has no chain head: it holds no events, so there "
            "is no frozen population for a cutover catalog to bind",
            "legacy_store_empty",
            project=project,
        )
    count = _count_rows(conn, "events")
    scheme_rows = conn.execute(
        SQL("SELECT scheme_id, COUNT(*) AS n FROM events GROUP BY scheme_id")
    ).fetchall()
    counts = {(row["scheme_id"] or "unset"): int(row["n"]) for row in scheme_rows}
    return LegacyMeasurement(
        head_event_hash="sha256:" + bytes(head_row["head_hash"]).hex(),
        event_count=count,
        scheme_counts=counts,
    )


@dataclass(frozen=True)
class NewEpochMeasurement:
    project_instance_id: str
    trust_domain_id: str
    cutover_event_hash: str
    new_epoch_head_event_hash: str


def measure_new_epoch(conn: Any, *, project: str) -> NewEpochMeasurement:
    """Measure the opened v6 store: identity, epoch-opening event, current head.

    Judgment call 3: ``cutover_event_hash`` is ``project_identity.genesis_event_hash``
    — under EPOCH-RESET the fresh schema's ``project_initialized`` IS the event that
    opened the epoch. Nothing here is operator-asserted.
    """
    from psycopg.sql import SQL

    from ._v6_writer import read_project_identity

    identity = read_project_identity(conn)
    if identity is None:
        _unverified(
            f"project {project!r} has not opened a v6 epoch (no project_identity row); "
            "run `regista genesis init` before cataloguing it",
            "new_epoch_not_opened",
            project=project,
        )
    head_row = conn.execute(
        SQL("SELECT head_hash FROM event_chain_head WHERE id = TRUE")
    ).fetchone()
    if head_row is None or head_row["head_hash"] is None:
        _unverified(
            f"project {project!r} has a project_identity row but no chain head; the "
            "store is inconsistent and is not catalogued",
            "new_epoch_head_absent",
            project=project,
        )
    return NewEpochMeasurement(
        project_instance_id=str(identity.project_instance_id),
        trust_domain_id=str(identity.trust_domain_id),
        cutover_event_hash="sha256:" + identity.genesis_event_hash.hex(),
        new_epoch_head_event_hash="sha256:" + bytes(head_row["head_hash"]).hex(),
    )


__all__ = [
    "CATALOG_INPUTS_TYPE",
    "CATALOG_INPUTS_VERSION",
    "CATALOG_KEYS",
    "CATALOG_KIND_CUTOVER",
    "CORE_KEYS",
    "ESTATE_CATALOG_DOMAIN",
    "ESTATE_CATALOG_TYPE",
    "ESTATE_CATALOG_VERSION",
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
    "build_estate_catalog",
    "estate_catalog_canonical_core",
    "estate_catalog_core",
    "estate_catalog_digest",
    "estate_catalog_signature_input",
    "measure_frozen_legacy",
    "measure_new_epoch",
    "parse_catalog_inputs",
    "parse_estate_catalog",
    "sign_estate_catalog",
    "verify_estate_catalog",
]
