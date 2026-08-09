"""Authenticated event semantics — the single verification primitive (WI-267).

The defect this module closes
-----------------------------
Signature verification used to authenticate the stored ``canonical_envelope``
bytes and return as soon as they verified. Every consumer then read the
**unsigned row columns**. An attacker with database write access could rewrite
``transition``, ``payload``, ``timestamp``, ``event_seq``, ``prev_event_hash``,
``on_behalf_of``, ``key_id``, ``entity_id`` or ``workflow_name``/``version`` in
the row and everything still reported "verified".

The design rule
---------------
    The stored canonical envelope is the cryptographic artifact; the row is its
    indexed projection. Verify the exact stored bytes, then require every field
    signed by that envelope version to agree with its row representation before
    any consumer uses the row.

Consequences that are load-bearing and must not be relaxed:

* **No fallback.** Once a stored envelope exists it is the *only* envelope. A
  parse, signature or reconciliation failure is ``INVALID``; no candidate is
  rebuilt from the row columns under attack.
* **The scheme comes from trusted key metadata, never from the row.** The row's
  ``scheme_id`` is outside every envelope version and is advisory only.
* **The verification key is resolved from the envelope's ``key_id``**, not the
  row's, so a row-only key_id rewrite surfaces as a reconciliation mismatch
  rather than as an ambiguous "unknown key".
* **``global_seq`` is unsigned by design** (``spec.md`` §17.11) — it is assigned
  after signing. It is validated structurally and may never appear in
  ``authenticated_fields``.
* **A signed-field mismatch can never be turned into a pass.** No policy field,
  environment variable or flag exists that does so; the invariant is asserted in
  ``VerificationResult.__post_init__``.

See ``FIELD-MATRIX.md`` / ``RESULT-MODEL.md`` / ``CUTOVER-POLICY.md`` (S1 design
inputs) for the normative field tables this module implements.
"""

from __future__ import annotations

import json
import uuid as _uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol
from uuid import UUID

from ._jcs import canonicalize

__all__ = [
    "Applicability",
    "Backend",
    "BundleKeyResolver",
    "EnvelopeVersion",
    "EventRow",
    "FailureReason",
    "FieldMismatch",
    "KeySetResolver",
    "StaticKeyResolver",
    "TrustedKey",
    "TrustedKeyResolver",
    "TrustedKeySource",
    "VerificationPolicy",
    "VerificationResult",
    "classify_envelope",
    "parse_envelope_strict",
    "verify_event_strict",
]


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


class EnvelopeVersion(StrEnum):
    V1 = "v1"
    V2 = "v2"  # also chain-less v3 — byte-identical, see FIELD-MATRIX §1
    V3 = "v3"
    V4 = "v4"
    V5 = "v5"
    ABSENT = "absent"  # canonical_envelope IS NULL (pre-002 rows)
    UNPARSEABLE = "unparseable"
    UNKNOWN_SCHEMA = "unknown_schema"
    KEYLESS_DUMMY = "keyless_dummy"  # InMemory zero-byte material


class Applicability(StrEnum):
    """The single field every caller is allowed to branch on."""

    FULLY_AUTHENTICATED = "fully_authenticated"
    LEGACY_PARTIAL = "legacy_partial"
    INVALID = "invalid"
    UNVERIFIABLE = "unverifiable"


class TrustedKeySource(StrEnum):
    PRINCIPAL_REGISTRY = "principal_registry"
    KEYSET_FILE = "keyset_file"
    SUPPLIED_PUBLIC_KEY = "supplied_public_key"
    BUNDLE_EMBEDDED = "bundle_embedded"
    NONE = "none"


class FailureReason(StrEnum):
    # envelope
    ENVELOPE_ABSENT = "envelope_absent"
    ENVELOPE_UNPARSEABLE = "envelope_unparseable"
    ENVELOPE_UNKNOWN_SCHEMA = "envelope_unknown_schema"
    ENVELOPE_SCHEMA_INCOMPLETE = "envelope_schema_incomplete"
    # signature
    SIGNATURE_INVALID = "signature_invalid"
    CANONICAL_HASH_MISMATCH = "canonical_hash_mismatch"
    SCHEME_UNRESOLVABLE = "scheme_unresolvable"
    SCHEME_MISMATCH = "scheme_mismatch"
    # key / principal
    KEY_UNRESOLVABLE = "key_unresolvable"
    KEY_REVOKED = "key_revoked"
    KEY_NOT_VALID_AT_TIME = "key_not_valid_at_time"
    KEY_ID_MISMATCH = "key_id_mismatch"
    UNREGISTERED_SIGNER = "unregistered_signer"
    PRINCIPAL_ACTOR_MISMATCH = "principal_actor_mismatch"
    # reconciliation
    ROW_FIELD_MISMATCH = "row_field_mismatch"
    ENTITY_ALIAS_MISMATCH = "entity_alias_mismatch"
    # chain
    CHAIN_LINK_MISMATCH = "chain_link_mismatch"
    CHAIN_LINK_ABSENT = "chain_link_absent"
    # legacy
    LEGACY_ENVELOPE_VERSION = "legacy_envelope_version"
    UNSIGNED_EVENT = "unsigned_event"


class Backend(StrEnum):
    """Where the row came from.

    Load-bearing for exactly one rule: the keyless-dummy exemption is a property
    of the **backend**, not of the byte pattern. A Postgres row exhibiting the
    InMemory dummy pattern is an attack (or a corrupted import), not an unsigned
    event, and stays ``INVALID``.
    """

    POSTGRES = "postgres"
    IN_MEMORY = "in_memory"
    BUNDLE = "bundle"


# ---------------------------------------------------------------------------
# Strict envelope schemas (RESULT-MODEL §3.1)
# ---------------------------------------------------------------------------

_V1_REQUIRED = frozenset(
    {"event_id", "work_item_id", "actor_id", "on_behalf_of", "transition", "payload"}
)
_V2_REQUIRED = _V1_REQUIRED | {
    "key_id",
    "event_seq",
    "workflow_name",
    "workflow_version",
    "timestamp",
}
_V3_REQUIRED = _V2_REQUIRED
_V4_REQUIRED = frozenset(
    {
        "event_id",
        "entity_kind",
        "entity_id",
        "actor_id",
        "key_id",
        "event_seq",
        "workflow_name",
        "workflow_version",
        "timestamp",
        "hash_alg",
        "on_behalf_of",
        "transition",
        "payload",
    }
)
_V5_REQUIRED = _V4_REQUIRED | {"actor_kind", "actor_metadata"}

#: Presence-significant: emitted only when the signer's argument was not None.
#: Absent and present-with-null are *different signed bytes*, so these are
#: reconciled by presence as well as value (FIELD-MATRIX §5).
_CHAIN_OPTIONAL = frozenset({"prev_event_hash", "global_seq", "prev_global_event_hash"})

_REQUIRED_FIELDS: dict[EnvelopeVersion, frozenset[str]] = {
    EnvelopeVersion.V1: _V1_REQUIRED,
    EnvelopeVersion.V2: _V2_REQUIRED,
    EnvelopeVersion.V3: _V3_REQUIRED,
    EnvelopeVersion.V4: _V4_REQUIRED,
    EnvelopeVersion.V5: _V5_REQUIRED,
}

_OPTIONAL_FIELDS: dict[EnvelopeVersion, frozenset[str]] = {
    EnvelopeVersion.V1: frozenset(),
    EnvelopeVersion.V2: frozenset(),
    EnvelopeVersion.V3: _CHAIN_OPTIONAL,
    EnvelopeVersion.V4: _CHAIN_OPTIONAL,
    EnvelopeVersion.V5: _CHAIN_OPTIONAL,
}

#: Real envelope versions, newest first — classification tries them in order.
_KNOWN_VERSIONS: tuple[EnvelopeVersion, ...] = (
    EnvelopeVersion.V5,
    EnvelopeVersion.V4,
    EnvelopeVersion.V3,
    EnvelopeVersion.V1,
)

#: Row columns no envelope version has ever signed. Always reported unsigned.
_NEVER_SIGNED = frozenset({"global_seq", "scheme_id"})
#: Every row column a consumer might read. Used to populate ``unsigned_fields``
#: on the outcomes where *nothing* was authenticated, so a consumer that checks
#: membership before trusting a field is correct in those cases too.
_ALL_ROW_FIELDS = frozenset(
    {
        "event_id",
        "work_item_id",
        "entity_kind",
        "entity_id",
        "actor_id",
        "actor_kind",
        "actor_metadata",
        "key_id",
        "event_seq",
        "workflow_name",
        "workflow_version",
        "timestamp",
        "hash_alg",
        "on_behalf_of",
        "transition",
        "payload",
        "prev_event_hash",
        "prev_global_event_hash",
        "global_seq",
        "scheme_id",
    }
)


def _reject_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number {value!r} in signing envelope")


def _reject_duplicate_keys(pairs: Sequence[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r} in signing envelope")
        seen[key] = value
    return seen


def parse_envelope_strict(envelope: bytes) -> dict[str, Any]:
    """Parse stored envelope bytes, refusing everything JCS could not have made.

    Raises ``ValueError`` on: invalid JSON, a non-object top level, duplicate
    keys, or NaN/Infinity. RFC 8785 can emit none of those, so any of them means
    the bytes were not produced by this system's canonicalizer.
    """
    obj = json.loads(
        envelope,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )
    if not isinstance(obj, dict):
        raise ValueError("signing envelope is not a JSON object")
    return obj


def classify_envelope(obj: Mapping[str, Any]) -> EnvelopeVersion:
    """Strictly classify a parsed envelope.

    Unlike the permissive classifier this replaces, nothing falls through to v1:
    a missing required field or an unrecognised key is ``UNKNOWN_SCHEMA``. The
    old ``issuperset`` classifier let *any subset* of v5's fields — including
    ``{}`` and an attacker-authored object — be treated as a v1 envelope, which
    is the weakest possible claim and therefore the most attractive target.
    """
    keys = frozenset(obj.keys())
    for version in _KNOWN_VERSIONS:
        required = _REQUIRED_FIELDS[version]
        optional = _OPTIONAL_FIELDS[version]
        if required <= keys and (keys - required) <= optional:
            if version is EnvelopeVersion.V3 and not (keys & _CHAIN_OPTIONAL):
                # v2 and chain-less v3 are byte-identical; the distinction is
                # not recoverable from the bytes and does not need to be.
                return EnvelopeVersion.V2
            return version
    return EnvelopeVersion.UNKNOWN_SCHEMA


def classify_envelope_bytes(envelope: bytes) -> EnvelopeVersion:
    try:
        obj = parse_envelope_strict(envelope)
    except (ValueError, TypeError):
        return EnvelopeVersion.UNPARSEABLE
    return classify_envelope(obj)


# ---------------------------------------------------------------------------
# The result model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FieldMismatch:
    """One envelope field that disagrees with its row column.

    ``envelope_repr``/``row_repr`` are deliberately short, redacted renderings —
    never a raw payload — so a mismatch can be triaged from a log line without
    leaking event content.
    """

    field: str
    envelope_repr: str
    row_repr: str
    presence_only: bool = False

    def __str__(self) -> str:
        kind = "presence" if self.presence_only else "value"
        return f"{self.field} ({kind}: envelope={self.envelope_repr} row={self.row_repr})"


@dataclass(frozen=True)
class VerificationPolicy:
    """Bounded, explicit, and non-silent. There is no 'lenient' mode.

    **There is no field here that can turn a signed-field mismatch into a
    success.** ``mismatched_fields != ()`` forces ``INVALID`` under every policy;
    that is a class invariant of :class:`VerificationResult`, not a convention.

    ``accept_legacy_before_global_seq`` is an *administrative* bound, not a
    cryptographic one: ``global_seq`` is unsigned by design, so an attacker with
    row-write access can move an event across the watermark. That is acceptable
    only because crossing it can never turn ``INVALID`` into a pass — it can only
    turn ``LEGACY_PARTIAL`` into ``INVALID`` or the reverse, and the reverse still
    requires the signature and every signed field to reconcile.
    """

    #: Envelope versions that may report FULLY_AUTHENTICATED. v5 is the floor:
    #: it is the only version that signs actor_kind/actor_metadata, which is
    #: what the review gate and assurance make decisions from.
    full_authentication_versions: frozenset[EnvelopeVersion] = frozenset(
        {EnvelopeVersion.V5}
    )
    #: Legacy versions that may report LEGACY_PARTIAL instead of INVALID.
    #: Expected to shrink, never grow.
    accept_legacy_versions: frozenset[EnvelopeVersion] = frozenset(
        {EnvelopeVersion.V4}
    )
    #: The cutover watermark. ``None`` means "not yet set for this project".
    accept_legacy_before_global_seq: int | None = None
    #: InMemory keyless events may be *processed*; they are never authenticated.
    accept_unsigned_keyless: bool = False


DEFAULT_POLICY = VerificationPolicy()


@dataclass(frozen=True)
class VerificationResult:
    """The one structured verdict, produced by :func:`verify_event_strict`.

    ``ok`` is the only boolean bridge and means ``fully_authenticated`` and
    nothing else. ``accepted`` additionally admits a legacy version the policy
    explicitly named (and, for the InMemory backend, an explicitly permitted
    unsigned keyless event) — every use of it is therefore a greppable statement
    that legacy is being accepted.
    """

    # --- identity -------------------------------------------------------
    event_id: UUID | None
    entity_kind: str
    entity_id: UUID | None
    global_seq: int | None  # structural only; never authenticated

    # --- envelope -------------------------------------------------------
    envelope_version: EnvelopeVersion
    envelope_present: bool
    envelope_schema_valid: bool

    # --- signature ------------------------------------------------------
    signature_valid: bool
    scheme_id: str | None  # DERIVED from key metadata, not the row
    row_scheme_id: str | None  # what the row claimed, for reporting only
    hash_alg: str | None  # taken from the ENVELOPE for v4/v5

    # --- trusted key ----------------------------------------------------
    trusted_key_source: TrustedKeySource
    trusted_key_id: str | None
    principal_id: str | None = None
    principal_binding_verified: bool = False

    # --- reconciliation -------------------------------------------------
    row_reconciled: bool = False
    mismatched_fields: tuple[FieldMismatch, ...] = ()
    authenticated_fields: frozenset[str] = frozenset()
    unsigned_fields: frozenset[str] = frozenset()

    # --- chain ----------------------------------------------------------
    prev_event_hash_ok: bool | None = None
    prev_global_event_hash_ok: bool | None = None

    # --- outcome --------------------------------------------------------
    applicability: Applicability = Applicability.UNVERIFIABLE
    accepted: bool = False
    reasons: tuple[FailureReason, ...] = ()
    legacy_reason: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        # Mechanism 1: legacy_partial is never reachable from a mismatch.
        # Legacy describes fields the version never signed; it can never
        # describe fields that were signed and disagree.
        if self.mismatched_fields and self.applicability is not Applicability.INVALID:
            raise AssertionError(
                "VerificationResult invariant violated: mismatched_fields is "
                f"non-empty but applicability is {self.applicability!r}; a "
                "signed-field mismatch is always INVALID"
            )
        # global_seq is assigned post-signing (spec.md §17.11). Claiming it is
        # authenticated would be a false claim about the 017 backfill.
        if "global_seq" in self.authenticated_fields:
            raise AssertionError(
                "VerificationResult invariant violated: global_seq is unsigned "
                "by design and must never appear in authenticated_fields"
            )
        if self.accepted and self.applicability is Applicability.INVALID:
            raise AssertionError(
                "VerificationResult invariant violated: INVALID is never accepted"
            )
        if self.applicability is Applicability.LEGACY_PARTIAL and not self.unsigned_fields:
            raise AssertionError(
                "VerificationResult invariant violated: LEGACY_PARTIAL must name "
                "the fields it left unauthenticated"
            )

    @property
    def ok(self) -> bool:
        """True iff nothing the consumer may read was left unauthenticated."""
        return self.applicability is Applicability.FULLY_AUTHENTICATED

    @property
    def mismatched_field_names(self) -> tuple[str, ...]:
        return tuple(m.field for m in self.mismatched_fields)

    def summary(self) -> str:
        parts = [f"applicability={self.applicability.value}"]
        parts.append(f"envelope={self.envelope_version.value}")
        if self.reasons:
            parts.append("reasons=" + ",".join(r.value for r in self.reasons))
        if self.mismatched_fields:
            parts.append("mismatched=" + ",".join(self.mismatched_field_names))
        if self.detail:
            parts.append(self.detail)
        return "; ".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id) if self.event_id else None,
            "entity_kind": self.entity_kind,
            "entity_id": str(self.entity_id) if self.entity_id else None,
            "global_seq": self.global_seq,
            "envelope_version": self.envelope_version.value,
            "envelope_present": self.envelope_present,
            "envelope_schema_valid": self.envelope_schema_valid,
            "signature_valid": self.signature_valid,
            "scheme_id": self.scheme_id,
            "row_scheme_id": self.row_scheme_id,
            "hash_alg": self.hash_alg,
            "trusted_key_source": self.trusted_key_source.value,
            "trusted_key_id": self.trusted_key_id,
            "principal_id": self.principal_id,
            "principal_binding_verified": self.principal_binding_verified,
            "row_reconciled": self.row_reconciled,
            "mismatched_fields": [
                {
                    "field": m.field,
                    "envelope": m.envelope_repr,
                    "row": m.row_repr,
                    "presence_only": m.presence_only,
                }
                for m in self.mismatched_fields
            ],
            "authenticated_fields": sorted(self.authenticated_fields),
            "unsigned_fields": sorted(self.unsigned_fields),
            "prev_event_hash_ok": self.prev_event_hash_ok,
            "prev_global_event_hash_ok": self.prev_global_event_hash_ok,
            "applicability": self.applicability.value,
            "accepted": self.accepted,
            "reasons": [r.value for r in self.reasons],
            "legacy_reason": self.legacy_reason,
            "detail": self.detail,
        }


# ---------------------------------------------------------------------------
# The row view
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EventRow:
    """A backend-neutral view of the ``events`` row under verification.

    Built from a Postgres row mapping, an :class:`~regista._types.Event`, or a
    bundle event dict, so Postgres and InMemory run *the same* reconciliation
    and cannot drift in what "verified" means.
    """

    event_id: UUID
    work_item_id: UUID | None
    entity_kind: str
    entity_id: UUID | None
    actor_id: str
    actor_kind: str | None
    actor_metadata: Any
    key_id: str | None
    event_seq: int | None
    workflow_name: str | None
    workflow_version: int | None
    timestamp: datetime | None
    hash_alg: str | None
    on_behalf_of: Any
    transition: str | None
    payload: Any
    prev_event_hash: bytes | None
    prev_global_event_hash: bytes | None
    global_seq: int | None
    canonical_envelope: bytes | None
    signature: bytes | None
    payload_canonical_hash: bytes | None
    row_scheme_id: str | None
    backend: Backend = Backend.POSTGRES

    @property
    def effective_entity_id(self) -> UUID | None:
        return self.entity_id if self.entity_id is not None else self.work_item_id

    @classmethod
    def from_event(cls, event: Any, *, backend: Backend = Backend.POSTGRES) -> EventRow:
        return cls(
            event_id=event.event_id,
            work_item_id=event.work_item_id,
            entity_kind=getattr(event, "entity_kind", "work_item") or "work_item",
            entity_id=getattr(event, "entity_id", None),
            actor_id=event.actor_id,
            actor_kind=getattr(event, "actor_kind", None),
            actor_metadata=getattr(event, "actor_metadata", None),
            key_id=event.key_id,
            event_seq=event.event_seq,
            workflow_name=event.workflow_name,
            workflow_version=event.workflow_version,
            timestamp=event.timestamp,
            hash_alg=getattr(event, "hash_alg", None) or "sha-256",
            on_behalf_of=getattr(event, "on_behalf_of", None),
            transition=event.transition,
            payload=event.payload,
            prev_event_hash=_as_bytes(getattr(event, "prev_event_hash", None)),
            prev_global_event_hash=_as_bytes(
                getattr(event, "prev_global_event_hash", None)
            ),
            global_seq=getattr(event, "global_seq", None),
            canonical_envelope=_as_bytes(getattr(event, "canonical_envelope", None)),
            signature=_as_bytes(event.signature),
            payload_canonical_hash=_as_bytes(event.payload_canonical_hash),
            row_scheme_id=getattr(event, "scheme_id", None),
            backend=backend,
        )

    @classmethod
    def from_mapping(
        cls, row: Mapping[str, Any], *, backend: Backend = Backend.POSTGRES
    ) -> EventRow:
        return cls(
            event_id=_as_uuid(row["event_id"]),  # type: ignore[arg-type]
            work_item_id=_as_uuid(row.get("work_item_id")),
            entity_kind=row.get("entity_kind") or "work_item",
            entity_id=_as_uuid(row.get("entity_id")),
            actor_id=row["actor_id"],
            actor_kind=row.get("actor_kind"),
            actor_metadata=row.get("actor_metadata"),
            key_id=row.get("key_id"),
            event_seq=row.get("event_seq"),
            workflow_name=row.get("workflow_name"),
            workflow_version=row.get("workflow_version"),
            timestamp=_as_datetime(row.get("timestamp")),
            hash_alg=row.get("hash_alg") or "sha-256",
            on_behalf_of=row.get("on_behalf_of"),
            transition=row.get("transition"),
            payload=row.get("payload"),
            prev_event_hash=_as_bytes(row.get("prev_event_hash")),
            prev_global_event_hash=_as_bytes(row.get("prev_global_event_hash")),
            global_seq=row.get("global_seq"),
            canonical_envelope=_as_bytes(row.get("canonical_envelope")),
            signature=_as_bytes(row.get("signature")),
            payload_canonical_hash=_as_bytes(row.get("payload_canonical_hash")),
            row_scheme_id=row.get("scheme_id"),
            backend=backend,
        )


def _as_bytes(value: Any) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return bytes.fromhex(value)
    return bytes(value)


def _as_uuid(value: Any) -> UUID | None:
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    return _uuid.UUID(str(value))


def _as_datetime(value: Any) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Trusted key resolution — the scheme comes from HERE, never from the row
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustedKey:
    key_id: str
    material: bytes
    #: The authoritative scheme for this key. ``None`` only when the caller
    #: supplied raw key material with no accompanying metadata, in which case
    #: the row's claim is all there is and the result says so.
    scheme_id: str | None
    source: TrustedKeySource
    principal_id: str | None = None
    #: An already-instantiated scheme, used in preference to a registry lookup
    #: so a caller holding a scheme object (including a test-registered one)
    #: does not depend on the mutable global registry.
    scheme_obj: Any = None

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"TrustedKey(key_id={self.key_id!r}, material=<redacted>, "
            f"scheme_id={self.scheme_id!r}, source={self.source.value!r})"
        )


class TrustedKeyResolver(Protocol):
    """Resolves the ``key_id`` **from the signed envelope** to trusted material."""

    def resolve(self, key_id: str | None) -> TrustedKey | None: ...


@dataclass(frozen=True)
class StaticKeyResolver:
    """A single caller-supplied key.

    ``scheme_id=None`` means the caller supplied bare material with no trusted
    metadata; the row's claim is then used and ``scheme_id`` is reported in
    ``unsigned_fields``. Callers that *can* name the scheme should.
    """

    material: bytes
    scheme_id: str | None = None
    key_id: str | None = None
    source: TrustedKeySource = TrustedKeySource.SUPPLIED_PUBLIC_KEY
    principal_id: str | None = None
    scheme_obj: Any = None

    def resolve(self, key_id: str | None) -> TrustedKey | None:
        if self.key_id is not None and key_id is not None and key_id != self.key_id:
            return None
        return TrustedKey(
            key_id=key_id or self.key_id or "",
            material=self.material,
            scheme_id=self.scheme_id,
            source=self.source,
            principal_id=self.principal_id,
            scheme_obj=self.scheme_obj,
        )


@dataclass(frozen=True)
class KeySetResolver:
    """Resolves against a local :class:`~regista._keys.KeySet`.

    ``KeyEntry.scheme`` is the trusted metadata the write path already uses to
    pick the scheme, so it is what the read path must use too.
    """

    key_set: Any
    source: TrustedKeySource = TrustedKeySource.KEYSET_FILE

    def resolve(self, key_id: str | None) -> TrustedKey | None:
        if key_id is None or self.key_set is None:
            return None
        try:
            entry = self.key_set.get_key(key_id)
        except Exception:
            return None
        if entry is None:
            return None
        return _trusted_key_from_entry(entry, key_id, self.source)


def _trusted_key_from_entry(
    entry: Any, key_id: str, source: TrustedKeySource
) -> TrustedKey:
    from ._signing_scheme import asymmetric_scheme_ids

    scheme = getattr(entry, "scheme", None)
    public_key = getattr(entry, "public_key", None)
    secret = getattr(entry, "secret", None)
    material = secret
    if scheme in asymmetric_scheme_ids() and public_key:
        material = public_key
    if material is None:
        material = public_key
    return TrustedKey(
        key_id=key_id,
        material=bytes(material) if material is not None else b"",
        scheme_id=scheme,
        source=source,
        principal_id=getattr(entry, "principal_id", None),
    )


@dataclass(frozen=True)
class BundleKeyResolver:
    """Resolves against the public-key registry carried inside a bundle.

    The registry is *inside the artifact under verification* — a circular trust
    root (S5). That is out of scope for WI-267 and is why the source is reported
    as ``BUNDLE_EMBEDDED`` rather than a trusted root: the verdict boundary work
    reads this field.
    """

    keys_by_id: Mapping[str, Mapping[str, Any]]

    def resolve(self, key_id: str | None) -> TrustedKey | None:
        if key_id is None:
            return None
        entry = self.keys_by_id.get(key_id)
        if entry is None:
            return None
        return TrustedKey(
            key_id=key_id,
            material=entry["public_key"],
            scheme_id=entry.get("scheme"),
            source=TrustedKeySource.BUNDLE_EMBEDDED,
            principal_id=entry.get("principal_id"),
        )


# ---------------------------------------------------------------------------
# Comparison rules (FIELD-MATRIX §6)
# ---------------------------------------------------------------------------

_MAX_REPR = 48


def _repr_of(value: Any) -> str:
    """Short, redactable rendering — never a raw payload."""
    if value is None:
        return "<null>"
    if isinstance(value, bytes):
        return f"<{len(value)} bytes {value[:6].hex()}…>"
    if isinstance(value, dict | list):
        try:
            import hashlib

            digest = hashlib.sha256(canonicalize(value)).hexdigest()[:12]
        except Exception:
            digest = "?"
        kind = "object" if isinstance(value, dict) else "array"
        return f"<{kind} len={len(value)} jcs:{digest}>"
    text = str(value)
    if len(text) > _MAX_REPR:
        return text[:_MAX_REPR] + "…"
    return text


class _Absent:
    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "<absent>"


ABSENT = _Absent()


def _cmp_uuid(env_value: Any, row_value: Any) -> bool:
    if row_value is None:
        return False
    try:
        return _uuid.UUID(str(env_value)) == _as_uuid(row_value)
    except (ValueError, TypeError, AttributeError):
        return False


def _cmp_text(env_value: Any, row_value: Any) -> bool:
    if env_value is None or row_value is None:
        return env_value is None and row_value is None
    if not isinstance(env_value, str) or not isinstance(row_value, str):
        return False
    return env_value == row_value


def _cmp_int(env_value: Any, row_value: Any) -> bool:
    # Reject bool (a Python int subclass) and any float, integral or not: the
    # signed bytes for 1, 1.0 and true all differ.
    if isinstance(env_value, bool) or not isinstance(env_value, int):
        return False
    if isinstance(row_value, bool) or not isinstance(row_value, int):
        return False
    return env_value == row_value


def _cmp_timestamp(env_value: Any, row_value: Any) -> bool:
    """Compare *instants*, not strings.

    The envelope stores a fixed ISO-8601 string; the row stores an instant that
    psycopg renders in the session time zone. The same row therefore yields
    different text under ``TZ=UTC`` and ``TZ=America/Phoenix``. That is a
    rendering artefact, not tamper. A naive/aware mix is refused rather than
    coerced.
    """
    if not isinstance(env_value, str) or not isinstance(row_value, datetime):
        return False
    try:
        parsed = datetime.fromisoformat(env_value)
    except (ValueError, TypeError):
        return False
    if (parsed.tzinfo is None) != (row_value.tzinfo is None):
        return False
    return parsed == row_value


def _cmp_hash_hex(env_value: Any, row_value: Any) -> bool:
    if not isinstance(env_value, str) or row_value is None:
        return False
    try:
        return bytes.fromhex(env_value) == _as_bytes(row_value)
    except (ValueError, TypeError):
        return False


def _cmp_json(env_value: Any, row_value: Any) -> bool:
    """Compare canonical JCS bytes.

    Not raw text (jsonb normalises key order and whitespace) and not Python
    ``==`` (which conflates ``1``/``1.0`` and ``True``/``1`` where the signed
    bytes differ).
    """
    try:
        return canonicalize(env_value) == canonicalize(row_value)
    except Exception:
        return False


# envelope field -> (row attribute, comparator)
_COMPARATORS: dict[str, Any] = {
    "event_id": ("event_id", _cmp_uuid),
    "work_item_id": ("work_item_id", _cmp_uuid),
    "entity_kind": ("entity_kind", _cmp_text),
    "entity_id": ("effective_entity_id", _cmp_uuid),
    "actor_id": ("actor_id", _cmp_text),
    "actor_kind": ("actor_kind", _cmp_text),
    "actor_metadata": ("actor_metadata", _cmp_json),
    "key_id": ("key_id", _cmp_text),
    "event_seq": ("event_seq", _cmp_int),
    "workflow_name": ("workflow_name", _cmp_text),
    "workflow_version": ("workflow_version", _cmp_int),
    "timestamp": ("timestamp", _cmp_timestamp),
    "hash_alg": ("hash_alg", _cmp_text),
    "on_behalf_of": ("on_behalf_of", _cmp_json),
    "transition": ("transition", _cmp_text),
    "payload": ("payload", _cmp_json),
    "prev_event_hash": ("prev_event_hash", _cmp_hash_hex),
    "prev_global_event_hash": ("prev_global_event_hash", _cmp_hash_hex),
    "global_seq": ("global_seq", _cmp_int),
}

#: Fields whose *nullability* is meaningful and which therefore compare
#: null-to-null cleanly rather than through the type comparator.
_NULLABLE_FIELDS = frozenset(
    {"actor_metadata", "on_behalf_of", "transition", "payload"}
)

#: Row columns that no version signs, plus per-version additions, form
#: ``unsigned_fields``. Keyed by envelope version.
_VERSION_UNSIGNED: dict[EnvelopeVersion, frozenset[str]] = {
    EnvelopeVersion.V1: frozenset(
        {
            "actor_kind",
            "actor_metadata",
            "entity_kind",
            "entity_id",
            "hash_alg",
            "key_id",
            "event_seq",
            "workflow_name",
            "workflow_version",
            "timestamp",
        }
    ),
    EnvelopeVersion.V2: frozenset(
        {"actor_kind", "actor_metadata", "entity_kind", "entity_id", "hash_alg"}
    ),
    EnvelopeVersion.V3: frozenset(
        {"actor_kind", "actor_metadata", "entity_kind", "entity_id", "hash_alg"}
    ),
    # work_item_id is not itself signed from v4 onward; it is nevertheless
    # *constrained* to equal the signed entity_id by the alias check below, so
    # it is safe to use as an entity identifier — it is listed here because it
    # carries no signature of its own.
    EnvelopeVersion.V4: frozenset({"actor_kind", "actor_metadata", "work_item_id"}),
    EnvelopeVersion.V5: frozenset({"work_item_id"}),
}


def _reconcile(
    envelope: Mapping[str, Any], version: EnvelopeVersion, row: EventRow
) -> tuple[list[FieldMismatch], set[str]]:
    """Total row↔envelope reconciliation for one envelope version.

    Every key the version *may* carry is checked, by presence for the
    presence-significant chain fields and by value for the always-emitted ones.
    """
    mismatches: list[FieldMismatch] = []
    authenticated: set[str] = set()

    checkable = _REQUIRED_FIELDS[version] | _OPTIONAL_FIELDS[version]
    for name in sorted(checkable):
        row_attr, comparator = _COMPARATORS[name]
        row_value = getattr(row, row_attr)
        present = name in envelope
        env_value = envelope.get(name, ABSENT)

        if name in _CHAIN_OPTIONAL:
            # Presence-significant: absent ⇔ row NULL. A row that gains a value
            # where the envelope omitted it is a mismatch, not a benign upgrade.
            if name == "global_seq":
                # UNSIGNED BY DESIGN (spec.md §17.11): assigned post-signing, so
                # absence reconciles against ANY row value. Never authenticated.
                if present and not comparator(env_value, row_value):
                    mismatches.append(
                        FieldMismatch(
                            field=name,
                            envelope_repr=_repr_of(env_value),
                            row_repr=_repr_of(row_value),
                        )
                    )
                continue
            if not present:
                if row_value is not None:
                    mismatches.append(
                        FieldMismatch(
                            field=name,
                            envelope_repr="<absent>",
                            row_repr=_repr_of(row_value),
                            presence_only=True,
                        )
                    )
                else:
                    authenticated.add(name)
                continue
            if row_value is None:
                mismatches.append(
                    FieldMismatch(
                        field=name,
                        envelope_repr=_repr_of(env_value),
                        row_repr="<null>",
                        presence_only=True,
                    )
                )
                continue
            if comparator(env_value, row_value):
                authenticated.add(name)
            else:
                mismatches.append(
                    FieldMismatch(
                        field=name,
                        envelope_repr=_repr_of(env_value),
                        row_repr=_repr_of(row_value),
                    )
                )
            continue

        # Always-emitted key: presence carries no information, the value does.
        if name in _NULLABLE_FIELDS and env_value is None and row_value is None:
            authenticated.add(name)
            continue
        if comparator(env_value, row_value):
            authenticated.add(name)
        else:
            mismatches.append(
                FieldMismatch(
                    field=name,
                    envelope_repr=_repr_of(env_value),
                    row_repr=_repr_of(row_value),
                )
            )

    # The alias check. work_item_id is the ORIGINAL 001 column; entity_id is
    # derived from it by the events_set_entity_id trigger (migration 031). From
    # v4 onward the signature covers entity_id and work_item_id is
    # unauthenticated, so without this check the unsigned column can steer a
    # consumer to a different work item than the one the signature covers.
    if version in (EnvelopeVersion.V4, EnvelopeVersion.V5):
        if (
            row.work_item_id is not None
            and row.entity_id is not None
            and row.work_item_id != row.entity_id
        ):
            mismatches.append(
                FieldMismatch(
                    field="work_item_id!=entity_id",
                    envelope_repr=_repr_of(row.entity_id),
                    row_repr=_repr_of(row.work_item_id),
                )
            )

    authenticated.discard("global_seq")
    return mismatches, authenticated


# ---------------------------------------------------------------------------
# The primitive
# ---------------------------------------------------------------------------

_KEYLESS_KEY_ID = "in-memory"
_KEYLESS_BYTES = b"\x00" * 32


def _is_keyless_dummy(row: EventRow) -> bool:
    """InMemory keyless material — an event that was never signed.

    All criteria must hold, and the last one is the point: a Postgres row
    exhibiting this byte pattern is an attack or a corrupted import, not an
    unsigned event, and must stay INVALID. The exemption is a property of the
    backend, not of the bytes.
    """
    return (
        row.backend is Backend.IN_MEMORY
        and row.key_id == _KEYLESS_KEY_ID
        and row.signature == _KEYLESS_BYTES
        and row.canonical_envelope == _KEYLESS_BYTES
        and row.payload_canonical_hash == _KEYLESS_BYTES
    )


def _base_kwargs(row: EventRow) -> dict[str, Any]:
    return {
        "event_id": row.event_id,
        "entity_kind": row.entity_kind,
        "entity_id": row.effective_entity_id,
        "global_seq": row.global_seq,
        "row_scheme_id": row.row_scheme_id,
    }


def verify_event_strict(
    row: EventRow,
    *,
    keys: TrustedKeyResolver,
    policy: VerificationPolicy = DEFAULT_POLICY,
) -> VerificationResult:
    """Verify the stored envelope bytes, then reconcile the row against them.

    This is the only function in the tree that decides whether an event is
    authenticated. Any path that reimplements part of it is a bug.
    """
    from ._signing_scheme import get_scheme, resolve_hash_function

    base = _base_kwargs(row)

    # (1) Never-signed row columns are reported unsigned in every outcome.
    unsigned: set[str] = set(_NEVER_SIGNED)

    # (2) An event that was never signed is UNVERIFIABLE, not INVALID. Detected
    #     before parsing: the dummy envelope is not JSON and would otherwise be
    #     reported as "tampered with", which it was not.
    if _is_keyless_dummy(row):
        return VerificationResult(
            **base,
            envelope_version=EnvelopeVersion.KEYLESS_DUMMY,
            envelope_present=False,
            envelope_schema_valid=False,
            signature_valid=False,
            scheme_id=None,
            hash_alg=None,
            trusted_key_source=TrustedKeySource.NONE,
            trusted_key_id=None,
            unsigned_fields=frozenset(unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.UNVERIFIABLE,
            accepted=policy.accept_unsigned_keyless,
            reasons=(FailureReason.UNSIGNED_EVENT,),
            detail="keyless InMemory event: never signed, nothing to verify",
        )

    # (3) No stored envelope at all (pre-002 rows). Nothing failed; there is
    #     nothing to check. UNVERIFIABLE, never INVALID — the operator response
    #     is completely different.
    if not row.canonical_envelope:
        return VerificationResult(
            **base,
            envelope_version=EnvelopeVersion.ABSENT,
            envelope_present=False,
            envelope_schema_valid=False,
            signature_valid=False,
            scheme_id=None,
            hash_alg=None,
            trusted_key_source=TrustedKeySource.NONE,
            trusted_key_id=None,
            unsigned_fields=frozenset(unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.UNVERIFIABLE,
            reasons=(FailureReason.ENVELOPE_ABSENT,),
            detail="no stored canonical_envelope; offline reconstruction is an "
            "explicit operator action, never a verify-path fallback",
        )

    stored = row.canonical_envelope

    # (4) Strict parse. No fallback to a rebuilt candidate from here on.
    try:
        envelope = parse_envelope_strict(stored)
    except (ValueError, TypeError) as exc:
        return VerificationResult(
            **base,
            envelope_version=EnvelopeVersion.UNPARSEABLE,
            envelope_present=True,
            envelope_schema_valid=False,
            signature_valid=False,
            scheme_id=None,
            hash_alg=None,
            trusted_key_source=TrustedKeySource.NONE,
            trusted_key_id=None,
            unsigned_fields=frozenset(unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.ENVELOPE_UNPARSEABLE,),
            detail=f"stored envelope is not canonical JSON: {exc}",
        )

    version = classify_envelope(envelope)
    if version is EnvelopeVersion.UNKNOWN_SCHEMA:
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=False,
            signature_valid=False,
            scheme_id=None,
            hash_alg=None,
            trusted_key_source=TrustedKeySource.NONE,
            trusted_key_id=None,
            unsigned_fields=frozenset(unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.ENVELOPE_UNKNOWN_SCHEMA,),
            detail=(
                "stored envelope matches no known schema strictly "
                f"(keys={sorted(envelope)[:12]}); the permissive classifier "
                "this replaced would have called it v1"
            ),
        )

    version_unsigned = unsigned | _VERSION_UNSIGNED[version]

    # (5) The verification key is resolved from the ENVELOPE's key_id, never the
    #     row's. A row-only key_id rewrite therefore surfaces as a
    #     reconciliation mismatch, not as an ambiguous "unknown key".
    envelope_key_id = envelope.get("key_id")
    if version is EnvelopeVersion.V1:
        # v1 signs no key_id at all: key selection for a v1 event is itself
        # unauthenticated, and the result must carry that.
        envelope_key_id = row.key_id
    lookup_key_id = envelope_key_id if isinstance(envelope_key_id, str) else None

    trusted = keys.resolve(lookup_key_id)
    if trusted is None:
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=None,
            hash_alg=None,
            trusted_key_source=TrustedKeySource.NONE,
            trusted_key_id=lookup_key_id,
            unsigned_fields=frozenset(version_unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.UNVERIFIABLE,
            reasons=(FailureReason.KEY_UNRESOLVABLE,),
            detail=f"no trusted key for key_id={lookup_key_id!r}",
        )

    # (6) S2-interim: the scheme comes from trusted key metadata. Where the
    #     registry names a scheme, it wins, and disagreement with the row's
    #     self-declared scheme_id is an error — relabelling an ed25519 event as
    #     hmac-sha256 must not exempt it from asymmetric verification.
    derived_scheme_id = trusted.scheme_id
    if derived_scheme_id is None:
        derived_scheme_id = row.row_scheme_id or "hmac-sha256"
    elif row.row_scheme_id is not None and row.row_scheme_id != derived_scheme_id:
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=derived_scheme_id,
            hash_alg=None,
            trusted_key_source=trusted.source,
            trusted_key_id=trusted.key_id,
            principal_id=trusted.principal_id,
            unsigned_fields=frozenset(version_unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.SCHEME_MISMATCH,),
            detail=(
                f"row claims scheme_id={row.row_scheme_id!r} but the trusted key "
                f"{trusted.key_id!r} is {derived_scheme_id!r}; the key's scheme wins"
            ),
        )

    try:
        scheme = trusted.scheme_obj or get_scheme(derived_scheme_id)
    except Exception as exc:
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=derived_scheme_id,
            hash_alg=None,
            trusted_key_source=trusted.source,
            trusted_key_id=trusted.key_id,
            principal_id=trusted.principal_id,
            unsigned_fields=frozenset(version_unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.SCHEME_UNRESOLVABLE,),
            detail=f"cannot resolve signing scheme {derived_scheme_id!r}: {exc}",
        )

    # (7) The hash algorithm comes from the ENVELOPE for v4/v5, so a row-only
    #     hash_alg rewrite is a reconciliation failure rather than an ambiguous
    #     signature failure. v1-v3 never signed it and are sha-256 by
    #     construction.
    if version in (EnvelopeVersion.V4, EnvelopeVersion.V5):
        env_hash_alg = envelope.get("hash_alg")
        effective_hash_alg = env_hash_alg if isinstance(env_hash_alg, str) else "sha-256"
    else:
        effective_hash_alg = "sha-256"

    signature = row.signature or b""
    canonical_hash = row.payload_canonical_hash or b""

    # (8) Defence in depth: the SigningScheme protocol does not *require* an
    #     implementation to check envelope_hash, so check it here rather than
    #     trusting every scheme to.
    try:
        hash_fn = resolve_hash_function(effective_hash_alg)
        computed = hash_fn(stored).digest()
    except Exception as exc:
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=derived_scheme_id,
            hash_alg=effective_hash_alg,
            trusted_key_source=trusted.source,
            trusted_key_id=trusted.key_id,
            principal_id=trusted.principal_id,
            unsigned_fields=frozenset(version_unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.CANONICAL_HASH_MISMATCH,),
            detail=f"cannot resolve hash algorithm {effective_hash_alg!r}: {exc}",
        )

    import hmac as _hmac

    if not _hmac.compare_digest(computed, canonical_hash):
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=derived_scheme_id,
            hash_alg=effective_hash_alg,
            trusted_key_source=trusted.source,
            trusted_key_id=trusted.key_id,
            principal_id=trusted.principal_id,
            unsigned_fields=frozenset(version_unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.CANONICAL_HASH_MISMATCH,),
            detail="payload_canonical_hash does not match the stored envelope",
        )

    try:
        signature_valid = bool(
            scheme.verify(
                stored,
                signature,
                canonical_hash,
                trusted.material,
                hash_alg=effective_hash_alg,
            )
        )
    except Exception:
        signature_valid = False

    if not signature_valid:
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=False,
            scheme_id=derived_scheme_id,
            hash_alg=effective_hash_alg,
            trusted_key_source=trusted.source,
            trusted_key_id=trusted.key_id,
            principal_id=trusted.principal_id,
            unsigned_fields=frozenset(version_unsigned | _ALL_ROW_FIELDS),
            applicability=Applicability.INVALID,
            reasons=(FailureReason.SIGNATURE_INVALID,),
            detail=(
                f"signature invalid over the stored envelope under trusted key "
                f"{trusted.key_id!r} ({derived_scheme_id})"
            ),
        )

    # (9) Total reconciliation. The signature proves what the signer committed
    #     to; a row that disagrees was written by something other than the
    #     append path.
    mismatches, authenticated = _reconcile(envelope, version, row)

    prev_ok: bool | None = None
    if "prev_event_hash" in authenticated or any(
        m.field == "prev_event_hash" for m in mismatches
    ):
        prev_ok = "prev_event_hash" in authenticated
    prev_global_ok: bool | None = None
    if "prev_global_event_hash" in authenticated or any(
        m.field == "prev_global_event_hash" for m in mismatches
    ):
        prev_global_ok = "prev_global_event_hash" in authenticated

    if mismatches:
        reasons: list[FailureReason] = [FailureReason.ROW_FIELD_MISMATCH]
        if any(m.field == "work_item_id!=entity_id" for m in mismatches):
            reasons.append(FailureReason.ENTITY_ALIAS_MISMATCH)
        if any(m.field == "key_id" for m in mismatches):
            reasons.append(FailureReason.KEY_ID_MISMATCH)
        return VerificationResult(
            **base,
            envelope_version=version,
            envelope_present=True,
            envelope_schema_valid=True,
            signature_valid=True,
            scheme_id=derived_scheme_id,
            hash_alg=effective_hash_alg,
            trusted_key_source=trusted.source,
            trusted_key_id=trusted.key_id,
            principal_id=trusted.principal_id,
            row_reconciled=False,
            mismatched_fields=tuple(mismatches),
            authenticated_fields=frozenset(authenticated),
            unsigned_fields=frozenset(version_unsigned),
            prev_event_hash_ok=prev_ok,
            prev_global_event_hash_ok=prev_global_ok,
            applicability=Applicability.INVALID,
            reasons=tuple(reasons),
            detail=(
                "row disagrees with the signed envelope on: "
                + ", ".join(str(m) for m in mismatches)
            ),
        )

    # (10) The signature is valid over the stored bytes and the row agrees on
    #      every field this version signs. What remains is a policy question
    #      about the version itself.
    common = {
        **base,
        "envelope_version": version,
        "envelope_present": True,
        "envelope_schema_valid": True,
        "signature_valid": True,
        "scheme_id": derived_scheme_id,
        "hash_alg": effective_hash_alg,
        "trusted_key_source": trusted.source,
        "trusted_key_id": trusted.key_id,
        "principal_id": trusted.principal_id,
        "row_reconciled": True,
        "authenticated_fields": frozenset(authenticated),
        "unsigned_fields": frozenset(version_unsigned),
        "prev_event_hash_ok": prev_ok,
        "prev_global_event_hash_ok": prev_global_ok,
    }

    if version in policy.full_authentication_versions:
        return VerificationResult(
            **common,
            applicability=Applicability.FULLY_AUTHENTICATED,
            accepted=True,
        )

    watermark = policy.accept_legacy_before_global_seq
    over_watermark = (
        watermark is not None
        and row.global_seq is not None
        and row.global_seq >= watermark
    )
    if version in policy.accept_legacy_versions and not over_watermark:
        return VerificationResult(
            **common,
            applicability=Applicability.LEGACY_PARTIAL,
            accepted=True,
            reasons=(FailureReason.LEGACY_ENVELOPE_VERSION,),
            legacy_reason=(
                f"envelope {version.value} does not sign "
                + ", ".join(sorted(version_unsigned))
                + "; those fields are unauthenticated for this event"
            ),
        )

    detail = (
        f"envelope {version.value} is not accepted by policy "
        f"(accept_legacy_versions={sorted(v.value for v in policy.accept_legacy_versions)})"
    )
    if over_watermark:
        detail = (
            f"envelope {version.value} at global_seq={row.global_seq} is at or "
            f"above the cutover watermark {watermark}: a legacy envelope written "
            "after the cutover is a regression, not history"
        )
    return VerificationResult(
        **common,
        applicability=Applicability.INVALID,
        reasons=(FailureReason.LEGACY_ENVELOPE_VERSION,),
        detail=detail,
    )

