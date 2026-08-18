"""Presented material for v6 referent resolution (``TRUST-DOMAIN.md`` §5.10, §8.4).

Why this module exists
----------------------
``_verification._verify_v6_row`` used to be handed three things: the row, the parsed
envelope, and a ``TrustedKeyResolver``. None of them can see **another event**. But
``TRUST-DOMAIN.md`` §5.10 steps 1-4 are *chain traversal*:

    3. ``A`` must precede ``E`` **by chain traversal**: ``A`` is reachable from ``E``
       by following ``chain.previous_project_event_hash``. Not by ``occurred_at`` …
       and not by ``global_seq``.

So the verifier needs a fourth input: the material it was **presented**. That is
what a :class:`ReferentResolver` is. It is deliberately *not* a store handle, a
query interface, or anything that could fetch:

    §8.4 — "The verifier performs **no network I/O**. … A verifier that silently
    fetches its own trust material has no trust root at all; it has whatever the
    network gave it."

Three properties make the abstraction sound rather than merely convenient:

1. **Addressing is by v6 event hash**, and the v6 event hash covers the canonical
   envelope bytes *and* the signature (``compute_v6_event_hash``). So a referent
   that resolves is a referent whose bytes are exactly the bytes the referring
   event committed to. Tampering with a presented anchor does not produce a
   *different* anchor — it produces **no** anchor, which §5.11 already has a verdict
   for. The resolver therefore never needs to re-verify a signature to be sound
   about *content*; establishing each presented event's own *authority* is the
   caller's separate, per-event obligation (replay and bundle verification both
   verify every event they present).
2. **The material carries its own completeness claim** (:class:`MaterialCompleteness`).
   §5.11's first two rows differ only in that claim: an unresolvable anchor is
   ``UNVERIFIABLE`` from a partial export and ``INVALID`` from material that claims
   completeness, "because the completeness claim is false. That is a fact about the
   artifact, not an absence." A store connection claims completeness — the strict
   reading, per the P1.7 notes' flag #4.
3. **The projection is never a source.** Nothing here reads ``principal_keys``.
   §5.9 rule 1 and §5.11's last row make that the S6 defect, and the point of
   routing every referent through one narrow protocol is that the absence is
   structural rather than a convention someone can forget.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final, Protocol, runtime_checkable

from ._errors import ErrorCode, RegistaError

__all__ = [
    "NO_REFERENTS",
    "BundleReferents",
    "MappingReferents",
    "MaterialCompleteness",
    "NoReferents",
    "ReferentEvent",
    "ReferentResolver",
    "StoreReferents",
    "referent_from_bytes",
    "store_referents",
]


class MaterialCompleteness(StrEnum):
    """What the presented material *claims* about its own coverage (§5.11).

    The three values are not a strictness dial with a middle setting; they are three
    different statements, and only the first licenses ``INVALID`` for an absent
    referent:

    ``COMPLETE_STORE``
        "Every event of this project's chain is here." A live store connection, or a
        ``complete-store`` bundle. An absent referent contradicts the claim.
    ``CONTIGUOUS_RANGE``
        "Every event between these two chain positions is here, and nothing else."
        A windowed export, a scoped replay. An absent referent is outside scope and
        must be *named* as such (§9 criterion 15).
    ``UNDECLARED``
        No claim at all — a single row handed to a field-wise helper. Absence proves
        nothing whatsoever.
    """

    COMPLETE_STORE = "complete_store"
    CONTIGUOUS_RANGE = "contiguous_range"
    UNDECLARED = "undeclared"


#: Ordering used only to reject a *loosening* completeness override. A policy may
#: tighten what the material claimed (an operator who knows the export is complete);
#: it may never soften a store's claim into "partial", because that would turn
#: §5.11's ``INVALID`` row into its ``UNVERIFIABLE`` row with a flag — the shape the
#: no-fallback discipline exists to remove.
_COMPLETENESS_STRICTNESS: Final[dict[MaterialCompleteness, int]] = {
    MaterialCompleteness.UNDECLARED: 0,
    MaterialCompleteness.CONTIGUOUS_RANGE: 1,
    MaterialCompleteness.COMPLETE_STORE: 2,
}


def resolve_completeness(
    material: MaterialCompleteness, override: MaterialCompleteness | None
) -> MaterialCompleteness:
    """Combine the material's own claim with an explicit policy claim, tighten-only.

    ``None`` means "the material's own claim governs", which is the default and the
    only form that cannot be used to weaken a verdict.
    """

    if override is None:
        return material
    if _COMPLETENESS_STRICTNESS[override] < _COMPLETENESS_STRICTNESS[material]:
        raise RegistaError(
            ErrorCode.INVALID_ARGUMENT,
            f"VerificationPolicy.material_completeness={override.value!r} would "
            f"loosen the presented material's own claim ({material.value!r}). A "
            "completeness claim may be tightened by a caller who knows more, never "
            "softened: softening turns TRUST-DOMAIN.md §5.11's INVALID row into its "
            "UNVERIFIABLE row, which is a fallback with extra steps.",
            detail={"material": material.value, "override": override.value},
        )
    return override


@dataclass(frozen=True)
class ReferentEvent:
    """One event of the presented material, addressed by its v6 event hash.

    ``envelope`` is the **strict-parsed** v6 envelope, so every accessor below reads
    signed structure rather than a row column. ``event_hash`` is the domain-tagged v6
    hash over ``canonical_envelope || signature``, which is what every referring
    field (``signing.key_binding_event_hash``, ``chain.previous_project_event_hash``,
    ``workflow.registration_event_hash``) names.
    """

    event_hash: str
    envelope: Mapping[str, Any]

    @property
    def transition(self) -> str:
        return str(self.envelope["transition"])

    @property
    def project_instance_id(self) -> str:
        return str(self.envelope["project_instance_id"])

    @property
    def trust_domain_id(self) -> str:
        return str(self.envelope["trust_domain_id"])

    @property
    def actor_principal_id(self) -> str:
        return str(self.envelope["actor"]["principal_id"])

    @property
    def signing_key_id(self) -> str:
        return str(self.envelope["signing"]["key_id"])

    @property
    def previous_project_event_hash(self) -> str | None:
        value = self.envelope["chain"]["previous_project_event_hash"]
        return None if value is None else str(value)

    @property
    def payload(self) -> Mapping[str, Any]:
        payload = self.envelope["payload"]
        return payload if isinstance(payload, Mapping) else {}


def referent_from_bytes(
    canonical_envelope: bytes | memoryview | None,
    signature: bytes | memoryview | None,
) -> ReferentEvent | None:
    """Build a referent from stored bytes, or ``None`` if they are not v6 material.

    Returning ``None`` rather than raising is deliberate: presented material may
    legitimately contain v1-v5 rows, rows whose envelope column is NULL, and — in an
    adversarial artifact — rows that are not envelopes at all. None of those *is* a
    v6 referent, so none of them can satisfy a v6 referent field; the caller's
    verdict for "referent not found" already covers them, and raising here would
    convert an absent anchor into an exception at an unrelated call site.
    """

    if not canonical_envelope or not signature:
        return None
    from ._signing import compute_v6_event_hash
    from ._verification import V6EnvelopeError, parse_v6_envelope_strict

    envelope_bytes = bytes(canonical_envelope)
    signature_bytes = bytes(signature)
    try:
        envelope = parse_v6_envelope_strict(envelope_bytes)
    except (V6EnvelopeError, TypeError, ValueError):
        return None
    digest = compute_v6_event_hash(envelope_bytes, signature_bytes)
    return ReferentEvent(event_hash="sha256:" + digest.hex(), envelope=envelope)


@runtime_checkable
class ReferentResolver(Protocol):
    """The presented material, as the verifier is allowed to see it.

    Two members, no query surface. ``resolve_referent`` is a *lookup in what the
    caller already handed over*; there is deliberately no ``fetch``, no ``search``
    and no connection on this protocol, because §8.4's table is a list of things the
    verifier is **given**.
    """

    @property
    def completeness(self) -> MaterialCompleteness:
        """What this material claims about its own coverage (§5.11)."""

    def resolve_referent(self, event_hash: str) -> ReferentEvent | None:
        """The presented event whose v6 hash is ``event_hash``, or ``None``."""

    def describe(self) -> str:
        """A short label for the verdict detail, so a report names its own scope."""


@dataclass(frozen=True)
class NoReferents:
    """Material that presents nothing and claims nothing.

    Used by the field-wise helpers, which are handed one row and no chain at all.
    Its verdict for any v6 event is §5.11 row 1 — ``UNVERIFIABLE`` /
    ``KEY_BINDING_UNRESOLVED``, "absence of evidence" — and that is the honest answer
    for a caller who presented one event: the signature may well be fine, and this
    material cannot say whether the key was ever accepted.

    It is a named, greppable type rather than ``None``, so "no material was
    presented" appears in the call site instead of being the shape of a missing
    argument.
    """

    @property
    def completeness(self) -> MaterialCompleteness:
        return MaterialCompleteness.UNDECLARED

    def resolve_referent(self, event_hash: str) -> ReferentEvent | None:
        return None

    def describe(self) -> str:
        return "no presented material (single row)"


NO_REFERENTS: Final[NoReferents] = NoReferents()


@dataclass(frozen=True)
class MappingReferents:
    """Material presented as an explicit hash → event mapping.

    The general form: a bundle section, a replay window, a hand-built test corpus.
    Callers that hold ``(canonical_envelope, signature)`` pairs should use
    :meth:`from_pairs`, which computes the addressing hash rather than trusting a
    caller-supplied one — a mapping keyed by a *claimed* hash would let presented
    material answer to a name its bytes do not have.
    """

    events: Mapping[str, ReferentEvent]
    material_completeness: MaterialCompleteness = MaterialCompleteness.UNDECLARED
    label: str = "presented event mapping"

    @property
    def completeness(self) -> MaterialCompleteness:
        return self.material_completeness

    def resolve_referent(self, event_hash: str) -> ReferentEvent | None:
        return self.events.get(event_hash)

    def describe(self) -> str:
        return f"{self.label} ({len(self.events)} v6 events, {self.completeness.value})"

    @classmethod
    def from_pairs(
        cls,
        pairs: Iterable[tuple[bytes | memoryview | None, bytes | memoryview | None]],
        *,
        completeness: MaterialCompleteness = MaterialCompleteness.UNDECLARED,
        label: str = "presented event mapping",
    ) -> MappingReferents:
        events: dict[str, ReferentEvent] = {}
        for envelope, signature in pairs:
            referent = referent_from_bytes(envelope, signature)
            if referent is not None:
                events[referent.event_hash] = referent
        return cls(events=events, material_completeness=completeness, label=label)


@dataclass
class StoreReferents:
    """Material presented as an **open project store**, indexed lazily.

    Completeness is ``COMPLETE_STORE``: §5.11 names "an online store" beside
    ``complete-store`` as material that claims completeness, so an anchor this store
    does not contain is a contradicted claim rather than a gap. That is the stricter
    of the two readings and is the P1.7 notes' flag #4 decision.

    **Cost, stated rather than hidden.** ``events`` has no ``event_hash`` column, so
    the index is built by one ordered pass that recomputes each v6 hash. The pass is
    lazy — a store whose events are all v1-v5 never pays for it, because no v6 row
    reaches referent resolution — and cached for the resolver's lifetime, so a replay
    over N events pays once rather than N times. A per-row helper that constructs a
    fresh resolver each call therefore pays once *per call*; that is acceptable for
    single-event verification and is the reason replay builds one resolver and reuses
    it. An ``event_hash`` generated column would remove the pass entirely and is
    filed rather than smuggled in here: it is a migration, and this is a verifier.

    ``rows`` is a zero-argument callable returning row mappings with at least
    ``canonical_envelope`` and ``signature``, which is what keeps this type identical
    for Postgres and for the in-memory backend — neither the SQL nor the facade
    appears here.
    """

    rows: Any
    label: str = "open project store"
    _index: dict[str, ReferentEvent] | None = field(default=None, init=False, repr=False)

    @property
    def completeness(self) -> MaterialCompleteness:
        return MaterialCompleteness.COMPLETE_STORE

    def _build(self) -> dict[str, ReferentEvent]:
        index: dict[str, ReferentEvent] = {}
        for row in self.rows():
            referent = referent_from_bytes(
                row.get("canonical_envelope"), row.get("signature")
            )
            if referent is not None:
                index[referent.event_hash] = referent
        return index

    def resolve_referent(self, event_hash: str) -> ReferentEvent | None:
        if self._index is None:
            self._index = self._build()
        return self._index.get(event_hash)

    def describe(self) -> str:
        indexed = "unindexed" if self._index is None else f"{len(self._index)} v6 events"
        return f"{self.label} ({indexed}, {self.completeness.value})"


@dataclass(frozen=True)
class BundleReferents:
    """Material presented as an audit bundle's ``events`` section.

    The completeness claim is **derived from the bundle's own manifest**, not asserted
    by the caller: ``since_seq``/``until_seq`` both absent is a whole-store export
    (``complete-store``), and either one present is a window
    (``contiguous-range``). ``BUNDLE-V3.md`` §3.5's explicit ``scope`` member is
    P3.3's; deriving it from the two members the v2 manifest already carries is the
    same statement in the vocabulary this tree has, and it is what makes §9
    criterion 15 testable now.

    ``declared-selection`` is cut from 0.6.0, so there is no third case.
    """

    events: Mapping[str, ReferentEvent]
    material_completeness: MaterialCompleteness
    event_count: int

    @property
    def completeness(self) -> MaterialCompleteness:
        return self.material_completeness

    def resolve_referent(self, event_hash: str) -> ReferentEvent | None:
        return self.events.get(event_hash)

    def describe(self) -> str:
        return (
            f"audit bundle ({self.event_count} events, "
            f"{len(self.events)} v6-addressable, {self.completeness.value})"
        )

    @classmethod
    def from_bundle(
        cls,
        manifest: Mapping[str, Any],
        events: Sequence[Mapping[str, Any] | Any],
    ) -> BundleReferents:
        """Index a bundle's events and derive its completeness claim.

        ``events`` may be dicts (as read from the artifact) or ``Event`` objects (as
        the offline verifier holds them); both expose ``canonical_envelope`` and
        ``signature``, so one accessor covers the two.
        """

        windowed = (
            manifest.get("since_seq") is not None
            or manifest.get("until_seq") is not None
        )
        indexed: dict[str, ReferentEvent] = {}
        for event in events:
            if isinstance(event, Mapping):
                envelope = event.get("canonical_envelope")
                signature = event.get("signature")
            else:
                envelope = getattr(event, "canonical_envelope", None)
                signature = getattr(event, "signature", None)
            referent = referent_from_bytes(envelope, signature)
            if referent is not None:
                indexed[referent.event_hash] = referent
        return cls(
            events=indexed,
            material_completeness=(
                MaterialCompleteness.CONTIGUOUS_RANGE
                if windowed
                else MaterialCompleteness.COMPLETE_STORE
            ),
            event_count=len(list(events)),
        )


def store_referents(conn: Any, *, label: str = "project store") -> StoreReferents:
    """Present an open store connection as material (§8.4).

    Build this **once per verification pass**, not once per event: the index costs one
    ordered scan of ``events`` (there is no ``event_hash`` column to address a referent
    by), so paying it per event turns an O(n) replay into O(n²). Replay and the
    single-event helpers differ only in how long the resolver lives.
    """

    from psycopg.sql import SQL

    def rows() -> list[Mapping[str, Any]]:
        fetched: list[Mapping[str, Any]] = conn.execute(
            SQL("SELECT canonical_envelope, signature FROM events")
        ).fetchall()
        return fetched

    return StoreReferents(rows=rows, label=label)


def walk_project_chain(
    start: str | None, referents: ReferentResolver, *, limit: int = 2_000_000
) -> Iterator[ReferentEvent]:
    """Yield presented events from ``start`` backwards along the project chain.

    Ordering is established **entirely** by ``chain.previous_project_event_hash``
    (§5.10 step 3): no ``occurred_at``, no ``global_seq``, no side table. The walk
    stops at the chain root (``previous_project_event_hash is None``), at the first
    hash the material does not present, or on a revisit — a hash-linked chain cannot
    contain a cycle, so a revisit means the material is not a chain and continuing
    would loop forever on adversarial input.
    """

    seen: set[str] = set()
    cursor = start
    for _ in range(limit):
        if cursor is None or cursor in seen:
            return
        seen.add(cursor)
        event = referents.resolve_referent(cursor)
        if event is None:
            return
        yield event
        cursor = event.previous_project_event_hash
