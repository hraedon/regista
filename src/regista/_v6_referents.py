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
from typing import Any, Final, Protocol, cast, runtime_checkable

from ._errors import ErrorCode, RegistaError

__all__ = [
    "NO_REFERENTS",
    "BundleReferents",
    "MappingReferents",
    "MaterialCompleteness",
    "NoReferents",
    "ReferentEvent",
    "ReferentResolver",
    "ReferentSummary",
    "StoreReferents",
    "authorization_credential_hashes",
    "credential_from_document",
    "credential_material_claim",
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


def credential_material_claim(referents: Any) -> MaterialCompleteness:
    """What ``referents`` claims about its action-delegation credential coverage.

    Falls back to the material's event claim for a resolver that does not state one
    separately — which is the behaviour every resolver had before the claim was split,
    and the right reading for material that is one undifferentiated mapping.
    """

    claim = getattr(referents, "credential_completeness", None)
    if isinstance(claim, MaterialCompleteness):
        return claim
    return cast(MaterialCompleteness, referents.completeness)


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


#: Shared empty answer for the overwhelmingly common direct-authorization event, so
#: carrying the authorization pre-read below costs a pointer rather than an object on
#: every event in the log.
_NO_CREDENTIAL_HASHES: Final[frozenset[str]] = frozenset()


def authorization_credential_hashes(envelope: Mapping[str, Any]) -> frozenset[str]:
    """The action-delegation credential hashes an envelope's authorization names.

    Defensive about shape rather than strict: the callers are a resolver indexing
    presented material and a verifier walking ancestors, and neither may turn an
    unexpected authorization block into an exception at an unrelated call site. A
    strict-parsed v6 envelope always satisfies the shape (``V6_AUTHORIZATION_KEYS``
    with a validated ``credentials`` array), so the guards only fire on material that
    reached here without that parse.
    """

    authorization = envelope.get("authorization")
    if not isinstance(authorization, Mapping):
        return _NO_CREDENTIAL_HASHES
    credentials = authorization.get("credentials")
    if not isinstance(credentials, list) or not credentials:
        return _NO_CREDENTIAL_HASHES
    return frozenset(
        item["credential_hash"]
        for item in credentials
        if isinstance(item, Mapping) and isinstance(item.get("credential_hash"), str)
    )


@dataclass(frozen=True, slots=True)
class ReferentSummary:
    """The seven signed members :class:`ReferentEvent`'s accessors read, held eagerly.

    Every one of these is read while *deciding* about a referent — its transition, its
    scope, its position on the chain — and none of them is the referent's content. The
    distinction is what lets a resolver index a whole store without holding the store:
    a summary is ~0.5 KiB per event where the parsed envelope is ~5 KiB, measured on
    real rows, and the difference is a footprint that tracks the log (see
    :class:`_LazyEnvelope` and WI-217).

    The repeated members are interned: a project's events share one project instance,
    one trust domain, a handful of principals and key ids, so interning makes the
    per-event cost the two things that genuinely differ — the chain link and the
    addressing hash.

    ``authorization_credential_hashes`` earns its place here for the same reason as the
    other six, established by measurement (WI-008 round two). The delegation verifier
    asks *every* ancestor which credentials it consumed, to count a credential's uses
    against ``max_uses``; reaching that through ``envelope`` made each of those
    questions a full store re-scan (:class:`_LazyEnvelope`), so one delegated append
    cost a scan per ancestor per credential — measured at 6.2 s for a single append on
    an 805-event project, twice per append, with the global chain-head lock held. It is
    a *decision* about the referent, not the referent's content, and it is derived from
    the same strict-parsed envelope, so it is a pre-read exactly as the rest are. The
    hashes alone are carried rather than the whole block: the count is all any caller
    reads, and an empty answer is shared.
    """

    transition: str
    project_instance_id: str
    trust_domain_id: str
    actor_principal_id: str
    signing_key_id: str
    previous_project_event_hash: str | None
    authorization_credential_hashes: frozenset[str]

    @classmethod
    def from_envelope(cls, envelope: Mapping[str, Any]) -> ReferentSummary:
        from sys import intern

        previous = envelope["chain"]["previous_project_event_hash"]
        return cls(
            transition=intern(str(envelope["transition"])),
            project_instance_id=intern(str(envelope["project_instance_id"])),
            trust_domain_id=intern(str(envelope["trust_domain_id"])),
            actor_principal_id=intern(str(envelope["actor"]["principal_id"])),
            signing_key_id=intern(str(envelope["signing"]["key_id"])),
            previous_project_event_hash=(
                None if previous is None else str(previous)
            ),
            authorization_credential_hashes=authorization_credential_hashes(envelope),
        )


@dataclass(frozen=True)
class ReferentEvent:
    """One event of the presented material, addressed by its v6 event hash.

    ``envelope`` is the **strict-parsed** v6 envelope, so every accessor below reads
    signed structure rather than a row column. ``event_hash`` is the domain-tagged v6
    hash over ``canonical_envelope || signature``, which is what every referring
    field (``signing.key_binding_event_hash``, ``chain.previous_project_event_hash``,
    ``workflow.registration_event_hash``) names.

    ``summary`` is an optional pre-read of the members the accessors need, supplied by
    a resolver that indexes many events and must not hold them all parsed. When it is
    absent every accessor reads the envelope, which is the original behaviour; when it
    is present the envelope may be loaded lazily and only ``payload`` (or a direct
    ``envelope[...]`` read) pays for it. It is a *pre-read*, never an override: it is
    built from the same strict-parsed envelope, so the two can only agree.
    """

    event_hash: str
    envelope: Mapping[str, Any]
    summary: ReferentSummary | None = None

    @property
    def transition(self) -> str:
        if self.summary is not None:
            return self.summary.transition
        return str(self.envelope["transition"])

    @property
    def project_instance_id(self) -> str:
        if self.summary is not None:
            return self.summary.project_instance_id
        return str(self.envelope["project_instance_id"])

    @property
    def trust_domain_id(self) -> str:
        if self.summary is not None:
            return self.summary.trust_domain_id
        return str(self.envelope["trust_domain_id"])

    @property
    def actor_principal_id(self) -> str:
        if self.summary is not None:
            return self.summary.actor_principal_id
        return str(self.envelope["actor"]["principal_id"])

    @property
    def signing_key_id(self) -> str:
        if self.summary is not None:
            return self.summary.signing_key_id
        return str(self.envelope["signing"]["key_id"])

    @property
    def previous_project_event_hash(self) -> str | None:
        if self.summary is not None:
            return self.summary.previous_project_event_hash
        value = self.envelope["chain"]["previous_project_event_hash"]
        return None if value is None else str(value)

    @property
    def authorization_credential_hashes(self) -> frozenset[str]:
        if self.summary is not None:
            return self.summary.authorization_credential_hashes
        return authorization_credential_hashes(self.envelope)

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

    @property
    def credential_completeness(self) -> MaterialCompleteness:
        """What it claims about its **action-delegation credential** coverage.

        A separate claim because it is a separate section of the artifact, and the two
        genuinely differ: a bundle v2 transports every event and no credential at all
        (``BUNDLE-V3.md`` §9 item 6), so a delegated event in one is *unverifiable*
        from bundle evidence — "unverifiable rather than silently trusted" — and
        emphatically not invalid, which is what reading the event-side claim for a
        credential question made it. §5.11's two rows apply per referent class; this
        member is which row a *credential* referent gets.
        """

    def resolve_referent(self, event_hash: str) -> ReferentEvent | None:
        """The presented event whose v6 hash is ``event_hash``, or ``None``."""

    def resolve_action_credential(self, credential_hash: str) -> Any | None:
        """The presented action-delegation credential addressed by its recomputed hash."""

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

    @property
    def credential_completeness(self) -> MaterialCompleteness:
        return MaterialCompleteness.UNDECLARED

    def resolve_referent(self, event_hash: str) -> ReferentEvent | None:
        return None

    def resolve_action_credential(self, credential_hash: str) -> Any | None:
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
    action_credentials: Mapping[str, Any] = field(default_factory=dict)
    material_completeness: MaterialCompleteness = MaterialCompleteness.UNDECLARED
    label: str = "presented event mapping"

    @property
    def completeness(self) -> MaterialCompleteness:
        return self.material_completeness

    @property
    def credential_completeness(self) -> MaterialCompleteness:
        # A caller who assembles the mapping chooses what goes in it, credentials
        # included, so its claim about the material is a claim about both sections.
        return self.material_completeness

    def resolve_referent(self, event_hash: str) -> ReferentEvent | None:
        return self.events.get(event_hash)

    def resolve_action_credential(self, credential_hash: str) -> Any | None:
        return self.action_credentials.get(credential_hash)

    def describe(self) -> str:
        return f"{self.label} ({len(self.events)} v6 events, {self.completeness.value})"

    @classmethod
    def from_pairs(
        cls,
        pairs: Iterable[tuple[bytes | memoryview | None, bytes | memoryview | None]],
        *,
        completeness: MaterialCompleteness = MaterialCompleteness.UNDECLARED,
        label: str = "presented event mapping",
        action_delegation_credentials: Iterable[
            Mapping[str, Any] | bytes | memoryview
        ] = (),
    ) -> MappingReferents:
        events: dict[str, ReferentEvent] = {}
        for envelope, signature in pairs:
            referent = referent_from_bytes(envelope, signature)
            if referent is not None:
                events[referent.event_hash] = referent
        credential_index: dict[str, Any] = {}
        for document in action_delegation_credentials:
            credential = credential_from_document(document)
            if credential is not None:
                credential_index[credential.credential_hash] = credential
        return cls(
            events=events,
            action_credentials=credential_index,
            material_completeness=completeness,
            label=label,
        )


#: How many full envelopes one store resolver may hold materialized at a time.
#: The healthy population is the trust plane — one acceptance per principal, one
#: workflow registration, the bootstrap event — so this is never reached in practice;
#: it exists so an adversarial log naming a *different* ordinary event as every event's
#: anchor cannot walk the retained set back up to the size of the log. Past the cap a
#: payload read still answers; it just re-reads instead of being remembered.
_MATERIALIZED_ENVELOPE_LIMIT: Final = 256


@dataclass
class _MaterializationBudget:
    """Shared allowance for materialized envelopes, so the bound is per *resolver*."""

    remaining: int = _MATERIALIZED_ENVELOPE_LIMIT

    def take(self) -> bool:
        if self.remaining <= 0:
            return False
        self.remaining -= 1
        return True


class _LazyEnvelope(Mapping[str, Any]):
    """A v6 envelope that is re-read from the store the first time it is *used*.

    This exists for one measured reason (WI-217, P1.7 phase 4). ``StoreReferents``
    indexes every v6 event in the store and retained each event's whole parsed envelope
    for the resolver's lifetime — which, for a replay, is the whole replay. So Phase 2's
    per-resolver cache silently defeated the streaming space bound WI-217 exists to
    defend: measured on an 8x log, replay's tracemalloc peak grew **5.5x** against a
    3.0x budget. A parsed envelope costs ~5 KiB per event on real rows against ~0.5 KiB
    for the members a *decision* about the referent needs (:class:`ReferentSummary`),
    and the difference is the term that tracks the log.

    So the index holds summaries and this proxy, and the envelope proper is re-read on
    demand — which in a healthy replay happens for the trust-plane referents alone (a
    key acceptance, a workflow registration, an enrolment, a revocation), because those
    are the only referents whose ``payload`` any verdict reads.

    Three properties keep that sound rather than merely smaller:

    * **Nothing is fabricated and nothing is partial.** This mapping either has the real
      envelope or fetches it; there is no subset view of it, so no consumer can read a
      member that has been quietly elided and conclude the envelope lacked it.
    * **The re-read is addressed by v6 event hash**, recomputed over the stored bytes,
      so it can only ever return the bytes this referent already stood for. A row edited
      since the index was built does not resolve to something else — it stops resolving.
    * **A vanished row is reported, not smoothed over.** ``ReferentEvent.payload``
      returning ``{}`` for a row that has since left the material would be an absence
      dressed as a fact, so the load raises instead.

    The re-read costs one scan of the store's envelope bytes (hash only — nothing is
    parsed until the matching row is found), which is why materializations are memoized,
    and bounded (:data:`_MATERIALIZED_ENVELOPE_LIMIT`) so the memo cannot become the
    cache this class replaced.
    """

    __slots__ = ("_event_hash", "_full", "_owner")

    def __init__(self, owner: StoreReferents, event_hash: str) -> None:
        self._owner = owner
        self._event_hash = event_hash
        self._full: Mapping[str, Any] | None = None

    def _materialize(self) -> Mapping[str, Any]:
        if self._full is not None:
            return self._full
        full = self._owner.load_envelope(self._event_hash)
        if self._owner._budget.take():
            self._full = full
        return full

    def __getitem__(self, key: str) -> Any:
        return self._materialize()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._materialize())

    def __len__(self) -> int:
        return len(self._materialize())

    def __repr__(self) -> str:
        state = "materialized" if self._full is not None else "not loaded"
        return f"_LazyEnvelope({self._event_hash}, {state})"


@dataclass
class StoreReferents:
    """Material presented as an **open project store**, indexed lazily.

    Completeness is ``COMPLETE_STORE``: §5.11 names "an online store" beside
    ``complete-store`` as material that claims completeness, so an anchor this store
    does not contain is a contradicted claim rather than a gap. That is the stricter
    of the two readings and is the P1.7 notes' flag #4 decision.

    **Cost, stated rather than hidden.** ``events`` has no ``event_hash`` column, so
    the index is built by one pass that recomputes each v6 hash. The pass is
    lazy — a store whose events are all v1-v5 never pays for it, because no v6 row
    reaches referent resolution — and cached for the resolver's lifetime, so a replay
    over N events pays once rather than N times. A per-row helper that constructs a
    fresh resolver each call therefore pays once *per call*; that is acceptable for
    single-event verification and is the reason replay builds one resolver and reuses
    it. An ``event_hash`` generated column would remove the pass entirely and is
    filed rather than smuggled in here: it is a migration, and this is a verifier.

    **What the index may hold is bounded, and that is load bearing.** Retaining every
    indexed event's whole parsed envelope made this resolver's footprint track the log
    size — exactly the property WI-217's streaming replay exists to defend, and
    measured at 5.5x peak growth on an 8x log against a 3.0x budget. The index
    therefore holds a :class:`ReferentSummary` per event and re-reads the envelope on
    demand (:class:`_LazyEnvelope`), which makes the retained term per-event *metadata*
    rather than per-event *content*; and ``rows()`` is consumed as a stream so the
    indexing pass does not materialize the log either.

    ``rows`` is a zero-argument callable returning an iterable of row mappings with at
    least ``canonical_envelope`` and ``signature``, which is what keeps this type
    identical for Postgres and for the in-memory backend — neither the SQL nor the
    facade appears here. It must be **re-callable**: a payload read re-reads through it.
    """

    rows: Any
    label: str = "open project store"
    credential_rows: Any | None = None
    _index: dict[str, ReferentEvent] | None = field(default=None, init=False, repr=False)
    _budget: _MaterializationBudget = field(
        default_factory=_MaterializationBudget, init=False, repr=False
    )
    _credential_index: dict[str, Any] | None = field(default=None, init=False, repr=False)

    @property
    def completeness(self) -> MaterialCompleteness:
        return MaterialCompleteness.COMPLETE_STORE

    @property
    def credential_completeness(self) -> MaterialCompleteness:
        # An open store holds the credential table beside the events, so it claims the
        # same completeness for both — unless it was constructed without a credential
        # read at all, in which case it presents no credential material and may not
        # call a credential it was never given the means to find "absent".
        if self.credential_rows is None:
            return MaterialCompleteness.UNDECLARED
        return MaterialCompleteness.COMPLETE_STORE

    def load_envelope(self, event_hash: str) -> Mapping[str, Any]:
        """Re-read and parse the one envelope addressed by ``event_hash``.

        Hash first, parse second: the scan computes ``compute_v6_event_hash`` over the
        stored bytes, which needs no JSON parse, and only parses the row that matches.

        Raises when the material no longer presents the row. That is deliberate and it
        is the reason this is not written to return ``None``: the only caller is
        :class:`_LazyEnvelope`, whose result feeds ``ReferentEvent.payload``, and an
        empty payload for a row that has *gone* would be an absence reported as a fact —
        precisely the shape §5.11 exists to keep out of verdicts.
        """

        from ._errors import ErrorCode, RegistaError
        from ._signing import compute_v6_event_hash
        from ._verification import parse_v6_envelope_strict

        wanted = event_hash.removeprefix("sha256:")
        for row in self.rows():
            envelope = row.get("canonical_envelope")
            signature = row.get("signature")
            if not envelope or not signature:
                continue
            envelope_bytes = bytes(envelope)
            if compute_v6_event_hash(envelope_bytes, bytes(signature)).hex() != wanted:
                continue
            return parse_v6_envelope_strict(envelope_bytes)
        raise RegistaError(
            ErrorCode.MATERIAL_CHANGED_UNDER_VERIFICATION,
            f"the presented material no longer contains the v6 event {event_hash}, "
            "which it presented when this resolver indexed it; a store that changes "
            "under a verification pass cannot be reported as evidence",
            detail={"event_hash": event_hash, "material": self.describe()},
        )

    def _build(self) -> dict[str, ReferentEvent]:
        index: dict[str, ReferentEvent] = {}
        for row in self.rows():
            referent = referent_from_bytes(
                row.get("canonical_envelope"), row.get("signature")
            )
            if referent is None:
                continue
            index[referent.event_hash] = ReferentEvent(
                event_hash=referent.event_hash,
                envelope=_LazyEnvelope(self, referent.event_hash),
                summary=ReferentSummary.from_envelope(referent.envelope),
            )
        return index

    def resolve_referent(self, event_hash: str) -> ReferentEvent | None:
        if self._index is None:
            self._index = self._build()
        return self._index.get(event_hash)

    def resolve_action_credential(self, credential_hash: str) -> Any | None:
        if self._credential_index is None:
            self._credential_index = {}
            if self.credential_rows is not None:
                for row in self.credential_rows():
                    document = row.get("document")
                    credential = credential_from_document(document)
                    if credential is not None:
                        self._credential_index[credential.credential_hash] = credential
        return self._credential_index.get(credential_hash)

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

    The credential section gets its **own** claim, and it defaults to "not transported"
    because that is what bundle v2 is: `BUNDLE-V3.md` §9 item 6 puts action-delegation
    documents in a v3 section that does not exist yet, and says in as many words that
    "bundle v2 does not transport credentials, and delegated audit from bundle-v2
    evidence is therefore unverifiable rather than silently trusted". Reading the
    event-side ``complete-store`` claim for a credential question instead reported an
    intact, legitimately delegated event as ``INVALID`` — under a "Signature
    verification failed" headline about a signature that verified.
    """

    events: Mapping[str, ReferentEvent]
    material_completeness: MaterialCompleteness
    event_count: int
    action_credentials: Mapping[str, Any] = field(default_factory=dict)
    credential_material_completeness: MaterialCompleteness = MaterialCompleteness.UNDECLARED

    @property
    def completeness(self) -> MaterialCompleteness:
        return self.material_completeness

    @property
    def credential_completeness(self) -> MaterialCompleteness:
        return self.credential_material_completeness

    def resolve_referent(self, event_hash: str) -> ReferentEvent | None:
        return self.events.get(event_hash)

    def resolve_action_credential(self, credential_hash: str) -> Any | None:
        return self.action_credentials.get(credential_hash)

    def describe(self) -> str:
        return (
            f"audit bundle ({self.event_count} events, "
            f"{len(self.events)} v6-addressable, {self.completeness.value}, "
            f"credentials {self.credential_completeness.value})"
        )

    @classmethod
    def from_bundle(
        cls,
        manifest: Mapping[str, Any],
        events: Sequence[Mapping[str, Any] | Any],
        action_delegation_credentials: Sequence[Mapping[str, Any] | bytes] | None = None,
    ) -> BundleReferents:
        """Index a bundle's events and derive its completeness claims.

        ``events`` may be dicts (as read from the artifact) or ``Event`` objects (as
        the offline verifier holds them); both expose ``canonical_envelope`` and
        ``signature``, so one accessor covers the two.

        ``action_delegation_credentials`` is ``None`` — *the artifact carries no
        credential section* — rather than empty, and the two are different facts. Only
        a format that transports credentials can say "this credential is absent from a
        complete section"; a bundle v2 has no section to be absent from, so ``None``
        is the honest default and the only one a v2 caller can truthfully pass. An
        empty sequence is a v3 artifact whose section is genuinely empty, and a
        credential referenced against *that* is a false completeness claim.
        """

        windowed = (
            manifest.get("since_seq") is not None
            or manifest.get("until_seq") is not None
        )
        indexed: dict[str, ReferentEvent] = {}
        # Counted in the same pass, deliberately. `event_count=len(list(events))`
        # iterated `events` a SECOND time after the loop above had already consumed it,
        # so a generator argument reported `event_count=0` — and `event_count` is what
        # `describe()` puts in every verdict detail naming this material's scope, so the
        # bundle's own size was misreported to an auditor while the index was correct
        # (phase-4 ceremony NB7). The annotation says `Sequence`, but a caller holding a
        # cursor or a comprehension satisfies it structurally, which is precisely the
        # kind of "works until it doesn't" the result model exists to remove.
        counted = 0
        for event in events:
            counted += 1
            if isinstance(event, Mapping):
                envelope = event.get("canonical_envelope")
                signature = event.get("signature")
            else:
                envelope = getattr(event, "canonical_envelope", None)
                signature = getattr(event, "signature", None)
            referent = referent_from_bytes(envelope, signature)
            if referent is not None:
                indexed[referent.event_hash] = referent
        credential_index: dict[str, Any] = {}
        for document in action_delegation_credentials or ():
            credential = credential_from_document(document)
            if credential is not None:
                credential_index[credential.credential_hash] = credential
        completeness = (
            MaterialCompleteness.CONTIGUOUS_RANGE
            if windowed
            else MaterialCompleteness.COMPLETE_STORE
        )
        return cls(
            events=indexed,
            material_completeness=completeness,
            event_count=counted,
            action_credentials=credential_index,
            credential_material_completeness=(
                MaterialCompleteness.UNDECLARED
                if action_delegation_credentials is None
                else completeness
            ),
        )


#: Rows per FETCH from the referent scan's server-side cursor (WI-217). Matches
#: ``_replay._EVENT_STREAM_SIZE``'s reasoning and psycopg's own ServerCursor default:
#: it bounds the block in ROWS, so on a project with very wide payloads the block's
#: byte cost rises with the payload width.
_REFERENT_STREAM_SIZE: Final = 100


def store_referents(conn: Any, *, label: str = "project store") -> StoreReferents:
    """Present an open store connection as material (§8.4).

    Build this **once per verification pass**, not once per event: the index costs one
    scan of ``events`` (there is no ``event_hash`` column to address a referent by), so
    paying it per event turns an O(n) replay into O(n²). Replay and the single-event
    helpers differ only in how long the resolver lives.

    The scan is **streamed** through a server-side cursor, for WI-217's reason and not
    merely for tidiness: ``fetchall()`` converts every row's envelope bytes to Python at
    once, so the pass that builds the index used to cost the whole log in peak memory
    even though the index itself no longer keeps it. Note that iterating a *client-side*
    cursor would not fix this — libpq buffers the whole result set in C heap, which
    tracemalloc cannot see and RSS very much can, so the measurement would improve while
    the machine's memory did not.

    ``conn.cursor`` is the discriminator, and the fallback is a statement rather than a
    refusal on purpose: the in-memory facade (``_in_memory_v6``) offers ``execute``
    only, its rows are already resident objects that ``fetchall`` merely references, and
    ``_genesis.read_genesis_from_connection`` depends on this working there (pinned by
    ``tests/test_wi287_inmem_parity.py``). A named cursor there would be a
    ``PARITY_BOUNDARY_POSTGRES_ONLY`` refusal in the middle of a shared read path.
    """

    from psycopg.sql import SQL

    statement: Any | None = None

    def event_statement() -> Any:
        nonlocal statement
        if statement is not None:
            return statement
        if getattr(conn, "provides_transactional_isolation", True) is False:
            statement = SQL("SELECT canonical_envelope, signature FROM events")
            return statement
        row = conn.execute(
            SQL("SELECT to_regclass(%s) AS relation"),
            ["events_archive"],
        ).fetchone()
        if row is not None and row["relation"] is not None:
            statement = SQL(
                "SELECT canonical_envelope, signature FROM events "
                "UNION ALL SELECT canonical_envelope, signature FROM events_archive"
            )
            return statement
        statement = SQL("SELECT canonical_envelope, signature FROM events")
        return statement

    def rows() -> Iterator[Mapping[str, Any]]:
        cursor_factory = getattr(conn, "cursor", None)
        if cursor_factory is None:
            yield from conn.execute(event_statement()).fetchall()
            return
        import uuid as _uuid

        # A server-side cursor needs a transaction; `conn.transaction()` opens one
        # or takes a savepoint inside the caller's, and the scan is drained inside
        # this block so the savepoint's lifetime is the scan's.
        with conn.transaction():
            scan_statement = event_statement()
            with cursor_factory(name=f"referents_{_uuid.uuid4().hex[:8]}") as scan:
                scan.itersize = _REFERENT_STREAM_SIZE
                scan.execute(scan_statement)
                yield from scan

    def credential_rows() -> Iterator[Mapping[str, Any]]:
        try:
            yield from conn.execute(
                SQL("SELECT document FROM action_delegation_credentials")
            ).fetchall()
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == "42P01":
                return
            if getattr(conn, "provides_transactional_isolation", True) is False:
                return
            raise

    return StoreReferents(rows=rows, label=label, credential_rows=credential_rows)


def credential_from_document(document: Mapping[str, Any] | bytes | memoryview | None) -> Any | None:
    if document is None:
        return None
    from ._action_delegation import ActionDelegationError, parse_action_delegation

    try:
        if isinstance(document, memoryview):
            document = bytes(document)
        return parse_action_delegation(document)
    except (ActionDelegationError, TypeError, ValueError):
        return None


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
