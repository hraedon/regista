"""Public offline verification surface for embedding consumers (0.7.1).

Consumers that embed regista as a library and verify events **offline** — an
audit-bundle verifier, an export tool, a CI gate — previously had to reach into
``regista._signing`` / ``regista._v6_referents`` to do it correctly, and every
one that reached less deeply than that silently downgraded v6 events to
``UNVERIFIABLE`` (a v6 verdict needs the *chain*, not just the row). This
module is the narrow, stable surface those consumers are supposed to use
instead. Three callables and the types needed to consume their results:

* :func:`bundle_referents` — present a bundle's manifest and events as the
  referent material v6 verification resolves anchors, workflow registrations
  and epoch position against.
* :func:`chain_head_hash` — the version-aware hash-chain link an event
  contributes (the domain-separated v6 formula for v6 envelopes, the legacy
  SHA-256 concatenation for v1-v5). One implementation, not a hand copy.
* :func:`verify_event_with_referents` — the structured verification result for
  one event under caller-supplied key material and caller-presented referents.

The honesty contract callers must respect: ``Applicability.INVALID`` is a
proven defect of the artifact (a signature that does not verify, or a row
rewritten under an intact signature); ``UNVERIFIABLE`` is an evidentiary gap —
most commonly a v6 event whose referents the presented material does not
contain, or the v6 genesis event itself, whose authority is the external
trust-domain enrolment rather than anything a bundle can carry. Not proven is
not proven false; the two must not be collapsed in either direction.

``referents`` is a required keyword argument on :func:`verify_event_with_referents`
deliberately: a call site that cannot say what material it is presenting cannot
get a v6 verdict, and the honest way to say "one row, no chain" is to pass
:data:`NO_REFERENTS` by name, which is greppable.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from ._types import Event
from ._v6_referents import NO_REFERENTS, BundleReferents, MaterialCompleteness, ReferentResolver
from ._verification import Applicability, EnvelopeVersion, VerificationPolicy, VerificationResult

__all__ = [
    "NO_REFERENTS",
    "Applicability",
    "BundleReferents",
    "EnvelopeVersion",
    "MaterialCompleteness",
    "ReferentResolver",
    "TrustLogVerificationReport",
    "VerificationPolicy",
    "VerificationResult",
    "bundle_referents",
    "chain_head_hash",
    "make_verification_policy",
    "verify_event_with_referents",
]


@dataclass(frozen=True, slots=True)
class TrustLogVerificationReport:
    """Read-only result returned by :meth:`Regista.verify_trust_log`.

    A successful call has already verified the pinned trust-genesis document,
    the stored genesis event, and every subsequent trust-log event. Failures
    are raised as :class:`regista.RegistaError` rather than represented as a
    false report, so callers cannot mistake an unavailable or unpinned chain
    for a verified empty log.
    """

    verified: bool
    event_count: int
    trust_domain_id: str
    genesis_event_hash: str

    def to_dict(self) -> dict[str, Any]:
        """Return the stable machine-readable report shape."""
        return {
            "verified": self.verified,
            "event_count": self.event_count,
            "trust_domain_id": self.trust_domain_id,
            "genesis_event_hash": self.genesis_event_hash,
        }


def make_verification_policy(
    *,
    project_instance_id: str | None = None,
    trust_domain_id: str | None = None,
    cutover_checkpoint_event_hash: str | None = None,
    accepted_legacy_envelope_versions: Iterable[EnvelopeVersion | str] = (),
) -> VerificationPolicy:
    """Build the bounded policy used by offline event consumers.

    The three identity values are caller-supplied, external pins. They are
    never read from a bundle or a store. Legacy acceptance is also explicit:
    pass only the historical envelope versions the consumer's archive policy
    permits. v5 and v6 remain the full-authentication versions.

    ``EnvelopeVersion`` values may be supplied as enum members or their wire
    spellings (``"v1"`` through ``"v4"``). Passing v5/v6 as a legacy version
    is rejected because those versions are authenticated under the full policy
    axis instead.
    """

    legacy_versions: set[EnvelopeVersion] = set()
    allowed_legacy = {
        EnvelopeVersion.V1,
        EnvelopeVersion.V2,
        EnvelopeVersion.V3,
        EnvelopeVersion.V4,
    }
    for version in accepted_legacy_envelope_versions:
        parsed = version if isinstance(version, EnvelopeVersion) else EnvelopeVersion(version)
        if parsed not in allowed_legacy:
            raise ValueError(
                f"accepted_legacy_envelope_versions contains {parsed.value!r}; "
                "only v1-v4 are legacy envelope versions"
            )
        legacy_versions.add(parsed)

    return VerificationPolicy(
        accept_legacy_versions=frozenset(legacy_versions),
        pinned_project_instance_id=project_instance_id,
        pinned_trust_domain_id=trust_domain_id,
        cutover_checkpoint_event_hash=cutover_checkpoint_event_hash,
    )


def bundle_referents(
    manifest: Mapping[str, Any],
    events: Sequence[Mapping[str, Any] | Any],
    action_delegation_credentials: Sequence[Mapping[str, Any] | bytes] | None = None,
) -> BundleReferents:
    """Index a bundle's events as the material v6 verification resolves against.

    ``manifest`` is the bundle manifest mapping; its ``since_seq``/``until_seq``
    members derive the completeness claim (both absent is a whole-store export,
    either present is a window), exactly as regista's own offline bundle
    verifier derives it — the caller does not assert completeness, the bundle
    does. ``events`` may be dicts (as read from the artifact) or ``Event``
    objects (as the verifier holds them).

    ``action_delegation_credentials`` is the bundle's credential section when
    it has one; a delegated v6 event is unverifiable from a bundle that does
    not transport its credentials, by design rather than by omission.
    """
    return BundleReferents.from_bundle(
        manifest,
        events,
        action_delegation_credentials=action_delegation_credentials,
    )


def chain_head_hash(canonical_envelope: bytes, signature: bytes) -> bytes:
    """The hash-chain head an event contributes, under its OWN envelope version.

    v6 envelopes hash with the domain-separated, length-framed v6 formula;
    v1-v5 hash with the plain SHA-256 envelope‖signature concatenation. This is
    the one implementation of the version dispatch — a hand copy of either
    formula is how a chain gets walked with the wrong one and every event
    becomes a false "root".
    """
    from ._signing import compute_chain_head_hash

    return compute_chain_head_hash(canonical_envelope, signature)


def verify_event_with_referents(
    event: Event,
    key_material: bytes,
    *,
    referents: ReferentResolver,
    scheme_id: str | None = None,
    policy: VerificationPolicy | None = None,
) -> VerificationResult:
    """Verify one stored event under caller-supplied key material and referents.

    Args:
        event: The stored event row (a :class:`regista.Event` or an object
            exposing the same fields). The stored canonical envelope is the
            only envelope: every field the envelope's version signs must agree
            with the row, and a disagreement is ``INVALID``.
        key_material: The trusted key bytes for the event's ``key_id``. For an
            asymmetric scheme this is the **public** key (verification never
            needs a secret); for a symmetric scheme it is the shared secret,
            and a caller holding it has implicitly vouched for the key.
        referents: The presented material (see :func:`bundle_referents`, or
            :data:`NO_REFERENTS` when the caller genuinely holds none).
        scheme_id: The trusted scheme for ``key_material``. Raw key bytes carry
            no scheme of their own; when omitted the event row's self-declared
            ``scheme_id`` is used — trusted exactly insofar as the caller
            vouched for the key, which is the same rule the private surface
            applies. Callers holding key metadata must pass it.

    Returns:
        The structured :class:`VerificationResult`. Branch on
        ``applicability`` (see module docstring for the honesty contract);
        ``accepted`` is the boolean convenience for "fully verified under the
        default policy" and is ``False`` for an evidentiary gap, which is not
        a failure of the artifact.
    """
    from ._signing import verify_event_result_with_public_key

    return verify_event_result_with_public_key(
        event,
        key_material,
        scheme_id=scheme_id,
        referents=referents,
        policy=policy,
    )
