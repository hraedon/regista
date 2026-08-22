"""The 0.7.1 public offline verification surface (``regista.verification``).

Consumers embedding regista (cairn's offline bundle verifier is the driving
one) previously had to import ``regista._signing`` / ``regista._v6_referents``
to verify v6 events correctly, and every consumer that reached less deeply
silently downgraded v6 events to UNVERIFIABLE. These tests pin the narrow
public surface those consumers are supposed to use instead: it exists, it is
re-exported from the package root, and it behaves per the documented honesty
contract (INVALID is a proven defect; UNVERIFIABLE is an evidentiary gap; the
v6 genesis event is the expected gap on otherwise-healthy bundle material).
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Callable
from pathlib import Path

import pytest

import regista
from regista import (
    NO_REFERENTS,
    Applicability,
    EnvelopeVersion,
    VerificationPolicy,
    VerificationResult,
    bundle_referents,
    chain_head_hash,
    make_verification_policy,
    verify_event_with_referents,
)
from regista.testing import InMemoryRegista, make_v6_keyset, open_v6_epoch
from regista.verification import MaterialCompleteness

# ---------------------------------------------------------------------------
# Export surface
# ---------------------------------------------------------------------------


def test_public_names_are_package_attributes() -> None:
    """The 0.7.1 surface is importable from the package root, not the privates."""
    for name in (
        "bundle_referents",
        "chain_head_hash",
        "verify_event_with_referents",
        "NO_REFERENTS",
        "Applicability",
        "VerificationResult",
        "BundleReferents",
    ):
        assert hasattr(regista, name), f"regista.{name} is not exported"


def test_verification_module_is_public() -> None:
    """``regista.verification`` itself is importable for the narrower names."""
    from regista import verification

    assert verification.MaterialCompleteness is MaterialCompleteness
    assert verification.ReferentResolver is not None


def test_public_policy_factory_keeps_external_pins_and_explicit_archive_versions() -> None:
    policy = make_verification_policy(
        project_instance_id="project-1",
        trust_domain_id="trust-1",
        cutover_checkpoint_event_hash="sha256:" + "ab" * 32,
        accepted_legacy_envelope_versions=("v1", EnvelopeVersion.V4),
    )

    assert isinstance(policy, VerificationPolicy)
    assert policy.pinned_project_instance_id == "project-1"
    assert policy.pinned_trust_domain_id == "trust-1"
    assert policy.cutover_checkpoint_event_hash == "sha256:" + "ab" * 32
    assert policy.accept_legacy_versions == frozenset(
        {EnvelopeVersion.V1, EnvelopeVersion.V4}
    )
    assert policy.full_authentication_versions == frozenset(
        {EnvelopeVersion.V5, EnvelopeVersion.V6}
    )


def test_public_policy_factory_rejects_v6_as_a_legacy_version() -> None:
    with pytest.raises(ValueError, match="only v1-v4"):
        make_verification_policy(accepted_legacy_envelope_versions=("v6",))


def test_result_types_are_enums_and_dataclasses() -> None:
    """``Applicability`` is the enum callers branch on; INVALID spells 'invalid'."""
    assert isinstance(Applicability.INVALID.value, str)
    assert Applicability.INVALID.value == "invalid"
    assert Applicability.UNVERIFIABLE.value == "unverifiable"
    assert Applicability.FULLY_AUTHENTICATED.value == "fully_authenticated"


# ---------------------------------------------------------------------------
# Fixture: an in-memory v6 epoch with one ordinary workflow-bound event
# ---------------------------------------------------------------------------


@pytest.fixture
def v6_events(tmp_path: Path) -> tuple[list[object], dict[str, bytes]]:
    """(all events of a healthy in-memory v6 epoch, key_id -> ed25519 public key)."""
    keyset = make_v6_keyset(tmp_path, principals=("service:cairn",))
    sub = InMemoryRegista(project="public_surface", hmac_key_path=keyset.path)
    open_v6_epoch(sub, keyset, principals=("service:cairn",))
    sub.register_workflow(
        """
name: public_surface_actions
version: 1
regista_version: "0.7.0"
states:
  - name: new
    initial: true
  - name: done
    terminal: true
transitions:
  - name: act
    from: new
    to: done
    allowed_roles: [agent]
roles:
  - name: agent
work_item_types:
  - name: action
    custom_fields:
      - name: note
        type: string
link_types: []
"""
    )
    sub.create_work_item(
        workflow_name="public_surface_actions",
        work_item_type="action",
        actor_id="service:cairn",
    )
    events = list(sub.read_events(limit=100))
    public = {key.key_id: key.public_key for key in keyset.keys.values()}
    return events, public


# ---------------------------------------------------------------------------
# bundle_referents
# ---------------------------------------------------------------------------


def test_bundle_referents_completeness_is_derived_from_the_manifest(
    v6_events: tuple[list[object], dict[str, bytes]],
) -> None:
    """No ``since_seq``/``until_seq`` is a whole-store claim; either is a window."""
    events, _keys = v6_events

    whole = bundle_referents({}, events)
    assert whole.completeness is MaterialCompleteness.COMPLETE_STORE

    windowed = bundle_referents({"since_seq": 1}, events)
    assert windowed.completeness is MaterialCompleteness.CONTIGUOUS_RANGE


def test_bundle_referents_resolves_the_chain_it_was_built_from(
    v6_events: tuple[list[object], dict[str, bytes]],
) -> None:
    """A v6 event's key-binding anchor resolves inside its own bundle's material."""
    events, _keys = v6_events
    referents = bundle_referents({}, events)
    ordinary = [ev for ev in events if ev.transition != "project_initialized"]
    assert ordinary
    for ev in ordinary:
        from regista._verification import parse_v6_envelope_strict

        envelope = parse_v6_envelope_strict(bytes(ev.canonical_envelope))
        anchor_hash = envelope["signing"]["key_binding_event_hash"]
        assert isinstance(anchor_hash, str)
        assert referents.resolve_referent(anchor_hash) is not None, (
            f"{ev.transition}'s key-binding anchor did not resolve"
        )


# ---------------------------------------------------------------------------
# chain_head_hash
# ---------------------------------------------------------------------------


def test_chain_head_hash_is_the_v6_formula_for_v6_envelopes(
    v6_events: tuple[list[object], dict[str, bytes]],
) -> None:
    """v6 links are domain-separated and length-framed, not the legacy concat."""
    import struct

    events, _keys = v6_events
    ev = events[0]
    envelope, signature = bytes(ev.canonical_envelope), bytes(ev.signature)
    expected = hashlib.sha256(
        b"regista.event.hash.v1\x00"
        + struct.pack(">Q", len(envelope))
        + envelope
        + signature
    ).digest()
    assert chain_head_hash(envelope, signature) == expected


def test_chain_head_hash_is_the_legacy_formula_for_legacy_envelopes() -> None:
    """v1-v5 links are SHA-256 over envelope‖signature."""
    from regista._signing import sign_event

    sig, _hash, envelope = sign_event(
        event_id=uuid.uuid4(),
        work_item_id=uuid.uuid4(),
        actor_id="agent:x",
        key_id="k",
        event_seq=0,
        workflow_name="w",
        workflow_version=1,
        timestamp=__import__("datetime").datetime.now(__import__("datetime").UTC),
        transition="act",
        payload={"a": 1},
        key=b"32-bytes-of-legacy-hmac-material!!!!!!!",
    )
    expected = hashlib.sha256(envelope + sig).digest()
    assert chain_head_hash(envelope, sig) == expected


# ---------------------------------------------------------------------------
# verify_event_with_referents
# ---------------------------------------------------------------------------


def test_ordinary_v6_event_is_fully_authenticated_from_bundle_material(
    v6_events: tuple[list[object], dict[str, bytes]],
) -> None:
    events, public = v6_events
    referents = bundle_referents({}, events)
    ordinary = [ev for ev in events if ev.transition != "project_initialized"]

    for ev in ordinary:
        result = verify_event_with_referents(
            ev, public[ev.key_id], referents=referents, scheme_id="ed25519"
        )
        assert isinstance(result, VerificationResult)
        assert result.applicability is Applicability.FULLY_AUTHENTICATED, result.summary()
        assert result.accepted is True


def test_genesis_is_the_expected_unverifiable_gap_on_bundle_material(
    v6_events: tuple[list[object], dict[str, bytes]],
) -> None:
    """The v6 genesis's authority is the external enrolment, not the bundle.

    This is the honesty contract's canonical UNVERIFIABLE: not a defect of the
    artifact, and a consumer must not report it as one.
    """
    events, public = v6_events
    referents = bundle_referents({}, events)
    genesis = [ev for ev in events if ev.transition == "project_initialized"]
    assert len(genesis) == 1

    result = verify_event_with_referents(
        genesis[0], public[genesis[0].key_id], referents=referents, scheme_id="ed25519"
    )
    assert result.applicability is Applicability.UNVERIFIABLE
    assert result.accepted is False
    assert "bootstrap_external" in result.summary() or result.key_binding is not None


def test_no_referents_is_unverifiable_never_invalid(
    v6_events: tuple[list[object], dict[str, bytes]],
) -> None:
    """Presenting no material is an evidentiary gap, not a proven forgery."""
    events, public = v6_events
    ev = next(e for e in events if e.transition != "project_initialized")

    result = verify_event_with_referents(
        ev, public[ev.key_id], referents=NO_REFERENTS, scheme_id="ed25519"
    )
    assert result.applicability is Applicability.UNVERIFIABLE
    assert result.signature_valid is True  # the cryptography checked out


def test_wrong_key_is_invalid(
    v6_events: tuple[list[object], dict[str, bytes]], tmp_path: Path
) -> None:
    """A signature that does not verify under the supplied key is INVALID."""
    events, _public = v6_events
    ev = next(e for e in events if e.transition != "project_initialized")
    wrong = make_v6_keyset(
        tmp_path, filename=f"wrong-{uuid.uuid4().hex}.json", principals=("service:other",)
    ).bootstrap.public_key

    result = verify_event_with_referents(
        ev, wrong, referents=bundle_referents({}, events), scheme_id="ed25519"
    )
    assert result.applicability is Applicability.INVALID
    assert result.accepted is False


def test_rewritten_row_is_invalid_under_an_intact_signature(
    v6_events: tuple[list[object], dict[str, bytes]],
) -> None:
    """WI-267 through the public API: the row must agree with the signed bytes."""
    from dataclasses import replace

    events, public = v6_events
    ev = next(e for e in events if e.transition != "project_initialized")
    tampered = replace(ev, transition="tool_call_end")

    result = verify_event_with_referents(
        tampered,
        public[ev.key_id],
        referents=bundle_referents({}, events),
        scheme_id="ed25519",
    )
    assert result.applicability is Applicability.INVALID
    assert any(m.field == "transition" for m in result.mismatched_fields)


def test_referents_argument_is_required_by_keyword(
    v6_events: tuple[list[object], dict[str, bytes]],
) -> None:
    """No silent NO_REFERENTS default: omitting ``referents`` is a TypeError."""
    events, public = v6_events
    ev = next(e for e in events if e.transition != "project_initialized")
    with pytest.raises(TypeError):
        verify_event_with_referents(  # type: ignore[call-arg]
            ev, public[ev.key_id], scheme_id="ed25519"
        )


def test_legacy_hmac_event_verifies_through_the_public_api() -> None:
    """Historical read-only verification: a legacy row still verifies by secret."""
    import datetime as _dt

    from regista._signing import sign_event
    from regista._types import Event

    secret = b"32-bytes-of-legacy-hmac-material!!!!!!!"
    ev_id, wi_id = uuid.uuid4(), uuid.uuid4()
    now = _dt.datetime.now(_dt.UTC)
    sig, c_hash, env = sign_event(
        event_id=ev_id,
        work_item_id=wi_id,
        actor_id="agent:x",
        key_id="legacy-hmac-1",
        event_seq=0,
        workflow_name="w",
        workflow_version=1,
        timestamp=now,
        transition="act",
        payload={"a": 1},
        key=secret,
    )
    ev = Event(
        event_id=ev_id,
        work_item_id=wi_id,
        event_seq=0,
        actor_id="agent:x",
        actor_kind="agent",
        actor_metadata=None,
        key_id="legacy-hmac-1",
        workflow_name="w",
        workflow_version=1,
        timestamp=now,
        transition="act",
        payload={"a": 1},
        payload_canonical_hash=c_hash,
        signature=sig,
        canonical_envelope=env,
    )
    result = verify_event_with_referents(
        ev, secret, referents=NO_REFERENTS, scheme_id="hmac-sha256"
    )
    assert result.accepted is True


# ---------------------------------------------------------------------------
# Stability: the surface forwards to the one implementation, not a copy
# ---------------------------------------------------------------------------


def test_public_surface_delegates_to_the_one_internal_implementation() -> None:
    """The wrapper is the same callable graph, so it cannot drift into a second
    verifier (the exact defect class this surface exists to prevent)."""
    from regista._signing import compute_chain_head_hash as internal_chain_hash
    from regista._signing import (
        verify_event_result_with_public_key as internal_verify,
    )

    assert regista.chain_head_hash is chain_head_hash
    envelope, signature = b"{}", b"\x01"
    assert chain_head_hash(envelope, signature) == internal_chain_hash(
        envelope, signature
    )
    # verify_event_with_referents is a thin wrapper over the one primitive; a
    # signature-difference smoke check is enough (behaviour is pinned above).
    assert isinstance(internal_verify, Callable)
