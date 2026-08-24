"""WI-337 — the published trust-log export (``TRUST-DOMAIN.md`` §4.2/§4.3, §5.4 step 5).

The artifact exists so a PROJECT bundle can reach ``externally_authenticated`` FULLY
OFFLINE: a non-root project key's chain to the pinned root crosses into the trust log,
and every trust-log verifier used to be store-backed, so §5.4 step 8's offline external
verification was impossible. This module proves two things and nothing weaker:

**The positive end-to-end.** ``mint_trust_log`` publishes a real, root-signed export via
the PRODUCTION builder; a project bundle built in the same trust domain (a *different*
project — the log is a separate chain, §5.10 step 5) is signed by a key the log enrolled;
and ``verify_audit_bundle_v3`` reaches ``externally_authenticated`` when handed the
verified export and drops to ``unauthenticated`` without it. Offline == online, by
construction: the verdict is earned by replaying the events under the SAME
``verify_trust_log_chain`` the live store uses.

**One test per attack class, each fail-closed.** An export ASSERTS nothing about the root
set — it is DERIVED by replay — so every forgery below is refused by a named ``reason``,
never a warning. Database-free on purpose (see ``_wi337_fixtures``): the byte contract and
the fail-closed refusals are the whole of what a published document promises, and a
conformance test that only runs where PostgreSQL is reachable silently stops running. The
live ceremony (``regista trust publish-log`` against a real store) is a separate concern.
"""

from __future__ import annotations

import base64
import copy
import json
import types
from typing import Any

import pytest
from _trust_fixtures import mint_co_signed, mint_solo
from _trust_log_fixtures import TrustLogKey
from _wi337_fixtures import mint_trust_log
from test_bundle_v3 import BOOTSTRAP, WORKER, _Chain

from regista._bundle import (
    AcceptBundledKeys,
    BundleApplicability,
    PolicyKeyResolver,
    TrustPolicy,
    _trust_log_export_material,
    verify_audit_bundle_v3,
)
from regista._bundle_v3 import canonical_bundle_bytes
from regista._errors import ErrorCode, RegistaError
from regista._jcs import canonicalize
from regista._testing_v6 import make_v6_keyset
from regista._trust_log_export import (
    export_referents,
    sign_trust_log_export,
    trust_log_export_digest,
    verify_trust_log_export,
)
from regista._verification import TrustedKeySource


def _reason(error: RegistaError) -> str | None:
    return error.detail.get("reason") if isinstance(error.detail, dict) else None


def _refuses(fn: Any, /, **kwargs: Any) -> RegistaError:
    with pytest.raises(RegistaError) as excinfo:
        fn(**kwargs)
    return excinfo.value


# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------


def _tlk(keyset: Any, principal_id: str) -> TrustLogKey:
    """The bundle keyset's key for *principal_id*, as a trust-log key (same bytes)."""

    k = keyset.key_for(principal_id)
    return TrustLogKey(
        key_id=k.key_id, seed=k.seed, public_key=k.public_key, fingerprint=k.fingerprint
    )


def _offline_scenario(tmp_path: Any) -> dict[str, Any]:
    """A published export + a project bundle whose keys the log enrolled.

    Returns everything the tests below vary: the fixture genesis, the memory log, the
    verified export (pinned with ``expect_head``), the full trust policy, and the bundle
    file path. The bundle's BOOTSTRAP and WORKER keys are enrolled in the log under their
    OWN principal ids, so the genesis's ``bootstrap_key_acceptance`` resolves to a real
    ``principal_key_enrolled`` referent (§5.10 step 5) and every event roots externally.
    """

    (tmp_path / "keys").mkdir(exist_ok=True)
    keyset = make_v6_keyset(str(tmp_path / "keys"))
    fixture = mint_solo()
    log = mint_trust_log(genesis=fixture)
    enrol_hash: dict[str, str] = {}
    for principal in (BOOTSTRAP, WORKER):
        log.register(principal)
        enrol_hash[principal] = log.enrol(principal, _tlk(keyset, principal))

    chain = _Chain(
        keyset,
        trust_domain_id=fixture.trust_domain_id,
        bootstrap_trust_event_hash=enrol_hash[BOOTSTRAP],
    )
    export_doc = log.export()
    verification = verify_trust_log_export(
        export_doc,
        genesis_document=fixture.document,
        expect_head=(log.hashes[-1], len(log.events)),
    )
    policy = TrustPolicy(
        trust_domain_id=fixture.trust_domain_id,
        required_root_governance=("solo",),
        accepted_project_instance_ids=frozenset([chain.project_instance_id]),
        bundle_signing={"permitted_principal_ids": [WORKER], "permitted_schemes": ["ed25519"]},
        source="trust_policy",
    )
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_bytes(canonical_bundle_bytes(chain.build()))
    return {
        "keyset": keyset,
        "fixture": fixture,
        "log": log,
        "export_doc": export_doc,
        "verification": verification,
        "policy": policy,
        "bundle_path": str(bundle_path),
        "chain": chain,
    }


# ---------------------------------------------------------------------------
# Positive end-to-end
# ---------------------------------------------------------------------------


def test_project_bundle_reaches_externally_authenticated_offline(tmp_path: Any) -> None:
    """The WI-337 win: a project bundle + a verified export == externally_authenticated.

    No database, no fetch: the export was replayed from the auditor's own pinned genesis,
    and the non-root worker key's chain to the pinned root is completed by that replay.
    """

    s = _offline_scenario(tmp_path)
    report = verify_audit_bundle_v3(
        s["bundle_path"], s["policy"], trust_log=s["verification"]
    ).to_dict()

    assert report["applicability"] == BundleApplicability.EXTERNALLY_AUTHENTICATED.value
    assert report["membership_signature"] == "valid_external_root"
    assert report["event_authentication"] == "full"
    assert report["event_trust_root"] == "externally_pinned"
    assert report["governance"] == "matches_policy"
    assert report["findings"] == []


def test_same_bundle_without_the_export_is_only_unauthenticated(tmp_path: Any) -> None:
    """Withholding the export is never MORE permissive: the top verdict becomes unreachable.

    This is the honest pre-WI-337 shape — a self-contained project bundle cannot reach
    ``externally_authenticated`` off bundle-only material — proving the export is load
    bearing rather than decorative.
    """

    s = _offline_scenario(tmp_path)
    report = verify_audit_bundle_v3(s["bundle_path"], s["policy"]).to_dict()
    assert report["applicability"] == BundleApplicability.UNAUTHENTICATED.value


def test_export_verify_reports_no_downgrade_between_online_and_offline(tmp_path: Any) -> None:
    """The verified export's derived head/count/actives ARE the replay's, not the claims."""

    s = _offline_scenario(tmp_path)
    v = s["verification"]
    log = s["log"]
    assert v.head_event_hash == log.hashes[-1]
    assert v.event_count == len(log.events)
    assert len(v.verified_root_signatures) == v.root_threshold
    # The referents offered are exactly the walked events (nothing revoked here).
    assert len(export_referents(v)) == v.event_count


# ---------------------------------------------------------------------------
# Attack class: cross-domain laundering (checked BEFORE any crypto)
# ---------------------------------------------------------------------------


def test_export_from_a_different_domain_is_refused(tmp_path: Any) -> None:
    log = mint_trust_log(principals={"agent:w1": "pk_w1"})
    export = log.export()
    other = mint_solo()  # a different trust domain entirely
    error = _refuses(
        verify_trust_log_export, document=export, genesis_document=other.document
    )
    assert error.code == ErrorCode.TRUST_LOG_EXPORT_UNVERIFIED
    assert _reason(error) == "trust_domain_mismatch"


def test_bundle_refuses_a_log_bound_to_another_domain(tmp_path: Any) -> None:
    """§4.4 criterion 4: a log for a different domain is a hard invalid, not a downgrade."""

    s = _offline_scenario(tmp_path)
    # A fully valid export — but for a DIFFERENT trust domain than the bundle/policy.
    other_fixture = mint_solo()
    other_log = mint_trust_log(genesis=other_fixture, principals={"agent:x": "pk_x"})
    other_verification = verify_trust_log_export(
        other_log.export(),
        genesis_document=other_fixture.document,
        expect_head=(other_log.hashes[-1], len(other_log.events)),
    )
    report = verify_audit_bundle_v3(
        s["bundle_path"], s["policy"], trust_log=other_verification
    ).to_dict()
    assert report["applicability"] == BundleApplicability.INVALID.value
    assert any("trust_log" in f for f in report["findings"])


# ---------------------------------------------------------------------------
# Attack class: forged / self-authorising / removed-root
# ---------------------------------------------------------------------------


def test_signature_by_a_non_root_key_is_refused(tmp_path: Any) -> None:
    """Signatures are checked against the REPLAY-derived set, never a self-asserted one."""

    log = mint_trust_log(principals={"agent:w1": "pk_w1"})
    export = log.export(sign=False)
    stranger = TrustLogKey.mint("k_stranger")
    forged = sign_trust_log_export(
        export, seed=stranger.seed, signer_id="root-x", fingerprint=stranger.fingerprint
    )
    error = _refuses(
        verify_trust_log_export, document=forged, genesis_document=log.genesis.document
    )
    assert _reason(error) == "root_signer_not_active"


def test_root_signature_that_does_not_verify_is_refused(tmp_path: Any) -> None:
    log = mint_trust_log(principals={"agent:w1": "pk_w1"})
    export = log.export()
    tampered = copy.deepcopy(export)
    tampered["root_signatures"][0]["signature"] = base64.b64encode(bytes(64)).decode()
    error = _refuses(
        verify_trust_log_export, document=tampered, genesis_document=log.genesis.document
    )
    assert _reason(error) == "root_signature_invalid"


def test_removed_root_cannot_reauthorise_the_log_that_records_its_removal(
    tmp_path: Any,
) -> None:
    """The removed-root forgery: after A/B -> A/C, a B signature over the export is refused.

    B still holds its key, but the replay of the log — which contains the very
    ``trust_root_rotated`` event that removed B — derives the current set as {A, C}. B is
    not in it, so its signature cannot re-authorise the publication.
    """

    g = mint_co_signed(threshold=2, signer_count=2)
    log = mint_trust_log(genesis=g)
    roots = [
        TrustLogKey(
            key_id=f"k_{sid}",
            seed=g.seeds[sid],
            public_key=g.public_keys[sid],
            fingerprint=g.fingerprints[sid],
        )
        for sid in g.signer_ids
    ]
    root_a, root_b = roots[0], roots[1]
    root_c = TrustLogKey.mint("k_root_c")
    log.rotate_root(
        added=[root_c],
        removed_fingerprints=[root_b.fingerprint],
        new_threshold=2,
        signing_root_keys=[root_a, root_b],
    )

    core = log.export(sign=False)
    # The honest publication is signed by the NEW set {A, C} and verifies.
    good = core
    for sid, key in (("root-a", root_a), ("root-c", root_c)):
        good = sign_trust_log_export(
            good, seed=key.seed, signer_id=sid, fingerprint=key.fingerprint
        )
    verified = verify_trust_log_export(good, genesis_document=g.document)
    assert root_b.fingerprint not in verified.root_signer_fingerprints
    assert root_c.fingerprint in verified.root_signer_fingerprints

    # The forgery: A (still a root) plus B (removed). B's signature is by a non-active key.
    forged = core
    for sid, key in (("root-a", root_a), ("root-b", root_b)):
        forged = sign_trust_log_export(
            forged, seed=key.seed, signer_id=sid, fingerprint=key.fingerprint
        )
    error = _refuses(verify_trust_log_export, document=forged, genesis_document=g.document)
    assert _reason(error) == "root_signer_not_active"


def test_unsigned_export_authorises_nothing(tmp_path: Any) -> None:
    log = mint_trust_log(principals={"agent:w1": "pk_w1"})
    export = log.export(sign=False)
    # Present the (empty) signature sections so the refusal is the intended
    # "root_signatures is empty: an unsigned export authorises nothing", not the earlier
    # closed-key-set violation the builder's section-less output would trip.
    export = {**export, "root_signatures": [], "countersignatures": [], "anchors": []}
    error = _refuses(
        verify_trust_log_export, document=export, genesis_document=log.genesis.document
    )
    assert _reason(error) == "root_signatures_absent"


# ---------------------------------------------------------------------------
# Attack class: sub-threshold / downgrade / claim-vs-replay disagreement
# ---------------------------------------------------------------------------


def test_sub_threshold_signatures_are_refused(tmp_path: Any) -> None:
    g = mint_co_signed(threshold=2, signer_count=2)
    log = mint_trust_log(genesis=g, principals={"agent:w1": "pk_w1"})
    export = log.export(sign=False)
    one = log.sign(export, signer_ids=[g.signer_ids[0]])  # only 1 of 2
    error = _refuses(verify_trust_log_export, document=one, genesis_document=g.document)
    assert _reason(error) == "root_threshold_not_met"


def test_restated_threshold_below_the_replay_is_refused(tmp_path: Any) -> None:
    """A downgrade claim inside signed bytes: the restatement must EQUAL the replay."""

    g = mint_co_signed(threshold=2, signer_count=2)
    log = mint_trust_log(genesis=g, principals={"agent:w1": "pk_w1"})
    export = log.export()
    tampered = copy.deepcopy(export)
    tampered["root_governance"]["threshold"] = 1
    error = _refuses(verify_trust_log_export, document=tampered, genesis_document=g.document)
    # The governance mode is derived from (threshold, signer_count), so a lowered threshold
    # first contradicts the derived mode — either way it is refused, never accepted.
    assert _reason(error) in {"governance_mode_mismatch", "threshold_contradicts_replay"}


def test_declared_head_that_is_not_the_replay_head_is_refused(tmp_path: Any) -> None:
    log = mint_trust_log(principals={"agent:w1": "pk_w1"})
    export = log.export()
    tampered = copy.deepcopy(export)
    tampered["trust_log"]["head_event_hash"] = "sha256:" + "ab" * 32
    error = _refuses(
        verify_trust_log_export, document=tampered, genesis_document=log.genesis.document
    )
    # Re-signing is not required: the head is a signed claim, so a mismatch is caught either
    # as a non-canonical/altered document or as a head-vs-replay disagreement.
    assert _reason(error) in {"head_contradicts_replay", "not_canonical_publication_bytes"}


# ---------------------------------------------------------------------------
# Attack class: truncation (a prefix of a hash chain is a valid hash chain)
# ---------------------------------------------------------------------------


def _prefix_export(full: Any, keep: int) -> dict[str, Any]:
    from regista._trust_log_export import OfflineTrustLogMaterial, build_trust_log_export

    material = OfflineTrustLogMaterial(events=tuple(full.events[:keep]), challenges={})
    doc = build_trust_log_export(
        material, genesis_document=full.genesis.document, created_at="2026-08-20T12:00:00.000000Z"
    )
    return full.sign(doc)


def test_a_published_prefix_replays_cleanly_but_reports_truncation_undetectable(
    tmp_path: Any,
) -> None:
    full = mint_trust_log(principals={"agent:w1": "pk_w1"})
    prefix = _prefix_export(full, keep=2)  # genesis + registrar only
    v = verify_trust_log_export(prefix, genesis_document=full.genesis.document)
    assert v.tail_truncation_undetectable is True
    assert v.event_count == 2


def test_expect_head_detects_the_prefix(tmp_path: Any) -> None:
    full = mint_trust_log(principals={"agent:w1": "pk_w1"})
    full_v = verify_trust_log_export(full.export(), genesis_document=full.genesis.document)
    prefix = _prefix_export(full, keep=2)
    error = _refuses(
        verify_trust_log_export,
        document=prefix,
        genesis_document=full.genesis.document,
        expect_head=(full_v.head_event_hash, full_v.event_count),
    )
    assert _reason(error) == "head_pin_contradicted"


def test_must_cover_detects_the_prefix(tmp_path: Any) -> None:
    full = mint_trust_log(principals={"agent:w1": "pk_w1"})
    full_v = verify_trust_log_export(full.export(), genesis_document=full.genesis.document)
    prefix = _prefix_export(full, keep=2)
    error = _refuses(
        verify_trust_log_export,
        document=prefix,
        genesis_document=full.genesis.document,
        must_cover={"head_event_hash": full_v.head_event_hash},
    )
    assert _reason(error) == "pinned_checkpoint_not_covered"


def test_bundle_refuses_an_unpinned_export_for_authority(tmp_path: Any) -> None:
    """A truncation pin is MANDATORY for authority — stricter than Rule H, on purpose.

    An unpinned export could be a prefix that hides a revocation, so granting authority off
    it is a named refusal rather than a quiet demotion.
    """

    s = _offline_scenario(tmp_path)
    unpinned = verify_trust_log_export(
        s["export_doc"], genesis_document=s["fixture"].document
    )
    assert unpinned.tail_truncation_undetectable is True
    error = _refuses(
        verify_audit_bundle_v3,
        bundle_path=s["bundle_path"],
        trust=s["policy"],
        trust_log=unpinned,
    )
    assert _reason(error) == "trust_log_export_unpinned"


def test_bundle_refuses_a_must_cover_only_export_for_authority(tmp_path: Any) -> None:
    """Sol #2: a must_cover (checkpoint) satisfaction alone is NOT the top verdict.

    Covering a min_trust_log_checkpoint proves the export reaches AT LEAST that point, not
    that it is the whole log — a STALE checkpoint predating a rotation would let a
    truncated export hide the later events yet still cover the checkpoint. So the bundle
    authority path requires an EXACT head pin; a must_cover-only presentation (which has
    ``tail_truncation_undetectable=False`` but ``head_pin_checked=False``) is refused
    rather than reaching ``externally_authenticated``, and must_cover keeps its honest
    lesser role (it still refuses a prefix that does not even reach the checkpoint).
    """

    s = _offline_scenario(tmp_path)
    log = s["log"]
    must_cover_only = verify_trust_log_export(
        s["export_doc"],
        genesis_document=s["fixture"].document,
        must_cover={"head_event_hash": log.hashes[-1]},
    )
    # It is pinned (not fully unpinned) but only by a checkpoint cover, not an exact head.
    assert must_cover_only.tail_truncation_undetectable is False
    assert must_cover_only.head_pin_checked is False
    error = _refuses(
        verify_audit_bundle_v3,
        bundle_path=s["bundle_path"],
        trust=s["policy"],
        trust_log=must_cover_only,
    )
    assert _reason(error) == "trust_log_export_head_pin_required"


def test_bundle_refuses_an_unsigned_or_subthreshold_export_for_authority(
    tmp_path: Any,
) -> None:
    """Opus footgun: an export verified with ``require_signatures=False`` grants NOTHING.

    ``verify_trust_log_export(require_signatures=False)`` is the builder's pre-sign
    self-check; it skips the root-threshold gate yet still returns a verification object.
    A consumer must not draw authority from that: the bundle path re-asserts signature
    sufficiency, so an UNSIGNED export (pinned with a valid exact head) that would
    otherwise drive the bundle to ``externally_authenticated`` is refused instead.
    """

    s = _offline_scenario(tmp_path)
    log = s["log"]
    unsigned = verify_trust_log_export(
        log.export(sign=False),
        genesis_document=s["fixture"].document,
        expect_head=(log.hashes[-1], len(log.events)),
        require_signatures=False,
    )
    # The self-check produced a pinned verification with NO verified root signatures.
    assert unsigned.head_pin_checked is True
    assert unsigned.verified_root_signatures == ()
    assert unsigned.root_threshold >= 1
    error = _refuses(
        verify_audit_bundle_v3,
        bundle_path=s["bundle_path"],
        trust=s["policy"],
        trust_log=unsigned,
    )
    assert error.code == ErrorCode.TRUST_LOG_EXPORT_AUTHORITY_INSUFFICIENT
    assert _reason(error) == "trust_log_export_signatures_insufficient"


# ---------------------------------------------------------------------------
# Attack class: tampered event / non-canonical bytes / substitution / ordering
# ---------------------------------------------------------------------------


def test_tampered_event_bytes_fail_closed(tmp_path: Any) -> None:
    log = mint_trust_log(principals={"agent:w1": "pk_w1"})
    export = log.export()
    tampered = copy.deepcopy(export)
    # Flip a byte in a carried event's signature: its v6 event hash changes, so the chain
    # linkage (or the array's chain-order requirement) breaks. Any of these is fail-closed.
    raw = bytearray(base64.b64decode(tampered["events"][2]["signature"]))
    raw[0] ^= 0x01
    tampered["events"][2]["signature"] = base64.b64encode(bytes(raw)).decode()
    error = _refuses(
        verify_trust_log_export, document=tampered, genesis_document=log.genesis.document
    )
    # Any TRUST_LOG* refusal is fail-closed: the tamper breaks the hash chain, so the walk
    # rejects it (the chain does not reach every stored event) before any verdict is formed.
    assert error.code.value.startswith("TRUST_LOG")


def test_non_canonical_publication_bytes_are_refused(tmp_path: Any) -> None:
    log = mint_trust_log(principals={"agent:w1": "pk_w1"})
    export = log.export()
    non_canonical = (json.dumps(export) + " ").encode("utf-8")
    error = _refuses(
        verify_trust_log_export,
        document=export,
        genesis_document=log.genesis.document,
        file_bytes=non_canonical,
    )
    assert _reason(error) == "not_canonical_publication_bytes"


def test_substituted_artifact_is_caught_by_expect_digest(tmp_path: Any) -> None:
    log = mint_trust_log(principals={"agent:w1": "pk_w1"})
    export = log.export()
    error = _refuses(
        verify_trust_log_export,
        document=export,
        genesis_document=log.genesis.document,
        expect_digest="sha256:" + "00" * 32,
    )
    assert _reason(error) == "export_digest_mismatch"
    # And the honest digest round-trips.
    good = verify_trust_log_export(
        export,
        genesis_document=log.genesis.document,
        expect_digest=trust_log_export_digest(export),
    )
    assert good.document_digest == trust_log_export_digest(export)


def test_events_out_of_chain_order_are_refused(tmp_path: Any) -> None:
    log = mint_trust_log(principals={"agent:w1": "pk_w1"})
    export = log.export()
    shuffled = copy.deepcopy(export)
    shuffled["events"][1], shuffled["events"][2] = (
        shuffled["events"][2],
        shuffled["events"][1],
    )
    # A JCS re-serialisation keeps the (now wrong) array order inside the signed bytes.
    shuffled_bytes = canonicalize(shuffled)
    error = _refuses(
        verify_trust_log_export,
        document=shuffled,
        genesis_document=log.genesis.document,
        file_bytes=shuffled_bytes,
    )
    assert _reason(error) in {"events_not_in_chain_order", "not_canonical_publication_bytes"}


# ---------------------------------------------------------------------------
# Attack class: revoked-key laundering
# ---------------------------------------------------------------------------


def test_revoked_key_introduction_is_withheld_from_referents(tmp_path: Any) -> None:
    """A key the log REVOKED must not authenticate anything — its enrolment is withheld.

    Revocation (``compromised``) is the estate saying the key's signatures may be
    forgeries, so ``export_referents`` withholds the enrolment/rotation that introduced it.
    """

    log = mint_trust_log(principals={"agent:w1": "pk_w1"})
    log.revoke("agent:w1", "pk_w1")
    v = verify_trust_log_export(log.export(), genesis_document=log.genesis.document)
    assert len(v.revoked_key_introductions) == 1
    withheld = set(v.revoked_key_introductions)
    referent_hashes = set(export_referents(v))
    assert withheld.isdisjoint(referent_hashes)
    # Exactly the enrolment is withheld; every other event is still offered.
    assert len(referent_hashes) == v.event_count - len(withheld)


def test_rotation_supersedes_the_old_key_but_keeps_its_history(tmp_path: Any) -> None:
    """K1→K2 rotation: K1 stays a historical referent but is NOT current authority.

    This is Sol #3/#4. The replay must record supersession so the OFFLINE classification
    matches the online resolver (`_genesis_open.resolve_enrolled_key`), which already
    excludes rotated-out keys. Two properties, both fail-closed:

    1. **History is preserved.** Superseded is not revoked: the enrolment event that
       INTRODUCED K1 stays in ``export_referents``. (The fixture's enrolment envelope is
       REGISTRAR-signed, so this does not prove a K1-signed historical enrolment; what it
       proves is that K1's introduction is RETAINED as a referent, and K1's own signing
       capability is demonstrated by the rotation's old-key co-signature.) A rotation thus
       does not retroactively unauthenticate honest history.
    2. **K1 is no longer current authority.** The replay marks K1 SUPERSEDED, so it is not
       in ``active_principal_keys`` and ``PolicyKeyResolver`` never returns it as
       ``EXTERNALLY_PINNED`` — an attacker retaining K1 cannot authenticate NEW material.
       K2, the incoming key, IS current authority.
    """

    principal = "agent:w1"
    k1 = TrustLogKey.mint("pk_w1")
    k2 = TrustLogKey.mint("pk_w2")
    log = mint_trust_log()
    log.register(principal)
    enrol_k1 = log.enrol(principal, k1)
    log.rotate(principal, supersedes=k1, new_key=k2)

    v = verify_trust_log_export(
        log.export(),
        genesis_document=log.genesis.document,
        expect_head=(log.hashes[-1], len(log.events)),
    )

    # The replay records supersession as observable state, not silence.
    status = v.chain.state.principal_key_status
    assert status[(principal, "pk_w1")] == "superseded"
    assert status[(principal, "pk_w2")] == "active"

    # (1) A rotation is not a revocation — nothing is withheld from referents, and K1's
    # own enrolment event is still offered as a historical referent.
    assert v.revoked_key_introductions == ()
    referents = export_referents(v)
    assert len(referents) == v.event_count
    assert enrol_k1 in referents

    # (2) The offline authority classification: K1 is superseded (not current), K2 active.
    authority = _trust_log_export_material(v, None)
    assert "pk_w2" in authority.active_principal_keys
    assert "pk_w1" not in authority.active_principal_keys
    assert "pk_w1" in authority.superseded_principal_keys
    assert "pk_w1" not in authority.revoked_principal_keys

    # And the resolver never returns the superseded key as externally pinned. K2 does.
    resolver = PolicyKeyResolver(
        material_by_key_id={},
        principal_by_key_id={},
        pinned_fingerprints=frozenset(),
        trust_log=authority,
    )
    assert resolver.resolve("pk_w1") is None
    resolved_k2 = resolver.resolve("pk_w2")
    assert resolved_k2 is not None
    assert resolved_k2.source is TrustedKeySource.EXTERNALLY_PINNED


def test_rotation_chain_supersedes_each_current_key_leaving_exactly_one_active(
    tmp_path: Any,
) -> None:
    """WI-347: a legitimate K1→K2→K3 chain (each rotation names the CURRENT active key)
    verifies, and leaves EXACTLY one active key — the invariant the projection enforces.

    Each rotation supersedes the one live key, so replay lands on the same single-active
    set the projection applier reaches by superseding every active key on each new key.
    This is the positive companion to the refusal below: the guard does not over-refuse a
    well-formed chain.
    """

    principal = "agent:w1"
    k1 = TrustLogKey.mint("pk_w1")
    k2 = TrustLogKey.mint("pk_w2")
    k3 = TrustLogKey.mint("pk_w3")
    log = mint_trust_log()
    log.register(principal)
    log.enrol(principal, k1)
    log.rotate(principal, supersedes=k1, new_key=k2)  # names the active key (K1)
    log.rotate(principal, supersedes=k2, new_key=k3)  # names the active key (K2)

    v = verify_trust_log_export(
        log.export(),
        genesis_document=log.genesis.document,
        expect_head=(log.hashes[-1], len(log.events)),
    )
    status = v.chain.state.principal_key_status
    assert status[(principal, "pk_w1")] == "superseded"
    assert status[(principal, "pk_w2")] == "superseded"
    assert status[(principal, "pk_w3")] == "active"
    # The invariant, stated directly: at most one active key per principal.
    active = [k for (p, k), s in status.items() if p == principal and s == "active"]
    assert active == ["pk_w3"]

    authority = _trust_log_export_material(v, None)
    assert "pk_w3" in authority.active_principal_keys
    assert "pk_w1" not in authority.active_principal_keys
    assert "pk_w2" not in authority.active_principal_keys


def test_rotation_superseding_a_non_current_key_is_refused_on_replay(
    tmp_path: Any,
) -> None:
    """WI-347 (Sol #3 / Opus finding #1): a rotation that names a SUPERSEDED key is
    refused by the replay — closing a pre-existing rotation-admission gap.

    Without the guard, enrol K1 → rotate K1→K2 → rotate K1→K3 all verified, because the
    second rotation named K1 (now merely SUPERSEDED, not revoked). That left K2 AND K3
    both active — a rotated-out key minting a new current-authority key and forking the
    active set. ``verify_trust_log_chain`` (via ``verify_trust_log_export``) must refuse.
    The admission half (``append_trust_log_event``) is covered in
    ``tests/test_wi301_trust_log_writer.py`` — both route through the same
    ``_classify_rotation`` chokepoint, so neither the public replay API nor the writer can
    slip past it.
    """

    from regista._trust_log_writer import verify_trust_log_chain

    principal = "agent:w1"
    k1 = TrustLogKey.mint("pk_w1")
    k2 = TrustLogKey.mint("pk_w2")
    k3 = TrustLogKey.mint("pk_w3")
    log = mint_trust_log()
    log.register(principal)
    log.enrol(principal, k1)
    log.rotate(principal, supersedes=k1, new_key=k2)
    log.rotate(principal, supersedes=k1, new_key=k3)  # ATTACK: supersedes the dead K1

    # Drive the replay walk itself — the same ``verify_trust_log_chain`` that both the
    # export builder and ``verify_trust_log_export`` route through — so the refusal is
    # the replay's, not a byproduct of signing or bundle admission.
    error = _refuses(
        verify_trust_log_chain,
        conn=log.material(),
        genesis_document=log.genesis.document,
    )
    assert error.code is ErrorCode.TRUST_LOG_ROTATION_SUPERSEDES_INACTIVE_KEY
    assert _reason(error) == "superseded_key_superseded"

    # And the honest export builder cannot even PRODUCE such a document — it replays first.
    build_error = _refuses(lambda: log.export())
    assert build_error.code is ErrorCode.TRUST_LOG_ROTATION_SUPERSEDES_INACTIVE_KEY


def test_reenrol_same_material_under_a_different_key_id_is_refused_on_replay(
    tmp_path: Any,
) -> None:
    """WI-348: a second ``principal_key_enrolled`` carrying an ALREADY-ACTIVE key's exact
    material under a DIFFERENT key_id is refused by the REPLAY — closing the enrolment
    twin of the WI-347 rotation gap.

    Without the guard the replay treated same-bytes as an idempotent no-op regardless of
    key_id and admitted the alias, leaving TWO active key_ids sharing one public key. The
    projection applier (``_apply_enrollment_projection``) supersedes every active row
    before inserting, so it holds only ONE active — replay and projection then DISAGREE.
    Worse, a later §5.6 rotation names ONE key_id; the twin stays active, so the
    rotated-out MATERIAL survives as current external authority via the alias and rotation
    fails to remove authority. ``verify_trust_log_chain`` (which both the export builder
    and ``verify_trust_log_export`` route through) must refuse. The admission half
    (``append_trust_log_event``) is covered in ``tests/test_wi301_trust_log_writer.py`` —
    both route through the same ``_check_enrollment_binds_fresh_key`` chokepoint.
    """

    from regista._trust_log_writer import verify_trust_log_chain

    principal = "agent:w1"
    k1 = TrustLogKey.mint("pk_w1")
    # The ALIAS: identical seed/public bytes/fingerprint, a DIFFERENT key_id — the
    # registrar-planted twin the claim requires.
    k1_alias = TrustLogKey(
        key_id="pk_w1_alias",
        seed=k1.seed,
        public_key=k1.public_key,
        fingerprint=k1.fingerprint,
    )
    log = mint_trust_log()
    log.register(principal)
    log.enrol(principal, k1)
    log.enrol(principal, k1_alias)  # ATTACK: same material, different key_id

    error = _refuses(
        verify_trust_log_chain,
        conn=log.material(),
        genesis_document=log.genesis.document,
    )
    assert error.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
    assert _reason(error) == "enrollment_alias_key_id_mismatch"

    # And the honest export builder cannot even PRODUCE such a document — it replays first.
    build_error = _refuses(lambda: log.export())
    assert build_error.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
    assert _reason(build_error) == "enrollment_alias_key_id_mismatch"


# ---------------------------------------------------------------------------
# Bundle admission gate: a verified log must still be BOUND to this bundle/pin
# ---------------------------------------------------------------------------


def test_trust_log_requires_a_full_trust_policy_not_accept_bundled(tmp_path: Any) -> None:
    s = _offline_scenario(tmp_path)
    error = _refuses(
        verify_audit_bundle_v3,
        bundle_path=s["bundle_path"],
        trust=AcceptBundledKeys(operator_acknowledges_no_external_trust=True),
        trust_log=s["verification"],
    )
    assert _reason(error) == "trust_log_requires_trust_policy"


def test_trust_log_must_be_a_verified_object_not_a_raw_document(tmp_path: Any) -> None:
    s = _offline_scenario(tmp_path)
    error = _refuses(
        verify_audit_bundle_v3,
        bundle_path=s["bundle_path"],
        trust=s["policy"],
        trust_log=s["export_doc"],  # a dict, never verified
    )
    assert _reason(error) == "trust_log_not_verified"


def test_bundle_evidence_contradicting_the_enrolled_key_is_invalid(tmp_path: Any) -> None:
    """§4.4 criterion 4: a bundled key that contradicts the log's enrolled one is invalid.

    Here the log enrols a DIFFERENT public key under the worker's ``key_id`` than the
    bundle's ``bundled_key_evidence`` carries. Binding 4 catches the disagreement and the
    verdict is a hard ``invalid`` — never a silent fall back to bundled-only.
    """

    (tmp_path / "keys").mkdir(exist_ok=True)
    keyset = make_v6_keyset(str(tmp_path / "keys"))
    fixture = mint_solo()
    log = mint_trust_log(genesis=fixture)
    bootstrap_hash = ""
    # Bootstrap enrolled truthfully so the genesis resolves; worker enrolled with a
    # MISMATCHED key sharing the bundle worker's key_id.
    log.register(BOOTSTRAP)
    bootstrap_hash = log.enrol(BOOTSTRAP, _tlk(keyset, BOOTSTRAP))
    worker_key = keyset.key_for(WORKER)
    impostor = TrustLogKey.mint(worker_key.key_id)  # same key_id, different bytes
    log.register(WORKER)
    log.enrol(WORKER, impostor)

    chain = _Chain(
        keyset,
        trust_domain_id=fixture.trust_domain_id,
        bootstrap_trust_event_hash=bootstrap_hash,
    )
    verification = verify_trust_log_export(
        log.export(),
        genesis_document=fixture.document,
        expect_head=(log.hashes[-1], len(log.events)),
    )
    policy = TrustPolicy(
        trust_domain_id=fixture.trust_domain_id,
        required_root_governance=("solo",),
        accepted_project_instance_ids=frozenset([chain.project_instance_id]),
        bundle_signing={"permitted_principal_ids": [WORKER], "permitted_schemes": ["ed25519"]},
        source="trust_policy",
    )
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_bytes(canonical_bundle_bytes(chain.build()))
    report = verify_audit_bundle_v3(
        str(bundle_path), policy, trust_log=verification
    ).to_dict()
    assert report["applicability"] == BundleApplicability.INVALID.value
    assert any("key_id" in f and "trust_log" in f for f in report["findings"])


# ---------------------------------------------------------------------------
# Attack class: the OFFLINE verify-catalog path must refuse an unpinned export
# (parity with the bundle path — Sol #1)
# ---------------------------------------------------------------------------


def _catalog_args(export_path: str, *, expect_head: str | None) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        trust_log_export=export_path,
        trust_log_export_digest=None,
        trust_log_export_expect_head=expect_head,
        trust_log_project=None,
    )


def test_catalog_offline_path_refuses_an_unpinned_export(tmp_path: Any) -> None:
    """Sol #1: ``verify-catalog --trust-log-export`` without an exact head pin is refused.

    The bundle path already refuses ``tail_truncation_undetectable`` in
    ``_trust_log_export_material``; the catalog authority path
    (``_cli._resolve_root_authority``) must do the SAME, or removed roots could publish a
    prefix ending before their rotation, sign it while still active in the prefix, and
    forge a catalog that ``verify-catalog`` accepts as current authority. This proves the
    parity: same class, same fail-closed answer, same ``trust_log_export_unpinned`` reason.
    """

    from regista._cli import _resolve_root_authority

    log = mint_trust_log(principals={"agent:w1": "pk_w1"})
    export_path = tmp_path / "export.json"
    export_path.write_bytes(canonicalize(log.export()))
    genesis = log.genesis.document

    error = _refuses(
        _resolve_root_authority,
        args=_catalog_args(str(export_path), expect_head=None),
        genesis_document=genesis,
    )
    assert error.code == ErrorCode.ESTATE_CATALOG_UNVERIFIED
    assert _reason(error) == "trust_log_export_unpinned"


def test_catalog_offline_path_accepts_an_exact_head_pinned_export(tmp_path: Any) -> None:
    """The honest counterpart: with the exact head pin, the same call derives authority."""

    from regista._cli import _resolve_root_authority

    log = mint_trust_log(principals={"agent:w1": "pk_w1"})
    export_path = tmp_path / "export.json"
    export_path.write_bytes(canonicalize(log.export()))
    genesis = log.genesis.document
    expect_head = f"{log.hashes[-1]}:{len(log.events)}"

    authority = _resolve_root_authority(
        _catalog_args(str(export_path), expect_head=expect_head), genesis
    )
    assert authority.source == "published_trust_log_export"
    assert authority.trust_log_event_count == len(log.events)
    assert authority.threshold >= 1
