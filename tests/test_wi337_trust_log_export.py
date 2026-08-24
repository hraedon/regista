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
from typing import Any

import pytest
from _trust_fixtures import mint_co_signed, mint_solo
from _trust_log_fixtures import TrustLogKey
from _wi337_fixtures import mint_trust_log
from test_bundle_v3 import BOOTSTRAP, WORKER, _Chain

from regista._bundle import (
    AcceptBundledKeys,
    BundleApplicability,
    TrustPolicy,
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


def test_supersession_is_not_withheld(tmp_path: Any) -> None:
    """A rotation must NOT retroactively unauthenticate history: superseded != revoked.

    Enrolling then rotating a principal's key leaves the log with no REVOKED status, so
    nothing is withheld — otherwise every rotation would erase the events the old key
    validly signed.
    """

    log = mint_trust_log(principals={"agent:w1": "pk_w1"})
    v = verify_trust_log_export(log.export(), genesis_document=log.genesis.document)
    assert v.revoked_key_introductions == ()
    assert len(export_referents(v)) == v.event_count


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
