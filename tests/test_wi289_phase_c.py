"""Bundle v3 Phase C — the trust root, the axis model and the verdict lattice.

``BUNDLE-V3.md`` §4 (trust root), §5 (axes + lattice) and §10 (auditor workflow), WI-289
Phase C. Everything here runs against real signed v6 envelopes built offline by the
``_Chain`` helper in ``test_bundle_v3`` — no store — so the whole of the trust model is
exercised without a database.

The pins these tests hardest, because they are the entire reason the phase exists:

* **not_checkable is not false.** For every policy-dependent axis, the absence of the input
  it needs reports the axis's honest not-checkable value, never a pass and never a failure
  (WI-269/S1).
* **the required argument is un-forgettable.** ``verify_audit_bundle_v3`` cannot be called
  without a ``TrustPolicy`` or ``AcceptBundledKeys`` (§4.1), and ``AcceptBundledKeys`` cannot
  be built without typing the acknowledgement out (§4.1).
* **the circularity ceiling holds.** A bundle-embedded key can never lift the verdict above
  ``bundle_rooted`` (Rule C).
"""

from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path
from typing import Any

import pytest
from test_bundle_v3 import WORKER, _Chain

from regista._bundle import (
    AcceptBundledKeys,
    BundleApplicability,
    EventAuthentication,
    EventTrustRootAxis,
    Governance,
    MembershipConsistency,
    MembershipSignature,
    RegistryChainConsistency,
    ScopeCorroboration,
    TrustPolicy,
    verify_audit_bundle_v3,
)
from regista._bundle_v3 import canonical_bundle_bytes
from regista._errors import RegistaError
from regista._testing_v6 import (
    BOOTSTRAP_PRINCIPAL,
    make_v6_keyset,
)

# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def keyset(tmp_path_factory: pytest.TempPathFactory) -> Any:
    return make_v6_keyset(tmp_path_factory.mktemp("phase_c_keys"))


@pytest.fixture(scope="module")
def chain(keyset: Any) -> _Chain:
    return _Chain(keyset)


@pytest.fixture()
def bundle_path(chain: _Chain, tmp_path: Path) -> Path:
    path = tmp_path / "bundle.json"
    path.write_bytes(canonical_bundle_bytes(chain.build()))
    return path


def _worker_bootstrap_fingerprints(chain: _Chain) -> list[str]:
    return [
        chain.keyset.key_for(WORKER).fingerprint,
        chain.keyset.key_for(BOOTSTRAP_PRINCIPAL).fingerprint,
    ]


def _full_policy(chain: _Chain, *, required_governance: tuple[str, ...] = ("solo",)) -> TrustPolicy:
    return TrustPolicy(
        trust_domain_id=chain.trust_domain_id,
        trust_domain_core_digest=chain.core_digest,
        genesis_document_digest=chain.document_digest,
        required_root_governance=required_governance,
        root_signer_fingerprints=frozenset(_worker_bootstrap_fingerprints(chain)),
        min_root_signatures=1,
        accepted_project_instance_ids=frozenset([chain.project_instance_id]),
        bundle_signing={
            "permitted_principal_ids": [WORKER],
            "permitted_schemes": ["ed25519"],
        },
        source="trust_policy",
    )


# ---------------------------------------------------------------------------
# §4.1 — the required-argument signature and the two trust types
# ---------------------------------------------------------------------------


class TestRequiredTrustArgument:
    def test_verify_refuses_a_non_trust_second_argument(self, bundle_path: Path) -> None:
        # There is no default and no None: the type is un-passable as anything else, and a
        # dynamic caller that supplies the wrong thing is refused rather than defaulted.
        with pytest.raises(RegistaError):
            verify_audit_bundle_v3(bundle_path, None)  # type: ignore[arg-type]
        with pytest.raises(RegistaError):
            verify_audit_bundle_v3(bundle_path, "trust me")  # type: ignore[arg-type]

    def test_accept_bundled_keys_cannot_be_built_without_the_acknowledgement(self) -> None:
        with pytest.raises(RegistaError):
            AcceptBundledKeys(operator_acknowledges_no_external_trust=False)

    def test_accept_bundled_keys_is_not_a_trust_policy(self) -> None:
        accept = AcceptBundledKeys(operator_acknowledges_no_external_trust=True)
        assert not isinstance(accept, TrustPolicy)
        # No implicit conversion: TrustPolicy is a different type entirely.
        assert type(accept) is AcceptBundledKeys


class TestTrustPolicyParsing:
    def test_a_policy_missing_a_required_field_is_refused(self) -> None:
        document = {
            "type": "regista.trust-policy",
            "version": 1,
            "trust_domain_id": str(uuid.uuid4()),
            # trust_domain_core_digest missing, plus others
        }
        with pytest.raises(RegistaError) as exc:
            TrustPolicy.from_mapping(document)
        assert "missing required" in str(exc.value)

    def test_a_full_policy_parses(self, tmp_path: Path) -> None:
        document = {
            "type": "regista.trust-policy",
            "version": 1,
            "trust_domain_id": str(uuid.uuid4()),
            "trust_domain_core_digest": "sha256:" + "0" * 64,
            "genesis_document_digest": "sha256:" + "1" * 64,
            "root_signer_fingerprints": ["ed25519:sha256:" + "a" * 64],
            "min_root_signatures": 1,
            "publication": {"kind": "git"},
            "accepted_project_instance_ids": [str(uuid.uuid4())],
            "min_trust_log_checkpoint": {"checkpoint_seq": 1},
            "bundle_signing": {"permitted_principal_ids": ["service:x"]},
            "legacy_epoch_policy": {"accept_legacy_shared_secret_events": False},
        }
        path = tmp_path / "policy.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        policy = TrustPolicy.from_file(path)
        assert policy.required_root_governance == ("co_signed",)  # strict default
        assert not policy.is_ad_hoc

    def test_ad_hoc_fingerprints_rejects_a_malformed_fingerprint(self) -> None:
        with pytest.raises(RegistaError):
            TrustPolicy.from_fingerprints(["not-a-fingerprint"])


# ---------------------------------------------------------------------------
# §5.1 — the axes, and the not_checkable ≠ false split
# ---------------------------------------------------------------------------


class TestAxesNotCheckableIsNotFalse:
    """Each policy-dependent axis reports its honest not-checkable value, never a pass."""

    def test_governance_is_unverified_restatement_under_ad_hoc_fingerprints(
        self, chain: _Chain, bundle_path: Path
    ) -> None:
        report = verify_audit_bundle_v3(
            bundle_path, TrustPolicy.from_fingerprints(_worker_bootstrap_fingerprints(chain))
        )
        # A9 is neither matches_policy (we did not replay) nor contradicts_policy (no
        # expectation was named). It is the honest middle: not a pass.
        assert report.governance is Governance.UNVERIFIED_RESTATEMENT

    def test_scope_corroboration_is_no_pin_when_no_head_supplied(
        self, chain: _Chain, bundle_path: Path
    ) -> None:
        report = verify_audit_bundle_v3(
            bundle_path, TrustPolicy.from_fingerprints(_worker_bootstrap_fingerprints(chain))
        )
        # A7 no_pin_supplied is not matches_pinned_head and not contradicts_pinned_head.
        assert report.scope_corroboration is ScopeCorroboration.NO_PIN_SUPPLIED

    def test_event_trust_root_is_bundled_only_not_absent_under_accept(
        self, bundle_path: Path
    ) -> None:
        report = verify_audit_bundle_v3(
            bundle_path, AcceptBundledKeys(operator_acknowledges_no_external_trust=True)
        )
        # The key BYTES are present (they travelled in the evidence), so A5 is bundled_only —
        # deliberately not `absent`, which would say no key material reached the verifier.
        assert report.event_trust_root is EventTrustRootAxis.BUNDLED_ONLY

    def test_membership_consistency_is_checkable_offline(
        self, bundle_path: Path
    ) -> None:
        report = verify_audit_bundle_v3(
            bundle_path, AcceptBundledKeys(operator_acknowledges_no_external_trust=True)
        )
        # A3 is structural: it does not need trust material, so a well-formed bundle reports
        # complete_for_claimed_scope regardless of the trust form.
        assert report.membership_consistency is MembershipConsistency.COMPLETE_FOR_CLAIMED_SCOPE

    def test_a_malformed_bundle_reports_axes_not_checkable_not_false(
        self, tmp_path: Path
    ) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text('{"statement": {"version": 2}}', encoding="utf-8")
        report = verify_audit_bundle_v3(
            bad, AcceptBundledKeys(operator_acknowledges_no_external_trust=True)
        )
        assert report.structure.value == "malformed"
        assert report.membership_consistency is MembershipConsistency.NOT_CHECKABLE
        assert report.event_authentication is EventAuthentication.NOT_CHECKABLE
        assert report.event_trust_root is EventTrustRootAxis.NOT_CHECKABLE
        assert report.applicability is BundleApplicability.INVALID


class TestScopeCorroborationAndRuleH:
    def test_a_matching_pinned_head_corroborates_and_clears_rule_h(
        self, chain: _Chain, bundle_path: Path
    ) -> None:
        report = verify_audit_bundle_v3(
            bundle_path,
            _full_policy(chain),
            known_head=(chain.hashes[-1], len(chain.records)),
        )
        assert report.scope_corroboration is ScopeCorroboration.MATCHES_PINNED_HEAD
        # Rule H: a head WAS pinned, so tail truncation is detectable.
        assert report.tail_truncation_undetectable is False

    def test_a_contradicting_pinned_head_is_invalid(
        self, chain: _Chain, bundle_path: Path
    ) -> None:
        report = verify_audit_bundle_v3(
            bundle_path,
            _full_policy(chain),
            known_head=("sha256:" + "9" * 64, 999),
        )
        assert report.scope_corroboration is ScopeCorroboration.CONTRADICTS_PINNED_HEAD
        assert report.applicability is BundleApplicability.INVALID

    def test_rule_h_flag_set_for_complete_store_without_a_pin(
        self, chain: _Chain, bundle_path: Path
    ) -> None:
        report = verify_audit_bundle_v3(bundle_path, _full_policy(chain))
        # complete-store + no pinned head → the flag is set, and it does NOT clamp.
        assert report.tail_truncation_undetectable is True


class TestRuleCCircularityCeiling:
    """G2 — Rule C is the SOLE trust-source ceiling and is demonstrably load-bearing.

    ``_summarize`` computes ``externally_authenticated`` from A2 + A4 alone; Rule C is what
    enforces the A5=externally_pinned requirement. Removing the Rule C clamp lets a root-signed
    statement over bundle-keyed events read as externally_authenticated — the F1 false
    assurance — so a unit test of the clamp fails if it is removed.
    """

    def test_accept_bundled_keys_is_clamped_to_bundle_rooted(
        self, bundle_path: Path
    ) -> None:
        report = verify_audit_bundle_v3(
            bundle_path, AcceptBundledKeys(operator_acknowledges_no_external_trust=True)
        )
        assert report.applicability is BundleApplicability.BUNDLE_ROOTED

    def _summarize(self, **overrides: Any) -> Any:
        from regista._bundle import _summarize

        kwargs: dict[str, Any] = {
            "membership_signature": MembershipSignature.VALID_EXTERNAL_ROOT,
            "membership_consistency": MembershipConsistency.COMPLETE_FOR_CLAIMED_SCOPE,
            "event_authentication": EventAuthentication.FULL,
            "event_trust_root": EventTrustRootAxis.EXTERNALLY_PINNED,
            "scope_corroboration": ScopeCorroboration.MATCHES_PINNED_HEAD,
            "governance": Governance.UNVERIFIED_RESTATEMENT,
            "accept_bundled": False,
            "any_bundle_embedded_used": False,
            "scope_kind": "complete-store",
            "policy_conformant": True,
            "trust_root_contradicts_genesis": False,
        }
        kwargs.update(overrides)
        return _summarize(**kwargs)[0]

    def test_rule_c_clamps_a_bundle_embedded_key_to_bundle_rooted(self) -> None:
        # A2 external + A4 full, but a bundle-embedded key was used (A5 bundled_only). Without
        # Rule C the base (A2 external + A4 full) would read externally_authenticated; the clamp
        # caps it at bundle_rooted. This is the exact false-assurance case F1 removes.
        assert (
            self._summarize(
                event_trust_root=EventTrustRootAxis.BUNDLED_ONLY,
                any_bundle_embedded_used=True,
            )
            is BundleApplicability.BUNDLE_ROOTED
        )

    def test_the_top_verdict_is_reachable_only_with_no_bundle_embedded_key(self) -> None:
        # The complement: A2 external + A4 full + A5 externally_pinned + no bundle-embedded key
        # → externally_authenticated. Proves the lattice's top verdict is computable and that
        # Rule C does not fire when it must not.
        assert (
            self._summarize()  # all-clean defaults
            is BundleApplicability.EXTERNALLY_AUTHENTICATED
        )

    def test_g1_bundled_only_reaches_bundle_rooted_under_a_trust_policy(self) -> None:
        # §5.2 "…and/or A5 = bundled_only" → bundle_rooted, reachable under a TrustPolicy (no
        # explicit AcceptBundledKeys), not only under acceptance (G1).
        assert (
            self._summarize(
                membership_signature=MembershipSignature.VALID_EXTERNAL_ROOT,
                event_authentication=EventAuthentication.LEGACY_PARTIAL,
                event_trust_root=EventTrustRootAxis.BUNDLED_ONLY,
                any_bundle_embedded_used=True,
            )
            is BundleApplicability.BUNDLE_ROOTED
        )


# ---------------------------------------------------------------------------
# §5.2 / F1 — externally_authenticated is chain-to-root, and WI-337-blocked offline
# ---------------------------------------------------------------------------


class TestExternallyAuthenticatedIsChainToRoot:
    def test_pinning_the_root_alone_does_not_reach_externally_authenticated(
        self, chain: _Chain, tmp_path: Path
    ) -> None:
        # The §10 workflow pins the ROOT and expects the acceptance chain to authenticate the
        # rest. That chain crosses into the trust log, which no offline verifier can check
        # (WI-337), so a complete-store project bundle does NOT reach externally_authenticated:
        # its genesis bootstrap is not externally authenticated, so A4 is not `full`.
        path = tmp_path / "bundle.json"
        path.write_bytes(canonical_bundle_bytes(chain.build()))
        root_only = TrustPolicy.from_fingerprints(
            [chain.keyset.key_for(BOOTSTRAP_PRINCIPAL).fingerprint]
        )
        report = verify_audit_bundle_v3(path, root_only)
        assert report.applicability is not BundleApplicability.EXTERNALLY_AUTHENTICATED
        assert report.event_authentication is not EventAuthentication.FULL

    def test_a_key_not_chained_to_a_pinned_root_is_not_externally_pinned(
        self, chain: _Chain, tmp_path: Path
    ) -> None:
        # A policy pinning an UNRELATED fingerprint: no event key matches it, none chains to it,
        # so every event key is bundled_only — never externally_pinned. (Red before the F1 fix
        # would have required pinning each event key's own fingerprint to lift A5.)
        path = tmp_path / "bundle.json"
        path.write_bytes(canonical_bundle_bytes(chain.build()))
        unrelated = TrustPolicy.from_fingerprints(["ed25519:sha256:" + "c" * 64])
        report = verify_audit_bundle_v3(path, unrelated)
        assert report.event_trust_root is EventTrustRootAxis.BUNDLED_ONLY
        assert report.applicability is not BundleApplicability.EXTERNALLY_AUTHENTICATED

    def test_no_trust_form_reaches_externally_authenticated_for_a_project_bundle(
        self, chain: _Chain, bundle_path: Path
    ) -> None:
        # The WI-337 block, stated as a property: no trust form the verifier accepts today can
        # lift a self-contained project bundle to externally_authenticated, because the event
        # keys' chain-to-root needs authenticated trust-log material that is not presentable
        # offline. Documented, not silently unreachable.
        for trust in (
            AcceptBundledKeys(operator_acknowledges_no_external_trust=True),
            TrustPolicy.from_fingerprints(_worker_bootstrap_fingerprints(chain)),
            _full_policy(chain),
        ):
            report = verify_audit_bundle_v3(bundle_path, trust)
            assert (
                report.applicability is not BundleApplicability.EXTERNALLY_AUTHENTICATED
            ), trust


class TestF2PolicyConformance:
    """F2 — every named full-policy requirement is evaluated; a contradiction → invalid."""

    def test_a_bogus_core_digest_is_invalid_not_a_pass(
        self, chain: _Chain, bundle_path: Path
    ) -> None:
        policy = _full_policy(chain)
        bogus = TrustPolicy(
            trust_domain_id=policy.trust_domain_id,
            trust_domain_core_digest="sha256:" + "0" * 64,  # wrong
            genesis_document_digest=policy.genesis_document_digest,
            required_root_governance=policy.required_root_governance,
            root_signer_fingerprints=policy.root_signer_fingerprints,
            min_root_signatures=1,
            accepted_project_instance_ids=policy.accepted_project_instance_ids,
            bundle_signing=policy.bundle_signing,
            source="trust_policy",
        )
        report = verify_audit_bundle_v3(bundle_path, bogus)
        assert report.applicability is BundleApplicability.INVALID
        assert report.policy_satisfied is not True

    def test_an_excluded_project_is_invalid_not_silently_disabled(
        self, chain: _Chain, bundle_path: Path
    ) -> None:
        policy = _full_policy(chain)
        excluded = TrustPolicy(
            trust_domain_id=policy.trust_domain_id,
            trust_domain_core_digest=policy.trust_domain_core_digest,
            genesis_document_digest=policy.genesis_document_digest,
            root_signer_fingerprints=policy.root_signer_fingerprints,
            min_root_signatures=1,
            accepted_project_instance_ids=frozenset([str(uuid.uuid4())]),  # not this project
            bundle_signing=policy.bundle_signing,
            source="trust_policy",
        )
        report = verify_audit_bundle_v3(bundle_path, excluded)
        assert report.applicability is BundleApplicability.INVALID
        assert report.policy_satisfied is not True

    def test_a_trust_root_contradicting_its_own_genesis_is_invalid(
        self, chain: _Chain, tmp_path: Path
    ) -> None:
        # The statement's trust_root restates the genesis digests; if it disagrees with the
        # bundle's OWN signed genesis event, that is a contradiction (invalid), not a finding.
        document = chain.build(
            trust_root=chain.trust_root(trust_domain_core_digest="sha256:" + "0" * 64)
        )
        path = tmp_path / "bundle.json"
        path.write_bytes(canonical_bundle_bytes(document))
        report = verify_audit_bundle_v3(
            path, AcceptBundledKeys(operator_acknowledges_no_external_trust=True)
        )
        assert report.applicability is BundleApplicability.INVALID
        assert any("trust_root_contradicts_genesis" in f for f in report.findings), report.findings


class TestF3BundleSigningAuthority:
    """F3 — a signer lacking bundle-signing authority gets A2 invalid, not a passing value."""

    def test_a_policy_forbidden_signer_is_invalid(
        self, chain: _Chain, bundle_path: Path
    ) -> None:
        policy = TrustPolicy(
            trust_domain_id=chain.trust_domain_id,
            trust_domain_core_digest=chain.core_digest,
            genesis_document_digest=chain.document_digest,
            root_signer_fingerprints=frozenset(_worker_bootstrap_fingerprints(chain)),
            min_root_signatures=1,
            accepted_project_instance_ids=frozenset([chain.project_instance_id]),
            bundle_signing={"permitted_principal_ids": [], "permitted_schemes": ["ed25519"]},
            source="trust_policy",
        )
        report = verify_audit_bundle_v3(bundle_path, policy)
        assert report.membership_signature is MembershipSignature.INVALID
        assert report.applicability is BundleApplicability.INVALID

    def test_an_in_scope_anchor_without_may_sign_bundles_makes_a2_invalid(self) -> None:
        # The builder refuses to SIGN a bundle whose key lacks may_sign_bundles (O3, fail-closed
        # at export), so this verify-side defence is exercised at the axis boundary against a
        # forged core report: a crypto-valid signature whose in-scope anchor was checked and
        # does NOT grant may_sign_bundles is A2 invalid, never valid_bundled_key (F3/§3.4).
        from types import SimpleNamespace

        from regista._bundle import _membership_signature_axis

        core = SimpleNamespace(
            statement_signature_valid=True,
            signer_authority_checked=True,
            signer_may_sign_bundles=False,  # in-scope anchor lacks the scope → failure
        )
        statement = {
            "signer": {
                "principal_id": "agent:worker",
                "key_id": "pk_x",
                "scheme_id": "ed25519",
                "fingerprint": "ed25519:sha256:" + "a" * 64,
            }
        }
        axis = _membership_signature_axis(
            statement=statement,
            core=core,  # type: ignore[arg-type]
            accept_bundled=True,
            policy=None,
            pinned_fingerprints=frozenset(),
            signer_public_key=b"\x00" * 32,
            scope_kind="complete-store",
            findings=[],
        )
        assert axis is MembershipSignature.INVALID


class TestF4RangeAwareCorroboration:
    """F4 — a whole-project head pin does not falsely invalidate a valid contiguous-range."""

    def _range_bundle(self, chain: _Chain, tmp_path: Path) -> Path:
        document = chain.build(
            event_records=chain.records[2:],
            authority_records=chain.records,
            scope_kind="contiguous-range",
            preceding_event_hash=chain.hashes[1],
        )
        path = tmp_path / "range.json"
        path.write_bytes(canonical_bundle_bytes(document))
        return path

    def test_a_project_head_pin_does_not_contradict_a_range(
        self, chain: _Chain, tmp_path: Path
    ) -> None:
        path = self._range_bundle(chain, tmp_path)
        # The §10-prescribed whole-project head (count=4) against a range of 2 events: a
        # subset, not a contradiction. A7 must be no_pin_supplied, and the verdict must not be
        # invalid *because of* the head.
        report = verify_audit_bundle_v3(
            path,
            AcceptBundledKeys(operator_acknowledges_no_external_trust=True),
            known_head=(chain.hashes[-1], len(chain.records)),
        )
        assert report.scope_corroboration is ScopeCorroboration.NO_PIN_SUPPLIED
        assert report.applicability is not BundleApplicability.INVALID

    def test_a_range_matching_its_own_head_corroborates(
        self, chain: _Chain, tmp_path: Path
    ) -> None:
        path = self._range_bundle(chain, tmp_path)
        # A pin that IS the range's own last event + count corroborates it.
        report = verify_audit_bundle_v3(
            path,
            AcceptBundledKeys(operator_acknowledges_no_external_trust=True),
            known_head=(chain.hashes[-1], 2),
        )
        assert report.scope_corroboration is ScopeCorroboration.MATCHES_PINNED_HEAD

    def test_an_outside_range_acceptance_is_not_registry_inconsistent(
        self, chain: _Chain, tmp_path: Path
    ) -> None:
        path = self._range_bundle(chain, tmp_path)
        report = verify_audit_bundle_v3(
            path, AcceptBundledKeys(operator_acknowledges_no_external_trust=True)
        )
        # The key acceptances lie outside the window; A8 must not read that as inconsistent.
        assert report.registry_chain_consistency is not RegistryChainConsistency.INCONSISTENT


class TestF5NotCheckableOnMalformed:
    """F5 — A10/A11/A12 do not assert a factual '0 conflicts' on input that never verified."""

    def test_malformed_input_does_not_claim_zero_conflicts(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text('{"statement": {"version": 2}}', encoding="utf-8")
        report = verify_audit_bundle_v3(
            bad, AcceptBundledKeys(operator_acknowledges_no_external_trust=True)
        )
        assert report.event_verification_ran is False
        rendered = report.to_dict()
        # not_checkable, not a false factual zero/empty.
        assert rendered["identity_conflict_count"] is None
        assert rendered["event_attribution_counts"] is None
        assert rendered["key_binding_counts"] is None

    def test_a_verified_bundle_does_report_the_counts(self, bundle_path: Path) -> None:
        report = verify_audit_bundle_v3(
            bundle_path, AcceptBundledKeys(operator_acknowledges_no_external_trust=True)
        )
        assert report.event_verification_ran is True
        assert report.to_dict()["event_attribution_counts"] is not None


# ---------------------------------------------------------------------------
# §3.2 item 2 — direct root_signatures[] verified against the policy
# ---------------------------------------------------------------------------


class TestDirectRootSignatures:
    def _root_signed_bundle(
        self, chain: _Chain, tmp_path: Path, *, root_principal: str
    ) -> tuple[Path, str]:
        from regista._bundle_v3 import (
            parse_bundle_v3_document,
            sign_statement,
            statement_signing_input,
        )
        from regista._signing_scheme import Ed25519Scheme

        document = chain.build()
        statement = dict(document["statement"])
        del statement["signer"]
        key = chain.keyset.key_for(root_principal)
        # The root signatures are over the statement WITHOUT signer and WITHOUT
        # root_signatures — they cannot cover themselves (§3.4).
        signature, _ = Ed25519Scheme().sign(
            statement_signing_input(statement), key.seed
        )
        statement["root_signatures"] = [
            {
                "signer_id": root_principal,
                "fingerprint": key.fingerprint,
                "public_key": key.public_key_b64,
                "signature": base64.b64encode(signature).decode(),
            }
        ]
        document = dict(document)
        document["statement"] = statement
        # Drop the now-stale single-signer statement_signature block: a root-threshold
        # statement carries its signatures in root_signatures[].
        document["statement_signature"] = sign_statement(
            statement, private_key=key.seed, key_id=key.key_id
        )
        path = tmp_path / "root_bundle.json"
        path.write_bytes(canonical_bundle_bytes(document))
        parse_bundle_v3_document(path.read_bytes())  # smoke: it parses
        return path, key.fingerprint

    def test_root_signatures_verify_against_a_pinned_root(
        self, chain: _Chain, tmp_path: Path
    ) -> None:
        path, fingerprint = self._root_signed_bundle(
            chain, tmp_path, root_principal=BOOTSTRAP_PRINCIPAL
        )
        policy = TrustPolicy.from_fingerprints([fingerprint])
        report = verify_audit_bundle_v3(path, policy)
        assert report.membership_signature is MembershipSignature.VALID_EXTERNAL_ROOT

    def test_root_signatures_below_threshold_are_invalid(
        self, chain: _Chain, tmp_path: Path
    ) -> None:
        path, fingerprint = self._root_signed_bundle(
            chain, tmp_path, root_principal=BOOTSTRAP_PRINCIPAL
        )
        # Require two signatures but the bundle carries one → below threshold → invalid.
        policy = TrustPolicy(
            trust_domain_id=chain.trust_domain_id,
            trust_domain_core_digest=chain.core_digest,
            genesis_document_digest=chain.document_digest,
            root_signer_fingerprints=frozenset([fingerprint]),
            min_root_signatures=2,
            accepted_project_instance_ids=frozenset([chain.project_instance_id]),
            bundle_signing={"permitted_principal_ids": [], "permitted_schemes": ["ed25519"]},
            source="trust_policy",
        )
        report = verify_audit_bundle_v3(path, policy)
        assert report.membership_signature is MembershipSignature.INVALID
        assert report.applicability is BundleApplicability.INVALID

    def test_root_signatures_not_matching_a_pin_do_not_authenticate(
        self, chain: _Chain, tmp_path: Path
    ) -> None:
        path, _fingerprint = self._root_signed_bundle(
            chain, tmp_path, root_principal=BOOTSTRAP_PRINCIPAL
        )
        # A different pin: the root signature verifies cryptographically but its signer is not
        # the one the auditor pinned, so it authenticates nothing (trust comes from the pin).
        policy = TrustPolicy.from_fingerprints(["ed25519:sha256:" + "e" * 64])
        report = verify_audit_bundle_v3(path, policy)
        assert report.membership_signature is MembershipSignature.INVALID
