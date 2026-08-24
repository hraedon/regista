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
import hashlib
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
from regista._bundle_v3 import canonical_bundle_bytes, digest_text
from regista._errors import RegistaError
from regista._testing_v6 import (
    BOOTSTRAP_PRINCIPAL,
    _test_digest,
    make_v6_keyset,
    v6_producer,
)
from regista._v6_referents import ReferentEvent

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


def _enrolment_referent(chain: _Chain, principal_id: str) -> ReferentEvent:
    """A synthetic trust-log ``principal_key_enrolled`` referent the acceptance points at.

    This is the trust-domain lifecycle material an auditor holds out of band (§8.4, §10). It
    lives on a separate chain (its own ``project_instance_id``), so it is never ordered into
    the project chain; it is a pure lookup by referent hash.
    """

    key = chain.keyset.key_for(principal_id)
    envelope = {
        "type": "regista.event",
        "version": 6,
        "project_instance_id": str(uuid.uuid4()),
        "trust_domain_id": chain.trust_domain_id,
        "event_id": str(uuid.uuid4()),
        "entity": {"kind": "principal", "id": str(uuid.uuid4())},
        "entity_seq": 1,
        "actor": {"principal_id": "service:root", "kind": "system", "metadata": {}},
        "signing": {"scheme_id": "ed25519", "key_id": "pk_root", "key_binding_event_hash": None},
        "authorization": {"mode": "direct", "credentials": []},
        "workflow": None,
        "occurred_at": "2026-08-23T11:00:00.000000Z",
        "transition": "principal_key_enrolled",
        "payload": {
            "type": "regista.principal-key-enrolled",
            "principal_id": principal_id,
            "key_id": key.key_id,
            "fingerprint": key.fingerprint,
            "public_key": key.public_key_b64,
        },
        "chain": {
            "hash_algorithm": "sha-256",
            "previous_entity_event_hash": None,
            "previous_project_event_hash": None,
        },
        "producer": v6_producer().as_envelope_member(),
    }
    return ReferentEvent(event_hash="placeholder", envelope=envelope)


def _presented_trust_log(chain: _Chain) -> dict[str, ReferentEvent]:
    """Enrolment referents keyed by the exact ``trust_event_hash`` each acceptance names."""

    genesis_teh = _test_digest("regista.testing.v6.test-root-enrolment:" + BOOTSTRAP_PRINCIPAL)
    worker_teh = digest_text(hashlib.sha256(b"enrolment").digest())
    return {
        genesis_teh: _enrolment_referent(chain, BOOTSTRAP_PRINCIPAL),
        worker_teh: _enrolment_referent(chain, WORKER),
    }


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
    def test_accept_bundled_keys_is_clamped_to_bundle_rooted(
        self, bundle_path: Path
    ) -> None:
        report = verify_audit_bundle_v3(
            bundle_path, AcceptBundledKeys(operator_acknowledges_no_external_trust=True)
        )
        assert report.applicability is BundleApplicability.BUNDLE_ROOTED

    def test_a_bundle_embedded_key_can_never_exceed_bundle_rooted(
        self, chain: _Chain, tmp_path: Path
    ) -> None:
        # A policy that pins NO fingerprints: every event key resolves as BUNDLE_EMBEDDED, so
        # Rule C forbids the verdict from ever exceeding bundle_rooted even with a full policy
        # and the trust log presented. The ceiling is mechanical, not a function of intent.
        path = tmp_path / "bundle.json"
        path.write_bytes(canonical_bundle_bytes(chain.build()))
        policy = TrustPolicy(
            trust_domain_id=chain.trust_domain_id,
            trust_domain_core_digest=chain.core_digest,
            genesis_document_digest=chain.document_digest,
            required_root_governance=("solo",),
            root_signer_fingerprints=frozenset(),  # nothing pinned
            min_root_signatures=1,
            accepted_project_instance_ids=frozenset([chain.project_instance_id]),
            bundle_signing={"permitted_principal_ids": [WORKER], "permitted_schemes": ["ed25519"]},
            source="trust_policy",
        )
        report = verify_audit_bundle_v3(
            path, policy, presented_trust_log=_presented_trust_log(chain)
        )
        # No pin matched, so nothing is externally rooted; the verdict never exceeds
        # bundle_rooted, and here it is even lower (unauthenticated) because no accept was given.
        rank = {
            BundleApplicability.INVALID: 0,
            BundleApplicability.UNAUTHENTICATED: 1,
            BundleApplicability.BUNDLE_ROOTED: 2,
            BundleApplicability.EXTERNALLY_AUTHENTICATED: 3,
        }
        assert rank[report.applicability] <= rank[BundleApplicability.BUNDLE_ROOTED]
        assert report.event_trust_root is EventTrustRootAxis.BUNDLED_ONLY


# ---------------------------------------------------------------------------
# §5.2 — the full externally_authenticated happy path
# ---------------------------------------------------------------------------


class TestExternallyAuthenticatedHappyPath:
    def test_a_real_v6_epoch_reaches_externally_authenticated(
        self, chain: _Chain, tmp_path: Path
    ) -> None:
        path = tmp_path / "bundle.json"
        path.write_bytes(canonical_bundle_bytes(chain.build()))
        report = verify_audit_bundle_v3(
            path,
            _full_policy(chain),
            known_head=(chain.hashes[-1], len(chain.records)),
            presented_trust_log=_presented_trust_log(chain),
        )
        assert report.membership_signature is MembershipSignature.VALID_EXTERNAL_ROOT
        assert report.event_trust_root is EventTrustRootAxis.EXTERNALLY_PINNED
        assert report.event_authentication is EventAuthentication.FULL
        assert report.applicability is BundleApplicability.EXTERNALLY_AUTHENTICATED
        assert report.policy_satisfied is True
        assert report.registry_chain_consistency is RegistryChainConsistency.CONSISTENT

    def test_without_the_trust_log_the_same_bundle_falls_short(
        self, chain: _Chain, bundle_path: Path
    ) -> None:
        # The genesis bootstrap cannot reach externally-pinned full authentication without the
        # trust-log enrolment, so A4 is not `full` and the verdict is below externally
        # authenticated — the honest boundary, not a defect (§9 residual 6).
        report = verify_audit_bundle_v3(
            bundle_path,
            _full_policy(chain),
            known_head=(chain.hashes[-1], len(chain.records)),
        )
        assert report.applicability is not BundleApplicability.EXTERNALLY_AUTHENTICATED
        assert report.event_authentication is not EventAuthentication.FULL


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
