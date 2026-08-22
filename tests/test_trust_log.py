"""Trust-domain log event contracts (P2.2, ``docs/0.6.0/TRUST-DOMAIN.md`` §5).

Pure-contract tests: no database. The projection/rebuild half, and §9 criteria 12,
13, 17 and 18, live in ``tests/test_trust_projection.py``.

§9 criteria covered here:

* **16** — an enrolment event lacking ``public_key`` is rejected at validation time
  (``TestCriterion16EnrolmentRequiresPublicKey``).
* **18** (payload/authority half) — a recovery rotation without
  ``dual_authorization.old_key_signature`` is accepted only at the current root
  threshold and is reported ``recovery_rotated``
  (``TestCriterion18RecoveryRequiresRootThreshold``).
"""

from __future__ import annotations

import base64
import copy
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from _trust_fixtures import mint_co_signed, mint_genesis, mint_solo
from _trust_log_fixtures import (
    TrustLogKey,
    make_authorized_by,
    make_custody_declaration_payload,
    make_enrollment_payload,
    make_possession_challenge,
    make_registrar_delegation_payload,
    make_revocation_payload,
    make_root_rotation_payload,
    make_rotation_payload,
    make_trust_domain_established_payload,
)

from regista._errors import ErrorCode, RegistaError
from regista._trust_domain import GovernanceState
from regista._trust_log import (
    KEY_BINDING_DUAL_ROTATED,
    KEY_BINDING_RECOVERY_ROTATED,
    PRINCIPAL_KEY_ENROLLED,
    PRINCIPAL_KEY_REVOKED,
    PRINCIPAL_KEY_ROTATED,
    REGISTRAR_DELEGATED,
    TRUST_DOMAIN_CUSTODY_DECLARED,
    TRUST_DOMAIN_ESTABLISHED,
    TRUST_ROOT_ROTATED,
    RegistrarCredential,
    apply_root_rotation,
    authorize_lifecycle_operation,
    classify_rotation_authority,
    expected_entity_kind,
    parse_principal_key_enrolled,
    parse_principal_key_revoked,
    parse_principal_key_rotated,
    parse_registrar_delegated,
    parse_trust_domain_custody_declared,
    parse_trust_domain_established,
    parse_trust_log_payload,
    parse_trust_root_rotated,
    validate_established_against_genesis,
    validate_key_binding_bootstrap,
    verify_possession_proof_v2,
    verify_root_threshold,
)

_TDID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"


def _reason(exc_info) -> str:
    return exc_info.value.detail["reason"]


# ---------------------------------------------------------------------------
# §9 criterion 16
# ---------------------------------------------------------------------------


class TestCriterion16EnrolmentRequiresPublicKey:
    """§9.16 / WI-273: an enrolment lacking ``public_key`` is rejected at write time.

    This is the fix for Defect A (§5.1): a verifier replaying enrolment events must
    be able to *obtain* the key, not merely check a candidate against a fingerprint.
    Without the bytes the projection is unrebuildable, which is the entire S6 remedy.
    """

    def test_enrolment_without_public_key_is_rejected(self):
        key = TrustLogKey.mint("pk_no_bytes")
        payload = make_enrollment_payload(
            trust_domain_id=_TDID,
            principal_id="agent:no-bytes",
            key=key,
            omit_public_key=True,
        )
        assert "public_key" not in payload
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_enrolled(payload)
        assert exc_info.value.code is ErrorCode.TRUST_LOG_PAYLOAD_INVALID
        assert _reason(exc_info) == "unknown_or_missing_field"
        assert "public_key" in exc_info.value.detail["missing"]

    def test_rotation_without_public_key_is_rejected_too(self):
        """The rotation payload is enrolment plus more, so it inherits the rule."""
        old = TrustLogKey.mint("pk_old")
        new = TrustLogKey.mint("pk_new")
        payload = make_rotation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:rot",
            key=new,
            supersedes_key_id=old.key_id,
            superseded_key=old,
        )
        del payload["public_key"]
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_rotated(payload)
        assert "public_key" in exc_info.value.detail["missing"]

    def test_a_valid_enrolment_carries_the_bytes_and_they_round_trip(self):
        key = TrustLogKey.mint("pk_good")
        payload = make_enrollment_payload(
            trust_domain_id=_TDID, principal_id="agent:good", key=key,
        )
        parsed = parse_principal_key_enrolled(payload)
        # The bytes are recoverable from the event alone — the whole point.
        assert parsed.key.public_key == key.public_key
        assert parsed.key.fingerprint == key.fingerprint

    def test_fingerprint_that_disagrees_with_the_bytes_is_invalid(self):
        """§5.5: the fingerprint is a convenience, the bytes are the artifact."""
        key = TrustLogKey.mint("pk_mismatch")
        other = TrustLogKey.mint("pk_other")
        payload = make_enrollment_payload(
            trust_domain_id=_TDID,
            principal_id="agent:mismatch",
            key=key,
            fingerprint_override=other.fingerprint,
        )
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_enrolled(payload)
        assert _reason(exc_info) == "fingerprint_mismatch"
        assert exc_info.value.detail["recomputed"] == key.fingerprint

    def test_a_public_key_of_the_wrong_length_is_invalid(self):
        key = TrustLogKey.mint("pk_short")
        payload = make_enrollment_payload(
            trust_domain_id=_TDID, principal_id="agent:short", key=key,
        )
        payload["public_key"] = base64.b64encode(b"\x01" * 31).decode("ascii")
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_enrolled(payload)
        assert _reason(exc_info) == "wrong_key_length"

    def test_a_non_ed25519_scheme_is_refused(self):
        """§5.2: the trust log is Ed25519 from its genesis event, no legacy epoch."""
        key = TrustLogKey.mint("pk_hmac")
        payload = make_enrollment_payload(
            trust_domain_id=_TDID, principal_id="agent:hmac", key=key,
        )
        payload["scheme_id"] = "hmac-sha256"
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_enrolled(payload)
        assert _reason(exc_info) == "unsupported_scheme"


# ---------------------------------------------------------------------------
# §9 criterion 18 — recovery authority
# ---------------------------------------------------------------------------


class TestCriterion18RecoveryRequiresRootThreshold:
    """§9.18, Resolution 5 / D-8.

    A recovery rotation carries no outgoing-key signature and is accepted **only**
    at the current root threshold — the online registrar may prepare and submit the
    request but cannot authorise it. Every recovery reports ``recovery_rotated``.
    """

    def _governance(self, roots, threshold):
        return GovernanceState(
            threshold=threshold,
            signer_fingerprints=tuple(sorted(r.fingerprint for r in roots)),
        )

    def test_recovery_at_root_threshold_is_accepted_and_classified(self):
        roots = [TrustLogKey.mint("root-a"), TrustLogKey.mint("root-b")]
        governance = self._governance(roots, 2)
        new = TrustLogKey.mint("pk_recovered")
        payload = make_rotation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:lost-key",
            key=new,
            supersedes_key_id="pk_lost",
            mode="recovery",
            recovery_reason="key-lost",
            root_keys=roots,
        )
        parsed = parse_principal_key_rotated(payload)
        assert parsed.dual_authorization.old_key_signature is None
        classification = classify_rotation_authority(
            parsed,
            governance=governance,
            root_public_keys={r.fingerprint: r.public_key for r in roots},
            payload=payload,
        )
        # The reported value is what propagates into VerificationResult (§8.3) and
        # bundle verdicts. Visible classification is retained, not a substitute for
        # prevention.
        assert classification == KEY_BINDING_RECOVERY_ROTATED
        assert parsed.is_recovery is True

    def test_recovery_below_the_current_root_threshold_is_refused(self):
        roots = [TrustLogKey.mint("root-a"), TrustLogKey.mint("root-b")]
        governance = self._governance(roots, 2)
        new = TrustLogKey.mint("pk_recovered")
        # Only ONE of the two required roots signs.
        payload = make_rotation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:lost-key",
            key=new,
            supersedes_key_id="pk_lost",
            mode="recovery",
            recovery_reason="key-lost",
            root_keys=roots[:1],
        )
        parsed = parse_principal_key_rotated(payload)
        with pytest.raises(RegistaError) as exc_info:
            classify_rotation_authority(
                parsed,
                governance=governance,
                root_public_keys={r.fingerprint: r.public_key for r in roots},
                payload=payload,
            )
        assert exc_info.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
        assert _reason(exc_info) == "root_threshold_not_met"
        assert exc_info.value.detail["verified"] == 1
        assert exc_info.value.detail["threshold"] == 2

    def test_a_registrar_cannot_authorise_a_recovery(self):
        """The residual online-takeover path Resolution 5 closes.

        A registrar-signed "recovery" presents zero root signatures, so it fails the
        threshold check. There is no argument that makes it pass.
        """
        roots = [TrustLogKey.mint("root-a")]
        governance = self._governance(roots, 1)
        new = TrustLogKey.mint("pk_takeover")
        payload = make_rotation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:victim",
            key=new,
            supersedes_key_id="pk_victim",
            mode="recovery",
            recovery_reason="key-compromised",
            root_keys=[],
            authorized_by=make_authorized_by(authority="registrar"),
        )
        parsed = parse_principal_key_rotated(payload)
        with pytest.raises(RegistaError) as exc_info:
            classify_rotation_authority(
                parsed,
                governance=governance,
                root_public_keys={r.fingerprint: r.public_key for r in roots},
                payload=payload,
            )
        assert _reason(exc_info) == "root_threshold_not_met"

    def test_a_signature_by_a_non_current_root_does_not_count(self):
        roots = [TrustLogKey.mint("root-a")]
        stranger = TrustLogKey.mint("root-stranger")
        governance = self._governance(roots, 1)
        new = TrustLogKey.mint("pk_x")
        payload = make_rotation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:x",
            key=new,
            supersedes_key_id="pk_y",
            mode="recovery",
            recovery_reason="custody-migration",
            root_keys=[stranger],
        )
        parsed = parse_principal_key_rotated(payload)
        with pytest.raises(RegistaError) as exc_info:
            classify_rotation_authority(
                parsed,
                governance=governance,
                root_public_keys={
                    r.fingerprint: r.public_key for r in [*roots, stranger]
                },
                payload=payload,
            )
        assert _reason(exc_info) == "root_signer_not_current"

    def test_recovery_mode_without_a_reason_is_invalid(self):
        roots = [TrustLogKey.mint("root-a")]
        new = TrustLogKey.mint("pk_z")
        payload = make_rotation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:z",
            key=new,
            supersedes_key_id="pk_zz",
            mode="recovery",
            recovery_reason="key-lost",
            root_keys=roots,
        )
        payload["dual_authorization"]["recovery_reason"] = None
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_rotated(payload)
        assert _reason(exc_info) == "recovery_mode_missing_reason"


class TestDualRotation:
    """§5.6 ``mode: dual`` — the outgoing key must have signed the rotation."""

    def test_dual_rotation_with_the_outgoing_key_signature_verifies(self):
        old = TrustLogKey.mint("pk_old")
        new = TrustLogKey.mint("pk_new")
        payload = make_rotation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:dual",
            key=new,
            supersedes_key_id=old.key_id,
            superseded_key=old,
        )
        parsed = parse_principal_key_rotated(payload)
        classification = classify_rotation_authority(
            parsed,
            governance=GovernanceState(
                threshold=1, signer_fingerprints=("ed25519:sha256:" + "0" * 64,),
            ),
            root_public_keys={},
            payload=payload,
            superseded_public_key=old.public_key,
        )
        assert classification == KEY_BINDING_DUAL_ROTATED

    def test_dual_rotation_signed_by_the_wrong_key_is_refused(self):
        old = TrustLogKey.mint("pk_old")
        impostor = TrustLogKey.mint("pk_impostor")
        new = TrustLogKey.mint("pk_new")
        payload = make_rotation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:dual",
            key=new,
            supersedes_key_id=old.key_id,
            superseded_key=impostor,
        )
        parsed = parse_principal_key_rotated(payload)
        with pytest.raises(RegistaError) as exc_info:
            classify_rotation_authority(
                parsed,
                governance=GovernanceState(
                    threshold=1,
                    signer_fingerprints=("ed25519:sha256:" + "0" * 64,),
                ),
                root_public_keys={},
                payload=payload,
                superseded_public_key=old.public_key,
            )
        assert _reason(exc_info) == "old_key_signature_invalid"

    def test_dual_mode_without_an_old_key_signature_is_invalid_at_parse_time(self):
        old = TrustLogKey.mint("pk_old")
        new = TrustLogKey.mint("pk_new")
        payload = make_rotation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:dual",
            key=new,
            supersedes_key_id=old.key_id,
            superseded_key=old,
        )
        payload["dual_authorization"]["old_key_signature"] = None
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_rotated(payload)
        assert _reason(exc_info) == "dual_mode_missing_old_key_signature"

    def test_rotation_must_name_a_superseded_key(self):
        new = TrustLogKey.mint("pk_new")
        old = TrustLogKey.mint("pk_old")
        payload = make_rotation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:dual",
            key=new,
            supersedes_key_id=old.key_id,
            superseded_key=old,
        )
        payload["supersedes_key_id"] = None
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_rotated(payload)
        assert _reason(exc_info) == "rotation_supersedes_key_id_missing"

    def test_a_key_cannot_supersede_itself(self):
        key = TrustLogKey.mint("pk_self")
        payload = make_rotation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:self",
            key=key,
            supersedes_key_id=key.key_id,
            superseded_key=key,
        )
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_rotated(payload)
        assert _reason(exc_info) == "rotation_supersedes_self"

    def test_an_enrolment_may_not_carry_supersedes_key_id(self):
        key = TrustLogKey.mint("pk_e")
        payload = make_enrollment_payload(
            trust_domain_id=_TDID, principal_id="agent:e", key=key,
        )
        payload["supersedes_key_id"] = "pk_previous"
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_enrolled(payload)
        assert _reason(exc_info) == "enrolment_supersedes_key_id"


# ---------------------------------------------------------------------------
# Bootstrap A — the one permitted null
# ---------------------------------------------------------------------------


class TestBootstrapANullKeyBinding:
    """A-prime Bootstrap A / Resolution 1: exactly one null is permitted, and the
    genesis event's authority is proven on presented evidence."""

    def _root_key(self, fixture, signer_id=None):
        signer_id = signer_id or fixture.signer_ids[0]
        return TrustLogKey(
            key_id="k_" + signer_id,
            seed=fixture.seeds[signer_id],
            public_key=fixture.public_keys[signer_id],
            fingerprint=fixture.fingerprints[signer_id],
        )

    def _payload(self, fixture, signer_ids=("root-a",)):
        keys = [self._root_key(fixture, s) for s in signer_ids]
        return make_trust_domain_established_payload(fixture.document, root_keys=keys)

    def _root_pub(self, fixture):
        return {
            fixture.fingerprints[s]: fixture.public_keys[s]
            for s in fixture.signer_ids
        }

    def _call(self, fixture, *, event_seq=1, payload=None, signer=None, document=None):
        payload = payload if payload is not None else self._payload(fixture)
        signer = signer if signer is not None else fixture.signer_ids[0]
        return validate_key_binding_bootstrap(
            TRUST_DOMAIN_ESTABLISHED,
            None,
            event_seq=event_seq,
            payload=payload,
            genesis_document=document or fixture.document,
            root_public_keys=self._root_pub(fixture),
            signer_fingerprint=fixture.fingerprints[signer],
        )

    def test_trust_domain_established_with_a_valid_bootstrap_is_accepted(self):
        fixture = mint_solo()
        self._call(fixture)

    @pytest.mark.parametrize(
        "transition",
        [
            PRINCIPAL_KEY_ENROLLED,
            PRINCIPAL_KEY_ROTATED,
            PRINCIPAL_KEY_REVOKED,
            REGISTRAR_DELEGATED,
            TRUST_ROOT_ROTATED,
            TRUST_DOMAIN_CUSTODY_DECLARED,
        ],
    )
    def test_a_null_on_any_other_transition_is_the_named_invalid(self, transition):
        with pytest.raises(RegistaError) as exc_info:
            validate_key_binding_bootstrap(transition, None)
        assert exc_info.value.code is ErrorCode.TRUST_LOG_BOOTSTRAP_NOT_PERMITTED
        assert _reason(exc_info) == "KEY_BINDING_BOOTSTRAP_NOT_PERMITTED"

    def test_event_not_at_position_one_is_refused(self):
        fixture = mint_solo()
        with pytest.raises(RegistaError) as exc_info:
            self._call(fixture, event_seq=2)
        assert _reason(exc_info) == "bootstrap_event_not_position_one"

    def test_bootstrap_not_signed_by_a_genesis_root_key_is_refused(self):
        fixture = mint_solo()
        stranger = TrustLogKey.mint("stranger")
        with pytest.raises(RegistaError) as exc_info:
            validate_key_binding_bootstrap(
                TRUST_DOMAIN_ESTABLISHED,
                None,
                event_seq=1,
                payload=self._payload(fixture),
                genesis_document=fixture.document,
                root_public_keys=self._root_pub(fixture),
                signer_fingerprint=stranger.fingerprint,
            )
        assert _reason(exc_info) == "bootstrap_signer_not_a_root_key"

    def test_threshold_not_met_is_refused(self):

        fixture = mint_genesis(
            threshold=2, signer_count=2, seeds=[bytes([i]) * 32 for i in range(1, 3)]
        )
        with pytest.raises(RegistaError) as exc_info:
            self._call(fixture, payload=self._payload(fixture, ("root-a",)))
        assert _reason(exc_info) == "root_threshold_not_met"

    def test_threshold_met_two_of_two_is_accepted(self):
        fixture = mint_genesis(
            threshold=2, signer_count=2, seeds=[bytes([i]) * 32 for i in range(1, 3)]
        )
        self._call(fixture, payload=self._payload(fixture, ("root-a", "root-b")))

    def test_genesis_document_digest_mutation_is_refused(self):
        import copy
        import hashlib

        from regista._jcs import canonicalize

        fixture = mint_solo()
        doc = copy.deepcopy(fixture.document)
        doc["binding_core"]["nonce"] = "f" * 64
        doc["trust_domain_core_digest"] = "sha256:" + hashlib.sha256(
            canonicalize(doc["binding_core"])
        ).hexdigest()
        with pytest.raises(RegistaError) as exc_info:
            self._call(fixture, document=doc)
        assert _reason(exc_info) in ("genesis_document_digest_mismatch", "core_digest_mismatch")

    def test_bootstrap_with_no_evidence_presented_is_refused_not_waved_through(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_key_binding_bootstrap(TRUST_DOMAIN_ESTABLISHED, None)
        assert _reason(exc_info) == "bootstrap_evidence_not_presented"

    def test_trust_domain_established_may_not_carry_a_non_null_hash(self):
        with pytest.raises(RegistaError) as exc_info:
            validate_key_binding_bootstrap(
                TRUST_DOMAIN_ESTABLISHED, "sha256:" + "3" * 64,
            )
        assert _reason(exc_info) == "bootstrap_hash_must_be_null"

    def test_a_non_null_hash_on_an_ordinary_transition_is_fine(self):
        validate_key_binding_bootstrap(
            PRINCIPAL_KEY_ENROLLED, "sha256:" + "4" * 64,
        )


class TestTrustDomainEstablished:
    """§5.2/§5.3: the log's first event restates the signed genesis identity."""

    def test_a_faithful_restatement_parses_and_matches_the_genesis(self):
        fixture = mint_co_signed()
        payload = make_trust_domain_established_payload(fixture.document)
        parsed = parse_trust_domain_established(payload)
        assert parsed.trust_domain_id == fixture.trust_domain_id
        assert parsed.trust_domain_core_digest == fixture.trust_domain_core_digest
        validate_established_against_genesis(parsed, fixture.document)

    def test_the_governance_state_is_readable_for_section_5_4_replay(self):
        fixture = mint_co_signed(threshold=2, signer_count=3)
        payload = make_trust_domain_established_payload(fixture.document)
        parsed = parse_trust_domain_established(payload)
        state = parsed.governance_state
        assert state.threshold == 2
        assert state.signer_count == 3
        assert set(state.signer_fingerprints) == set(fixture.fingerprints.values())

    def test_a_tampered_binding_core_breaks_the_recomputed_digest(self):
        fixture = mint_solo()
        payload = make_trust_domain_established_payload(fixture.document)
        payload["binding_core"]["nonce"] = "f" * 64
        with pytest.raises(RegistaError) as exc_info:
            parse_trust_domain_established(payload)
        assert _reason(exc_info) == "core_digest_mismatch"

    def test_a_restatement_of_a_different_domain_is_refused(self):
        """Byte equality, not field-by-field — so WI-292 composes untouched.

        Both documents here are individually **valid**; they just describe different
        trust domains. That is the case the check has to catch: an event restating
        some other estate's genesis. (A document that is internally inconsistent is
        caught earlier, by ``parse_trust_genesis`` — see the test below.)
        """
        ours = mint_solo()
        theirs = mint_solo()
        assert ours.trust_domain_id != theirs.trust_domain_id
        parsed = parse_trust_domain_established(
            make_trust_domain_established_payload(ours.document)
        )
        with pytest.raises(RegistaError) as exc_info:
            validate_established_against_genesis(parsed, theirs.document)
        assert _reason(exc_info) == "binding_core_restatement_mismatch"

    def test_an_internally_inconsistent_genesis_is_rejected_before_comparison(self):
        fixture = mint_solo()
        parsed = parse_trust_domain_established(
            make_trust_domain_established_payload(fixture.document)
        )
        forged = copy.deepcopy(fixture.document)
        forged["binding_core"]["created_at"] = "2020-01-01T00:00:00.000000Z"
        with pytest.raises(RegistaError) as exc_info:
            validate_established_against_genesis(parsed, forged)
        # The genesis document's own derivation fails first; the event never gets
        # compared against a document that does not verify.
        assert _reason(exc_info) == "core_digest_mismatch"

    def test_governance_mode_must_agree_with_threshold_and_signer_count(self):
        fixture = mint_co_signed(threshold=2, signer_count=3)
        payload = make_trust_domain_established_payload(fixture.document)
        payload["initial_governance"]["mode"] = "solo"
        with pytest.raises(RegistaError) as exc_info:
            parse_trust_domain_established(payload)
        assert _reason(exc_info) == "mode_threshold_disagreement"

    @pytest.mark.parametrize("mutation", ["drop_custody", "add_unknown_field"])
    def test_restatement_validation_reads_only_the_signer_fingerprint(self, mutation):
        """WI-292 guard: the signer entry's field set is not enumerated here.

        Custody moved out of ``binding_core`` into a mandatory top-level
        ``initial_custody`` block (committed on the P2.1 branch as 512efac). This test
        is written to hold on **both** sides of that change: whatever a signer entry
        contains, the restatement parses, because the digest is recomputed over
        whatever bytes are present rather than over a hardcoded field list.

        If this test ever fails, P2.2 has grown a signer-shape assumption and the
        composition guarantee is gone.
        """
        from regista._trust_domain import derive_core_digest, derive_trust_domain_id

        fixture = mint_solo()
        payload = make_trust_domain_established_payload(fixture.document)
        for signer in payload["binding_core"]["signers"]:
            if mutation == "drop_custody":
                # NB4 (P2.2 review): this arm goes VACUOUS once WI-292 lands and
                # signers no longer carry custody — pop() becomes a no-op and the
                # case degenerates into "an unmodified core parses". It is kept
                # because it is the pre-WI-292 half of the guarantee; the
                # add_unknown_field arm is the one that stays load-bearing on both
                # sides, so do not delete that one when tidying this up.
                signer.pop("custody", None)
            else:
                signer["some_future_field"] = "value"
        # Recompute exactly as a genesis ceremony would for this core.
        digest = derive_core_digest(payload["binding_core"])
        payload["trust_domain_core_digest"] = digest
        payload["trust_domain_id"] = derive_trust_domain_id(digest)
        parsed = parse_trust_domain_established(payload)
        assert parsed.governance_state.signer_count == 1
        assert parsed.governance_state.signer_fingerprints == (
            fixture.fingerprints[fixture.signer_ids[0]],
        )


# ---------------------------------------------------------------------------
# §5.4 root rotation and the WI-280 monotone rules
# ---------------------------------------------------------------------------


class TestRootRotation:
    def test_replacing_a_signer_at_the_current_threshold_is_permitted(self):
        a, b = TrustLogKey.mint("root-a"), TrustLogKey.mint("root-b")
        replacement = TrustLogKey.mint("root-c")
        current = GovernanceState(
            threshold=2, signer_fingerprints=tuple(sorted([a.fingerprint, b.fingerprint])),
        )
        payload = make_root_rotation_payload(
            trust_domain_id=_TDID,
            added=[replacement],
            removed=[b.fingerprint],
            new_threshold=2,
            signing_root_keys=[a, b],
        )
        parsed = parse_trust_root_rotated(payload)
        verify_root_threshold(
            payload,
            current,
            {k.fingerprint: k.public_key for k in (a, b)},
        )
        new_state = apply_root_rotation(current, parsed)
        assert set(new_state.signer_fingerprints) == {
            a.fingerprint, replacement.fingerprint,
        }
        assert new_state.threshold == 2

    def test_raising_the_threshold_is_permitted(self):
        a, b = TrustLogKey.mint("root-a"), TrustLogKey.mint("root-b")
        current = GovernanceState(
            threshold=1, signer_fingerprints=tuple(sorted([a.fingerprint, b.fingerprint])),
        )
        payload = make_root_rotation_payload(
            trust_domain_id=_TDID, new_threshold=2, signing_root_keys=[a],
        )
        parsed = parse_trust_root_rotated(payload)
        new_state = apply_root_rotation(current, parsed)
        assert new_state.threshold == 2
        # A threshold increase is not an epoch change; trust_domain_id does not move.
        assert set(new_state.signer_fingerprints) == set(current.signer_fingerprints)

    def test_lowering_the_threshold_is_rejected_no_matter_who_signed_it(self):
        """WI-280 live rule, delegated to the P2.1 monotonicity primitive."""
        a, b = TrustLogKey.mint("root-a"), TrustLogKey.mint("root-b")
        current = GovernanceState(
            threshold=2, signer_fingerprints=tuple(sorted([a.fingerprint, b.fingerprint])),
        )
        payload = make_root_rotation_payload(
            trust_domain_id=_TDID, new_threshold=1, signing_root_keys=[a, b],
        )
        parsed = parse_trust_root_rotated(payload)
        # Both current roots signed it, and it is still refused.
        verify_root_threshold(
            payload, current, {k.fingerprint: k.public_key for k in (a, b)},
        )
        with pytest.raises(RegistaError) as exc_info:
            apply_root_rotation(current, parsed)
        assert exc_info.value.code is ErrorCode.TRUST_GOVERNANCE_TRANSITION_INVALID
        assert _reason(exc_info) == "threshold_decrease"

    def test_removing_a_signer_not_in_the_current_set_is_refused(self):
        a = TrustLogKey.mint("root-a")
        stranger = TrustLogKey.mint("stranger")
        current = GovernanceState(threshold=1, signer_fingerprints=(a.fingerprint,))
        payload = make_root_rotation_payload(
            trust_domain_id=_TDID,
            removed=[stranger.fingerprint],
            new_threshold=1,
            signing_root_keys=[a],
        )
        parsed = parse_trust_root_rotated(payload)
        with pytest.raises(RegistaError) as exc_info:
            apply_root_rotation(current, parsed)
        assert _reason(exc_info) == "removed_signer_not_current"

    def test_a_rotation_that_changes_nothing_is_refused(self):
        a = TrustLogKey.mint("root-a")
        current = GovernanceState(threshold=1, signer_fingerprints=(a.fingerprint,))
        payload = make_root_rotation_payload(
            trust_domain_id=_TDID, new_threshold=1, signing_root_keys=[a],
        )
        parsed = parse_trust_root_rotated(payload)
        with pytest.raises(RegistaError) as exc_info:
            apply_root_rotation(current, parsed)
        assert _reason(exc_info) == "rotation_changes_nothing"

    def test_an_added_signer_must_carry_its_public_key(self):
        a = TrustLogKey.mint("root-a")
        new = TrustLogKey.mint("root-new")
        payload = make_root_rotation_payload(
            trust_domain_id=_TDID, added=[new], new_threshold=1, signing_root_keys=[a],
        )
        del payload["added"][0]["public_key"]
        with pytest.raises(RegistaError) as exc_info:
            parse_trust_root_rotated(payload)
        assert _reason(exc_info) == "added_signer_incomplete"

    def test_a_tampered_payload_breaks_the_root_signatures(self):
        a = TrustLogKey.mint("root-a")
        current = GovernanceState(threshold=1, signer_fingerprints=(a.fingerprint,))
        payload = make_root_rotation_payload(
            trust_domain_id=_TDID, new_threshold=2, signing_root_keys=[a],
        )
        payload["reason"] = "tampered after signing"
        with pytest.raises(RegistaError) as exc_info:
            verify_root_threshold(payload, current, {a.fingerprint: a.public_key})
        assert _reason(exc_info) == "root_signature_invalid"

    def test_two_signatures_by_the_same_signer_do_not_raise_the_count(self):
        a = TrustLogKey.mint("root-a")
        b = TrustLogKey.mint("root-b")
        current = GovernanceState(
            threshold=2, signer_fingerprints=tuple(sorted([a.fingerprint, b.fingerprint])),
        )
        payload = make_root_rotation_payload(
            trust_domain_id=_TDID, new_threshold=2, signing_root_keys=[a],
        )
        payload["root_signatures"].append(dict(payload["root_signatures"][0]))
        with pytest.raises(RegistaError) as exc_info:
            verify_root_threshold(
                payload, current, {k.fingerprint: k.public_key for k in (a, b)},
            )
        assert _reason(exc_info) == "duplicate_root_signature"


# ---------------------------------------------------------------------------
# §5.4 registrar rules
# ---------------------------------------------------------------------------


class TestRegistrarDelegation:
    def test_a_well_formed_delegation_parses(self):
        root = TrustLogKey.mint("root-a")
        payload = make_registrar_delegation_payload(
            trust_domain_id=_TDID, root_keys=[root],
        )
        parsed = parse_registrar_delegated(payload)
        assert parsed.registrar_principal_id == "service:registrar-1"
        assert "principal_key_enrolled" in parsed.scopes

    def test_not_after_is_mandatory(self):
        root = TrustLogKey.mint("root-a")
        payload = make_registrar_delegation_payload(
            trust_domain_id=_TDID, root_keys=[root],
        )
        payload["not_after"] = None
        with pytest.raises(RegistaError) as exc_info:
            parse_registrar_delegated(payload)
        assert _reason(exc_info) == "registrar_not_after_missing"

    def test_a_validity_window_over_400_days_is_refused(self):
        root = TrustLogKey.mint("root-a")
        not_before = datetime(2026, 8, 20, tzinfo=UTC)
        payload = make_registrar_delegation_payload(
            trust_domain_id=_TDID,
            root_keys=[root],
            not_before=not_before.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
            not_after=(not_before + timedelta(days=401)).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            ) + "Z",
        )
        with pytest.raises(RegistaError) as exc_info:
            parse_registrar_delegated(payload)
        assert _reason(exc_info) == "registrar_validity_too_long"
        assert exc_info.value.detail["max_days"] == 400

    def test_exactly_400_days_is_permitted(self):
        root = TrustLogKey.mint("root-a")
        not_before = datetime(2026, 8, 20, tzinfo=UTC)
        payload = make_registrar_delegation_payload(
            trust_domain_id=_TDID,
            root_keys=[root],
            not_before=not_before.strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
            not_after=(not_before + timedelta(days=400)).strftime(
                "%Y-%m-%dT%H:%M:%S.%f"
            ) + "Z",
        )
        parsed = parse_registrar_delegated(payload)
        assert parsed.not_after - parsed.not_before == timedelta(days=400)

    def test_a_scope_outside_lifecycle_administration_is_refused(self):
        """§5.12: registrar delegation never authorises writing work-item events."""
        root = TrustLogKey.mint("root-a")
        payload = make_registrar_delegation_payload(
            trust_domain_id=_TDID,
            root_keys=[root],
            scopes=["principal_key_enrolled", "work_item_transitioned"],
        )
        with pytest.raises(RegistaError) as exc_info:
            parse_registrar_delegated(payload)
        assert _reason(exc_info) == "scope_outside_registrar_authority"
        assert exc_info.value.detail["unknown"] == ["work_item_transitioned"]

    def test_a_registrar_cannot_delegate(self):
        """§5.4: naming a principal that is itself a registrar is INVALID."""
        from regista._trust_log import refuse_registrar_delegating_registrar

        root = TrustLogKey.mint("root-a")
        payload = make_registrar_delegation_payload(
            trust_domain_id=_TDID,
            registrar_principal_id="service:registrar-1",
            root_keys=[root],
        )
        parsed = parse_registrar_delegated(payload)
        with pytest.raises(RegistaError) as exc_info:
            refuse_registrar_delegating_registrar(
                parsed, existing_registrar_principal_ids=["service:registrar-1"],
            )
        assert exc_info.value.code is ErrorCode.TRUST_LOG_AUTHORITY_INVALID
        assert _reason(exc_info) == "registrar_cannot_delegate"

    def test_delegating_to_a_non_registrar_principal_is_fine(self):
        from regista._trust_log import refuse_registrar_delegating_registrar

        root = TrustLogKey.mint("root-a")
        payload = make_registrar_delegation_payload(
            trust_domain_id=_TDID,
            registrar_principal_id="service:registrar-2",
            root_keys=[root],
        )
        parsed = parse_registrar_delegated(payload)
        refuse_registrar_delegating_registrar(
            parsed, existing_registrar_principal_ids=["service:registrar-1"],
        )


class TestRegistrarAuthorityEnforcement:
    """§5.4 expiry and scope enforcement on lifecycle operations."""

    def _credential(self, **overrides):
        base = {
            "delegation_event_hash": "sha256:" + "a" * 64,
            "registrar_principal_id": "service:registrar-1",
            "key_id": "pk_registrar_1",
            "fingerprint": "ed25519:sha256:" + "b" * 64,
            "scopes": frozenset(
                {"principal_key_enrolled", "principal_key_rotated"}
            ),
            "not_before": datetime(2026, 8, 1, tzinfo=UTC),
            "not_after": datetime(2026, 9, 1, tzinfo=UTC),
            "max_operations": None,
        }
        base.update(overrides)
        return RegistrarCredential(**base)

    def _authorized_by(self):
        from regista._trust_log import _parse_authorized_by

        return _parse_authorized_by(make_authorized_by(), "authorized_by")

    def test_an_in_window_in_scope_operation_is_authorised(self):
        credential = self._credential()
        authority = authorize_lifecycle_operation(
            PRINCIPAL_KEY_ENROLLED,
            self._authorized_by(),
            registrars={credential.delegation_event_hash: credential},
            at=datetime(2026, 8, 15, tzinfo=UTC),
        )
        assert authority == "registrar"

    def test_an_expired_delegation_is_invalid_not_degraded(self):
        credential = self._credential()
        with pytest.raises(RegistaError) as exc_info:
            authorize_lifecycle_operation(
                PRINCIPAL_KEY_ENROLLED,
                self._authorized_by(),
                registrars={credential.delegation_event_hash: credential},
                at=datetime(2026, 10, 1, tzinfo=UTC),
            )
        assert _reason(exc_info) == "registrar_delegation_expired"

    def test_an_operation_before_not_before_is_refused(self):
        credential = self._credential()
        with pytest.raises(RegistaError) as exc_info:
            authorize_lifecycle_operation(
                PRINCIPAL_KEY_ENROLLED,
                self._authorized_by(),
                registrars={credential.delegation_event_hash: credential},
                at=datetime(2026, 7, 1, tzinfo=UTC),
            )
        assert _reason(exc_info) == "registrar_delegation_expired"

    def test_an_out_of_scope_operation_is_refused(self):
        credential = self._credential()
        with pytest.raises(RegistaError) as exc_info:
            authorize_lifecycle_operation(
                PRINCIPAL_KEY_REVOKED,
                self._authorized_by(),
                registrars={credential.delegation_event_hash: credential},
                at=datetime(2026, 8, 15, tzinfo=UTC),
            )
        assert _reason(exc_info) == "registrar_scope_exceeded"

    def test_a_revoked_delegation_is_refused(self):
        credential = self._credential(revoked=True)
        with pytest.raises(RegistaError) as exc_info:
            authorize_lifecycle_operation(
                PRINCIPAL_KEY_ENROLLED,
                self._authorized_by(),
                registrars={credential.delegation_event_hash: credential},
                at=datetime(2026, 8, 15, tzinfo=UTC),
            )
        assert _reason(exc_info) == "registrar_delegation_revoked"

    def test_an_unresolvable_delegation_hash_is_refused(self):
        with pytest.raises(RegistaError) as exc_info:
            authorize_lifecycle_operation(
                PRINCIPAL_KEY_ENROLLED,
                self._authorized_by(),
                registrars={},
                at=datetime(2026, 8, 15, tzinfo=UTC),
            )
        assert _reason(exc_info) == "registrar_delegation_unresolved"

    def test_max_operations_is_enforced(self):
        credential = self._credential(max_operations=2)
        authorize_lifecycle_operation(
            PRINCIPAL_KEY_ENROLLED,
            self._authorized_by(),
            registrars={credential.delegation_event_hash: credential},
            at=datetime(2026, 8, 15, tzinfo=UTC),
            operations_used=1,
        )
        with pytest.raises(RegistaError) as exc_info:
            authorize_lifecycle_operation(
                PRINCIPAL_KEY_ENROLLED,
                self._authorized_by(),
                registrars={credential.delegation_event_hash: credential},
                at=datetime(2026, 8, 15, tzinfo=UTC),
                operations_used=2,
            )
        assert _reason(exc_info) == "registrar_max_operations_exhausted"

    def test_root_authority_needs_no_stored_credential(self):
        from regista._trust_log import _parse_authorized_by

        authority = authorize_lifecycle_operation(
            PRINCIPAL_KEY_REVOKED,
            _parse_authorized_by(
                make_authorized_by(authority="root", principal_id="root", key_id="pk_r"),
                "authorized_by",
            ),
            registrars={},
            at=datetime(2026, 8, 15, tzinfo=UTC),
        )
        assert authority == "root"

    def test_a_registrar_authorisation_must_name_its_delegation_event(self):
        from regista._trust_log import _parse_authorized_by

        raw = make_authorized_by(authority="registrar")
        raw["delegation_event_hash"] = None
        with pytest.raises(RegistaError) as exc_info:
            _parse_authorized_by(raw, "authorized_by")
        assert _reason(exc_info) == "registrar_delegation_hash_missing"


# ---------------------------------------------------------------------------
# §5.5 possession proof v2
# ---------------------------------------------------------------------------


class TestPossessionProofV2:
    def test_a_correct_proof_verifies_against_its_challenge(self):
        key = TrustLogKey.mint("pk_possess")
        challenge = make_possession_challenge(
            trust_domain_id=_TDID,
            principal_id="agent:possess",
            fingerprint=key.fingerprint,
        )
        payload = make_enrollment_payload(
            trust_domain_id=_TDID,
            principal_id="agent:possess",
            key=key,
            challenge=challenge,
        )
        verify_possession_proof_v2(payload, challenge)

    def test_a_proof_by_a_different_key_does_not_verify(self):
        key = TrustLogKey.mint("pk_a")
        impostor = TrustLogKey.mint("pk_b")
        challenge = make_possession_challenge(
            trust_domain_id=_TDID,
            principal_id="agent:possess",
            fingerprint=key.fingerprint,
        )
        payload = make_enrollment_payload(
            trust_domain_id=_TDID,
            principal_id="agent:possess",
            key=key,
            challenge=challenge,
        )
        # Swap in a signature made by a key that is not the one being enrolled.
        payload["possession_proof"]["signature"] = base64.b64encode(
            impostor.sign(challenge.signing_input())
        ).decode("ascii")
        with pytest.raises(RegistaError) as exc_info:
            verify_possession_proof_v2(payload, challenge)
        assert _reason(exc_info) == "possession_proof_verification_failed"

    def test_a_proof_answering_a_different_challenge_is_refused(self):
        key = TrustLogKey.mint("pk_c")
        challenge = make_possession_challenge(
            trust_domain_id=_TDID,
            principal_id="agent:possess",
            fingerprint=key.fingerprint,
        )
        other = make_possession_challenge(
            trust_domain_id=_TDID,
            principal_id="agent:possess",
            fingerprint=key.fingerprint,
            challenge_id=str(uuid.uuid4()),
        )
        payload = make_enrollment_payload(
            trust_domain_id=_TDID,
            principal_id="agent:possess",
            key=key,
            challenge=challenge,
        )
        with pytest.raises(RegistaError) as exc_info:
            verify_possession_proof_v2(payload, other)
        assert _reason(exc_info) == "possession_challenge_binding_mismatch"

    def test_the_v2_domain_is_required(self):
        key = TrustLogKey.mint("pk_d")
        payload = make_enrollment_payload(
            trust_domain_id=_TDID, principal_id="agent:d", key=key,
        )
        payload["possession_proof"]["domain"] = "regista.principal-possession.v1"
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_enrolled(payload)
        assert _reason(exc_info) == "possession_domain_not_v2"

    def test_the_v2_signing_input_uses_the_byte_prefix_framing(self):
        """§5.5: ``domain || uint64be(len(p)) || p`` over the JCS challenge object."""
        import struct

        from regista._jcs import canonicalize
        from regista._trust_log import POSSESSION_PREFIX_V2

        challenge = make_possession_challenge(
            trust_domain_id=_TDID,
            principal_id="agent:framing",
            fingerprint="ed25519:sha256:" + "0" * 64,
        )
        body = canonicalize(challenge.to_dict())
        expected = POSSESSION_PREFIX_V2 + struct.pack(">Q", len(body)) + body
        assert challenge.signing_input() == expected
        # v2 keeps the in-object domain field as well (D-9: belt-and-braces).
        assert challenge.to_dict()["domain"] == "regista.principal-possession.v2"
        # ...and adds the two v2 fields.
        assert challenge.to_dict()["trust_domain_id"] == _TDID
        assert "enrollment_request_digest" in challenge.to_dict()


# ---------------------------------------------------------------------------
# §5.7 revocation
# ---------------------------------------------------------------------------


class TestRevocationPayload:
    def test_a_well_formed_revocation_parses(self):
        payload = make_revocation_payload(
            trust_domain_id=_TDID, principal_id="agent:r", key_id="pk_r",
        )
        parsed = parse_principal_key_revoked(payload)
        assert parsed.reason == "compromised"
        assert parsed.effective_from_kind == "on_chain_position"
        assert parsed.effective_from_event_hash == "self"

    def test_a_wall_clock_effective_from_is_refused(self):
        """§5.7: revocation is prospective by chain position, never by wall-clock."""
        payload = make_revocation_payload(
            trust_domain_id=_TDID, principal_id="agent:r", key_id="pk_r",
        )
        payload["effective_from"] = {
            "kind": "wall_clock",
            "trust_log_event_hash": "self",
        }
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_revoked(payload)
        assert _reason(exc_info) == "effective_from_kind_not_chain_position"

    def test_an_unknown_reason_is_refused(self):
        payload = make_revocation_payload(
            trust_domain_id=_TDID, principal_id="agent:r", key_id="pk_r",
            reason="because",
        )
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_revoked(payload)
        assert _reason(exc_info) == "unknown_revocation_reason"

    def test_a_declared_suspicion_must_name_a_range(self):
        payload = make_revocation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:r",
            key_id="pk_r",
            retroactive={
                "declared": True,
                "suspect_from_event_hash": None,
                "note": "maybe compromised",
            },
        )
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_revoked(payload)
        assert _reason(exc_info) == "declared_suspicion_missing_range"

    def test_an_undeclared_suspicion_may_not_carry_detail(self):
        payload = make_revocation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:r",
            key_id="pk_r",
            retroactive={
                "declared": False,
                "suspect_from_event_hash": "sha256:" + "c" * 64,
                "note": None,
            },
        )
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_revoked(payload)
        assert _reason(exc_info) == "undeclared_suspicion_has_detail"

    def test_a_declared_suspicion_with_a_range_parses(self):
        payload = make_revocation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:r",
            key_id="pk_r",
            retroactive={
                "declared": True,
                "suspect_from_event_hash": "sha256:" + "c" * 64,
                "note": "disclosed 2026-08-17",
            },
        )
        parsed = parse_principal_key_revoked(payload)
        assert parsed.retroactive_suspicion.declared is True
        assert parsed.retroactive_suspicion.note == "disclosed 2026-08-17"


# ---------------------------------------------------------------------------
# WI-292 custody declarations
# ---------------------------------------------------------------------------


class TestCustodyDeclaration:
    """WI-292: custody lives outside ``binding_core``; corrections are log events."""

    def test_the_first_declaration_has_no_predecessor(self):
        root = TrustLogKey.mint("root-a")
        payload = make_custody_declaration_payload(
            trust_domain_id=_TDID,
            fingerprints=[root.fingerprint],
            declaration_seq=1,
            root_keys=[root],
        )
        parsed = parse_trust_domain_custody_declared(payload)
        assert parsed.declaration_seq == 1
        assert parsed.supersedes_declaration_digest is None

    def test_a_correction_must_name_the_declaration_it_supersedes(self):
        root = TrustLogKey.mint("root-a")
        payload = make_custody_declaration_payload(
            trust_domain_id=_TDID,
            fingerprints=[root.fingerprint],
            declaration_seq=2,
            supersedes_declaration_digest=None,
            root_keys=[root],
        )
        with pytest.raises(RegistaError) as exc_info:
            parse_trust_domain_custody_declared(payload)
        assert _reason(exc_info) == "custody_supersession_broken"

    def test_the_first_declaration_may_not_supersede_anything(self):
        root = TrustLogKey.mint("root-a")
        payload = make_custody_declaration_payload(
            trust_domain_id=_TDID,
            fingerprints=[root.fingerprint],
            declaration_seq=1,
            supersedes_declaration_digest="sha256:" + "d" * 64,
            root_keys=[root],
        )
        with pytest.raises(RegistaError) as exc_info:
            parse_trust_domain_custody_declared(payload)
        assert _reason(exc_info) == "custody_supersession_broken"

    def test_a_valid_correction_parses_and_preserves_its_predecessor(self):
        root = TrustLogKey.mint("root-a")
        payload = make_custody_declaration_payload(
            trust_domain_id=_TDID,
            fingerprints=[root.fingerprint],
            declaration_seq=2,
            supersedes_declaration_digest="sha256:" + "d" * 64,
            reason="holder changed after offboarding",
            root_keys=[root],
        )
        parsed = parse_trust_domain_custody_declared(payload)
        assert parsed.declaration_seq == 2
        assert parsed.supersedes_declaration_digest == "sha256:" + "d" * 64

    def test_a_correction_is_root_threshold_authorised(self):
        a, b = TrustLogKey.mint("root-a"), TrustLogKey.mint("root-b")
        governance = GovernanceState(
            threshold=2,
            signer_fingerprints=tuple(sorted([a.fingerprint, b.fingerprint])),
        )
        payload = make_custody_declaration_payload(
            trust_domain_id=_TDID,
            fingerprints=[a.fingerprint, b.fingerprint],
            declaration_seq=1,
            root_keys=[a, b],
        )
        verified = verify_root_threshold(
            payload, governance, {k.fingerprint: k.public_key for k in (a, b)},
        )
        assert len(verified) == 2

    def test_a_correction_below_threshold_is_refused(self):
        a, b = TrustLogKey.mint("root-a"), TrustLogKey.mint("root-b")
        governance = GovernanceState(
            threshold=2,
            signer_fingerprints=tuple(sorted([a.fingerprint, b.fingerprint])),
        )
        payload = make_custody_declaration_payload(
            trust_domain_id=_TDID,
            fingerprints=[a.fingerprint],
            declaration_seq=1,
            root_keys=[a],
        )
        with pytest.raises(RegistaError) as exc_info:
            verify_root_threshold(
                payload, governance, {k.fingerprint: k.public_key for k in (a, b)},
            )
        assert _reason(exc_info) == "root_threshold_not_met"

    def test_duplicate_fingerprints_in_one_declaration_are_refused(self):
        root = TrustLogKey.mint("root-a")
        payload = make_custody_declaration_payload(
            trust_domain_id=_TDID,
            fingerprints=[root.fingerprint, root.fingerprint],
            root_keys=[root],
        )
        with pytest.raises(RegistaError) as exc_info:
            parse_trust_domain_custody_declared(payload)
        assert _reason(exc_info) == "duplicate_custody_fingerprint"


# ---------------------------------------------------------------------------
# Dispatcher, entity kinds, and the cut/deferred boundaries
# ---------------------------------------------------------------------------


class TestDispatcherAndScopeBoundaries:
    def test_witness_lifecycle_transitions_are_refused_as_cut(self):
        """§7 CUT marker / D-7: not "unknown", specifically cut."""
        for transition in (
            "witness_registered",
            "witness_key_rotated",
            "witness_paused",
            "witness_resumed",
            "witness_revoked",
        ):
            with pytest.raises(RegistaError) as exc_info:
                parse_trust_log_payload(transition, {})
            assert exc_info.value.code is ErrorCode.WITNESS_LIFECYCLE_CUT
            assert _reason(exc_info) == "witness_lifecycle_cut_from_0_6_0"

    @pytest.mark.parametrize(
        "transition",
        [
            "bundle_signing_authority_granted",
            "bundle_signing_authority_revoked",
            "trust_log_checkpoint_published",
            "trust_log_checkpoint_observed",
            "principal_key_accepted",
            "principal_alias_bound",
        ],
    )
    def test_deferred_transitions_name_their_owning_package(self, transition):
        with pytest.raises(RegistaError) as exc_info:
            parse_trust_log_payload(transition, {})
        assert _reason(exc_info) == "transition_owned_by_another_package"
        assert exc_info.value.detail["owner"]

    def test_an_unknown_transition_is_refused(self):
        with pytest.raises(RegistaError) as exc_info:
            parse_trust_log_payload("not_a_transition", {})
        assert _reason(exc_info) == "unknown_transition"

    def test_the_dispatcher_routes_each_known_transition(self):
        key = TrustLogKey.mint("pk_dispatch")
        payload = make_enrollment_payload(
            trust_domain_id=_TDID, principal_id="agent:dispatch", key=key,
        )
        parsed = parse_trust_log_payload(PRINCIPAL_KEY_ENROLLED, payload)
        assert parsed.principal_id == "agent:dispatch"

    def test_entity_kinds_come_from_the_closed_registry(self):
        """§5.2 AMENDED: ``project_system`` is prose, never a wire value."""
        from regista._verification import V6_ENTITY_KINDS

        assert expected_entity_kind(TRUST_DOMAIN_ESTABLISHED) == "trust_domain"
        assert expected_entity_kind(TRUST_ROOT_ROTATED) == "trust_domain"
        assert expected_entity_kind(REGISTRAR_DELEGATED) == "trust_domain"
        assert expected_entity_kind(PRINCIPAL_KEY_ENROLLED) == "principal"
        assert expected_entity_kind(PRINCIPAL_KEY_ROTATED) == "principal"
        assert expected_entity_kind(PRINCIPAL_KEY_REVOKED) == "principal"
        for kind in {
            expected_entity_kind(t)
            for t in (
                TRUST_DOMAIN_ESTABLISHED,
                PRINCIPAL_KEY_ENROLLED,
                TRUST_DOMAIN_CUSTODY_DECLARED,
            )
        }:
            assert kind in V6_ENTITY_KINDS

    def test_unknown_payload_fields_are_rejected(self):
        key = TrustLogKey.mint("pk_extra")
        payload = make_enrollment_payload(
            trust_domain_id=_TDID, principal_id="agent:extra", key=key,
        )
        payload["surprise"] = "extra"
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_enrolled(payload)
        assert _reason(exc_info) == "unknown_or_missing_field"
        assert exc_info.value.detail["unknown"] == ["surprise"]

    def test_the_payload_type_string_is_checked(self):
        key = TrustLogKey.mint("pk_type")
        payload = make_enrollment_payload(
            trust_domain_id=_TDID, principal_id="agent:type", key=key,
        )
        payload["type"] = "regista.key-rotation"
        with pytest.raises(RegistaError) as exc_info:
            parse_principal_key_enrolled(payload)
        assert _reason(exc_info) == "wrong_payload_type"


class TestAuthorizationCoreFraming:
    """The signature-exclusion rule (judgment calls 1 and 2 in the module docstring)."""

    def test_root_signatures_are_excluded_from_the_signed_core(self):
        from regista._trust_log import trust_log_authorization_core

        root = TrustLogKey.mint("root-a")
        payload = make_root_rotation_payload(
            trust_domain_id=_TDID, new_threshold=2, signing_root_keys=[root],
        )
        core = trust_log_authorization_core(payload)
        assert "root_signatures" not in core
        # Adding another signature must not change the bytes the first one signed.
        before = trust_log_authorization_core(payload)
        payload["root_signatures"].append(
            {"signer_id": "root-z", "fingerprint": root.fingerprint,
             "signature": base64.b64encode(b"\x00" * 64).decode("ascii")}
        )
        assert trust_log_authorization_core(payload) == before

    def test_the_old_key_signature_is_nulled_not_removed(self):
        from regista._trust_log import trust_log_authorization_core

        old = TrustLogKey.mint("pk_old")
        new = TrustLogKey.mint("pk_new")
        payload = make_rotation_payload(
            trust_domain_id=_TDID,
            principal_id="agent:core",
            key=new,
            supersedes_key_id=old.key_id,
            superseded_key=old,
        )
        core = trust_log_authorization_core(payload)
        # Present-but-null: the field's presence stays inside the signed bytes, so
        # "dual with no signature" cannot be confused with "recovery".
        assert "old_key_signature" in core["dual_authorization"]
        assert core["dual_authorization"]["old_key_signature"] is None
        assert core["dual_authorization"]["mode"] == "dual"
