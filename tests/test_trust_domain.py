"""P2.1 contracts: trust-domain genesis document, derivation, verification.

Conformance mapping to ``docs/0.6.0/TRUST-DOMAIN.md`` §9 "Genesis":

1. ``test_genesis_criterion_1_threshold_one_three_signers_is_solo_effective`` (+
   ``test_genesis_criterion_1_stating_co_signed_is_invalid_even_resigned``)
2. ``test_genesis_criterion_2_removing_signature_below_threshold_is_invalid``
3. ``test_genesis_criterion_3_editing_mode_alone_is_invalid`` (+ threshold variant)
4. ``test_genesis_criterion_4_binding_core_edit_changes_digest_and_id`` (+
   ``test_genesis_criterion_4_pinned_policy_sees_a_different_domain``)
5. ``test_genesis_criterion_5_countersignature_and_anchor_change_nothing``
6. Mode-derivation half only: ``test_mode_derivation_table``,
   ``test_solo_mode_appears_in_verification_report`` and
   ``TestTrustCLI.test_sign_then_verify_roundtrip`` (the CLI report prints the mode).
   The bundle-renderer half — a solo genesis producing bundles whose *signed
   membership statement* contains ``"mode": "solo"`` — is DEFERRED to P3.3
   (bundle v3), which owns the renderer.

These tests are hermetic: no database, no network — ephemeral test Ed25519 keys only
(the production ceremony is explicitly out of P2.1's contracts half).
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

import nacl.signing
import pytest
from _trust_fixtures import (
    TrustRootFixture,
    make_signature_entry,
    mint_co_signed,
    mint_genesis,
    mint_solo,
    mint_solo_effective,
)

from regista._errors import ErrorCode, RegistaError
from regista._jcs import canonicalize
from regista._principal_keys import _compute_fingerprint
from regista._trust_domain import (
    MODE_CO_SIGNED,
    MODE_SOLO,
    MODE_SOLO_EFFECTIVE,
    TRUST_GENESIS_CORE_DOMAIN,
    TRUST_GENESIS_SIGNING_DOMAIN,
    GovernanceState,
    derive_core_digest,
    derive_governance_mode,
    derive_trust_domain_id,
    genesis_signature_input,
    parse_trust_genesis,
    validate_governance_transition,
    verify_trust_genesis,
)

VECTORS_DIR = Path(__file__).resolve().parent / "vectors" / "v6"


def _assert_invalid(
    document: dict[str, Any],
    code: ErrorCode | None = None,
    reason: str | None = None,
) -> RegistaError:
    with pytest.raises(RegistaError) as excinfo:
        verify_trust_genesis(document)
    err = excinfo.value
    if code is not None:
        assert err.code == code, f"expected {code}, got {err.code}: {err}"
    if reason is not None:
        assert err.detail is not None and err.detail.get("reason") == reason, (
            f"expected reason {reason!r}, got {err.detail!r}: {err}"
        )
    return err


def _resign(fixture: TrustRootFixture, document: dict[str, Any]) -> dict[str, Any]:
    """Replace all signatures with fresh ones over the (possibly mutated) document."""
    document = copy.deepcopy(document)
    document["signatures"] = []
    for signer_id in fixture.signer_ids:
        document["signatures"].append(
            make_signature_entry(
                document, fixture.seeds[signer_id], signer_id, fixture.fingerprints[signer_id]
            )
        )
    return document


def _countersignature_entry() -> dict[str, Any]:
    return {
        "custodian_id": "custodian-1",
        "scheme_id": "ed25519",
        "fingerprint": "ed25519:sha256:" + "ab" * 32,
        "over": "trust_domain_core_digest",
        "signature": base64.b64encode(b"\x01" * 64).decode("ascii"),
        "signed_at": "2026-08-21T00:00:00.000000Z",
        "statement": "observed at https://example.test on 2026-08-21",
    }


def _anchor_entry() -> dict[str, Any]:
    return {
        "kind": "git-tag",
        "over": "trust_domain_core_digest",
        "obtained_at": "2026-08-21T00:00:00.000000Z",
        "evidence": {"tag": "trust-genesis-v1"},
    }


# ---------------------------------------------------------------------------
# Gate 0 vector conformance — the PRODUCTION derivation must reproduce the
# committed vector byte-for-byte. tests/test_v6_vectors.py::test_trust_genesis
# keeps its independent reimplementation; this test imports the module instead.
#
# LOUD NOTE on the vector's shape: tests/vectors/v6/trust-genesis.json predates
# the WI-280 overlay — its binding_core still embeds a `governance` block and its
# public keys are hex, both retired from the production schema (§3.2 + WI-280,
# base64-raw-32). The derivation (§3.3: JCS + domain tag + u64be framing + UUIDv5)
# is shape-agnostic over the mapping, so the production functions reproduce the
# frozen bytes exactly; the strict parser meanwhile REJECTS that legacy shape
# (see test_wi280_governance_inside_binding_core_rejected).
# ---------------------------------------------------------------------------


class TestVectorConformance:
    @pytest.fixture(scope="class")
    def case(self) -> dict[str, Any]:
        return json.loads((VECTORS_DIR / "trust-genesis.json").read_text(encoding="utf-8"))

    @pytest.fixture(scope="class")
    def manifest(self) -> dict[str, Any]:
        return json.loads((VECTORS_DIR / "manifest.json").read_text(encoding="utf-8"))

    def test_domain_tags_match_manifest(self, manifest: dict[str, Any]) -> None:
        assert TRUST_GENESIS_CORE_DOMAIN == manifest["domain_tags"][
            "trust_genesis_core"
        ].encode("utf-8")
        assert TRUST_GENESIS_SIGNING_DOMAIN == manifest["domain_tags"][
            "trust_genesis_signing"
        ].encode("utf-8")

    def test_core_digest_reproduces_vector(self, case: dict[str, Any]) -> None:
        digest = derive_core_digest(case["input"]["binding_core"])
        assert digest == case["expected"]["trust_domain_core_digest"]

    def test_trust_domain_id_reproduces_vector(self, case: dict[str, Any]) -> None:
        digest = derive_core_digest(case["input"]["binding_core"])
        assert derive_trust_domain_id(digest) == case["expected"]["trust_domain_id"]

    def test_signature_input_reproduces_vector(
        self, case: dict[str, Any], manifest: dict[str, Any]
    ) -> None:
        seed = bytes.fromhex(manifest["test_seed_hex"])
        sig_input = genesis_signature_input(case["input"]["genesis_document_minus_extras"])
        signature = nacl.signing.SigningKey(seed).sign(sig_input).signature
        assert signature.hex() == case["expected"]["genesis_signature_hex"]


# ---------------------------------------------------------------------------
# §9 Genesis criteria 1-5, verbatim
# ---------------------------------------------------------------------------


def test_genesis_criterion_1_threshold_one_three_signers_is_solo_effective() -> None:
    fixture = mint_solo_effective(signer_count=3)
    report = verify_trust_genesis(fixture.document)
    assert report.root_governance.mode == MODE_SOLO_EFFECTIVE
    assert report.root_governance.mode != MODE_CO_SIGNED


def test_genesis_criterion_1_stating_co_signed_is_invalid_even_resigned() -> None:
    # Even a properly re-signed document stating co_signed over threshold:1 /
    # signer_count:3 is INVALID — the mode is derived, never trusted as stated.
    fixture = mint_solo_effective(signer_count=3)
    doc = copy.deepcopy(fixture.document)
    doc["initial_governance"]["mode"] = MODE_CO_SIGNED
    doc = _resign(fixture, doc)
    _assert_invalid(
        doc, ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID, "mode_threshold_disagreement"
    )


def test_genesis_criterion_2_removing_signature_below_threshold_is_invalid() -> None:
    fixture = mint_co_signed(threshold=2, signer_count=2)
    assert verify_trust_genesis(fixture.document).signatures_verified == 2
    doc = copy.deepcopy(fixture.document)
    del doc["signatures"][1]
    # Invalid, never "verified with one signature".
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID, "threshold_not_met")


def test_genesis_criterion_3_editing_mode_alone_is_invalid() -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    doc["initial_governance"]["mode"] = MODE_SOLO_EFFECTIVE
    _assert_invalid(
        doc, ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID, "mode_threshold_disagreement"
    )


def test_genesis_criterion_3_editing_threshold_alone_is_invalid() -> None:
    fixture = mint_co_signed(threshold=2, signer_count=2)
    doc = copy.deepcopy(fixture.document)
    doc["initial_governance"]["threshold"] = 1  # derives solo_effective, stated co_signed
    _assert_invalid(
        doc, ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID, "mode_threshold_disagreement"
    )


def test_genesis_criterion_3_consistent_governance_edit_breaks_signatures() -> None:
    # Editing the whole restatement consistently passes the mode table but the
    # signatures no longer verify: initial_governance is inside document_core.
    fixture = mint_co_signed(threshold=2, signer_count=2)
    doc = copy.deepcopy(fixture.document)
    doc["initial_governance"]["threshold"] = 1
    doc["initial_governance"]["mode"] = MODE_SOLO_EFFECTIVE
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID, "bad_signature")


def test_genesis_criterion_4_binding_core_edit_changes_digest_and_id() -> None:
    fixture = mint_co_signed()
    core = copy.deepcopy(fixture.document["binding_core"])
    core["nonce"] = "f" * 64
    new_digest = derive_core_digest(core)
    assert new_digest != fixture.trust_domain_core_digest
    assert derive_trust_domain_id(new_digest) != fixture.trust_domain_id
    # The stated digest/id no longer match the edited core: derivation mismatch.
    doc = copy.deepcopy(fixture.document)
    doc["binding_core"]["nonce"] = "f" * 64
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_DERIVATION_MISMATCH, "core_digest_mismatch")


def test_genesis_criterion_4_pinned_policy_sees_a_different_domain() -> None:
    # Same signers (deterministic seeds), one nonce apart: both documents verify,
    # but a policy pinning A's core digest rejects B as a DIFFERENT DOMAIN.
    seeds = [bytes([i + 1]) * 32 for i in range(2)]
    fixture_a = mint_genesis(threshold=2, signer_count=2, seeds=seeds)
    fixture_b = mint_genesis(threshold=2, signer_count=2, seeds=seeds, nonce="e" * 64)
    pinned_core_digest = fixture_a.trust_domain_core_digest  # the auditor's pin
    report_b = verify_trust_genesis(fixture_b.document)  # valid in itself...
    assert report_b.trust_domain_core_digest != pinned_core_digest  # ...but not the pinned domain
    assert report_b.trust_domain_id != fixture_a.trust_domain_id


# ---------------------------------------------------------------------------
# §9 criterion 4, narrowed by WI-292 (decided 2026-08-17; owner deferral to the
# agreeing claude-fable and gpt-5.6-sol reviews). Custody sits outside the
# identifier, so the interesting property is that identity and custody move
# INDEPENDENTLY: (i) binding_core edits rotate digest+id; (ii) a custody edit
# rotates neither but invalidates every genesis signature; (iii) pinning the
# document digest is strictly stronger than pinning the domain; (iv) the P2.2
# custody-change event seam; (v) corrections preserve history; (vi) strict entry
# rules; (vii) reports label custody declared-and-unverified.
#
# (i) is test_genesis_criterion_4_binding_core_edit_changes_digest_and_id above.
# ---------------------------------------------------------------------------


def _genesis_document_digest(document: dict[str, Any]) -> str:
    """What a policy pins when it pins the *document* rather than the domain."""
    return "sha256:" + hashlib.sha256(canonicalize(document)).hexdigest()


def test_genesis_criterion_4ii_custody_edit_changes_no_digest_but_invalidates_signatures() -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    doc["initial_custody"][0]["declared_mode"] = "online-vault"

    # Neither derived value moves: custody is not an input to §3.3.
    assert derive_core_digest(doc["binding_core"]) == fixture.trust_domain_core_digest
    assert doc["trust_domain_core_digest"] == fixture.trust_domain_core_digest
    assert doc["trust_domain_id"] == fixture.trust_domain_id

    # But initial_custody is inside document_core, so every genesis signature breaks.
    assert genesis_signature_input(doc) != genesis_signature_input(fixture.document)
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID, "bad_signature")

    # Re-signed by the same roots at the same threshold, the SAME domain verifies with
    # the corrected declaration — a label fix costs signatures, never an epoch.
    resigned = _resign(fixture, doc)
    report = verify_trust_genesis(resigned)
    assert report.trust_domain_id == fixture.trust_domain_id
    assert report.trust_domain_core_digest == fixture.trust_domain_core_digest
    assert "online-vault" in report.root_governance.custody_declared


def test_genesis_criterion_4iii_pinned_document_digest_rejects_altered_custody() -> None:
    # Pinning the DOMAIN cannot see a custody edit; pinning the DOCUMENT can. Both
    # statements are asserted here so the difference is not left to the reader.
    fixture = mint_co_signed()
    pinned_document_digest = _genesis_document_digest(fixture.document)
    pinned_core_digest = fixture.trust_domain_core_digest

    altered = copy.deepcopy(fixture.document)
    altered["initial_custody"][0]["declared_holder"] = "human:someone-else"
    resigned = _resign(fixture, altered)  # a fully valid document...

    report = verify_trust_genesis(resigned)
    assert report.trust_domain_core_digest == pinned_core_digest  # ...same domain...
    assert _genesis_document_digest(resigned) != pinned_document_digest  # ...different document


def test_genesis_criterion_4iv_custody_change_event_seam_is_not_implemented_here() -> None:
    # (iv) A valid custody-change trust-log event changes replayed custody while
    # preserving digest+id. The EVENT CONTRACT is P2.2's catalogue (§5) and is
    # deliberately absent from P2.1: this test pins the seam so the absence is a
    # recorded boundary rather than an oversight, and fails if P2.1 grows a mutator.
    import regista._trust_domain as trust_domain

    mutating_verbs = ("apply", "change", "mutate", "update", "set_")
    assert not [
        name
        for name in dir(trust_domain)
        if "custody" in name.lower() and any(v in name.lower() for v in mutating_verbs)
    ]
    # What P2.1 does own: the replay input. Genesis custody is readable per signer,
    # which is what a P2.2 replay starts from before applying its events.
    fixture = mint_co_signed()
    parsed = parse_trust_genesis(fixture.document)
    for signer in parsed.signers:
        assert parsed.custody_by_fingerprint(signer.fingerprint) is not None


def test_genesis_criterion_4v_correction_preserves_the_superseded_declaration() -> None:
    # (v) The superseded declaration survives as evidence. In P2.1 the carrier is the
    # signed genesis document itself: the original text is still verifiable after a
    # correction is issued, so a later denial contradicts something the roots signed.
    # (Replay history for post-genesis corrections is P2.2's.)
    fixture = mint_co_signed()
    original = copy.deepcopy(fixture.document)
    corrected = _resign(
        fixture, _mutate(original, "initial_custody.0.declared_mode", "online-vault")
    )

    original_report = verify_trust_genesis(original)
    corrected_report = verify_trust_genesis(corrected)
    assert "offline-host" in original_report.root_governance.custody_declared
    assert "online-vault" in corrected_report.root_governance.custody_declared
    # Same domain, two verifiable custody claims, one of them superseded: the
    # contradiction is documented rather than erased.
    assert original_report.trust_domain_id == corrected_report.trust_domain_id


def test_genesis_criterion_4vi_custody_block_is_mandatory() -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    del doc["initial_custody"]
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "unknown_or_missing_field")


def test_genesis_criterion_4vi_custody_mandatory_even_when_all_unspecified() -> None:
    # Declining to declare is a declaration, and it is written down.
    fixture = mint_co_signed(declared_mode="unspecified", declared_holder="human:undeclared")
    report = verify_trust_genesis(fixture.document)
    assert report.root_governance.custody_declared == ("unspecified", "unspecified")
    assert report.root_governance.custody_verified is False


def test_genesis_criterion_4vi_missing_entry_invalid() -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    del doc["initial_custody"][1]
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "custody_missing_signer")


def test_genesis_criterion_4vi_duplicate_entry_invalid() -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    doc["initial_custody"][1] = copy.deepcopy(doc["initial_custody"][0])
    _assert_invalid(
        doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "duplicate_custody_fingerprint"
    )


def test_genesis_criterion_4vi_extraneous_entry_invalid() -> None:
    # An entry naming a fingerprint that is not a genesis signer: custody for a key
    # the domain never rooted.
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    stranger = dict(doc["initial_custody"][0])
    stranger["fingerprint"] = "ed25519:sha256:" + "f" * 64  # sorts last
    doc["initial_custody"].append(stranger)
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "custody_unknown_signer")


def test_genesis_criterion_4vi_unsorted_entries_invalid() -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    doc["initial_custody"] = list(reversed(doc["initial_custody"]))
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "custody_not_sorted")


def test_genesis_criterion_4vii_reports_label_custody_declared_and_unverified() -> None:
    # (vii) in the machine-readable channel as well as the human one; the human half
    # is TestTrustCLI::test_sign_then_verify_roundtrip ("unverified operator claims").
    report = verify_trust_genesis(mint_co_signed().document)
    data = report.to_dict()
    assert data["root_governance"]["custody_verified"] is False
    assert data["root_governance"]["custody_declared"] == ["offline-host", "offline-host"]
    assert data["custody_declared_holders_unverified"] == [
        "human:test-owner",
        "human:test-owner",
    ]


def test_wi292_custody_inside_binding_core_signer_rejected() -> None:
    # WI-292 relocation guard, the mirror of test_wi280_governance_inside_binding_core_rejected:
    # the pre-WI-292 shape (custody nested in a signer) is an unknown field now.
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    doc["binding_core"]["signers"][0]["custody"] = {
        "declared_mode": "offline-host",
        "declared_holder": "human:test-owner",
        "attestation": None,
    }
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "unknown_or_missing_field")


def test_wi292_custody_is_not_in_the_derivation() -> None:
    # Two documents identical except for custody: same digest, same id. The clearest
    # statement that an unverified claim is not part of the estate's name.
    seeds = [bytes([i + 1]) * 32 for i in range(2)]
    a = mint_genesis(threshold=2, signer_count=2, seeds=seeds, declared_mode="offline-airgapped")
    b = mint_genesis(threshold=2, signer_count=2, seeds=seeds, declared_mode="online-vault")
    assert a.trust_domain_core_digest == b.trust_domain_core_digest
    assert a.trust_domain_id == b.trust_domain_id
    # ...and both are independently valid, with their own declarations.
    assert verify_trust_genesis(a.document).root_governance.custody_declared == (
        "offline-airgapped",
        "offline-airgapped",
    )
    assert verify_trust_genesis(b.document).root_governance.custody_declared == (
        "online-vault",
        "online-vault",
    )


def test_genesis_criterion_5_countersignature_and_anchor_change_nothing() -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    doc["countersignatures"].append(_countersignature_entry())
    doc["anchors"].append(_anchor_entry())
    report = verify_trust_genesis(doc)  # no signature invalidated, no re-signing done
    assert report.trust_domain_core_digest == fixture.trust_domain_core_digest
    assert report.trust_domain_id == fixture.trust_domain_id
    assert report.signatures_verified == 2
    # 0.6.0 verifies neither; they are reported, not trusted.
    assert report.countersignatures_status == "present_unverified"
    assert report.anchors_status == "present_unverified"
    assert report.countersignature_count == 1
    assert report.anchor_count == 1


# ---------------------------------------------------------------------------
# §9 item 6, mode-derivation half (bundle renderer half deferred to P3.3)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("threshold", "signer_count", "expected"),
    [
        (1, 1, MODE_SOLO),
        (1, 2, MODE_SOLO_EFFECTIVE),
        (1, 3, MODE_SOLO_EFFECTIVE),
        (2, 2, MODE_CO_SIGNED),
        (2, 3, MODE_CO_SIGNED),
        (3, 3, MODE_CO_SIGNED),
    ],
)
def test_mode_derivation_table(threshold: int, signer_count: int, expected: str) -> None:
    assert derive_governance_mode(threshold, signer_count) == expected


@pytest.mark.parametrize(
    ("threshold", "signer_count", "reason"),
    [
        (0, 1, "threshold_below_one"),
        (-1, 3, "threshold_below_one"),
        (3, 2, "threshold_exceeds_signer_count"),
    ],
)
def test_mode_derivation_rejects_bad_shapes(
    threshold: int, signer_count: int, reason: str
) -> None:
    with pytest.raises(RegistaError) as excinfo:
        derive_governance_mode(threshold, signer_count)
    assert excinfo.value.code == ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID
    assert excinfo.value.detail is not None and excinfo.value.detail["reason"] == reason


def test_solo_mode_appears_in_verification_report() -> None:
    report = verify_trust_genesis(mint_solo().document)
    assert report.root_governance.mode == MODE_SOLO
    assert report.to_dict()["root_governance"]["mode"] == "solo"


# ---------------------------------------------------------------------------
# Mutation matrix over the signed fields — every edit invalid with a named reason
# ---------------------------------------------------------------------------


def _mutate(doc: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    doc = copy.deepcopy(doc)
    target: Any = doc
    parts = path.split(".")
    for part in parts[:-1]:
        target = target[int(part)] if part.isdigit() else target[part]
    last = parts[-1]
    if last.isdigit():
        target[int(last)] = value
    else:
        target[last] = value
    return doc


MUTATIONS: list[tuple[str, Any, ErrorCode, str]] = [
    ("type", "regista.trust-genesis-2", ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "wrong_type"),
    ("version", 2, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "wrong_version"),
    (
        "binding_core.type",
        "regista.trust-genesis.core-x",
        ErrorCode.TRUST_GENESIS_SCHEMA_INVALID,
        "wrong_type",
    ),
    (
        "binding_core.created_at",
        "2027-01-01T00:00:00.000000Z",
        ErrorCode.TRUST_GENESIS_DERIVATION_MISMATCH,
        "core_digest_mismatch",
    ),
    (
        "binding_core.nonce",
        "a" * 64,
        ErrorCode.TRUST_GENESIS_DERIVATION_MISMATCH,
        "core_digest_mismatch",
    ),
    (
        "binding_core.signers.0.signer_id",
        "root-x",
        ErrorCode.TRUST_GENESIS_DERIVATION_MISMATCH,
        "core_digest_mismatch",
    ),
    (
        # WI-292: custody is signed state OUTSIDE binding_core, so editing it does not
        # touch the digest — it breaks the signatures over document_core instead.
        "initial_custody.0.declared_mode",
        "online-vault",
        ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID,
        "bad_signature",
    ),
    (
        "binding_core.signers.0.fingerprint",
        "ed25519:sha256:" + "0" * 64,
        ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID,
        "fingerprint_mismatch",
    ),
    (
        "trust_domain_core_digest",
        "sha256:" + "0" * 64,
        ErrorCode.TRUST_GENESIS_DERIVATION_MISMATCH,
        "core_digest_mismatch",
    ),
    (
        "trust_log.project_instance_id",
        "99999999-9999-4999-8999-999999999999",
        ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID,
        "bad_signature",
    ),
    (
        "trust_log.project_name_hint",
        "not_the_signed_hint",
        ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID,
        "bad_signature",
    ),
    (
        "publication.url",
        "https://github.example/evil-attestations",
        ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID,
        "bad_signature",
    ),
    (
        "publication.path",
        "trust-domain-2.json",
        ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID,
        "bad_signature",
    ),
    (
        "initial_governance.signer_count",
        3,
        ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID,
        "signer_count_mismatch",
    ),
]


@pytest.mark.parametrize(("path", "value", "code", "reason"), MUTATIONS)
def test_mutation_matrix(path: str, value: Any, code: ErrorCode, reason: str) -> None:
    fixture = mint_co_signed(threshold=2, signer_count=2)
    assert verify_trust_genesis(fixture.document) is not None
    _assert_invalid(_mutate(fixture.document, path, value), code, reason)


def test_mutation_public_key_swap_is_fingerprint_mismatch() -> None:
    fixture = mint_co_signed()
    foreign = bytes(nacl.signing.SigningKey.generate().verify_key)
    doc = _mutate(
        fixture.document,
        "binding_core.signers.0.public_key",
        base64.b64encode(foreign).decode("ascii"),
    )
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID, "fingerprint_mismatch")


def test_mutation_trust_domain_id_is_named_mismatch() -> None:
    fixture = mint_co_signed()
    doc = _mutate(fixture.document, "trust_domain_id", str(uuid.uuid4()))
    _assert_invalid(
        doc, ErrorCode.TRUST_GENESIS_DERIVATION_MISMATCH, "trust_domain_id_mismatch"
    )


def test_corrupted_signature_entry_is_invalid_even_when_threshold_met() -> None:
    # threshold 2 of 3, all three sign, then one signature byte is flipped: the
    # document still has two good signatures, but a bad entry is never ignored —
    # that is how k-of-n silently becomes 1-of-n.
    fixture = mint_genesis(threshold=2, signer_count=3)
    doc = copy.deepcopy(fixture.document)
    raw = bytearray(base64.b64decode(doc["signatures"][0]["signature"]))
    raw[0] ^= 0xFF
    doc["signatures"][0]["signature"] = base64.b64encode(bytes(raw)).decode("ascii")
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID, "bad_signature")


def test_signature_by_unknown_signer_is_invalid() -> None:
    fixture = mint_co_signed()
    foreign_seed = bytes(nacl.signing.SigningKey.generate())
    foreign_fp = _compute_fingerprint(
        bytes(nacl.signing.SigningKey(foreign_seed).verify_key), "ed25519"
    )
    doc = copy.deepcopy(fixture.document)
    doc["signatures"].append(
        make_signature_entry(doc, foreign_seed, "root-z", foreign_fp)
    )
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID, "unknown_signer")


def test_duplicate_signature_entry_is_invalid() -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    doc["signatures"].append(copy.deepcopy(doc["signatures"][0]))
    _assert_invalid(
        doc, ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID, "duplicate_signature_entry"
    )


def test_extra_valid_signatures_are_permitted_and_reported() -> None:
    fixture = mint_genesis(threshold=2, signer_count=3)  # all 3 sign by default
    report = verify_trust_genesis(fixture.document)
    assert report.signatures_verified == 3
    assert report.extra_signatures == 1


def test_signers_must_be_sorted_by_fingerprint() -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    doc["binding_core"]["signers"].reverse()
    # Enforced, never silently sorted: the digest must be independent of
    # authoring order because the AUTHOR sorted, not because the parser fixed it.
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID, "signers_not_sorted")


def test_duplicate_key_material_is_invalid_not_co_signed() -> None:
    solo = mint_solo()
    doc = copy.deepcopy(solo.document)
    dup = copy.deepcopy(doc["binding_core"]["signers"][0])
    dup["signer_id"] = "root-b"
    doc["binding_core"]["signers"].append(dup)
    doc["initial_governance"] = {"mode": MODE_CO_SIGNED, "threshold": 2, "signer_count": 2}
    _assert_invalid(
        doc, ErrorCode.TRUST_GENESIS_GOVERNANCE_INVALID, "duplicate_signer_fingerprint"
    )


def test_custody_attestation_must_be_null_in_060() -> None:
    fixture = mint_solo()
    doc = _mutate(fixture.document, "initial_custody.0.attestation", {"kind": "tpm-quote"})
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "attestation_not_null")


# ---------------------------------------------------------------------------
# Unknown-field rejection, top level and nested
# ---------------------------------------------------------------------------


UNKNOWN_FIELD_SITES = [
    "",  # document top level
    "binding_core",
    "binding_core.signers.0",
    "initial_custody.0",
    "initial_governance",
    "trust_log",
    "publication",
    "signatures.0",
]


@pytest.mark.parametrize("site", UNKNOWN_FIELD_SITES)
def test_unknown_field_rejected(site: str) -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    target: Any = doc
    if site:
        for part in site.split("."):
            target = target[int(part)] if part.isdigit() else target[part]
    target["surprise"] = "x"
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "unknown_or_missing_field")


@pytest.mark.parametrize("section", ["countersignatures", "anchors"])
def test_unknown_field_rejected_in_unverified_sections(section: str) -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    entry = _countersignature_entry() if section == "countersignatures" else _anchor_entry()
    entry["surprise"] = "x"
    doc[section].append(entry)
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "unknown_or_missing_field")


def test_missing_field_rejected() -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    del doc["trust_log"]
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "unknown_or_missing_field")


def test_wi280_governance_inside_binding_core_rejected() -> None:
    # WI-280 regression guard: threshold/signer_count are NOT in binding_core.
    # The pre-overlay shape (still visible in the Gate 0 vector) must be rejected
    # by the strict parser.
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    doc["binding_core"]["governance"] = {
        "mode": MODE_CO_SIGNED,
        "threshold": 2,
        "signer_count": 2,
    }
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "unknown_or_missing_field")


def test_countersignature_over_restricted_to_core_digest() -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    entry = _countersignature_entry()
    entry["over"] = "trust_domain_id"  # retargeting at anything else is invalid
    doc["countersignatures"].append(entry)
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "invalid_over_target")


# ---------------------------------------------------------------------------
# Unverified-section SHAPE is contract (P2.1 review adoption 2)
#
# 0.6.0 verifies neither countersignatures nor anchors cryptographically (§3.5),
# and reports them as ``present_unverified``. That report is only meaningful over
# entries that are *shaped* like the thing they claim to be: "present_unverified"
# over a signature field holding "not base64" and a timestamp holding "whenever"
# asserts the existence of a countersignature that is not one. The check deferred
# in 0.6.0 is the cryptographic one, never the parse.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("signed_at", "sometime last tuesday", "malformed_value"),
        ("signed_at", "2026-08-21T00:00:00Z", "malformed_value"),  # no microseconds
        ("signed_at", "2026-08-21 00:00:00.000000Z", "malformed_value"),  # space, not T
        ("signed_at", "2026-02-30T00:00:00.000000Z", "impossible_timestamp"),
        ("signature", "this is not base64 at all!!", "malformed_base64"),
        ("signature", base64.b64encode(b"\x01" * 63).decode("ascii"), "wrong_signature_length"),
        ("scheme_id", "rsa-pkcs1", "unsupported_scheme"),
        ("fingerprint", "ed448:sha256:" + "ab" * 32, "fingerprint_scheme_mismatch"),
        ("fingerprint", "ed25519:sha256:NOTHEX" + "ab" * 29, "malformed_value"),
        ("custodian_id", "", "empty_string"),
        ("statement", "   ", "empty_string"),
    ],
)
def test_malformed_countersignature_field_rejected(field: str, value: str, reason: str) -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    entry = _countersignature_entry()
    entry[field] = value
    doc["countersignatures"].append(entry)
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, reason)


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("obtained_at", "whenever", "malformed_value"),
        ("obtained_at", "2026-08-21T00:00:00Z", "malformed_value"),
        ("obtained_at", "2026-08-32T00:00:00.000000Z", "impossible_timestamp"),
        ("obtained_at", "2026-13-01T00:00:00.000000Z", "impossible_timestamp"),
        ("evidence", [], "not_an_object"),
        ("evidence", {"receipt": {1: "x"}}, "non_string_key"),
        ("evidence", {"receipt": {"": "x"}}, "non_string_key"),
        ("evidence", {"receipt": {"nested": b"\x00"}}, "not_a_json_value"),
    ],
)
def test_malformed_anchor_field_rejected(field: str, value: Any, reason: str) -> None:
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    entry = _anchor_entry()
    entry[field] = value
    doc["anchors"].append(entry)
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, reason)


def test_well_shaped_unverified_entries_still_report_present_unverified() -> None:
    # The tightening rejects junk, not the sections themselves: a well-shaped entry
    # keeps its 0.6.0 status, including a nested free-form evidence object.
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    doc["countersignatures"].append(_countersignature_entry())
    anchor = _anchor_entry()
    anchor["evidence"] = {
        "tag": "trust-genesis-v1",
        "depth": 3,
        "signed": True,
        "receipt": None,
        "witnesses": ["a", {"b": 1.5}],
    }
    doc["anchors"].append(anchor)
    report = verify_trust_genesis(doc)
    assert report.countersignatures_status == "present_unverified"
    assert report.anchors_status == "present_unverified"


def test_impossible_timestamp_rejected_in_verified_sections() -> None:
    # The same calendar check applies to the fields that ARE signed.
    fixture = mint_co_signed()
    doc = copy.deepcopy(fixture.document)
    doc["signatures"][0]["signed_at"] = "2026-04-31T00:00:00.000000Z"
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "impossible_timestamp")
    doc = copy.deepcopy(fixture.document)
    doc["binding_core"]["created_at"] = "2026-08-20T25:00:00.000000Z"
    _assert_invalid(doc, ErrorCode.TRUST_GENESIS_SCHEMA_INVALID, "impossible_timestamp")


# ---------------------------------------------------------------------------
# Governance monotonicity primitive (WI-280) — for P2.2's replay
# ---------------------------------------------------------------------------


def _fingerprints(n: int) -> tuple[str, ...]:
    return tuple(
        _compute_fingerprint(bytes([i + 1]) * 32, "ed25519") for i in range(n)
    )


class TestGovernanceMonotonicity:
    def test_threshold_decrease_rejected_no_matter_what(self) -> None:
        fps = _fingerprints(3)
        current = GovernanceState(threshold=2, signer_fingerprints=fps[:2])
        # Even with a completely replaced (arguably "better") signer set, a
        # decrease is rejected — the function takes no signer identity at all,
        # so no authorization can make it valid.
        proposed = GovernanceState(threshold=1, signer_fingerprints=fps)
        with pytest.raises(RegistaError) as excinfo:
            validate_governance_transition(current, proposed)
        assert excinfo.value.code == ErrorCode.TRUST_GOVERNANCE_TRANSITION_INVALID
        assert excinfo.value.detail is not None
        assert excinfo.value.detail["reason"] == "threshold_decrease"

    def test_threshold_increase_accepted_no_epoch_change(self) -> None:
        fps = _fingerprints(3)
        current = GovernanceState(threshold=1, signer_fingerprints=fps)
        proposed = GovernanceState(threshold=2, signer_fingerprints=fps)
        transition = validate_governance_transition(current, proposed)
        assert transition.new_mode == MODE_CO_SIGNED
        # solo_effective -> co_signed is a cheap signed upgrade authorized at the
        # threshold active immediately BEFORE it.
        assert transition.authorization_threshold == 1

    def test_signer_replacement_at_current_threshold(self) -> None:
        fps = _fingerprints(4)
        current = GovernanceState(threshold=2, signer_fingerprints=fps[:2])
        proposed = GovernanceState(threshold=2, signer_fingerprints=(fps[0], fps[2]))
        transition = validate_governance_transition(current, proposed)
        assert transition.authorization_threshold == 2  # signed at the CURRENT threshold
        assert transition.new_mode == MODE_CO_SIGNED

    def test_duplicate_fingerprint_result_rejected(self) -> None:
        fps = _fingerprints(2)
        current = GovernanceState(threshold=2, signer_fingerprints=fps)
        proposed = GovernanceState(threshold=2, signer_fingerprints=(fps[0], fps[0]))
        with pytest.raises(RegistaError) as excinfo:
            validate_governance_transition(current, proposed)
        assert excinfo.value.detail is not None
        assert excinfo.value.detail["reason"] == "duplicate_signer_fingerprint"

    def test_proposed_threshold_must_fit_proposed_set(self) -> None:
        fps = _fingerprints(3)
        current = GovernanceState(threshold=2, signer_fingerprints=fps[:2])
        proposed = GovernanceState(threshold=3, signer_fingerprints=fps[:2])
        with pytest.raises(RegistaError) as excinfo:
            validate_governance_transition(current, proposed)
        assert excinfo.value.detail is not None
        assert excinfo.value.detail["reason"] == "threshold_exceeds_signer_count"

    def test_empty_proposed_set_rejected(self) -> None:
        fps = _fingerprints(1)
        current = GovernanceState(threshold=1, signer_fingerprints=fps)
        proposed = GovernanceState(threshold=1, signer_fingerprints=())
        with pytest.raises(RegistaError) as excinfo:
            validate_governance_transition(current, proposed)
        assert excinfo.value.detail is not None
        assert excinfo.value.detail["reason"] == "empty_signer_set"


# ---------------------------------------------------------------------------
# Report labeling (OPERATOR-FORGERY R1/R2) and fixture determinism
# ---------------------------------------------------------------------------


def test_custody_claims_labeled_unverified() -> None:
    report = verify_trust_genesis(mint_co_signed().document)
    data = report.to_dict()
    # declared_mode/declared_holder are unverified operator claims (R1): the
    # carrying keys say so, and custody_verified is hard False.
    assert data["root_governance"]["custody_verified"] is False
    assert "custody_declared" in data["root_governance"]
    assert "custody_declared_holders_unverified" in data
    # Independence of two keys is unverifiable in 0.6.0 (R2) — the literal string.
    assert data["root_governance"]["independence"] == "unverifiable"


def test_fixture_determinism_with_seeds() -> None:
    seeds = [bytes([7]) * 32, bytes([9]) * 32]
    a = mint_genesis(threshold=2, signer_count=2, seeds=seeds)
    b = mint_genesis(threshold=2, signer_count=2, seeds=seeds)
    assert a.trust_domain_core_digest == b.trust_domain_core_digest
    assert a.trust_domain_id == b.trust_domain_id


def test_parse_for_signing_allows_missing_signature_sections() -> None:
    fixture = mint_solo()
    doc = copy.deepcopy(fixture.document)
    for section in ("signatures", "countersignatures", "anchors"):
        del doc[section]
    parsed = parse_trust_genesis(doc, for_signing=True)
    assert parsed.trust_domain_id == fixture.trust_domain_id
    with pytest.raises(RegistaError):
        parse_trust_genesis(doc)  # verification-mode parse still requires them


def test_signature_input_is_stable_under_extras() -> None:
    # countersignatures/anchors are excluded from sig_bytes: adding them does not
    # change the bytes any signer signs.
    fixture = mint_co_signed()
    before = genesis_signature_input(fixture.document)
    doc = copy.deepcopy(fixture.document)
    doc["countersignatures"].append(_countersignature_entry())
    doc["anchors"].append(_anchor_entry())
    doc["signatures"] = []
    assert genesis_signature_input(doc) == before


# ---------------------------------------------------------------------------
# CLI: offline ceremony helpers (§5.4). Neither verb ever contacts a database.
# ---------------------------------------------------------------------------


class TestTrustCLI:
    def _write_unsigned(self, tmp_path: Path, fixture: TrustRootFixture) -> Path:
        doc = copy.deepcopy(fixture.document)
        for section in ("signatures", "countersignatures", "anchors"):
            del doc[section]
        path = tmp_path / "genesis-unsigned.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        return path

    def test_sign_then_verify_roundtrip(self, tmp_path: Path, capsys: Any) -> None:
        from regista._cli import main as cli_main

        fixture = mint_solo()
        doc_path = self._write_unsigned(tmp_path, fixture)
        key_path = tmp_path / "root-a.seed"
        key_path.write_text(fixture.seeds["root-a"].hex(), encoding="utf-8")
        sig_path = tmp_path / "root-a.sig.json"

        cli_main(
            [
                "trust",
                "sign-genesis",
                "--core",
                str(doc_path),
                "--key",
                str(key_path),
                "--out",
                str(sig_path),
            ]
        )
        out = capsys.readouterr().out
        # §5.4: prints the exact bytes it will sign.
        assert "signing_input_hex: " in out
        printed_hex = out.split("signing_input_hex: ", 1)[1].splitlines()[0]
        assert bytes.fromhex(printed_hex) == genesis_signature_input(fixture.document)

        entry = json.loads(sig_path.read_text(encoding="utf-8"))
        assert entry["signer_id"] == "root-a"
        assert entry["fingerprint"] == fixture.fingerprints["root-a"]

        signed = copy.deepcopy(fixture.document)
        signed["signatures"] = [entry]
        signed_path = tmp_path / "genesis-signed.json"
        signed_path.write_text(json.dumps(signed), encoding="utf-8")
        cli_main(["trust", "verify-genesis", str(signed_path)])
        out = capsys.readouterr().out
        # §3.7 report obligation: the mode string reaches the human report.
        assert "root_governance.mode: solo" in out
        assert "verdict: VALID" in out
        assert f"trust_domain_id: {fixture.trust_domain_id}" in out
        assert "unverified operator claims" in out

    def test_verify_genesis_solo_effective_mode_visible(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        from regista._cli import main as cli_main

        fixture = mint_solo_effective(signer_count=3)
        path = tmp_path / "genesis.json"
        path.write_text(json.dumps(fixture.document), encoding="utf-8")
        cli_main(["trust", "verify-genesis", str(path)])
        out = capsys.readouterr().out
        assert "root_governance.mode: solo_effective" in out

    def test_verify_genesis_json_output(self, tmp_path: Path, capsys: Any) -> None:
        from regista._cli import main as cli_main

        fixture = mint_co_signed()
        path = tmp_path / "genesis.json"
        path.write_text(json.dumps(fixture.document), encoding="utf-8")
        cli_main(["trust", "verify-genesis", str(path), "--json"])
        data = json.loads(capsys.readouterr().out)
        assert data["root_governance"]["mode"] == "co_signed"
        assert data["trust_domain_id"] == fixture.trust_domain_id
        assert data["root_governance"]["custody_verified"] is False

    def test_verify_genesis_invalid_exits_nonzero(self, tmp_path: Path, capsys: Any) -> None:
        from regista._cli import main as cli_main

        fixture = mint_co_signed()
        doc = copy.deepcopy(fixture.document)
        doc["initial_governance"]["mode"] = MODE_SOLO_EFFECTIVE
        path = tmp_path / "genesis-bad.json"
        path.write_text(json.dumps(doc), encoding="utf-8")
        with pytest.raises(SystemExit) as excinfo:
            cli_main(["trust", "verify-genesis", str(path)])
        assert excinfo.value.code == 1
        err = capsys.readouterr().err
        assert "TRUST_GENESIS_GOVERNANCE_INVALID" in err

    def test_sign_genesis_refuses_non_signer_key(self, tmp_path: Path, capsys: Any) -> None:
        from regista._cli import main as cli_main

        fixture = mint_solo()
        doc_path = self._write_unsigned(tmp_path, fixture)
        key_path = tmp_path / "foreign.seed"
        key_path.write_text(bytes(nacl.signing.SigningKey.generate()).hex(), encoding="utf-8")
        sig_path = tmp_path / "never-written.sig.json"
        with pytest.raises(SystemExit) as excinfo:
            cli_main(
                [
                    "trust",
                    "sign-genesis",
                    "--core",
                    str(doc_path),
                    "--key",
                    str(key_path),
                    "--out",
                    str(sig_path),
                ]
            )
        assert excinfo.value.code == 1
        assert not sig_path.exists()

    def test_sign_genesis_refuses_derivation_mismatch(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        # Never sign a document whose stated digest disagrees with its binding_core.
        from regista._cli import main as cli_main

        fixture = mint_solo()
        doc = copy.deepcopy(fixture.document)
        for section in ("signatures", "countersignatures", "anchors"):
            del doc[section]
        doc["trust_domain_core_digest"] = "sha256:" + "0" * 64
        doc_path = tmp_path / "genesis-tampered.json"
        doc_path.write_text(json.dumps(doc), encoding="utf-8")
        key_path = tmp_path / "root-a.seed"
        key_path.write_text(fixture.seeds["root-a"].hex(), encoding="utf-8")
        sig_path = tmp_path / "never-written.sig.json"
        with pytest.raises(SystemExit) as excinfo:
            cli_main(
                [
                    "trust",
                    "sign-genesis",
                    "--core",
                    str(doc_path),
                    "--key",
                    str(key_path),
                    "--out",
                    str(sig_path),
                ]
            )
        assert excinfo.value.code == 1
        assert not sig_path.exists()

    # -----------------------------------------------------------------------
    # P2.1 review adoption 1: --signed-at is validated at SIGNING time.
    # The tool must never mint an artifact its own verifier rejects — an offline
    # ceremony finds out only after the keys are back in the safe.
    # -----------------------------------------------------------------------

    @pytest.mark.parametrize(
        "signed_at",
        [
            "2026-08-21 00:00:00",  # the pre-fix reproduction: space, no microseconds
            "2026-08-21T00:00:00Z",  # no microseconds
            "2026-08-21T00:00:00.000000+00:00",  # offset spelling, not Z
            "2026-08-21T00:00:00.000Z",  # milliseconds
            "yesterday",
            "2026-02-30T00:00:00.000000Z",  # lexically fine, not a real date
        ],
    )
    def test_sign_genesis_refuses_malformed_signed_at(
        self, tmp_path: Path, capsys: Any, signed_at: str
    ) -> None:
        from regista._cli import main as cli_main

        fixture = mint_solo()
        doc_path = self._write_unsigned(tmp_path, fixture)
        key_path = tmp_path / "root-a.seed"
        key_path.write_text(fixture.seeds["root-a"].hex(), encoding="utf-8")
        sig_path = tmp_path / "never-written.sig.json"
        with pytest.raises(SystemExit) as excinfo:
            cli_main(
                [
                    "trust",
                    "sign-genesis",
                    "--core",
                    str(doc_path),
                    "--key",
                    str(key_path),
                    "--out",
                    str(sig_path),
                    "--signed-at",
                    signed_at,
                ]
            )
        assert excinfo.value.code == 1
        # Named refusal, and nothing was produced.
        assert "TRUST_GENESIS_SCHEMA_INVALID" in capsys.readouterr().err
        assert not sig_path.exists()

    def test_sign_genesis_signed_at_override_survives_its_own_verifier(
        self, tmp_path: Path, capsys: Any
    ) -> None:
        # The positive half of the same invariant: any --signed-at the signer accepts
        # must verify. Round-trips the accepted value through verify-genesis.
        from regista._cli import main as cli_main

        fixture = mint_solo()
        doc_path = self._write_unsigned(tmp_path, fixture)
        key_path = tmp_path / "root-a.seed"
        key_path.write_text(fixture.seeds["root-a"].hex(), encoding="utf-8")
        sig_path = tmp_path / "root-a.sig.json"
        cli_main(
            [
                "trust",
                "sign-genesis",
                "--core",
                str(doc_path),
                "--key",
                str(key_path),
                "--out",
                str(sig_path),
                "--signed-at",
                "2026-08-21T00:01:02.000003Z",
            ]
        )
        capsys.readouterr()
        entry = json.loads(sig_path.read_text(encoding="utf-8"))
        assert entry["signed_at"] == "2026-08-21T00:01:02.000003Z"
        signed = copy.deepcopy(fixture.document)
        signed["signatures"] = [entry]
        signed_path = tmp_path / "genesis-signed.json"
        signed_path.write_text(json.dumps(signed), encoding="utf-8")
        cli_main(["trust", "verify-genesis", str(signed_path)])
        assert "verdict: VALID" in capsys.readouterr().out

    def test_default_signed_at_is_accepted_by_the_verifier(self, tmp_path: Path) -> None:
        # The minted default must satisfy the same rule as an override.
        from regista._trust_domain import require_genesis_timestamp

        fixture = mint_solo()
        doc_path = self._write_unsigned(tmp_path, fixture)
        key_path = tmp_path / "root-a.seed"
        key_path.write_text(fixture.seeds["root-a"].hex(), encoding="utf-8")
        sig_path = tmp_path / "root-a.sig.json"
        from regista._cli import main as cli_main

        cli_main(
            [
                "trust",
                "sign-genesis",
                "--core",
                str(doc_path),
                "--key",
                str(key_path),
                "--out",
                str(sig_path),
            ]
        )
        entry = json.loads(sig_path.read_text(encoding="utf-8"))
        require_genesis_timestamp(entry["signed_at"], "signed_at")

    # -----------------------------------------------------------------------
    # P2.1 review adoption 3: --out never silently clobbers a collected signature.
    # -----------------------------------------------------------------------

    def test_sign_genesis_refuses_to_overwrite_out(self, tmp_path: Path, capsys: Any) -> None:
        from regista._cli import main as cli_main

        fixture = mint_solo()
        doc_path = self._write_unsigned(tmp_path, fixture)
        key_path = tmp_path / "root-a.seed"
        key_path.write_text(fixture.seeds["root-a"].hex(), encoding="utf-8")
        sig_path = tmp_path / "root-a.sig.json"
        # Stand in for a signature already collected from another signer.
        existing = '{"already": "collected"}\n'
        sig_path.write_text(existing, encoding="utf-8")
        with pytest.raises(SystemExit) as excinfo:
            cli_main(
                [
                    "trust",
                    "sign-genesis",
                    "--core",
                    str(doc_path),
                    "--key",
                    str(key_path),
                    "--out",
                    str(sig_path),
                ]
            )
        assert excinfo.value.code == 1
        assert "INVALID_ARGUMENT" in capsys.readouterr().err
        assert sig_path.read_text(encoding="utf-8") == existing

    def test_sign_genesis_force_overwrites_out(self, tmp_path: Path, capsys: Any) -> None:
        from regista._cli import main as cli_main

        fixture = mint_solo()
        doc_path = self._write_unsigned(tmp_path, fixture)
        key_path = tmp_path / "root-a.seed"
        key_path.write_text(fixture.seeds["root-a"].hex(), encoding="utf-8")
        sig_path = tmp_path / "root-a.sig.json"
        sig_path.write_text('{"already": "collected"}\n', encoding="utf-8")
        cli_main(
            [
                "trust",
                "sign-genesis",
                "--core",
                str(doc_path),
                "--key",
                str(key_path),
                "--out",
                str(sig_path),
                "--force",
            ]
        )
        capsys.readouterr()
        assert json.loads(sig_path.read_text(encoding="utf-8"))["signer_id"] == "root-a"
