"""Byte-level conformance vectors for the regista 0.6.0 cryptographic epoch (Gate 0, P0.3).

P0.3's acceptance criterion, from ``IMPLEMENTATION-PLAN.md``:

    *Each vector is reproducible from a clean checkout by one documented command, and a
    deliberate one-byte change to each input flips its expected hash.*

How that requirement is discharged here:

* ``tools/make_v6_vectors.py`` is the generator — it imports the vendored RFC 8785
  canonicalizer, PyNaCl, the stdlib, and (for the ``review-subject-state`` case only)
  ``regista._reducer``; every domain tag and framing rule comes from the frozen spec set
  (``V6-ENVELOPE.md`` §6.1 and its siblings), not from the generator.
* ``tests/vectors/v6/`` holds one JSON file per case plus a ``manifest.json``.
* This module recomputes the same bytes from the same inputs and asserts equality, then
  flips one byte in each input and asserts the digest changes.

The vectors are the artifact that makes a future non-Python verifier possible — nobody has
written one yet, but the frozen bytes are what an independent implementation checks against.

The v6 envelope, signature input, payload hash, event hash and strict parser assertions below
run through regista's production implementation. The remaining sibling-domain vectors stay
independent until their owning implementation packages land.

The test key is 32 bytes of 0x01 — NEVER usable in production.  It exists so every byte is
reproducible by an implementer with no private material.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import struct
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

import nacl.signing

from regista._jcs import canonicalize
from regista._lineage import MODEL_LINEAGE_FAMILIES
from regista._signing import (
    canonicalize_v6_envelope,
    compute_v6_event_hash,
    sign_v6_envelope,
    v6_signature_input,
)
from regista._verification import (
    EnvelopeVersion,
    classify_envelope_bytes,
    parse_v6_envelope_strict,
    verify_v6_signature,
)

VECTORS_DIR = Path(__file__).resolve().parents[1] / "tests" / "vectors" / "v6"
MANIFEST_PATH = VECTORS_DIR / "manifest.json"
MANIFEST = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

SEED = bytes.fromhex(MANIFEST["test_seed_hex"])
PUB = bytes.fromhex(MANIFEST["test_public_key_hex"])
SK = nacl.signing.SigningKey(SEED)

DOMAINS = {k: v.encode("utf-8") for k, v in MANIFEST["domain_tags"].items()}


def u64be(n: int) -> bytes:
    return struct.pack(">Q", n)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_str(data: bytes) -> str:
    return "sha256:" + sha256_hex(data)


def domain_digest(domain: bytes, *parts: bytes) -> str:
    return digest_str(domain + b"".join(parts))


def domain_digest_framed(domain: bytes, payload: bytes) -> str:
    return digest_str(domain + u64be(len(payload)) + payload)


def fingerprint(public_key: bytes) -> str:
    return "ed25519:sha256:" + sha256_hex(public_key)


def _load_case(name: str) -> dict[str, Any]:
    return json.loads((VECTORS_DIR / f"{name}.json").read_text(encoding="utf-8"))


CASE_NAMES = [c["name"] for c in MANIFEST["cases"]]


def _flip_one_byte(data: bytes) -> bytes:
    assert len(data) > 0
    mutated = bytearray(data)
    mutated[0] ^= 0xFF
    return bytes(mutated)


def _flip_one_char(s: str) -> str:
    assert len(s) > 0
    c = s[0]
    flipped_char = chr(ord(c) ^ 0x01) if ord(c) < 0x10FFFF else chr(0x41)
    return flipped_char + s[1:]


def test_manifest_loads_and_lists_every_case() -> None:
    assert len(MANIFEST["cases"]) == len(CASE_NAMES)
    assert len(CASE_NAMES) == len(set(CASE_NAMES)), "duplicate case names"
    assert MANIFEST["test_seed_hex"] == "01" * 32


@pytest.mark.parametrize("name", CASE_NAMES, ids=CASE_NAMES)
def test_vector_file_exists_and_round_trips(name: str) -> None:
    case = _load_case(name)
    assert case["category"], f"{name}: missing category"
    assert case["description"], f"{name}: missing description"
    assert case["input"], f"{name}: missing input"
    assert case["expected"], f"{name}: missing expected"


def test_v6_envelope_basic() -> None:
    case = _load_case("v6-envelope-basic")
    env = case["input"]["envelope_declaration_order"]
    canonical = canonicalize_v6_envelope(env)
    assert canonical == case["expected"]["canonical_bytes"].encode()
    assert len(canonical) == case["expected"]["canonical_len"]
    assert sha256_hex(canonical) == case["expected"]["canonical_sha256"]

    sig_input = v6_signature_input(canonical)
    assert sha256_hex(sig_input) == case["expected"]["signature_input_sha256"]

    signed = sign_v6_envelope(env, SEED)
    signature = signed.signature
    assert signature.hex() == case["expected"]["signature_hex"]

    assert signed.event_hash_text == case["expected"]["event_hash"]
    assert signed.payload_canonical_hash_text == case["expected"]["payload_canonical_hash"]
    result = verify_v6_signature(
        canonical,
        signature,
        PUB,
        payload_canonical_hash=case["expected"]["payload_canonical_hash"],
        expected_event_hash=case["expected"]["event_hash"],
        expected_project_instance_id=env["project_instance_id"],
        expected_trust_domain_id=env["trust_domain_id"],
    )
    assert result.signature_and_hashes_valid
    assert result.unchecked == ()
    assert result.project_binding_valid is True
    assert result.trust_domain_binding_valid is True
    assert result.envelope_version is EnvelopeVersion.V6
    assert parse_v6_envelope_strict(canonical) == json.loads(canonical)
    assert classify_envelope_bytes(canonical) is EnvelopeVersion.V6


def test_v6_envelope_has_sixteen_keys_in_jcs_order() -> None:
    case = _load_case("v6-envelope-canonical-order")
    env = case["input"]["envelope_declaration_order"]
    canonical = canonicalize_v6_envelope(env)
    parsed = json.loads(canonical)
    expected_order = [
        "actor",
        "authorization",
        "chain",
        "entity",
        "entity_seq",
        "event_id",
        "occurred_at",
        "payload",
        "producer",
        "project_instance_id",
        "signing",
        "transition",
        "trust_domain_id",
        "type",
        "version",
        "workflow",
    ]
    assert list(parsed.keys()) == expected_order
    assert list(parsed.keys()) == case["expected"]["top_level_key_order"]


def test_jcs_orders_by_utf16be_not_code_point() -> None:
    """The sixteen top-level keys are ASCII and cannot distinguish the two orderings.

    The payload keys can: a non-BMP character's UTF-16BE form starts with a surrogate
    (0xD83D), which sorts *before* U+FF21 (fullwidth A), while by code point it sorts after
    (``_vendor/rfc8785.py:164``). This is the one assertion in the suite that fails for an
    implementation that sorted by code point.
    """
    case = _load_case("v6-envelope-canonical-order")
    env = case["input"]["envelope_declaration_order"]
    parsed = json.loads(canonicalize_v6_envelope(env))
    payload_keys = list(parsed["payload"].keys())

    assert payload_keys == case["expected"]["payload_key_order"]
    assert payload_keys == sorted(env["payload"].keys(), key=lambda k: k.encode("utf-16be"))
    assert payload_keys != sorted(env["payload"].keys()), (
        "the vector must discriminate UTF-16BE ordering from code-point ordering"
    )
    assert case["expected"]["utf16be_order_differs_from_code_point_order"] is True
    assert payload_keys.index("\U0001f600") < payload_keys.index("\uff21")


def test_key_id_matches_the_spec_test_key_block() -> None:
    """`key_id` is an opaque fixture and must be the one V6-ENVELOPE §10.1 declares.

    Production key ids are random (`_principal_keys.py:49-50`), so nothing derives this
    value — which is exactly why it has to be pinned to the spec's own test-key block
    rather than computed. It is signed input in every envelope vector.
    """
    for name in ("v6-envelope-basic", "v6-envelope-no-model", "bootstrap-trust-genesis"):
        env = _load_case(name)["input"]["envelope_declaration_order"]
        assert env["signing"]["key_id"] == "pk_1bf310ecef19e79a", (
            f"{name}: key_id must equal the V6-ENVELOPE §10.1 test key id"
        )


def test_v6_envelope_no_model() -> None:
    case = _load_case("v6-envelope-no-model")
    env = case["input"]["envelope_declaration_order"]
    canonical = canonicalize_v6_envelope(env)
    assert canonical == case["expected"]["canonical_bytes"].encode()
    parsed = json.loads(canonical)
    assert parsed["producer"]["model"] is None
    assert parsed["producer"]["model_lineage"] is None
    assert parsed["producer"]["harness"] == "claude-code"


def test_producer_lineage_is_a_registered_family() -> None:
    for name in CASE_NAMES:
        case = _load_case(name)
        envelope = case.get("input", {}).get("envelope_declaration_order")
        if not isinstance(envelope, dict) or "producer" not in envelope:
            continue
        lineage = envelope["producer"]["model_lineage"]
        if lineage is not None:
            assert lineage in MODEL_LINEAGE_FAMILIES


@pytest.mark.parametrize(
    "name",
    [
        "bootstrap-trust-genesis",
        "bootstrap-cutover-checkpoint",
        "bootstrap-project-initialized",
    ],
    ids=lambda n: n,
)
def test_bootstrap_cases_have_null_key_binding(name: str) -> None:
    case = _load_case(name)
    env = case["input"]["envelope_declaration_order"]
    canonical = canonicalize_v6_envelope(env)
    parsed = json.loads(canonical)
    assert parsed["signing"]["key_binding_event_hash"] is None
    signed = sign_v6_envelope(env, SEED)
    assert case["expected"]["event_hash"] == signed.event_hash_text
    assert case["expected"]["payload_canonical_hash"] == signed.payload_canonical_hash_text


def test_bootstrap_cutover_uses_legacy_head_hash() -> None:
    case = _load_case("bootstrap-cutover-checkpoint")
    env = case["input"]["envelope_declaration_order"]
    parsed = json.loads(canonicalize_v6_envelope(env))
    assert parsed["chain"]["previous_project_event_hash"] == case["input"]["legacy_head_hash"]
    assert parsed["payload"]["previous_epoch"]["head_hash_construction"] == (
        "sha256(canonical_envelope||signature)"
    )


def test_bootstrap_project_initialized_has_empty_epoch() -> None:
    case = _load_case("bootstrap-project-initialized")
    env = case["input"]["envelope_declaration_order"]
    parsed = json.loads(canonicalize_v6_envelope(env))
    assert parsed["payload"]["previous_epoch"]["event_count"] == 0
    assert parsed["payload"]["previous_epoch"]["head_event_hash"] is None
    assert parsed["chain"]["previous_project_event_hash"] is None


def test_fingerprint_primary() -> None:
    case = _load_case("fingerprint-primary")
    assert fingerprint(PUB) == case["expected"]["fingerprint"]
    assert case["expected"]["fingerprint"] == "ed25519:sha256:" + sha256_hex(PUB)


def test_fingerprint_second_key_differs() -> None:
    case = _load_case("fingerprint-second-key")
    second_pub = bytes(nacl.signing.SigningKey(bytes([0x02]) * 32).verify_key)
    assert fingerprint(second_pub) == case["expected"]["fingerprint"]
    primary = _load_case("fingerprint-primary")["expected"]["fingerprint"]
    assert case["expected"]["fingerprint"] != primary, "fingerprints must be key-distinct"


def test_version_aware_event_hash() -> None:
    case = _load_case("version-aware-event-hash")
    canonical = case["input"]["canonical_bytes"].encode()
    signature = bytes.fromhex(case["input"]["signature_hex"])

    v6_hash = "sha256:" + compute_v6_event_hash(canonical, signature).hex()
    legacy_hash = digest_str(canonical + signature)

    assert v6_hash == case["expected"]["v6_event_hash"]
    assert legacy_hash == case["expected"]["legacy_event_hash"]
    assert v6_hash != legacy_hash, (
        "v6 domain-tagged + length-framed hash must differ from legacy sha256(env||sig)"
    )


def test_legacy_seam_checkpoint() -> None:
    case = _load_case("legacy-seam-checkpoint")
    legacy_canonical = case["input"]["legacy_canonical_bytes"].encode()
    legacy_sig = bytes.fromhex(case["input"]["legacy_signature_hex"])
    legacy_head = digest_str(legacy_canonical + legacy_sig)
    assert legacy_head == case["expected"]["legacy_head_hash"]

    checkpoint_env = case["input"]["checkpoint_envelope"]
    parsed = json.loads(canonicalize(checkpoint_env))
    assert parsed["chain"]["previous_project_event_hash"] == legacy_head

    signed = sign_v6_envelope(checkpoint_env, SEED)
    assert signed.event_hash_text == case["expected"]["checkpoint_event_hash"]


def _merkle_leaf(scope_ordinal: int, event_hash_hex: str) -> str:
    eh = bytes.fromhex(event_hash_hex.removeprefix("sha256:"))
    return digest_str(DOMAINS["bundle_member"] + u64be(scope_ordinal) + eh)


def _merkle_node(left: str, right: str) -> str:
    lb = bytes.fromhex(left.removeprefix("sha256:"))
    rb = bytes.fromhex(right.removeprefix("sha256:"))
    return digest_str(DOMAINS["bundle_node"] + lb + rb)


def _merkle_root_rfc6962(leaf_hashes: list[str]) -> str:
    if not leaf_hashes:
        return digest_str(b"")  # MTH({}) = SHA256() — BUNDLE-V3.md:214

    def mth(ds: list[str]) -> str:
        if len(ds) == 1:
            return ds[0]
        k = 1
        while k * 2 < len(ds):
            k *= 2
        return _merkle_node(mth(ds[:k]), mth(ds[k:]))

    return mth(leaf_hashes)


@pytest.mark.parametrize(
    "name",
    [
        "bundle-merkle-single",
        "bundle-merkle-two",
        "bundle-merkle-three",
        "bundle-merkle-five",
    ],
    ids=lambda n: n,
)
def test_bundle_merkle_tree(name: str) -> None:
    case = _load_case(name)
    ehs = case["input"]["event_hashes"]
    leaves = [_merkle_leaf(i, h) for i, h in enumerate(ehs)]
    root = _merkle_root_rfc6962(leaves)
    assert root == case["expected"]["membership_root"]
    if "leaf_0" in case["expected"]:
        assert leaves[0] == case["expected"]["leaf_0"]


def test_bundle_merkle_single_leaf_is_root() -> None:
    case = _load_case("bundle-merkle-single")
    assert case["expected"]["membership_root"] == case["expected"]["leaf_0"]


def test_bundle_merkle_two_combines() -> None:
    case = _load_case("bundle-merkle-two")
    assert case["expected"]["membership_root"] == case["expected"]["node_0_1"]


def test_bundle_merkle_empty_root_is_sha256_of_empty_string() -> None:
    """BUNDLE-V3.md:214 — ``MTH({}) = SHA256()``, unreachable but specified.

    Returning null here instead would be a silent disagreement between two conforming
    implementations at the one input neither of them can test against real data.
    """
    case = _load_case("bundle-merkle-empty")
    assert case["expected"]["membership_root"] == "sha256:" + hashlib.sha256(b"").hexdigest()
    assert _merkle_root_rfc6962([]) == case["expected"]["membership_root"]
    assert case["expected"]["reachable"] is False


def test_bundle_merkle_mixed_epoch() -> None:
    """A tree spanning the cutover seam — BUNDLE-V3 §3.3 correction 1.

    Each leaf takes the *referenced event's* version-derived hash. Recomputed here from
    the raw legacy envelopes and v6 envelopes in the vector, not copied from its members.
    """
    case = _load_case("bundle-merkle-mixed-epoch")
    members = case["input"]["members"]

    legacy_bytes = [b.encode() for b in case["input"]["legacy_canonical_bytes"]]
    legacy_sigs = [bytes.fromhex(s) for s in case["input"]["legacy_signatures_hex"]]
    for i, (lb, ls) in enumerate(zip(legacy_bytes, legacy_sigs, strict=True)):
        assert members[i]["envelope_version"] == 5
        assert members[i]["event_hash"] == digest_str(lb + ls), (
            "legacy leaves must use sha256(canonical_envelope||signature)"
        )

    for i, env in enumerate(case["input"]["v6_envelopes"], start=2):
        signed = sign_v6_envelope(env, SEED)
        expected = signed.event_hash_text
        assert members[i]["envelope_version"] == 6
        assert members[i]["event_hash"] == expected, (
            "v6 leaves must use the domain-separated, length-framed construction"
        )

    leaves = [_merkle_leaf(m["scope_ordinal"], m["event_hash"]) for m in members]
    assert leaves == case["expected"]["leaves"]
    assert _merkle_root_rfc6962(leaves) == case["expected"]["membership_root"]


def test_mixed_epoch_leaf_would_differ_under_a_hardcoded_legacy_formula() -> None:
    """The failure BUNDLE-V3 correction 1 exists to prevent.

    Computing a v6 member's leaf with the v1-v5 formula yields a different root, so a
    bundle built that way would not match the hash the chain itself commits to.
    """
    case = _load_case("bundle-merkle-mixed-epoch")
    members = case["input"]["members"]
    correct = [_merkle_leaf(m["scope_ordinal"], m["event_hash"]) for m in members]

    wrong_members = list(members)
    v6_env = case["input"]["v6_envelopes"][0]
    canonical = canonicalize(v6_env)
    signature = SK.sign(DOMAINS["event_signing"] + canonical).signature
    wrong_members[2] = {**members[2], "event_hash": digest_str(canonical + signature)}
    wrong = [_merkle_leaf(m["scope_ordinal"], m["event_hash"]) for m in wrong_members]

    assert wrong != correct
    assert _merkle_root_rfc6962(wrong) != case["expected"]["membership_root"]


def test_bundle_merkle_leaf_and_node_domains_differ() -> None:
    leaf = _merkle_leaf(0, "sha256:" + "aa" * 32)
    node = _merkle_node(leaf, leaf)
    assert leaf != node, "leaf and node domains must produce distinct values"


def test_workflow_definition_digest() -> None:
    case = _load_case("workflow-definition-digest")
    definition = case["input"]["definition"]
    b = canonicalize(definition)
    assert b == case["expected"]["canonical_bytes"].encode()
    digest = domain_digest_framed(DOMAINS["workflow_definition"], b)
    assert digest == case["expected"]["definition_hash"]


def test_review_subject_state_matches_reducer_v1() -> None:
    from reducer_v1_vectors import WORKFLOW, _basic

    from regista._reducer import REDUCER_VERSION, content_state_digest, reduce_and_canonicalize

    case = _load_case("review-subject-state")
    envelopes = _basic()
    assert case["expected"]["reducer_version"] == REDUCER_VERSION
    reduced_canonical = reduce_and_canonicalize(envelopes, workflow_definitions=WORKFLOW)
    assert reduced_canonical == case["expected"]["reduced_canonical_bytes"].encode()
    digest = content_state_digest(envelopes, workflow_definitions=WORKFLOW)
    assert digest == case["expected"]["content_state_digest"]


def test_review_subject_state_agrees_with_frozen_digests() -> None:
    from reducer_v1_vectors import WORKFLOW, _basic

    from regista._reducer import content_state_digest

    frozen = json.loads(
        (Path(__file__).parent / "reducer_v1_frozen_digests.json").read_text("utf-8")
    )
    case = _load_case("review-subject-state")
    envelopes = _basic()
    digest = content_state_digest(envelopes, workflow_definitions=WORKFLOW)
    assert digest == frozen["digests_content_only"]["basic-workflow-walk"]
    assert digest == case["expected"]["content_state_digest"]


def test_review_subject_state_construction_matches_the_raw_domain_tag() -> None:
    """`content_state_digest` is the one frozen digest a production function produces.

    Recomputing it from the raw tag is what verifies the tag transcription itself — every
    other domain in the registry is exercised by a hand-built construction, this one was
    only ever taken on trust from `_reducer`.
    """
    case = _load_case("review-subject-state")
    reduced = case["expected"]["reduced_canonical_bytes"].encode()
    assert (
        domain_digest(DOMAINS["review_subject_state"], reduced)
        == (case["expected"]["content_state_digest"])
    )


REVIEW_SUBJECT_MEMBERS = [
    "artifacts",
    "content_state_digest",
    "declared_not_reviewed",
    "entity_id",
    "entity_kind",
    "project_instance_id",
    "reviewed_through_event_hash",
]


def test_review_subject() -> None:
    case = _load_case("review-subject")
    subject = case["input"]["review_subject_after_sorting"]
    b = canonicalize(subject)
    assert b == case["expected"]["canonical_bytes"].encode()
    digest = domain_digest(DOMAINS["review_subject"], b)
    assert digest == case["expected"]["subject_digest"]


def test_review_subject_has_exactly_the_specified_members() -> None:
    """REVIEW-VERDICTS §2.3, less `subject_profile` — cut by RECONCILIATION:421.

    `entity_kind`/`entity_id`, never `work_item_id`: the subject is a chain, not a row.
    A member set that differs from the spec's produces a different `subject_digest` for
    the same review, which is the whole failure this vector exists to prevent.
    """
    case = _load_case("review-subject")
    subject = case["input"]["review_subject_after_sorting"]
    assert sorted(subject.keys()) == REVIEW_SUBJECT_MEMBERS
    assert case["expected"]["members"] == REVIEW_SUBJECT_MEMBERS
    assert "subject_profile" not in subject
    assert "work_item_id" not in subject


def test_review_subject_artifact_lists_are_sorted_before_canonicalization() -> None:
    """RECONCILIATION:424 — artifacts by (media_type, locator, digest), exclusions by
    (media_type, locator, reason), so two gates reviewing the same thing agree."""
    case = _load_case("review-subject")
    declared = case["input"]["artifacts_declaration_order"]
    excluded = case["input"]["declared_not_reviewed_declaration_order"]
    subject = case["input"]["review_subject_after_sorting"]

    assert subject["artifacts"] == sorted(
        declared, key=lambda a: (a["media_type"], a["locator"], a["digest"])
    )
    assert subject["declared_not_reviewed"] == sorted(
        excluded, key=lambda a: (a["media_type"], a["locator"], a["reason"])
    )
    assert subject["artifacts"] != declared, (
        "the vector must declare artifacts out of order or it pins no sort"
    )
    assert subject["declared_not_reviewed"] != excluded


def test_review_subject_digest_is_order_independent() -> None:
    """The same review submitted with the artifact lists in any order digests identically."""
    case = _load_case("review-subject")
    subject = case["input"]["review_subject_after_sorting"]
    shuffled = {
        **subject,
        "artifacts": list(reversed(subject["artifacts"])),
        "declared_not_reviewed": list(reversed(subject["declared_not_reviewed"])),
    }
    resorted = {
        **shuffled,
        "artifacts": sorted(
            shuffled["artifacts"], key=lambda a: (a["media_type"], a["locator"], a["digest"])
        ),
        "declared_not_reviewed": sorted(
            shuffled["declared_not_reviewed"],
            key=lambda a: (a["media_type"], a["locator"], a["reason"]),
        ),
    }
    assert (
        domain_digest(DOMAINS["review_subject"], canonicalize(resorted))
        == (case["expected"]["subject_digest"])
    )
    assert (
        domain_digest(DOMAINS["review_subject"], canonicalize(shuffled))
        != (case["expected"]["subject_digest"])
    ), "JSON arrays are ordered — an unsorted list must not reach canonicalization"


def test_delegation_credential() -> None:
    case = _load_case("delegation-credential")
    doc = case["input"]["document_minus_signature"]
    b = canonicalize(doc)
    assert b == case["expected"]["canonical_bytes"].encode()

    sig_input = DOMAINS["delegation_signing"] + u64be(len(b)) + b
    signature = SK.sign(sig_input).signature
    assert signature.hex() == case["expected"]["signature_hex"]

    cred_hash = domain_digest_framed(DOMAINS["delegation_hash"], b)
    assert cred_hash == case["expected"]["credential_hash"]

    sig_input_domain = DOMAINS["delegation_signing"]
    assert sig_input_domain != DOMAINS["delegation_hash"], (
        "signing and hash domains must be distinct"
    )


def test_trust_genesis() -> None:
    case = _load_case("trust-genesis")
    binding_core = case["input"]["binding_core"]
    core_bytes = canonicalize(binding_core)
    assert core_bytes == case["expected"]["core_canonical_bytes"].encode()

    core_digest = domain_digest_framed(DOMAINS["trust_genesis_core"], core_bytes)
    assert core_digest == case["expected"]["trust_domain_core_digest"]

    expected_td_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_OID,
            "regista.trust-domain:" + core_digest.removeprefix("sha256:"),
        )
    )
    assert expected_td_id == case["expected"]["trust_domain_id"]

    genesis_doc = case["input"]["genesis_document_minus_extras"]
    sig_bytes = canonicalize(genesis_doc)
    sig_input = DOMAINS["trust_genesis_signing"] + u64be(len(sig_bytes)) + sig_bytes
    signature = SK.sign(sig_input).signature
    assert signature.hex() == case["expected"]["genesis_signature_hex"]


def test_trust_checkpoint() -> None:
    case = _load_case("trust-checkpoint")
    doc = case["input"]["document_minus_signature"]
    b = canonicalize(doc)
    assert b == case["expected"]["canonical_bytes"].encode()
    sig_input = DOMAINS["trust_checkpoint"] + u64be(len(b)) + b
    signature = SK.sign(sig_input).signature
    assert signature.hex() == case["expected"]["signature_hex"]


def test_cutover_checkpoint() -> None:
    case = _load_case("cutover-checkpoint")
    doc = case["input"]["checkpoint_statement"]
    b = canonicalize(doc)
    assert b == case["expected"]["canonical_bytes"].encode()
    digest = domain_digest(DOMAINS["checkpoint"], b)
    assert digest == case["expected"]["checkpoint_digest"]


def test_producer_policy() -> None:
    case = _load_case("producer-policy")
    doc = case["input"]["document"]
    b = canonicalize(doc)
    assert b == case["expected"]["canonical_bytes"].encode()
    digest = domain_digest_framed(DOMAINS["producer_policy"], b)
    assert digest == case["expected"]["producer_policy_digest"]


def test_estate_catalog() -> None:
    case = _load_case("estate-catalog")
    doc = case["input"]["document"]
    b = canonicalize(doc)
    assert b == case["expected"]["canonical_bytes"].encode()
    digest = domain_digest_framed(DOMAINS["estate_catalog"], b)
    assert digest == case["expected"]["estate_catalog_digest"]


def test_trust_log_export() -> None:
    case = _load_case("trust-log-export")
    doc = case["input"]["document"]
    b = canonicalize(doc)
    assert b == case["expected"]["canonical_bytes"].encode()
    digest = domain_digest_framed(DOMAINS["trust_log_export"], b)
    assert digest == case["expected"]["trust_log_export_digest"]
    # The production framing helper must reproduce the frozen digest from the same core
    # document (WI-337). The case document carries no signature sections, so its core is
    # itself, which is exactly what trust_log_export_signature_input covers.
    from regista._trust_log_export import (
        TRUST_LOG_EXPORT_DOMAIN,
        trust_log_export_digest,
    )

    assert TRUST_LOG_EXPORT_DOMAIN == DOMAINS["trust_log_export"]
    assert trust_log_export_digest(doc) == case["expected"]["trust_log_export_digest"]


def test_producer_lineage_is_a_family_not_a_versioned_model() -> None:
    """`model_lineage` is the family; `model` is the build (V6-ENVELOPE §1.8).

    They are separate members so that a version bump is not a change of lineage:
    `claude-opus-5` and `claude-opus-4-8` are the same lineage and must compare SAME.
    This matters because `_assurance.lineage_relation` compares by exact string
    membership with DISTINCT as the *default*, so any spelling variance fails **open** —
    it manufactures the independence a cross-lineage review exists to demonstrate
    (regista WI-285). An undeclared lineage fails closed; a mis-spelled one does not.

    Every envelope vector is an exemplar an implementer copies, so a vector carrying a
    versioned or vendor-qualified lineage teaches the defect. These vectors did exactly
    that until 2026-08-10 (`model_lineage: "anthropic/claude-opus-5"`).
    """
    checked = 0
    for name in CASE_NAMES:
        case = _load_case(name)
        env = case["input"].get("envelope_declaration_order")
        if not isinstance(env, dict) or "producer" not in env:
            continue
        producer = env["producer"]
        model, lineage = producer.get("model"), producer.get("model_lineage")
        if lineage is None:
            assert model is None, f"{name}: a model with no lineage is undeclared, not lineage-free"
            continue
        checked += 1
        assert "/" not in lineage, (
            f"{name}: lineage {lineage!r} is vendor-qualified; the vendor belongs to the "
            "model id, not the family"
        )
        assert lineage != model, (
            f"{name}: lineage {lineage!r} equals the model — the family must not carry the build"
        )
        assert model is not None and model.startswith(lineage), (
            f"{name}: model {model!r} should extend its family {lineage!r}; if a canonical "
            "vocabulary chooses a non-prefix family name, this assertion is the right place "
            "to record that decision (WI-285)"
        )
    assert checked, "no producer-bearing vector exercised the family rule"


def test_all_domain_tags_are_distinct_and_null_terminated() -> None:
    tags = MANIFEST["domain_tags"]
    raw_tags = list(tags.values())
    assert len(raw_tags) == len(set(raw_tags)), "duplicate domain tags"
    for tag in raw_tags:
        assert tag.endswith("\x00"), f"domain tag {tag!r} must be \\x00-terminated"


def test_all_domain_tags_are_pairwise_prefix_free() -> None:
    tags = sorted(MANIFEST["domain_tags"].values())
    for i, a in enumerate(tags):
        for b in tags[i + 1 :]:
            assert not a.startswith(b) and not b.startswith(a), (
                f"prefix-related domain tags {a!r} and {b!r} "
                "— the \\x00 terminator must prevent this"
            )


def test_v6_envelope_basic_one_byte_flip_changes_hash() -> None:
    case = _load_case("v6-envelope-basic")
    env = case["input"]["envelope_declaration_order"]
    canonical = canonicalize_v6_envelope(env)
    original_hash = case["expected"]["canonical_sha256"]

    mutated_env = dict(env)
    first_key = next(iter(env))
    nested = env[first_key]
    if isinstance(nested, dict):
        inner_key = next(iter(nested))
        inner_val = nested[inner_key]
        if isinstance(inner_val, str) and inner_val:
            mutated_inner = dict(nested)
            mutated_inner[inner_key] = _flip_one_char(inner_val)
            mutated_env[first_key] = mutated_inner
        elif isinstance(inner_val, (int, bool)):
            mutated_inner = dict(nested)
            mutated_inner[inner_key] = inner_val + 1 if isinstance(inner_val, int) else False
            mutated_env[first_key] = mutated_inner
    elif isinstance(nested, str) and nested:
        mutated_env[first_key] = _flip_one_char(nested)

    mutated_canonical = canonicalize(mutated_env)
    assert sha256_hex(mutated_canonical) != original_hash, (
        "one-byte change to the envelope must flip the canonical digest"
    )

    mutated_sig_input = DOMAINS["event_signing"] + mutated_canonical
    original_sig_input = DOMAINS["event_signing"] + canonical
    assert sha256_hex(mutated_sig_input) != sha256_hex(original_sig_input)

    mutated_signature = SK.sign(mutated_sig_input).signature
    original_signature = SK.sign(original_sig_input).signature
    assert mutated_signature != original_signature

    mutated_event_hash = digest_str(
        DOMAINS["event_hash"]
        + u64be(len(mutated_canonical))
        + mutated_canonical
        + mutated_signature
    )
    assert mutated_event_hash != case["expected"]["event_hash"]


def test_workflow_definition_digest_one_byte_flip_changes_hash() -> None:
    case = _load_case("workflow-definition-digest")
    definition = case["input"]["definition"]
    original = case["expected"]["definition_hash"]

    mutated = dict(definition)
    first_state = definition["states"][0]
    mutated["states"] = [_flip_one_char(first_state), *definition["states"][1:]]
    b = canonicalize(mutated)
    assert domain_digest_framed(DOMAINS["workflow_definition"], b) != original


def test_fingerprint_one_byte_flip_changes_hash() -> None:
    case = _load_case("fingerprint-primary")
    original = case["expected"]["fingerprint"]
    flipped_pub = _flip_one_byte(PUB)
    assert fingerprint(flipped_pub) != original


def test_merkle_leaf_one_byte_flip_changes_hash() -> None:
    case = _load_case("bundle-merkle-single")
    original = case["expected"]["leaf_0"]
    flipped_eh = "sha256:" + ("ab" + "aa" * 31)
    flipped_leaf = _merkle_leaf(0, flipped_eh)
    assert flipped_leaf != original


def test_merkle_root_one_byte_flip_changes_hash() -> None:
    case = _load_case("bundle-merkle-three")
    original_root = case["expected"]["membership_root"]
    ehs = case["input"]["event_hashes"]
    flipped_ehs = [ehs[0], "sha256:" + ("ab" + "aa" * 31), ehs[2]]
    leaves = [_merkle_leaf(i, h) for i, h in enumerate(flipped_ehs)]
    assert _merkle_root_rfc6962(leaves) != original_root


def test_delegation_hash_one_byte_flip_changes_hash() -> None:
    case = _load_case("delegation-credential")
    original = case["expected"]["credential_hash"]
    doc = case["input"]["document_minus_signature"]
    mutated = dict(doc)
    mutated["credential_id"] = _flip_one_char(doc["credential_id"])
    b = canonicalize(mutated)
    assert domain_digest_framed(DOMAINS["delegation_hash"], b) != original


def test_trust_genesis_core_one_byte_flip_changes_hash() -> None:
    case = _load_case("trust-genesis")
    original = case["expected"]["trust_domain_core_digest"]
    binding_core = case["input"]["binding_core"]
    mutated = dict(binding_core)
    mutated["nonce"] = _flip_one_char(binding_core["nonce"])
    b = canonicalize(mutated)
    assert domain_digest_framed(DOMAINS["trust_genesis_core"], b) != original


def test_trust_genesis_id_changes_when_core_changes() -> None:
    case = _load_case("trust-genesis")
    original_td_id = case["expected"]["trust_domain_id"]
    binding_core = case["input"]["binding_core"]
    mutated = dict(binding_core)
    mutated["nonce"] = _flip_one_char(binding_core["nonce"])
    b = canonicalize(mutated)
    new_digest = domain_digest_framed(DOMAINS["trust_genesis_core"], b)
    new_td_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_OID,
            "regista.trust-domain:" + new_digest.removeprefix("sha256:"),
        )
    )
    assert new_td_id != original_td_id


def test_producer_policy_one_byte_flip_changes_hash() -> None:
    case = _load_case("producer-policy")
    original = case["expected"]["producer_policy_digest"]
    doc = case["input"]["document"]
    mutated = dict(doc)
    entry = dict(doc["entries"][0])
    entry["host"] = _flip_one_char(entry["host"])
    mutated["entries"] = [entry, *doc["entries"][1:]]
    b = canonicalize(mutated)
    assert domain_digest_framed(DOMAINS["producer_policy"], b) != original


def test_estate_catalog_one_byte_flip_changes_hash() -> None:
    case = _load_case("estate-catalog")
    original = case["expected"]["estate_catalog_digest"]
    doc = case["input"]["document"]
    mutated = dict(doc)
    project = dict(doc["projects"][0])
    project["project_name_hint"] = _flip_one_char(project["project_name_hint"])
    mutated["projects"] = [project, *doc["projects"][1:]]
    b = canonicalize(mutated)
    assert domain_digest_framed(DOMAINS["estate_catalog"], b) != original


@pytest.mark.parametrize("member", REVIEW_SUBJECT_MEMBERS)
def test_every_review_subject_member_change_changes_hash(member: str) -> None:
    case = _load_case("review-subject")
    original = case["expected"]["subject_digest"]
    subject = case["input"]["review_subject_after_sorting"]
    mutated = copy.deepcopy(subject)
    if member == "artifacts":
        mutated[member][0]["digest"] = _flip_one_char(mutated[member][0]["digest"])
    elif member == "declared_not_reviewed":
        mutated[member][0]["reason"] = _flip_one_char(mutated[member][0]["reason"])
    else:
        mutated[member] = _flip_one_char(mutated[member])
    b = canonicalize(mutated)
    assert domain_digest(DOMAINS["review_subject"], b) != original


def test_cutover_checkpoint_one_byte_flip_changes_hash() -> None:
    case = _load_case("cutover-checkpoint")
    original = case["expected"]["checkpoint_digest"]
    doc = case["input"]["checkpoint_statement"]
    mutated = dict(doc)
    mutated["cutover_event_hash"] = _flip_one_char(doc["cutover_event_hash"])
    b = canonicalize(mutated)
    assert domain_digest(DOMAINS["checkpoint"], b) != original


def test_trust_checkpoint_one_byte_flip_changes_signature() -> None:
    case = _load_case("trust-checkpoint")
    doc = case["input"]["document_minus_signature"]
    b = canonicalize(doc)
    original_sig = SK.sign(DOMAINS["trust_checkpoint"] + u64be(len(b)) + b).signature
    assert original_sig.hex() == case["expected"]["signature_hex"]

    mutated = dict(doc)
    mutated["checkpoint_seq"] = doc["checkpoint_seq"] + 1
    mb = canonicalize(mutated)
    mutated_sig = SK.sign(DOMAINS["trust_checkpoint"] + u64be(len(mb)) + mb).signature
    assert mutated_sig != original_sig


def test_payload_numeric_bounds_accepts_the_boundary() -> None:
    """V6-ENVELOPE §2.5 as amended by P0.2: `|v| < 2**53`, integers and floats alike."""
    case = _load_case("payload-numeric-bounds")
    env = case["input"]["envelope_declaration_order"]
    canonical = canonicalize(env)
    assert canonical == case["expected"]["canonical_bytes"].encode()

    payload = case["input"]["accepted_payload"]
    assert payload["max_positive_int"] == 2**53 - 1
    assert payload["max_negative_int"] == -(2**53 - 1)
    for value in payload.values():
        if isinstance(value, int | float) and not isinstance(value, bool):
            assert abs(value) < 2**53

    signature = SK.sign(DOMAINS["event_signing"] + canonical).signature
    assert signature.hex() == case["expected"]["signature_hex"]
    assert case["expected"]["event_hash"] == digest_str(
        DOMAINS["event_hash"] + u64be(len(canonical)) + canonical + signature
    )


def test_payload_numeric_bounds_rejected_band_is_measured_not_asserted() -> None:
    """The half of §2.5 the canonicalizer will not enforce for you.

    Integers at or above `2**53` raise. Floats in `2**53 <= |v| < 1e21` do not: they
    canonicalize to an integer literal outside the safe domain, so the *second* pass
    fails — signable, canonical, and no computable digest. That asymmetry is the reason
    the rule is magnitude-based and applies to both types, and a strict parser that only
    trusts the canonicalizer inherits the gap.
    """
    case = _load_case("payload-numeric-bounds")
    by_label = {r["label"]: r for r in case["input"]["rejected_values"]}

    assert by_label["int_at_2_53"]["rejects_at_canonicalization"] is True
    assert by_label["int_at_negative_2_53"]["rejects_at_canonicalization"] is True

    band = by_label["float_in_measured_band"]
    assert band["rejects_at_canonicalization"] is False
    assert band["recanonicalizing_that_output_fails"] is True

    round_tripping = by_label["float_at_1e21"]
    assert round_tripping["rejects_at_canonicalization"] is False
    assert round_tripping["recanonicalizing_that_output_fails"] is False

    # The measurement, re-run: 1e16 prints as an integer literal, and that literal is
    # outside the domain the canonicalizer will accept back.
    produced = canonicalize({"v": 1e16})
    assert produced == b'{"v":10000000000000000}'
    with pytest.raises(Exception):
        canonicalize(json.loads(produced))


def test_occurred_at_has_exactly_one_lexical_form() -> None:
    """V6-ENVELOPE §2.3 / DD-4, and the `24:00` divergence P0.2 measured."""
    case = _load_case("occurred-at-lexical-form")
    env = case["input"]["envelope_declaration_order"]
    assert env["occurred_at"] == case["input"]["accepted"]
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", case["input"]["accepted"])

    canonical = canonicalize_v6_envelope(env)
    assert canonical == case["expected"]["canonical_bytes"].encode()

    pattern = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z")
    rejected = {r["value"] for r in case["input"]["rejected"]}
    assert "2026-08-09T24:00:00.000000Z" in rejected, (
        "the 24:00 form must be pinned as rejected — it is lexically well-formed, which is "
        "why only an explicit rule keeps it out of signed bytes"
    )
    for value in rejected:
        mutated = dict(env)
        mutated["occurred_at"] = value
        with pytest.raises(ValueError):
            canonicalize_v6_envelope(mutated)
        if value == "2026-08-09T24:00:00.000000Z":
            # Matches the pattern but is rejected on the calendar rule, not the lexical one.
            assert pattern.fullmatch(value)
            continue
        assert not pattern.fullmatch(value), f"{value!r} must not match the §2.3 form"


def test_occurred_at_rejected_forms_change_the_signed_bytes() -> None:
    """Each rejected spelling is a different signed artifact, not a synonym."""
    case = _load_case("occurred-at-lexical-form")
    env = case["input"]["envelope_declaration_order"]
    original = canonicalize(env)
    for entry in case["input"]["rejected"]:
        mutated = {**env, "occurred_at": entry["value"]}
        assert canonicalize(mutated) != original


def test_cross_domain_non_confusability() -> None:
    """The same input hashed under two different domains must produce different values.

    This is the property that makes domain separation meaningful: a value from one domain
    cannot be replayed as a value from another (V6-ENVELOPE §6.3, mechanism 1).
    """
    payload = b'{"x":1}'
    h1 = domain_digest_framed(DOMAINS["workflow_definition"], payload)
    h2 = domain_digest_framed(DOMAINS["delegation_hash"], payload)
    h3 = domain_digest_framed(DOMAINS["producer_policy"], payload)
    h4 = domain_digest_framed(DOMAINS["estate_catalog"], payload)
    h5 = domain_digest(DOMAINS["checkpoint"], payload)
    h6 = domain_digest(DOMAINS["review_subject"], payload)
    values = [h1, h2, h3, h4, h5, h6]
    assert len(values) == len(set(values)), "cross-domain hashes must all be distinct"


def test_v6_signing_input_is_never_a_v5_signing_input() -> None:
    """A v5 signature input starts with '{'; a v6 input starts with the domain tag.

    No byte string is both, so no v5 signature can be presented as a v6 signature
    or vice versa (V6-ENVELOPE §5.3).
    """
    case = _load_case("v6-envelope-basic")
    canonical = case["expected"]["canonical_bytes"].encode()
    v6_input = DOMAINS["event_signing"] + canonical
    assert v6_input[:1] != b"{"
    assert canonical[:1] == b"{"
    assert not v6_input.startswith(b"{")
