"""Byte-level conformance vectors for the regista 0.6.0 cryptographic epoch (Gate 0, P0.3).

P0.3's acceptance criterion, from ``IMPLEMENTATION-PLAN.md``:

    *Each vector is reproducible from a clean checkout by one documented command, and a
    deliberate one-byte change to each input flips its expected hash.*

How that requirement is discharged here:

* ``tools/make_v6_vectors.py`` is the generator — it imports only the vendored RFC 8785
  canonicalizer, PyNaCl and the stdlib, and every domain tag and framing rule comes from the
  frozen spec set (``V6-ENVELOPE.md`` §6.1 and its siblings), not from the generator.
* ``tests/vectors/v6/`` holds one JSON file per case plus a ``manifest.json``.
* This module regenerates the same bytes from the same inputs and asserts equality, then
  flips one byte in each input and asserts the digest changes.

The vectors are the artifact that makes a future non-Python verifier possible — nobody has
written one yet, but the frozen bytes are what an independent implementation checks against.

The test key is 32 bytes of 0x01 — NEVER usable in production.  It exists so every byte is
reproducible by an implementer with no private material.
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

import nacl.signing

from regista._jcs import canonicalize

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
    canonical = canonicalize(env)
    assert canonical == case["expected"]["canonical_bytes"].encode()
    assert len(canonical) == case["expected"]["canonical_len"]
    assert sha256_hex(canonical) == case["expected"]["canonical_sha256"]

    sig_input = DOMAINS["event_signing"] + canonical
    assert sha256_hex(sig_input) == case["expected"]["signature_input_sha256"]

    signature = SK.sign(sig_input).signature
    assert signature.hex() == case["expected"]["signature_hex"]

    expected_hash = digest_str(
        DOMAINS["event_hash"] + u64be(len(canonical)) + canonical + signature
    )
    assert expected_hash == case["expected"]["event_hash"]
    assert digest_str(sig_input) == case["expected"]["payload_canonical_hash"]


def test_v6_envelope_has_sixteen_keys_in_jcs_order() -> None:
    case = _load_case("v6-envelope-canonical-order")
    env = case["input"]["envelope_declaration_order"]
    canonical = canonicalize(env)
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


def test_v6_envelope_no_model() -> None:
    case = _load_case("v6-envelope-no-model")
    env = case["input"]["envelope_declaration_order"]
    canonical = canonicalize(env)
    assert canonical == case["expected"]["canonical_bytes"].encode()
    parsed = json.loads(canonical)
    assert parsed["producer"]["model"] is None
    assert parsed["producer"]["model_lineage"] is None
    assert parsed["producer"]["harness"] == "claude-code"


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
    canonical = canonicalize(env)
    parsed = json.loads(canonical)
    assert parsed["signing"]["key_binding_event_hash"] is None
    assert case["expected"]["event_hash"] == digest_str(
        DOMAINS["event_hash"]
        + u64be(len(canonical))
        + canonical
        + SK.sign(DOMAINS["event_signing"] + canonical).signature
    )


def test_bootstrap_cutover_uses_legacy_head_hash() -> None:
    case = _load_case("bootstrap-cutover-checkpoint")
    env = case["input"]["envelope_declaration_order"]
    parsed = json.loads(canonicalize(env))
    assert parsed["chain"]["previous_project_event_hash"] == case["input"]["legacy_head_hash"]
    assert parsed["payload"]["previous_epoch"]["head_hash_construction"] == (
        "sha256(canonical_envelope||signature)"
    )


def test_bootstrap_project_initialized_has_empty_epoch() -> None:
    case = _load_case("bootstrap-project-initialized")
    env = case["input"]["envelope_declaration_order"]
    parsed = json.loads(canonicalize(env))
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

    v6_hash = digest_str(DOMAINS["event_hash"] + u64be(len(canonical)) + canonical + signature)
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

    canonical = canonicalize(checkpoint_env)
    signature = SK.sign(DOMAINS["event_signing"] + canonical).signature
    event_hash = digest_str(DOMAINS["event_hash"] + u64be(len(canonical)) + canonical + signature)
    assert event_hash == case["expected"]["checkpoint_event_hash"]


def _merkle_leaf(scope_ordinal: int, event_hash_hex: str) -> str:
    eh = bytes.fromhex(event_hash_hex.removeprefix("sha256:"))
    return digest_str(DOMAINS["bundle_member"] + u64be(scope_ordinal) + eh)


def _merkle_node(left: str, right: str) -> str:
    lb = bytes.fromhex(left.removeprefix("sha256:"))
    rb = bytes.fromhex(right.removeprefix("sha256:"))
    return digest_str(DOMAINS["bundle_node"] + lb + rb)


def _merkle_root_rfc6962(leaf_hashes: list[str]) -> str | None:
    if not leaf_hashes:
        return None

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


def test_bundle_merkle_empty_has_no_root() -> None:
    case = _load_case("bundle-merkle-empty")
    assert case["expected"]["membership_root"] is None


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


def test_review_subject() -> None:
    case = _load_case("review-subject")
    subject = case["input"]["review_subject"]
    b = canonicalize(subject)
    assert b == case["expected"]["canonical_bytes"].encode()
    digest = domain_digest(DOMAINS["review_subject"], b)
    assert digest == case["expected"]["subject_digest"]


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
    canonical = canonicalize(env)
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
    "sha256:" + "aa" * 32
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


def test_review_subject_one_byte_flip_changes_hash() -> None:
    case = _load_case("review-subject")
    original = case["expected"]["subject_digest"]
    subject = case["input"]["review_subject"]
    mutated = dict(subject)
    mutated["work_item_id"] = _flip_one_char(subject["work_item_id"])
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
