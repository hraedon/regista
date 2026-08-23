"""WI-330 ``regista trust catalog`` / ``trust verify-catalog``: the signed estate
cutover catalog (``TRUST-DOMAIN.md`` §4.3).

agent-suite's cutover runbook §5.4 step 4 told the operator to "produce and publish the
signed estate cutover catalog through regista's documented catalog command", and no
such command existed — while the artifact itself was fully specified (§4.3) and
byte-frozen (``tests/vectors/v6/estate-catalog.json``). Three things are under test,
and they are different in kind:

**Byte conformance.** ``test_frozen_vector_*`` and
``test_builder_reproduces_the_frozen_vector_bytes`` pin the implementation to the
frozen vector: the same canonical bytes, the same length, the same domain-framed
digest, and — the stronger claim — the *builder* fed the vector's own values emits
those exact bytes. If the framing, the core-key set or the JCS handling drifts, these
fail. ``tests/test_v6_vectors.py::test_estate_catalog`` recomputes the vector from the
generator's own domain table; these recompute it from ``regista._estate_catalog``,
which is the code an operator actually runs.

**Fail-closed refusals.** Every rejection is asserted by its machine-readable
``reason``, never by message text, because the whole value of a named refusal is that
a caller can branch on it. Unknown top-level keys, a non-canonical publication file, a
signer the pinned genesis never committed to, a threshold not met, a ``scheme_counts``
sum that contradicts ``legacy_event_count`` — none of these is a warning.

Everything here is **database-free on purpose**. The byte pin is the artifact's whole
contract, and a conformance test that only runs where PostgreSQL is reachable is a
conformance test that silently stops running. The live ceremony —
``trust catalog`` against a real trust log, a real published checkpoint channel and a
real opened epoch — is ``test_wi330_estate_catalog_live.py``.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import struct
import uuid
from typing import Any

import nacl.signing
import pytest
from _trust_fixtures import mint_co_signed, mint_solo, mint_solo_effective

from regista._cli import cmd_trust_verify_catalog
from regista._errors import ErrorCode, RegistaError
from regista._estate_catalog import (
    CATALOG_KEYS,
    CORE_KEYS,
    ESTATE_CATALOG_DOMAIN,
    SIGNATURE_SECTIONS,
    CatalogProject,
    build_estate_catalog,
    estate_catalog_canonical_core,
    estate_catalog_core,
    estate_catalog_digest,
    estate_catalog_signature_input,
    parse_catalog_inputs,
    parse_estate_catalog,
    sign_estate_catalog,
    verify_estate_catalog,
)
from regista._jcs import canonicalize

VECTOR_PATH = os.path.join(os.path.dirname(__file__), "vectors", "v6", "estate-catalog.json")


def _vector() -> dict[str, Any]:
    with open(VECTOR_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def _vector_document() -> dict[str, Any]:
    return _vector()["input"]["document"]


def _refusal(fn, *args, **kwargs) -> RegistaError:
    with pytest.raises(RegistaError) as excinfo:
        fn(*args, **kwargs)
    return excinfo.value


def _reason(error: RegistaError) -> str:
    detail = error.detail or {}
    return str(detail.get("reason"))


# ===========================================================================
# Byte conformance against the frozen vector
# ===========================================================================


def test_frozen_vector_canonical_bytes_and_digest() -> None:
    """THE conformance pin: the frozen vector's exact bytes, from its own input.

    ``tests/vectors/v6/estate-catalog.json`` is the artifact every implementation of
    0.6.0 must reproduce. This derives both expected values — ``canonical_bytes`` and
    ``estate_catalog_digest`` — from the vector's ``input.document`` through the
    production module, so a change to the core-key set, the JCS wrapper, the domain
    separator or the length framing fails here rather than at cutover time.
    """
    case = _vector()
    document = case["input"]["document"]
    expected = case["expected"]

    canonical = estate_catalog_canonical_core(document)
    assert canonical == expected["canonical_bytes"].encode("utf-8")
    assert len(canonical) == expected["canonical_len"]
    assert estate_catalog_digest(document) == expected["estate_catalog_digest"]


def test_frozen_vector_digest_is_domain_separated_and_length_framed() -> None:
    """Recompute the digest from the raw spec strings, not the module's constants.

    §4.3: "Domain separator ``b"regista.estate-catalog.v1\\x00"``, same framing" —
    i.e. V6-ENVELOPE §6.1's NUL-terminated tag plus §5.3's uint64be length prefix. A
    module that dropped the NUL, or the length, or hashed the bare JCS bytes, would
    still be self-consistent; only recomputation from the spec text catches it.
    """
    case = _vector()
    document = case["input"]["document"]
    body = case["expected"]["canonical_bytes"].encode("utf-8")

    domain = b"regista.estate-catalog.v1" + b"\x00"
    framed = domain + struct.pack(">Q", len(body)) + body
    assert ESTATE_CATALOG_DOMAIN == domain
    assert estate_catalog_signature_input(document) == framed
    assert (
        case["expected"]["estate_catalog_digest"]
        == "sha256:" + hashlib.sha256(framed).hexdigest()
    )
    # A bare sha256 over the canonical bytes is NOT the digest. Asserting the
    # inequality is what makes the framing load-bearing rather than decorative.
    assert case["expected"]["estate_catalog_digest"] != (
        "sha256:" + hashlib.sha256(body).hexdigest()
    )


def test_frozen_vector_input_is_exactly_the_signed_core_key_set() -> None:
    """The vector's document is the core: the three signature sections are excluded."""
    document = _vector_document()
    assert set(document) == CORE_KEYS
    assert SIGNATURE_SECTIONS == {"root_signatures", "countersignatures", "anchors"}
    assert CATALOG_KEYS == CORE_KEYS | SIGNATURE_SECTIONS


def test_frozen_vector_parses_under_the_strict_parser() -> None:
    """The frozen bytes are not merely reproducible — they are ACCEPTED."""
    parsed = parse_estate_catalog(_vector_document(), for_signing=True)
    assert parsed.catalog_kind == "cutover"
    assert parsed.trust_domain_id == "018f3a5c-7b21-4e6d-8f90-a1b2c3d4e5f6"
    assert parsed.root_governance.mode == "solo_effective"
    assert parsed.root_governance.threshold == 1
    assert parsed.root_governance.signer_count == 2
    assert len(parsed.projects) == 1
    entry = parsed.projects[0]
    assert entry.project_name_hint == "agent_notes"
    assert entry.legacy_event_count == 1000
    assert entry.legacy_head_event_hash == "sha256:" + "dd" * 32
    assert entry.cutover_event_hash == "sha256:" + "cc" * 32
    assert entry.new_epoch_head_event_hash == "sha256:" + "ee" * 32
    assert dict(entry.scheme_counts) == {"hmac-sha256": 800, "ed25519": 200}
    assert parsed.trust_log_checkpoint_digest == "sha256:" + "ff" * 32
    assert parsed.prev_commit is None


def test_builder_reproduces_the_frozen_vector_bytes() -> None:
    """The BUILDER — not just the hasher — emits the frozen bytes.

    Stronger than digest conformance: it proves the assembly order, the key set and
    the ``projects[]`` member shape are the frozen ones. If ``build_estate_catalog``
    ever added, renamed or reordered a field, this fails even though every hashing
    helper still agrees with itself.
    """
    case = _vector()
    document = case["input"]["document"]
    entry = document["projects"][0]

    built = build_estate_catalog(
        trust_domain_id=document["trust_domain_id"],
        trust_domain_core_digest=document["trust_domain_core_digest"],
        root_governance=document["root_governance"],
        projects=[
            CatalogProject(
                project_instance_id=entry["project_instance_id"],
                project_name_hint=entry["project_name_hint"],
                cutover_event_hash=entry["cutover_event_hash"],
                legacy_head_event_hash=entry["legacy_head_event_hash"],
                legacy_event_count=entry["legacy_event_count"],
                scheme_counts=entry["scheme_counts"],
                new_epoch_head_event_hash=entry["new_epoch_head_event_hash"],
            )
        ],
        trust_log_checkpoint_digest=document["trust_log_checkpoint_digest"],
        created_at=document["created_at"],
        prev_commit=document["prev_commit"],
        catalog_kind=document["catalog_kind"],
    )
    assert estate_catalog_canonical_core(built) == case["expected"]["canonical_bytes"].encode()
    assert estate_catalog_digest(built) == case["expected"]["estate_catalog_digest"]
    # The unsigned document carries all three sections, empty.
    assert set(built) == CATALOG_KEYS
    assert built["root_signatures"] == []
    assert built["countersignatures"] == []
    assert built["anchors"] == []


def test_signing_does_not_change_the_digest() -> None:
    """Signatures are outside the signed bytes, so the digest is stable across signing.

    This is why ``--dry-run`` can report the digest the real run will produce rather
    than an approximation of it.
    """
    document = _vector_document()
    unsigned_digest = estate_catalog_digest(document)
    seed = bytes([0x01]) * 32
    signed = sign_estate_catalog(
        {**document, "root_signatures": [], "countersignatures": [], "anchors": []},
        seed=seed,
        signer_id="root-a",
        fingerprint="ed25519:sha256:"
        + hashlib.sha256(bytes(nacl.signing.SigningKey(seed).verify_key)).hexdigest(),
    )
    assert estate_catalog_digest(signed) == unsigned_digest
    assert estate_catalog_core(signed) == document


@pytest.mark.parametrize("field", sorted(CORE_KEYS))
def test_every_core_field_is_covered_by_the_digest(field: str) -> None:
    """Mutating ANY core field moves the digest — no field is decorative.

    The catalog's whole job is to bind facts; a field outside the hashed bytes could be
    edited after signing without detection.
    """
    document = _vector_document()
    original = estate_catalog_digest(document)
    mutated = dict(document)
    value = mutated[field]
    if isinstance(value, str):
        mutated[field] = value + "x"
    elif isinstance(value, int):
        mutated[field] = value + 1
    elif isinstance(value, list):
        mutated[field] = [*value, {"tampered": True}]
    elif isinstance(value, dict):
        mutated[field] = {**value, "tampered": True}
    else:  # prev_commit is null in the vector
        mutated[field] = "0" * 40
    assert estate_catalog_digest(mutated) != original


# ===========================================================================
# Strict-parse refusals — shape, grammar, internal consistency
# ===========================================================================


def _published(document: dict[str, Any]) -> dict[str, Any]:
    return {**document, "root_signatures": [], "countersignatures": [], "anchors": []}


def test_unknown_top_level_key_is_rejected() -> None:
    document = _published(_vector_document())
    document["published_by"] = "operator"
    error = _refusal(parse_estate_catalog, document, for_signing=True)
    assert error.code == ErrorCode.ESTATE_CATALOG_SCHEMA_INVALID
    assert _reason(error) == "closed_key_set_violated"
    assert error.detail["unknown"] == ["published_by"]


def test_missing_core_key_is_rejected() -> None:
    document = _published(_vector_document())
    del document["trust_log_checkpoint_digest"]
    error = _refusal(parse_estate_catalog, document, for_signing=True)
    assert _reason(error) == "closed_key_set_violated"
    assert error.detail["missing"] == ["trust_log_checkpoint_digest"]


def test_unknown_project_key_is_rejected() -> None:
    document = _published(_vector_document())
    document["projects"] = [{**document["projects"][0], "notes": "migrated by hand"}]
    error = _refusal(parse_estate_catalog, document, for_signing=True)
    assert _reason(error) == "closed_key_set_violated"
    assert error.detail["path"] == "projects[0]"


def test_wrong_type_and_version_are_rejected() -> None:
    document = _published(_vector_document())
    assert _reason(_refusal(parse_estate_catalog, {**document, "type": "regista.catalog"},
                            for_signing=True)) == "wrong_type"
    assert _reason(_refusal(parse_estate_catalog, {**document, "version": 2},
                            for_signing=True)) == "wrong_version"
    # `true` is not the integer 1: bool is an int subclass and a document that says
    # `"version": true` is malformed, not version 1.
    assert _reason(_refusal(parse_estate_catalog, {**document, "version": True},
                            for_signing=True)) == "wrong_version"


def test_project_heads_catalog_kind_is_refused_by_name() -> None:
    """§4.3 rule 4's optional ``project_heads`` catalog is NOT implemented.

    Its ``projects[]`` entries carry no legacy binding, so it is a different shape
    with no frozen vector, and rule 4 states it is explicitly not a release gate.
    A named refusal beats a guessed shape.
    """
    document = _published(_vector_document())
    error = _refusal(
        parse_estate_catalog, {**document, "catalog_kind": "project_heads"}, for_signing=True
    )
    assert _reason(error) == "catalog_kind_unsupported"
    assert error.detail["catalog_kind"] == "project_heads"


def test_scheme_counts_must_sum_to_legacy_event_count() -> None:
    """Judgment call 4: the two numbers describe one frozen population."""
    document = _published(_vector_document())
    entry = dict(document["projects"][0])
    entry["scheme_counts"] = {"hmac-sha256": 800, "ed25519": 199}
    document["projects"] = [entry]
    error = _refusal(parse_estate_catalog, document, for_signing=True)
    assert _reason(error) == "scheme_counts_do_not_sum_to_event_count"
    assert error.detail["scheme_total"] == 999
    assert error.detail["legacy_event_count"] == 1000


def test_governance_mode_must_be_the_derived_one() -> None:
    """§3.4: the mode is derived and merely restated; a false label is INVALID."""
    document = _published(_vector_document())
    document["root_governance"] = {"mode": "co_signed", "threshold": 1, "signer_count": 2}
    error = _refusal(parse_estate_catalog, document, for_signing=True)
    assert _reason(error) == "governance_mode_mismatch"
    assert error.detail["derived"] == "solo_effective"


def test_threshold_above_signer_count_is_rejected() -> None:
    document = _published(_vector_document())
    document["root_governance"] = {"mode": "co_signed", "threshold": 3, "signer_count": 2}
    assert _reason(_refusal(parse_estate_catalog, document, for_signing=True)) == (
        "threshold_exceeds_signer_count"
    )


def test_empty_projects_array_is_rejected() -> None:
    """A catalog covering no project asserts nothing (CUTOVER-CLASSIFICATION.md:588)."""
    document = _published(_vector_document())
    document["projects"] = []
    assert _reason(_refusal(parse_estate_catalog, document, for_signing=True)) == "projects_empty"


def test_duplicate_project_entries_are_rejected() -> None:
    document = _published(_vector_document())
    entry = document["projects"][0]
    document["projects"] = [entry, entry]
    assert _reason(_refusal(parse_estate_catalog, document, for_signing=True)) == (
        "duplicate_project_instance_id"
    )

    other = {**entry, "project_instance_id": str(uuid.uuid4())}
    document["projects"] = [entry, other]
    assert _reason(_refusal(parse_estate_catalog, document, for_signing=True)) == (
        "duplicate_project_name_hint"
    )


def test_bool_is_not_an_integer_count() -> None:
    document = _published(_vector_document())
    document["projects"] = [{**document["projects"][0], "legacy_event_count": True}]
    assert _reason(_refusal(parse_estate_catalog, document, for_signing=True)) == "not_an_integer"


def test_malformed_digest_grammar_is_rejected() -> None:
    document = _published(_vector_document())
    document["projects"] = [
        {**document["projects"][0], "legacy_head_event_hash": "sha256:" + "DD" * 32}
    ]
    error = _refusal(parse_estate_catalog, document, for_signing=True)
    assert _reason(error) == "malformed_value"
    assert error.detail["path"] == "projects[0].legacy_head_event_hash"


def test_malformed_prev_commit_and_created_at_are_rejected() -> None:
    document = _published(_vector_document())
    assert _reason(_refusal(parse_estate_catalog, {**document, "prev_commit": "abc"},
                            for_signing=True)) == "malformed_value"
    coarse = {**document, "created_at": "2026-08-20T12:00:00Z"}
    assert _reason(_refusal(parse_estate_catalog, coarse, for_signing=True)) == (
        "malformed_timestamp"
    )


def test_inline_countersignatures_and_anchors_are_refused() -> None:
    """§4.3 rule 3: later attestations are new immutable records, not appended fields."""
    document = _published(_vector_document())
    document["root_signatures"] = [
        {"signer_id": "root-a", "fingerprint": "ed25519:sha256:" + "ab" * 32,
         "signature": base64.b64encode(b"z" * 64).decode("ascii")}
    ]
    for section in ("countersignatures", "anchors"):
        candidate = {**document, section: [{"anything": True}]}
        assert _reason(_refusal(parse_estate_catalog, candidate)) == (
            "inline_attestations_unsupported"
        )


def test_published_catalog_without_root_signatures_is_refused() -> None:
    document = _published(_vector_document())
    assert _reason(_refusal(parse_estate_catalog, document)) == "root_signatures_absent"
    # ... but the same document is fine as a to-be-signed core.
    parse_estate_catalog(document, for_signing=True)


def test_duplicate_root_signature_fingerprints_are_refused() -> None:
    entry = {
        "signer_id": "root-a",
        "fingerprint": "ed25519:sha256:" + "ab" * 32,
        "signature": base64.b64encode(b"z" * 64).decode("ascii"),
    }
    document = {**_published(_vector_document()), "root_signatures": [entry, dict(entry)]}
    assert _reason(_refusal(parse_estate_catalog, document)) == "duplicate_root_signature"


def test_short_signature_is_refused() -> None:
    document = {
        **_published(_vector_document()),
        "root_signatures": [
            {
                "signer_id": "root-a",
                "fingerprint": "ed25519:sha256:" + "ab" * 32,
                "signature": base64.b64encode(b"z" * 32).decode("ascii"),
            }
        ],
    }
    assert _reason(_refusal(parse_estate_catalog, document)) == "signature_length_invalid"


# ===========================================================================
# Verification against a pinned genesis
# ===========================================================================


def _sign_catalog(fixture, *, signer_index: int = 0, **overrides: Any) -> dict[str, Any]:
    """Build and root-sign a catalog bound to ``fixture``'s trust domain."""
    entry = _vector_document()["projects"][0]
    fields: dict[str, Any] = {
        "trust_domain_id": fixture.trust_domain_id,
        "trust_domain_core_digest": fixture.trust_domain_core_digest,
        "root_governance": {
            "mode": fixture.mode,
            "threshold": fixture.threshold,
            "signer_count": fixture.signer_count,
        },
        "projects": [
            CatalogProject(
                project_instance_id=entry["project_instance_id"],
                project_name_hint=entry["project_name_hint"],
                cutover_event_hash=entry["cutover_event_hash"],
                legacy_head_event_hash=entry["legacy_head_event_hash"],
                legacy_event_count=entry["legacy_event_count"],
                scheme_counts=entry["scheme_counts"],
                new_epoch_head_event_hash=entry["new_epoch_head_event_hash"],
            )
        ],
        "trust_log_checkpoint_digest": "sha256:" + "ff" * 32,
        "created_at": "2026-08-20T12:00:00.000000Z",
        "prev_commit": None,
    }
    fields.update(overrides)
    document = build_estate_catalog(**fields)
    signer_id = fixture.signer_ids[signer_index]
    return sign_estate_catalog(
        document,
        seed=fixture.seeds[signer_id],
        signer_id=signer_id,
        fingerprint=fixture.fingerprints[signer_id],
    )


def test_verify_happy_path() -> None:
    """Every piece of evidence presented at once: file bytes, digest pin, checkpoint."""
    fixture = mint_solo()
    checkpoint_bytes = b"published-checkpoint-bytes"
    signed = _sign_catalog(
        fixture,
        trust_log_checkpoint_digest="sha256:" + hashlib.sha256(checkpoint_bytes).hexdigest(),
    )
    report = verify_estate_catalog(
        signed,
        genesis_document=fixture.document,
        file_bytes=canonicalize(signed),
        expect_digest=estate_catalog_digest(signed),
        trust_log_checkpoint_bytes=checkpoint_bytes,
    )
    assert report.verdict == "VALID"
    assert report.signatures_verified == 1
    assert report.extra_signatures == 0
    assert report.digest_pin_status == "matched"
    assert report.trust_log_checkpoint_status == "matched"
    assert report.project_count == 1
    assert report.project_name_hints == ("agent_notes",)


def test_verify_reports_unpresented_evidence_rather_than_skipping_it() -> None:
    """Absent evidence is REPORTED, never silently passed over."""
    fixture = mint_solo()
    signed = _sign_catalog(fixture)
    report = verify_estate_catalog(signed, genesis_document=fixture.document)
    assert report.verdict == "VALID"
    assert report.digest_pin_status == "not_pinned"
    assert report.trust_log_checkpoint_status == "not_presented"


def test_verify_refuses_a_tampered_signature() -> None:
    fixture = mint_solo()
    signed = _sign_catalog(fixture)
    signed["created_at"] = "2026-08-20T12:00:01.000000Z"
    error = _refusal(verify_estate_catalog, signed, genesis_document=fixture.document)
    assert error.code == ErrorCode.ESTATE_CATALOG_UNVERIFIED
    assert _reason(error) == "root_signature_invalid"


def test_verify_refuses_a_signer_the_genesis_never_committed_to() -> None:
    """An unknown key is a REFUSAL, not a dropped signature.

    Dropping it would turn a k-of-n check into a (k-1)-of-n one for anyone who can add
    a bogus entry, which is the exact hole ``verify_root_threshold`` documents.
    """
    fixture = mint_solo()
    stranger = nacl.signing.SigningKey.generate()
    document = build_estate_catalog(
        trust_domain_id=fixture.trust_domain_id,
        trust_domain_core_digest=fixture.trust_domain_core_digest,
        root_governance={
            "mode": fixture.mode,
            "threshold": fixture.threshold,
            "signer_count": fixture.signer_count,
        },
        projects=[
            CatalogProject(**{
                key: _vector_document()["projects"][0][key]
                for key in (
                    "project_instance_id", "project_name_hint", "cutover_event_hash",
                    "legacy_head_event_hash", "legacy_event_count", "scheme_counts",
                    "new_epoch_head_event_hash",
                )
            })
        ],
        trust_log_checkpoint_digest="sha256:" + "ff" * 32,
        created_at="2026-08-20T12:00:00.000000Z",
    )
    signed = sign_estate_catalog(
        document,
        seed=bytes(stranger),
        signer_id="root-a",
        fingerprint="ed25519:sha256:"
        + hashlib.sha256(bytes(stranger.verify_key)).hexdigest(),
    )
    error = _refusal(verify_estate_catalog, signed, genesis_document=fixture.document)
    assert _reason(error) == "root_signer_not_presented"


def test_verify_refuses_a_signer_id_that_contradicts_the_genesis() -> None:
    fixture = mint_solo()
    signed = _sign_catalog(fixture)
    signed["root_signatures"][0]["signer_id"] = "root-impostor"
    error = _refusal(verify_estate_catalog, signed, genesis_document=fixture.document)
    assert _reason(error) == "root_signer_id_mismatch"


def test_verify_refuses_a_catalog_below_the_threshold() -> None:
    """A 2-of-2 domain: one valid signature is not enough, and is not rounded up."""
    fixture = mint_co_signed(threshold=2, signer_count=2)
    signed = _sign_catalog(fixture)
    error = _refusal(verify_estate_catalog, signed, genesis_document=fixture.document)
    assert _reason(error) == "root_threshold_not_met"
    assert error.detail["verified"] == 1
    assert error.detail["threshold"] == 2


def test_verify_accepts_a_co_signed_catalog_at_threshold() -> None:
    fixture = mint_co_signed(threshold=2, signer_count=2)
    signed = _sign_catalog(fixture)
    second = fixture.signer_ids[1]
    signed = sign_estate_catalog(
        signed,
        seed=fixture.seeds[second],
        signer_id=second,
        fingerprint=fixture.fingerprints[second],
    )
    report = verify_estate_catalog(signed, genesis_document=fixture.document)
    assert report.verdict == "VALID"
    assert report.signatures_verified == 2
    assert report.root_governance.mode == "co_signed"


def test_verify_refuses_a_catalog_for_another_trust_domain() -> None:
    fixture = mint_solo()
    other = mint_solo()
    signed = _sign_catalog(fixture)
    error = _refusal(verify_estate_catalog, signed, genesis_document=other.document)
    assert _reason(error) == "trust_domain_mismatch"


def test_verify_refuses_a_catalog_that_lowers_the_root_threshold() -> None:
    """WI-280: the threshold is monotone non-decreasing; a document may not lower it."""
    fixture = mint_co_signed(threshold=2, signer_count=2)
    # A catalog claiming 1-of-2 in a 2-of-2 domain would meet its own stated bar with
    # a single signature. Refused on the stated threshold, before any signature check.
    signed = _sign_catalog(
        fixture,
        root_governance={"mode": "solo_effective", "threshold": 1, "signer_count": 2},
    )
    error = _refusal(verify_estate_catalog, signed, genesis_document=fixture.document)
    assert _reason(error) == "root_threshold_lowered"


def test_verify_refuses_a_non_canonical_publication_file() -> None:
    """§4.4: publications are canonical JCS bytes. Whitespace is not cosmetic here.

    Two files that parse to the same document but differ in bytes have different
    sha256s, and ``index.json`` plus every out-of-band pin compares sha256s.
    """
    fixture = mint_solo()
    signed = _sign_catalog(fixture)
    pretty = json.dumps(signed, indent=2, sort_keys=True).encode("utf-8")
    error = _refusal(
        verify_estate_catalog, signed, genesis_document=fixture.document, file_bytes=pretty
    )
    assert error.code == ErrorCode.ESTATE_CATALOG_SCHEMA_INVALID
    assert _reason(error) == "not_canonical_publication_bytes"


def test_verify_refuses_a_digest_that_disagrees_with_the_out_of_band_pin() -> None:
    fixture = mint_solo()
    signed = _sign_catalog(fixture)
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        expect_digest="sha256:" + "00" * 32,
    )
    assert _reason(error) == "estate_catalog_digest_mismatch"


def test_verify_refuses_a_checkpoint_that_is_not_the_bound_one() -> None:
    fixture = mint_solo()
    signed = _sign_catalog(fixture)
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        trust_log_checkpoint_bytes=b"a different checkpoint entirely",
    )
    assert _reason(error) == "trust_log_checkpoint_digest_mismatch"


def test_verify_refuses_an_under_signed_genesis_document() -> None:
    """An unverified genesis is not a source of root public keys.

    The refusal is the genesis verifier's own (``threshold_not_met`` /
    ``TRUST_GENESIS_SIGNATURE_INVALID``), delegated rather than re-implemented so the
    two cannot drift apart. What this pins is that ``verify_estate_catalog`` runs it
    *before* treating the document's signers as authority — a catalog signed by a key
    listed in an unverifiable genesis must not come back VALID.
    """
    fixture = mint_co_signed(threshold=2, signer_count=2)
    genesis = {**fixture.document, "signatures": fixture.document["signatures"][:1]}
    signed = _sign_catalog(fixture)
    error = _refusal(verify_estate_catalog, signed, genesis_document=genesis)
    assert error.code == ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID
    assert _reason(error) == "threshold_not_met"


def test_signing_twice_with_the_same_key_is_refused() -> None:
    """Two entries by one signer cannot raise the distinct-signer count."""
    fixture = mint_solo_effective(signer_count=3)
    signed = _sign_catalog(fixture)
    signer_id = fixture.signer_ids[0]
    error = _refusal(
        sign_estate_catalog,
        signed,
        seed=fixture.seeds[signer_id],
        signer_id=signer_id,
        fingerprint=fixture.fingerprints[signer_id],
    )
    assert _reason(error) == "duplicate_root_signature"


# ===========================================================================
# The operator measurements file
# ===========================================================================


def _inputs(*projects: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "regista.estate-catalog-inputs",
        "version": 1,
        "projects": list(projects),
    }


_RECORDED = {
    "legacy_head_event_hash": "sha256:" + "dd" * 32,
    "legacy_event_count": 1000,
    "scheme_counts": {"hmac-sha256": 800, "ed25519": 200},
}


def test_inputs_accepts_recorded_legacy_measurements() -> None:
    parsed = parse_catalog_inputs(_inputs({"project": "agent_notes", **_RECORDED}))
    assert len(parsed) == 1
    assert parsed[0].project == "agent_notes"
    assert parsed[0].project_name_hint == "agent_notes"
    assert parsed[0].legacy_project is None
    assert parsed[0].has_recorded_legacy_facts is True


def test_inputs_accepts_a_measurable_legacy_project() -> None:
    parsed = parse_catalog_inputs(
        _inputs({"project": "agent_notes", "legacy_project": "agent_notes_legacy"})
    )
    assert parsed[0].legacy_project == "agent_notes_legacy"
    assert parsed[0].has_recorded_legacy_facts is False


def test_inputs_refuse_an_entry_with_no_legacy_binding() -> None:
    """The legacy binding is the whole point of a cutover catalog: never defaulted."""
    error = _refusal(parse_catalog_inputs, _inputs({"project": "agent_notes"}))
    assert _reason(error) == "inputs_legacy_facts_incomplete"


def test_inputs_refuse_a_partial_legacy_record() -> None:
    error = _refusal(
        parse_catalog_inputs,
        _inputs(
            {
                "project": "agent_notes",
                "legacy_project": "agent_notes_legacy",
                "legacy_event_count": 1000,
            }
        ),
    )
    assert _reason(error) == "inputs_legacy_facts_partial"


def test_inputs_refuse_unknown_fields_and_duplicates() -> None:
    error = _refusal(
        parse_catalog_inputs,
        _inputs({"project": "agent_notes", "dsn": "postgres://x", **_RECORDED}),
    )
    assert _reason(error) == "closed_key_set_violated"
    assert error.detail["unknown"] == ["dsn"]

    error = _refusal(
        parse_catalog_inputs,
        _inputs({"project": "agent_notes", **_RECORDED}, {"project": "agent_notes", **_RECORDED}),
    )
    assert _reason(error) == "duplicate_input_project"


def test_inputs_refuse_the_legacy_schema_being_the_target_schema() -> None:
    error = _refusal(
        parse_catalog_inputs,
        _inputs({"project": "agent_notes", "legacy_project": "agent_notes", **_RECORDED}),
    )
    assert _reason(error) == "inputs_legacy_project_is_target"


def test_inputs_refuse_a_wrong_envelope() -> None:
    assert _reason(_refusal(parse_catalog_inputs, {"type": "x", "version": 1, "projects": []})) == (
        "wrong_inputs_type"
    )
    assert _reason(_refusal(parse_catalog_inputs, _inputs())) == "inputs_projects_empty"
    assert _reason(
        _refusal(parse_catalog_inputs, {**_inputs(), "version": 2})
    ) == "wrong_inputs_version"


# ===========================================================================
# CLI surface — verify-catalog is fully offline
# ===========================================================================


def _capture(fn, *args, **kwargs) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue()


def _verify_ns(**kwargs) -> argparse.Namespace:
    base: dict[str, Any] = {
        "dsn": None,
        "project": None,
        "hmac_key_path": None,
        "file": None,
        "genesis": None,
        "expect_digest": None,
        "trust_checkpoint": None,
        "json": True,
    }
    base.update(kwargs)
    return argparse.Namespace(**base)


def test_cli_verify_catalog_round_trip(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("REGISTA_TRUST_GENESIS_PATH", raising=False)
    fixture = mint_solo()
    signed = _sign_catalog(fixture)
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_bytes(canonicalize(signed))
    genesis_path = tmp_path / "genesis.json"
    genesis_path.write_text(json.dumps(fixture.document), encoding="utf-8")

    report = json.loads(
        _capture(
            cmd_trust_verify_catalog,
            _verify_ns(
                file=str(catalog_path),
                genesis=str(genesis_path),
                expect_digest=estate_catalog_digest(signed),
            ),
        )
    )
    assert report["verdict"] == "VALID"
    assert report["digest_pin_status"] == "matched"
    assert report["signatures_verified"] == 1


def test_cli_verify_catalog_human_output_names_what_it_did_not_prove(
    tmp_path, monkeypatch
) -> None:
    """The default (non-``--json``) report is what an operator actually reads.

    Two things it must say out loud: the verdict, and the limits of the verdict.
    Without an out-of-band ``--expect-digest`` the check proves internal coherence
    only — §4.1 / OPERATOR-FORGERY R3 — and an unsupplied checkpoint is reported
    ``not_presented`` rather than silently skipped.
    """
    monkeypatch.delenv("REGISTA_TRUST_GENESIS_PATH", raising=False)
    fixture = mint_solo()
    signed = _sign_catalog(fixture)
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_bytes(canonicalize(signed))
    genesis_path = tmp_path / "genesis.json"
    genesis_path.write_text(json.dumps(fixture.document), encoding="utf-8")

    output = _capture(
        cmd_trust_verify_catalog,
        _verify_ns(file=str(catalog_path), genesis=str(genesis_path), json=False),
    )
    assert "verdict: VALID" in output
    assert f"estate_catalog_digest: {estate_catalog_digest(signed)}" in output
    assert "digest_pin: not_pinned" in output
    assert "trust_log_checkpoint: not_presented" in output
    assert "OPERATOR-FORGERY R3" in output
    assert "no --trust-checkpoint was supplied" in output


def test_cli_verify_catalog_refuses_without_a_genesis(tmp_path, monkeypatch) -> None:
    """Without the pinned genesis there are no root keys, so a verdict would be vacuous."""
    monkeypatch.delenv("REGISTA_TRUST_GENESIS_PATH", raising=False)
    fixture = mint_solo()
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_bytes(canonicalize(_sign_catalog(fixture)))
    error = _refusal(cmd_trust_verify_catalog, _verify_ns(file=str(catalog_path)))
    assert _reason(error) == "genesis_document_absent"


def test_cli_verify_catalog_refuses_an_unreadable_file(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("REGISTA_TRUST_GENESIS_PATH", raising=False)
    fixture = mint_solo()
    genesis_path = tmp_path / "genesis.json"
    genesis_path.write_text(json.dumps(fixture.document), encoding="utf-8")
    error = _refusal(
        cmd_trust_verify_catalog,
        _verify_ns(file=str(tmp_path / "absent.json"), genesis=str(genesis_path)),
    )
    assert _reason(error) == "catalog_file_unreadable"


def test_cli_verify_catalog_refuses_non_json(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("REGISTA_TRUST_GENESIS_PATH", raising=False)
    fixture = mint_solo()
    genesis_path = tmp_path / "genesis.json"
    genesis_path.write_text(json.dumps(fixture.document), encoding="utf-8")
    bad = tmp_path / "catalog.json"
    bad.write_text("not json at all", encoding="utf-8")
    error = _refusal(
        cmd_trust_verify_catalog, _verify_ns(file=str(bad), genesis=str(genesis_path))
    )
    assert _reason(error) == "catalog_file_invalid_json"


def test_catalog_verbs_are_wired_into_the_trust_subparser() -> None:
    """The defect WI-330 reports is that no catalog verb exists. Pin that it does.

    ``regista trust --help`` is the surface the runbook's "documented catalog command"
    sentence points an operator at, so the help text — not just the callable — is what
    has to carry the verbs.
    """
    from regista._cli import main

    buf = io.StringIO()
    with pytest.raises(SystemExit) as excinfo, contextlib.redirect_stdout(buf):
        main(["trust", "--help"])
    assert excinfo.value.code == 0
    help_text = buf.getvalue()
    assert "catalog" in help_text
    assert "verify-catalog" in help_text


