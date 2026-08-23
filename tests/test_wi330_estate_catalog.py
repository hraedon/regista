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
    OPTIONAL_CORE_KEYS,
    SIGNATURE_SECTIONS,
    CatalogProject,
    RootAuthorityState,
    build_estate_catalog,
    estate_catalog_canonical_core,
    estate_catalog_core,
    estate_catalog_digest,
    estate_catalog_signature_input,
    genesis_root_authority,
    parse_catalog_inputs,
    parse_estate_catalog,
    parse_estate_manifest,
    sign_estate_catalog,
    verify_estate_catalog,
    verify_published_checkpoint,
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
# Fixture builders: a genesis, an AUTHENTICATED checkpoint, and a signed catalog
# ===========================================================================
#
# The checkpoint is now load-bearing (review F2/F3): it is what authorises the signing
# keys and fixes the threshold, so every verification test needs a real, signed,
# canonical one. `_checkpoint` mints it with the SAME signature input the production
# checkpoint verifier uses (`_genesis_open._checkpoint_signature_input`), and its
# knobs — `actives`, `governance`, `sign_with`, `extra_signers` — exist so a test can
# express a post-rotation root set that genesis alone cannot.


def _published(document: dict[str, Any]) -> dict[str, Any]:
    return {**document, "root_signatures": [], "countersignatures": [], "anchors": []}


def _fingerprint_of(public_key: bytes) -> str:
    return "ed25519:sha256:" + hashlib.sha256(public_key).hexdigest()


def _checkpoint(
    fixture,
    *,
    seq: int = 1,
    actives: tuple[str, ...] | None = None,
    governance: dict[str, Any] | None = None,
    sign_with: tuple[str, ...] | None = None,
    extra_signers: tuple[tuple[bytes, str, str], ...] = (),
    created_at: str = "2026-08-20T11:00:00.000000Z",
) -> bytes:
    """Mint a canonical, root-signed ``regista.trust-checkpoint`` document.

    Defaults describe the un-rotated estate: every genesis signer is active, governance
    is the genesis governance, and every signer signs.
    """
    from regista._genesis_open import _checkpoint_signature_input

    if actives is None:
        actives = tuple(sorted(fixture.fingerprints[s] for s in fixture.signer_ids))
    if governance is None:
        governance = {
            "mode": fixture.mode,
            "threshold": fixture.threshold,
            "signer_count": len(actives),
        }
    if sign_with is None:
        sign_with = tuple(fixture.signer_ids)
    document: dict[str, Any] = {
        "type": "regista.trust-checkpoint",
        "version": 1,
        "trust_domain_id": fixture.trust_domain_id,
        "trust_domain_core_digest": fixture.trust_domain_core_digest,
        "checkpoint_seq": seq,
        "trust_log": {
            "project_instance_id": "11111111-2222-3333-4444-555555555555",
            "event_count": 3,
            "genesis_event_hash": "sha256:" + "1a" * 32,
            "head_event_hash": "sha256:" + "2b" * 32,
            "max_global_seq": 3,
        },
        "root_governance": dict(governance),
        "active_root_fingerprints": list(actives),
        "prev_checkpoint_digest": None,
        "prev_commit": None,
        "created_at": created_at,
        "root_signatures": [],
        "countersignatures": [],
        "anchors": [],
    }
    message = _checkpoint_signature_input(document)
    entries = []
    for signer_id in sign_with:
        entries.append(
            {
                "signer_id": signer_id,
                "fingerprint": fixture.fingerprints[signer_id],
                "signature": base64.b64encode(
                    nacl.signing.SigningKey(fixture.seeds[signer_id]).sign(message).signature
                ).decode("ascii"),
            }
        )
    for seed, signer_id, fingerprint in extra_signers:
        entries.append(
            {
                "signer_id": signer_id,
                "fingerprint": fingerprint,
                "signature": base64.b64encode(
                    nacl.signing.SigningKey(seed).sign(message).signature
                ).decode("ascii"),
            }
        )
    document["root_signatures"] = entries
    return canonicalize(document)


def _build_for(fixture, *, checkpoint: bytes | None = None, **overrides: Any) -> dict[str, Any]:
    """The unsigned catalog core for ``fixture``, from the frozen vector's project entry."""
    entry = _vector_document()["projects"][0]
    digest = (
        "sha256:" + hashlib.sha256(checkpoint).hexdigest()
        if checkpoint is not None
        else "sha256:" + "ff" * 32
    )
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
        "trust_log_checkpoint_digest": digest,
        "created_at": "2026-08-20T12:00:00.000000Z",
        "prev_commit": None,
    }
    fields.update(overrides)
    return build_estate_catalog(**fields)


def _sign_catalog(
    fixture,
    *,
    checkpoint: bytes | None = None,
    sign_with: tuple[str, ...] | None = None,
    extra_signers: tuple[tuple[bytes, str, str], ...] = (),
    **overrides: Any,
) -> dict[str, Any]:
    """Build and root-sign a catalog bound to ``fixture``'s trust domain."""
    document = _build_for(fixture, checkpoint=checkpoint, **overrides)
    if sign_with is None:
        sign_with = (fixture.signer_ids[0],)
    signed = dict(document)
    for signer_id in sign_with:
        signed = sign_estate_catalog(
            signed,
            seed=fixture.seeds[signer_id],
            signer_id=signer_id,
            fingerprint=fixture.fingerprints[signer_id],
        )
    for seed, signer_id, fingerprint in extra_signers:
        signed = sign_estate_catalog(
            signed, seed=seed, signer_id=signer_id, fingerprint=fingerprint
        )
    return signed


def _walked(fixture) -> Any:
    """What a ROTATION-FREE trust-log walk yields: the genesis set, log-sourced.

    Post-FR3-1 the CLI always walks the log, so this — not a genesis-sourced authority —
    is the state the common case actually produces. ``verify_trust_log_chain`` seeds
    itself from genesis and applies no rotations, so the set and threshold are genesis's;
    only the provenance label differs, and that label is the point.
    """
    return _log_authority(fixture, fixture.signer_ids, threshold=fixture.threshold)


def _log_authority(fixture, signer_ids: tuple[str, ...], *, threshold: int) -> Any:
    """A ``RootAuthorityState`` standing for a REPLAYED trust log.

    ``trust_log_root_authority`` is the adapter that builds this from a real
    ``verify_trust_log_chain`` walk; the live module pins that adapter against a real
    log. Constructing the state directly here is what lets a DB-free test express a
    post-rotation root set, which genesis alone cannot describe.
    """
    fingerprints = tuple(sorted(fixture.fingerprints[s] for s in signer_ids))
    return RootAuthorityState(
        signer_fingerprints=fingerprints,
        threshold=threshold,
        public_keys={
            fixture.fingerprints[s]: fixture.public_keys[s] for s in signer_ids
        },
        signer_ids={fixture.fingerprints[s]: s for s in signer_ids},
        source="verified_trust_log",
        trust_log_event_count=2,
    )


def _manifest(trust_domain_id: str, ids: tuple[str, ...]) -> dict[str, Any]:
    return {
        "type": "regista.estate-manifest",
        "version": 1,
        "trust_domain_id": trust_domain_id,
        "project_instance_ids": list(ids),
    }


def _manifest_for(catalog: dict[str, Any]) -> dict[str, Any]:
    """The manifest that makes ``catalog`` exactly complete."""
    return _manifest(
        catalog["trust_domain_id"],
        tuple(entry["project_instance_id"] for entry in catalog["projects"]),
    )


# ===========================================================================
# Completeness (review F4): catalog_status and the expected-estate manifest
# ===========================================================================


def test_frozen_vector_carries_no_catalog_status_key() -> None:
    """The conformance constraint that decides how partiality is expressed.

    ``RECONCILIATION.md``:682-684 requires a partial catalog to say
    ``catalog_status: partial``. The frozen vector has no such key, so the field cannot
    be mandatory without changing the canonical bytes of every catalog. Absence is
    therefore the COMPLETE claim. This test exists so a future change that makes the
    field mandatory fails here, loudly, instead of silently breaking every published
    digest.
    """
    document = _vector_document()
    assert "catalog_status" not in document
    assert "catalog_status" not in CORE_KEYS
    assert OPTIONAL_CORE_KEYS == {"catalog_status"}
    # Still inside the signed core when present: it is not a signature section.
    assert "catalog_status" not in SIGNATURE_SECTIONS


def test_catalog_status_is_covered_by_the_signature() -> None:
    """A partial stamp cannot be stripped after signing.

    If ``catalog_status`` were outside the hashed bytes, an operator could sign a
    partial catalog and publish it as complete by deleting one key.
    """
    document = _vector_document()
    stamped = {**document, "catalog_status": "partial"}
    assert estate_catalog_digest(stamped) != estate_catalog_digest(document)
    assert b"catalog_status" in estate_catalog_canonical_core(stamped)


def test_catalog_status_may_only_say_partial() -> None:
    document = _published(_vector_document())
    for value in ("complete", "COMPLETE", "ok", ""):
        candidate = {**document, "catalog_status": value}
        assert _reason(_refusal(parse_estate_catalog, candidate, for_signing=True)) in {
            "catalog_status_invalid",
            "not_a_string",
        }


def test_builder_omits_catalog_status_for_a_complete_catalog() -> None:
    built = _build_for(mint_solo())
    assert "catalog_status" not in built
    built_partial = _build_for(mint_solo(), catalog_status="partial")
    assert built_partial["catalog_status"] == "partial"


def test_manifest_parsing_is_closed_and_bound_to_a_domain() -> None:
    domain = str(uuid.uuid4())
    ids = (str(uuid.uuid4()),)
    parsed_domain, parsed_ids = parse_estate_manifest(_manifest(domain, ids))
    assert parsed_domain == domain
    assert parsed_ids == ids

    assert _reason(
        _refusal(parse_estate_manifest, {**_manifest(domain, ids), "extra": 1})
    ) == "closed_key_set_violated"
    assert _reason(
        _refusal(parse_estate_manifest, {**_manifest(domain, ids), "type": "x"})
    ) == "wrong_manifest_type"
    assert _reason(
        _refusal(parse_estate_manifest, _manifest(domain, ()))
    ) == "manifest_projects_empty"
    assert _reason(
        _refusal(parse_estate_manifest, _manifest(domain, (ids[0], ids[0])))
    ) == "duplicate_manifest_project_instance_id"


# ===========================================================================
# Verification: the checkpoint is authenticated, not merely hashed (review F2)
# ===========================================================================


def test_verify_happy_path() -> None:
    """Every piece of evidence presented at once, and all of it checked."""
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    report = verify_estate_catalog(
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
        file_bytes=canonicalize(signed),
        expect_digest=estate_catalog_digest(signed),
    )
    assert report.verdict == "VALID"
    assert report.complete is True
    assert report.signatures_verified == 1
    assert report.digest_pin_status == "matched"
    assert report.completeness == "complete"
    assert report.catalog_status == "complete"
    assert report.checkpoint.signatures_verified == 1
    assert report.checkpoint.active_root_fingerprints == (
        fixture.fingerprints[fixture.signer_ids[0]],
    )


def test_verify_refuses_arbitrary_bytes_presented_as_a_checkpoint() -> None:
    """Reviewer probe (F2): arbitrary bytes used to report ``matched``.

    The old implementation compared only ``sha256(checkpoint_bytes)`` against the
    catalog's ``trust_log_checkpoint_digest``. Any blob whose digest the catalog happened
    to bind — and the catalog is written by the same operator — passed as a verified
    checkpoint. Now the bytes must BE a checkpoint.
    """
    fixture = mint_solo()
    blob = b"not a checkpoint at all"
    signed = _sign_catalog(
        fixture,
        trust_log_checkpoint_digest="sha256:" + hashlib.sha256(blob).hexdigest(),
    )
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=blob,
        expected_estate=_manifest_for(signed),
    )
    assert error.code == ErrorCode.ESTATE_CATALOG_SCHEMA_INVALID
    assert _reason(error) == "checkpoint_file_invalid_json"


def test_verify_refuses_a_checkpoint_with_invented_governance() -> None:
    """Reviewer probe (F2): ``signer_count: 99`` beside one fingerprint passed VALID.

    Nothing compared the checkpoint's stated ``signer_count`` with the number of
    fingerprints it actually listed, so a catalog could restate an invented governance
    block and satisfy its own threshold.
    """
    fixture = mint_solo()
    # `mode` is kept CONSISTENT with (threshold 1, signer_count 99) so the §3.4 derived
    # mode check cannot mask the finding: what is under test is that signer_count is
    # compared with the number of fingerprints actually listed.
    checkpoint = _checkpoint(
        fixture,
        governance={"mode": "solo_effective", "threshold": 1, "signer_count": 99},
    )
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "checkpoint_signer_count_contradicts_active_roots"
    assert error.detail["signer_count"] == 99
    assert error.detail["active_roots"] == 1


def test_verify_refuses_a_checkpoint_with_no_signatures() -> None:
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture, sign_with=())
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "checkpoint_root_signatures_absent"


def test_verify_refuses_a_checkpoint_whose_signature_does_not_verify() -> None:
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    tampered = json.loads(checkpoint.decode())
    tampered["checkpoint_seq"] = 2
    tampered_bytes = canonicalize(tampered)
    signed = _sign_catalog(
        fixture,
        trust_log_checkpoint_digest="sha256:" + hashlib.sha256(tampered_bytes).hexdigest(),
    )
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=tampered_bytes,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "checkpoint_root_signature_invalid"


def test_verify_refuses_a_non_canonical_checkpoint_file() -> None:
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    pretty = json.dumps(json.loads(checkpoint.decode()), indent=2, sort_keys=True).encode()
    signed = _sign_catalog(
        fixture,
        trust_log_checkpoint_digest="sha256:" + hashlib.sha256(pretty).hexdigest(),
    )
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=pretty,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "checkpoint_not_canonical_publication_bytes"


def test_verify_refuses_a_checkpoint_the_catalog_does_not_bind() -> None:
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    other = _checkpoint(fixture, seq=7)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=other,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "trust_log_checkpoint_digest_mismatch"


def test_verify_refuses_a_catalog_whose_governance_contradicts_the_checkpoint() -> None:
    """The catalog RESTATES the checkpoint's governance; a disagreement is invalid."""
    fixture = mint_solo_effective(signer_count=3)
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(
        fixture,
        checkpoint=checkpoint,
        root_governance={"mode": "solo", "threshold": 1, "signer_count": 1},
    )
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "root_governance_contradicts_checkpoint"


def test_verify_refuses_a_checkpoint_for_another_trust_domain() -> None:
    fixture = mint_solo()
    other = mint_solo()
    checkpoint = _checkpoint(other)
    signed = _sign_catalog(
        fixture,
        trust_log_checkpoint_digest="sha256:" + hashlib.sha256(checkpoint).hexdigest(),
    )
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "checkpoint_trust_domain_mismatch"


def test_verify_refuses_an_unsorted_active_root_list() -> None:
    fixture = mint_co_signed(threshold=2, signer_count=2)
    actives = tuple(fixture.fingerprints[s] for s in fixture.signer_ids)
    checkpoint = _checkpoint(fixture, actives=tuple(reversed(sorted(actives))))
    signed = _sign_catalog(fixture, checkpoint=checkpoint, sign_with=fixture.signer_ids)
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "checkpoint_active_roots_unsorted"


# ===========================================================================
# Root rotation (review F3): authority is the ACTIVE set, not genesis
# ===========================================================================


def test_verify_refuses_a_self_authorizing_checkpoint() -> None:
    """Sol's round-2 probe (FR2-1): a checkpoint that appoints its own signer.

    ``trust_domain_id`` and ``trust_domain_core_digest`` are PUBLIC — they are printed
    for direct exchange (§4.5 step 1) and appear in every published artifact. So an
    attacker can mint a checkpoint carrying the genuine domain identity while declaring
    ``active_root_fingerprints: [their own fresh key]`` at threshold 1-of-1, sign that
    checkpoint with the key it names, sign a catalog with the same key, and — while the
    checkpoint's signatures were verified against the checkpoint's OWN declared actives
    — have both accepted. Executed end to end by the reviewer: "checkpoint accepted:
    True, catalog accepted: True".

    Authority now chains from the pinned genesis, so the attacker's declared root set is
    reconciled against a set they cannot influence.
    """
    fixture = mint_solo()
    attacker = nacl.signing.SigningKey.generate()
    attacker_fp = _fingerprint_of(bytes(attacker.verify_key))

    # The forged checkpoint: GENUINE public domain identity, attacker as the sole root.
    checkpoint = _checkpoint(
        fixture,
        actives=(attacker_fp,),
        governance={"mode": "solo", "threshold": 1, "signer_count": 1},
        sign_with=(),
        extra_signers=((bytes(attacker), "root-a", attacker_fp),),
    )
    signed = _sign_catalog(
        fixture,
        checkpoint=checkpoint,
        root_governance={"mode": "solo", "threshold": 1, "signer_count": 1},
        sign_with=(),
        extra_signers=((bytes(attacker), "root-a", attacker_fp),),
    )

    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert error.code == ErrorCode.ESTATE_CATALOG_UNVERIFIED
    assert _reason(error) == "checkpoint_actives_contradict_authority"
    assert error.detail["checkpoint_actives"] == [attacker_fp]
    assert error.detail["derived_actives"] == [
        fixture.fingerprints[fixture.signer_ids[0]]
    ]
    # And the checkpoint alone is refused for the same reason, so no caller can get a
    # "verified checkpoint" object out of it and draw its own conclusions.
    standalone = _refusal(
        verify_published_checkpoint,
        checkpoint,
        genesis_document=fixture.document,
        authority=_walked(fixture),
    )
    assert _reason(standalone) == "checkpoint_actives_contradict_authority"


def test_verify_refuses_a_checkpoint_that_narrows_the_root_set_without_log_proof() -> None:
    """A rotation must be PROVEN by the log, not asserted by the checkpoint.

    The walk found no rotation, so the authority is the genesis set; a checkpoint that
    drops one of those roots is refused, and the operator is told to present the log that
    carries the rotation it is implying.
    """
    fixture = mint_solo_effective(signer_count=3)
    kept = fixture.signer_ids[0]
    checkpoint = _checkpoint(
        fixture,
        actives=(fixture.fingerprints[kept],),
        governance={"mode": "solo", "threshold": 1, "signer_count": 1},
        sign_with=(kept,),
    )
    error = _refusal(
        verify_published_checkpoint,
        checkpoint,
        genesis_document=fixture.document,
        authority=_walked(fixture),
    )
    assert _reason(error) == "checkpoint_actives_contradict_authority"
    assert error.detail["authority_source"] == "verified_trust_log"
    assert error.detail["derived_actives"] == list(_walked(fixture).signer_fingerprints)


def test_verify_refuses_a_checkpoint_that_restates_the_wrong_threshold() -> None:
    fixture = mint_solo_effective(signer_count=3)
    actives = tuple(sorted(fixture.fingerprints[s] for s in fixture.signer_ids))
    checkpoint = _checkpoint(
        fixture,
        actives=actives,
        governance={"mode": "co_signed", "threshold": 2, "signer_count": 3},
        sign_with=fixture.signer_ids[:2],
    )
    error = _refusal(
        verify_published_checkpoint,
        checkpoint,
        genesis_document=fixture.document,
        authority=_walked(fixture),
    )
    assert _reason(error) == "checkpoint_threshold_contradicts_authority"
    assert error.detail["stated"] == 2
    assert error.detail["derived"] == 1


def test_a_removed_root_is_refused_even_when_the_checkpoint_lists_it() -> None:
    """With the LOG-derived authority, a rotated-out root cannot sign a catalog.

    The authority here stands for a replayed log in which ``removed`` was rotated out;
    ``trust_log_root_authority`` is the adapter that produces exactly this object from a
    real chain walk, and the live module pins that adapter against a real log. What is
    under test is the security property: membership is decided by the authority, so the
    signature is refused even though the checkpoint (which matches the authority) is
    itself perfectly valid.
    """
    fixture = mint_solo_effective(signer_count=3)
    kept, removed = fixture.signer_ids[0], fixture.signer_ids[1]
    authority = _log_authority(fixture, (kept,), threshold=1)
    checkpoint = _checkpoint(
        fixture,
        actives=(fixture.fingerprints[kept],),
        governance={"mode": "solo", "threshold": 1, "signer_count": 1},
        sign_with=(kept,),
    )
    signed = _sign_catalog(
        fixture,
        checkpoint=checkpoint,
        root_governance={"mode": "solo", "threshold": 1, "signer_count": 1},
        sign_with=(removed,),
    )
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=authority,
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "root_signer_not_active"
    assert error.detail["fingerprint"] == fixture.fingerprints[removed]
    assert error.detail["authority_source"] == "verified_trust_log"

    # The kept root signs the same catalog core and it verifies.
    good = _sign_catalog(
        fixture,
        checkpoint=checkpoint,
        root_governance={"mode": "solo", "threshold": 1, "signer_count": 1},
        sign_with=(kept,),
    )
    report = verify_estate_catalog(
        good,
        genesis_document=fixture.document,
        authority=authority,
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(good),
    )
    assert report.verdict == "VALID"
    assert report.root_authority.source == "verified_trust_log"


def test_a_rotated_in_root_is_accepted_only_when_the_log_proves_the_rotation() -> None:
    """The other direction, and the reason there is no operator key channel.

    A root added by a §5.4 rotation appears in no document an offline auditor holds —
    but the log's ``trust_root_rotated`` event carries its ``added[].public_key``, so the
    replayed state has the bytes. With that authority the newcomer verifies; with the
    genesis authority (no log presented) the very same artifacts are refused. There is
    no third option in which an operator supplies the key: that flag existed and was the
    authority-smuggling channel FR2-1 exploited.
    """
    fixture = mint_solo()
    newcomer = nacl.signing.SigningKey.generate()
    newcomer_seed, newcomer_public = bytes(newcomer), bytes(newcomer.verify_key)
    newcomer_fp = _fingerprint_of(newcomer_public)

    checkpoint = _checkpoint(
        fixture,
        actives=(newcomer_fp,),
        governance={"mode": "solo", "threshold": 1, "signer_count": 1},
        sign_with=(),
        extra_signers=((newcomer_seed, "root-new", newcomer_fp),),
    )
    signed = _sign_catalog(
        fixture,
        checkpoint=checkpoint,
        root_governance={"mode": "solo", "threshold": 1, "signer_count": 1},
        sign_with=(),
        extra_signers=((newcomer_seed, "root-new", newcomer_fp),),
    )

    # Genesis authority: the rotation is unproven, so it is not believed.
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "checkpoint_actives_contradict_authority"

    # Log-derived authority carrying the rotation: accepted.
    rotated = RootAuthorityState(
        signer_fingerprints=(newcomer_fp,),
        threshold=1,
        public_keys={newcomer_fp: newcomer_public},
        signer_ids={},
        source="verified_trust_log",
        trust_log_event_count=2,
    )
    report = verify_estate_catalog(
        signed,
        genesis_document=fixture.document,
        authority=rotated,
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert report.verdict == "VALID"
    assert report.verified_fingerprints == (newcomer_fp,)


def test_no_operator_key_channel_remains_in_the_api() -> None:
    """FR2-1's remediation includes DELETING the smuggling channel, not narrowing it."""
    import inspect

    import regista._estate_catalog as module

    assert not hasattr(module, "resolve_root_public_keys")
    for fn in (verify_estate_catalog, verify_published_checkpoint):
        assert "additional_root_public_keys" not in inspect.signature(fn).parameters


def test_checkpoint_verifier_verifies_its_own_genesis_argument() -> None:
    """Review NEW-2: it is public and exported, so it cannot assume a verified genesis."""
    fixture = mint_co_signed(threshold=2, signer_count=2)
    checkpoint = _checkpoint(fixture, sign_with=fixture.signer_ids)
    under_signed = {**fixture.document, "signatures": fixture.document["signatures"][:1]}
    error = _refusal(
        verify_published_checkpoint,
        checkpoint,
        genesis_document=under_signed,
        # A caller could even hand in an authority derived elsewhere; the genesis check
        # still runs first.
        authority=_walked(fixture),
    )
    assert error.code == ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID
    assert _reason(error) == "threshold_not_met"


def test_governance_key_sets_agree_with_the_checkpoint_contract() -> None:
    """Review NEW-6: ``_parse_governance`` is reused for BOTH documents.

    ``verify_published_checkpoint`` validates a checkpoint's ``root_governance`` with the
    catalog's parser and then re-checks it against ``_genesis_open``'s own key set. That
    only composes while the two key sets are identical; if §4.3 ever gave one document an
    extra governance field, the shared parser would reject the other's valid documents.
    Pin the equality so that change is a failing test rather than a puzzling refusal.
    """
    from regista._estate_catalog import _GOVERNANCE_KEYS
    from regista._genesis_open import _CHECKPOINT_GOVERNANCE_KEYS

    assert _GOVERNANCE_KEYS == _CHECKPOINT_GOVERNANCE_KEYS == {
        "mode",
        "threshold",
        "signer_count",
    }


# ===========================================================================
# Threshold (review F5): k-of-n verification against the checkpoint
# ===========================================================================


def test_verify_refuses_a_catalog_below_the_checkpoint_threshold() -> None:
    fixture = mint_co_signed(threshold=2, signer_count=2)
    checkpoint = _checkpoint(fixture, sign_with=fixture.signer_ids)
    signed = _sign_catalog(
        fixture, checkpoint=checkpoint, sign_with=(fixture.signer_ids[0],)
    )
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "root_threshold_not_met"
    assert error.detail["verified"] == 1
    assert error.detail["threshold"] == 2


def test_verify_accepts_a_k_of_n_catalog_at_threshold() -> None:
    """F5's verification half: a 2-of-2 catalog verifies against the active set."""
    fixture = mint_co_signed(threshold=2, signer_count=2)
    checkpoint = _checkpoint(fixture, sign_with=fixture.signer_ids)
    signed = _sign_catalog(fixture, checkpoint=checkpoint, sign_with=fixture.signer_ids)
    report = verify_estate_catalog(
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert report.verdict == "VALID"
    assert report.signatures_verified == 2
    assert report.extra_signatures == 0
    assert report.root_governance.mode == "co_signed"


def test_signatures_can_be_appended_one_root_at_a_time() -> None:
    """The airgapped k-of-n flow: sign, courier, sign again, then verify."""
    fixture = mint_co_signed(threshold=2, signer_count=2)
    checkpoint = _checkpoint(fixture, sign_with=fixture.signer_ids)
    first = _sign_catalog(fixture, checkpoint=checkpoint, sign_with=(fixture.signer_ids[0],))
    second_id = fixture.signer_ids[1]
    complete = sign_estate_catalog(
        first,
        seed=fixture.seeds[second_id],
        signer_id=second_id,
        fingerprint=fixture.fingerprints[second_id],
    )
    # The claim did not move; only the signature array grew.
    assert estate_catalog_core(complete) == estate_catalog_core(first)
    assert estate_catalog_digest(complete) == estate_catalog_digest(first)
    report = verify_estate_catalog(
        complete,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(complete),
    )
    assert report.verdict == "VALID"
    assert report.signatures_verified == 2


def test_signing_twice_with_the_same_key_is_refused() -> None:
    """Two entries by one signer cannot raise the distinct-signer count."""
    fixture = mint_solo_effective(signer_count=3)
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
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
# Verification: the rest
# ===========================================================================


def test_verify_refuses_a_tampered_catalog() -> None:
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    signed["created_at"] = "2026-08-20T12:00:01.000000Z"
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "root_signature_invalid"


def test_verify_refuses_a_signer_id_that_contradicts_the_genesis() -> None:
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    signed["root_signatures"][0]["signer_id"] = "root-impostor"
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "root_signer_id_mismatch"


def test_verify_refuses_a_catalog_for_another_trust_domain() -> None:
    fixture = mint_solo()
    other = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=other.document,
        authority=_walked(other),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "trust_domain_mismatch"


def test_verify_refuses_a_non_canonical_publication_file() -> None:
    """§4.4: publications are canonical JCS bytes. Whitespace is not cosmetic here."""
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    pretty = json.dumps(signed, indent=2, sort_keys=True).encode("utf-8")
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
        file_bytes=pretty,
    )
    assert error.code == ErrorCode.ESTATE_CATALOG_SCHEMA_INVALID
    assert _reason(error) == "not_canonical_publication_bytes"


def test_verify_refuses_a_digest_that_disagrees_with_the_out_of_band_pin() -> None:
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
        expect_digest="sha256:" + "00" * 32,
    )
    assert _reason(error) == "estate_catalog_digest_mismatch"


def test_verify_refuses_an_under_signed_genesis_document() -> None:
    """An unverified genesis is not a source of root public keys.

    The refusal is the genesis verifier's own (``threshold_not_met`` /
    ``TRUST_GENESIS_SIGNATURE_INVALID``), delegated rather than re-implemented so the
    two cannot drift apart. What this pins is that ``verify_estate_catalog`` runs it
    *before* treating anything derived from that document as authority.
    """
    fixture = mint_co_signed(threshold=2, signer_count=2)
    checkpoint = _checkpoint(fixture, sign_with=fixture.signer_ids)
    signed = _sign_catalog(fixture, checkpoint=checkpoint, sign_with=fixture.signer_ids)
    genesis = {**fixture.document, "signatures": fixture.document["signatures"][:1]}
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=genesis,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert error.code == ErrorCode.TRUST_GENESIS_SIGNATURE_INVALID
    assert _reason(error) == "threshold_not_met"


# ===========================================================================
# Completeness verdicts (review F4)
# ===========================================================================


def test_verify_refuses_a_catalog_that_claims_complete_but_is_not() -> None:
    """Reviewer probe (F4): a one-project catalog for a two-project estate said VALID."""
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    absent = str(uuid.uuid4())
    manifest = _manifest(
        fixture.trust_domain_id,
        (signed["projects"][0]["project_instance_id"], absent),
    )
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=manifest,
    )
    assert error.code == ErrorCode.ESTATE_CATALOG_UNVERIFIED
    assert _reason(error) == "catalog_completeness_contradicted"
    assert error.detail["missing_project_instance_ids"] == [absent]


def test_verify_reports_partial_as_non_success() -> None:
    """A partial catalog authenticates and is STILL not a success."""
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint, catalog_status="partial")
    absent = str(uuid.uuid4())
    manifest = _manifest(
        fixture.trust_domain_id,
        (signed["projects"][0]["project_instance_id"], absent),
    )
    report = verify_estate_catalog(
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=manifest,
    )
    assert report.verdict == "PARTIAL"
    assert report.complete is False
    assert report.completeness == "partial"
    assert report.catalog_status == "partial"
    assert report.missing_project_instance_ids == (absent,)
    # The signatures were fine — that is exactly why the verdict has to carry it.
    assert report.signatures_verified == 1


def test_verify_refuses_a_false_partial_claim() -> None:
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint, catalog_status="partial")
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=_manifest_for(signed),
    )
    assert _reason(error) == "catalog_partial_claim_contradicted"


def test_verify_refuses_a_catalog_covering_an_unexpected_project() -> None:
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    manifest = _manifest(fixture.trust_domain_id, (str(uuid.uuid4()),))
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=manifest,
    )
    assert _reason(error) == "catalog_project_not_in_expected_estate"


def test_verify_refuses_a_manifest_for_another_trust_domain() -> None:
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    manifest = _manifest(
        str(uuid.uuid4()), (signed["projects"][0]["project_instance_id"],)
    )
    error = _refusal(
        verify_estate_catalog,
        signed,
        genesis_document=fixture.document,
        authority=_walked(fixture),
        trust_log_checkpoint_bytes=checkpoint,
        expected_estate=manifest,
    )
    assert _reason(error) == "expected_estate_trust_domain_mismatch"


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
_PREFLIGHT = {
    "expected_new_epoch_head_event_hash": "sha256:" + "ee" * 32,
    "expected_new_epoch_event_count": 1,
}


def test_inputs_accepts_recorded_legacy_measurements() -> None:
    parsed = parse_catalog_inputs(
        _inputs({"project": "agent_notes", **_RECORDED, **_PREFLIGHT})
    )
    assert len(parsed) == 1
    assert parsed[0].project == "agent_notes"
    assert parsed[0].project_name_hint == "agent_notes"
    assert parsed[0].legacy_project is None
    assert parsed[0].has_recorded_legacy_facts is True
    assert parsed[0].expected_new_epoch_event_count == 1


def test_inputs_accepts_a_measurable_legacy_project() -> None:
    parsed = parse_catalog_inputs(
        _inputs(
            {
                "project": "agent_notes",
                "legacy_project": "agent_notes_legacy",
                **_PREFLIGHT,
            }
        )
    )
    assert parsed[0].legacy_project == "agent_notes_legacy"
    assert parsed[0].has_recorded_legacy_facts is False


def test_inputs_require_the_approved_preflight_numbers() -> None:
    """Review F1: the command must not be the only witness to what it signs.

    ``ARCHITECTURE-0.6.0.md``:802-810 gates the ceremony on "Confirm the head/count
    equal the approved preflight result", so the operator has to state them.
    """
    error = _refusal(
        parse_catalog_inputs, _inputs({"project": "agent_notes", **_RECORDED})
    )
    assert _reason(error) == "inputs_preflight_absent"
    assert error.detail["missing"] == [
        "expected_new_epoch_head_event_hash",
        "expected_new_epoch_event_count",
    ]


def test_inputs_refuse_an_entry_with_no_legacy_binding() -> None:
    """The legacy binding is the whole point of a cutover catalog: never defaulted."""
    error = _refusal(
        parse_catalog_inputs, _inputs({"project": "agent_notes", **_PREFLIGHT})
    )
    assert _reason(error) == "inputs_legacy_facts_incomplete"


def test_inputs_refuse_a_partial_legacy_record() -> None:
    error = _refusal(
        parse_catalog_inputs,
        _inputs(
            {
                "project": "agent_notes",
                "legacy_project": "agent_notes_legacy",
                "legacy_event_count": 1000,
                **_PREFLIGHT,
            }
        ),
    )
    assert _reason(error) == "inputs_legacy_facts_partial"


def test_inputs_refuse_unknown_fields_and_duplicates() -> None:
    error = _refusal(
        parse_catalog_inputs,
        _inputs({"project": "agent_notes", "dsn": "postgres://x", **_RECORDED, **_PREFLIGHT}),
    )
    assert _reason(error) == "closed_key_set_violated"
    assert error.detail["unknown"] == ["dsn"]

    error = _refusal(
        parse_catalog_inputs,
        _inputs(
            {"project": "agent_notes", **_RECORDED, **_PREFLIGHT},
            {"project": "agent_notes", **_RECORDED, **_PREFLIGHT},
        ),
    )
    assert _reason(error) == "duplicate_input_project"


def test_inputs_refuse_the_legacy_schema_being_the_target_schema() -> None:
    error = _refusal(
        parse_catalog_inputs,
        _inputs(
            {
                "project": "agent_notes",
                "legacy_project": "agent_notes",
                **_RECORDED,
                **_PREFLIGHT,
            }
        ),
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
        "trust_checkpoint": None,
        "expected_estate": None,
        "trust_log_project": None,
        "trust_log_dsn": None,
        "expect_digest": None,
        "json": True,
    }
    base.update(kwargs)
    return argparse.Namespace(**base)


def _cli_files(tmp_path, fixture, signed, checkpoint, manifest=None):
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_bytes(canonicalize(signed))
    genesis_path = tmp_path / "genesis.json"
    genesis_path.write_text(json.dumps(fixture.document), encoding="utf-8")
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_bytes(checkpoint)
    manifest_path = tmp_path / "estate.json"
    manifest_path.write_text(
        json.dumps(manifest if manifest is not None else _manifest_for(signed)),
        encoding="utf-8",
    )
    return (
        str(catalog_path),
        str(genesis_path),
        str(checkpoint_path),
        str(manifest_path),
    )


def test_cli_verify_catalog_refuses_without_a_genesis(tmp_path, monkeypatch) -> None:
    """Without the pinned genesis there are no root keys, so a verdict would be vacuous."""
    monkeypatch.delenv("REGISTA_TRUST_GENESIS_PATH", raising=False)
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    catalog, _, cp, manifest = _cli_files(tmp_path, fixture, signed, checkpoint)
    error = _refusal(
        cmd_trust_verify_catalog,
        _verify_ns(file=catalog, trust_checkpoint=cp, expected_estate=manifest),
    )
    assert _reason(error) == "genesis_document_absent"


def test_cli_verify_catalog_refuses_an_unreadable_file(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("REGISTA_TRUST_GENESIS_PATH", raising=False)
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    _, genesis, cp, manifest = _cli_files(tmp_path, fixture, signed, checkpoint)
    error = _refusal(
        cmd_trust_verify_catalog,
        _verify_ns(
            file=str(tmp_path / "absent.json"),
            genesis=genesis,
            trust_checkpoint=cp,
            expected_estate=manifest,
        ),
    )
    assert _reason(error) == "catalog_file_unreadable"


def test_cli_verify_catalog_refuses_non_json(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("REGISTA_TRUST_GENESIS_PATH", raising=False)
    fixture = mint_solo()
    checkpoint = _checkpoint(fixture)
    signed = _sign_catalog(fixture, checkpoint=checkpoint)
    _, genesis, cp, manifest = _cli_files(tmp_path, fixture, signed, checkpoint)
    bad = tmp_path / "bad.json"
    bad.write_text("not json at all", encoding="utf-8")
    error = _refusal(
        cmd_trust_verify_catalog,
        _verify_ns(
            file=str(bad), genesis=genesis, trust_checkpoint=cp, expected_estate=manifest
        ),
    )
    assert _reason(error) == "catalog_file_invalid_json"


def test_cli_verify_catalog_refuses_when_no_trust_log_is_presented(
    tmp_path, monkeypatch
) -> None:
    """FR3-1: withholding the log must never be MORE permissive than presenting it.

    Sol's and Opus's probe: after a real A/B→C rotation, the REMOVED roots A and B still
    hold their keys. They forge a checkpoint declaring the *genesis* A/B set and a
    catalog signed under it. While `verify-catalog` fell back to
    ``genesis_root_authority`` when ``--trust-log-project`` was absent, that forgery
    verified VALID — the absence of evidence was being read as proof that no rotation had
    happened. There is now no such path: no log, no verdict.
    """
    monkeypatch.delenv("REGISTA_TRUST_GENESIS_PATH", raising=False)
    fixture = mint_co_signed(threshold=2, signer_count=2)
    # The forgery: a checkpoint + catalog perfectly consistent with the GENESIS set,
    # which is exactly what removed roots can still produce.
    checkpoint = _checkpoint(fixture, sign_with=fixture.signer_ids)
    signed = _sign_catalog(fixture, checkpoint=checkpoint, sign_with=fixture.signer_ids)
    catalog, genesis, cp, manifest = _cli_files(tmp_path, fixture, signed, checkpoint)

    error = _refusal(
        cmd_trust_verify_catalog,
        _verify_ns(
            file=catalog, genesis=genesis, trust_checkpoint=cp,
            expected_estate=manifest, trust_log_project=None,
        ),
    )
    assert error.code == ErrorCode.ESTATE_CATALOG_UNVERIFIED
    assert _reason(error) == "trust_log_not_presented"
    # The refusal has to tell the operator what to do, and disclose the consequence.
    assert "--trust-log-project" in str(error)
    assert "READ ACCESS" in str(error)

    # The same withholding is refused for the signing side too.
    from regista._cli import cmd_trust_sign_catalog

    sign_error = _refusal(
        cmd_trust_sign_catalog,
        argparse.Namespace(
            dsn=None, project=None, hmac_key_path=None, file=catalog,
            out=str(tmp_path / "signed.json"), key=["k.seed"], trust_checkpoint=cp,
            trust_log_project=None, trust_log_dsn=None, genesis=genesis,
            force=False, json=True,
        ),
    )
    assert _reason(sign_error) == "trust_log_not_presented"


def test_no_cli_verdict_path_can_reach_a_genesis_sourced_authority() -> None:
    """FR3-4: ``genesis_root_authority`` survives as a base case, not as a fallback.

    ``_resolve_root_authority`` is the ONLY way the CLI obtains an authority, and it
    raises rather than returning when the log is absent — so no report can print
    ``root_authority: genesis``. Asserted structurally, because a future refactor that
    reintroduced the fallback would otherwise pass every other test in this file.
    """
    import inspect

    from regista._cli import _resolve_root_authority

    source = inspect.getsource(_resolve_root_authority)
    assert "genesis_root_authority" not in source, (
        "the CLI authority resolver can reach the genesis base case again"
    )
    assert "trust_log_not_presented" in source


def test_genesis_authority_is_the_base_case_a_rotation_free_walk_reproduces() -> None:
    """Why requiring the log costs nothing for an un-rotated domain.

    ``verify_trust_log_chain`` seeds itself from genesis and applies rotations on top, so
    a rotation-free walk yields exactly the genesis signer set and threshold. The live
    module pins that against a real walk; this pins the claim the refusal message rests
    on — that presenting the log is never *worse* than the old fallback.
    """
    fixture = mint_solo_effective(signer_count=3)
    base = genesis_root_authority(fixture.document)
    walked = _walked(fixture)
    assert walked.signer_fingerprints == base.signer_fingerprints
    assert walked.threshold == base.threshold
    assert base.source == "genesis"
    assert walked.source == "verified_trust_log"


def test_catalog_verbs_are_wired_into_the_trust_subparser() -> None:
    """The defect WI-330 reports is that no catalog verb exists. Pin that it does."""
    from regista._cli import main

    buf = io.StringIO()
    with pytest.raises(SystemExit) as excinfo, contextlib.redirect_stdout(buf):
        main(["trust", "--help"])
    assert excinfo.value.code == 0
    help_text = buf.getvalue()
    assert "catalog" in help_text
    assert "sign-catalog" in help_text
    assert "verify-catalog" in help_text


def test_trust_catalog_rejects_project_and_projects_flags() -> None:
    """Review N-d: argparse abbreviation must not bind ``--project`` to an option.

    ``--project`` is a GLOBAL option that has to precede the subcommand. With
    ``allow_abbrev`` left on and an option named ``--projects``, argparse silently
    accepted ``trust catalog --project x`` as the inputs path.

    Review NEW-4: the first version of this test was VACUOUS — it accepted
    ``"unrecognized arguments" in err OR "required" in err``, and the missing-required-
    args error satisfied the second branch whether or not the abbreviation was fixed.
    Every required argument is now supplied, so the ONLY thing that can make argparse
    exit non-zero is the offending flag, and the specific message is asserted.
    """
    from regista._cli import main

    complete = [
        "trust", "catalog",
        "--inputs", "i.json",
        "--expected-estate", "e.json",
        "--out", "o.json",
        "--key", "k.seed",
        "--trust-checkpoint", "c.json",
    ]
    # Review NEW-8/FR3-3: `--project` and `--projects` are rejected whether or not
    # `allow_abbrev` is off, because no option they could abbreviate to exists any more.
    # `--input` is the DISCRIMINATING probe: it is a unique prefix of `--inputs`, so with
    # allow_abbrev=True argparse binds it and the command proceeds to fail on missing
    # CONFIG instead — a completely different error. Only allow_abbrev=False makes it
    # "unrecognized arguments".
    for flag in ("--project", "--projects", "--input", "--out-", "--ke"):
        err = io.StringIO()
        with pytest.raises(SystemExit) as excinfo, contextlib.redirect_stderr(err):
            main([*complete, flag, "x"])
        assert excinfo.value.code == 2, flag
        message = err.getvalue()
        assert "unrecognized arguments" in message, (flag, message)
        assert flag in message, (flag, message)
        assert "required" not in message, (
            f"{flag} produced a missing-required-args error, so this probe would pass "
            "even with the abbreviation bug present"
        )


def test_verify_catalog_requires_checkpoint_and_manifest_at_the_cli() -> None:
    """There is no invocation that skips the checkpoint and still reports a verdict."""
    from regista._cli import main

    err = io.StringIO()
    with pytest.raises(SystemExit) as excinfo, contextlib.redirect_stderr(err):
        main(["trust", "verify-catalog", "catalog.json"])
    assert excinfo.value.code == 2
    message = err.getvalue()
    assert "--trust-checkpoint" in message
    assert "--expected-estate" in message
    # FR3-1: the log is REQUIRED at the parser too, so an operator cannot even spell an
    # invocation that would have taken the old genesis fallback.
    assert "--trust-log-project" in message


def test_created_at_requires_exactly_six_fractional_digits() -> None:
    """Review N-b: ``strptime('%f')`` accepted one to six digits."""
    document = _published(_vector_document())
    for value in ("2026-08-20T12:00:00.1Z", "2026-08-20T12:00:00.12345Z",
                  "2026-08-20T12:00:00Z", "2026-08-20T12:00:00.1234567Z"):
        candidate = {**document, "created_at": value}
        assert _reason(
            _refusal(parse_estate_catalog, candidate, for_signing=True)
        ) == "malformed_timestamp", value
    # The frozen vector's own form still passes, so conformance is unaffected.
    parse_estate_catalog(document, for_signing=True)
