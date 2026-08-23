"""Bundle v3 core — ``BUNDLE-V3.md`` §2, §3 and §6, with no database.

Every test here runs against real signed v6 envelopes built offline, so the whole of the
format is exercised without a store. ``tests/test_bundle.py`` covers the store-facing
export/verify path; this module covers the document.

Three things it deliberately pins hardest, because they are the three a second
implementation would get wrong:

* **the frozen Merkle vectors, against the production functions.**
  ``tests/test_v6_vectors.py`` already recomputes the tree from a reference implementation
  local to that module — which proves the vectors are self-consistent and proves nothing
  about ``regista``. ``TestFrozenMerkleVectors`` runs ``_bundle_v3``'s own functions.
* **anti-downgrade.** A v1 or v2 artifact must be refused *by name*, before any other
  check, and never read as v3.
* **the closed key sets.** A tolerated extra key inside the signed statement is
  attacker-chosen content under a valid signature, which is the S4 shape the whole
  document exists to remove.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from regista._bundle_v3 import (
    BUNDLE_V3_FORMAT_VERSION,
    MEMBER_LEAF_DOMAIN,
    MEMBER_NODE_DOMAIN,
    REFERENCE_SECTIONS,
    SECTION_NAMES,
    STATEMENT_SIGNING_DOMAIN,
    SUPPORTED_FORMAT_VERSIONS,
    BundleV3Signer,
    BundleV3TrustRoot,
    build_bundle_v3_document,
    canonical_bundle_bytes,
    derive_chain_order,
    digest_text,
    membership_root,
    merkle_leaf,
    merkle_node,
    merkle_root,
    parse_bundle_v3_document,
    parse_event_member,
    section_digest,
    statement_signing_input,
    verify_bundle_v3_core,
)
from regista._errors import ErrorCode, RegistaError
from regista._signing import sign_v6_envelope
from regista._testing_v6 import (
    BOOTSTRAP_PRINCIPAL,
    genesis_envelope,
    make_v6_keyset,
    v6_producer,
)

VECTORS = Path(__file__).parent / "vectors" / "v6"

BOOTSTRAP = BOOTSTRAP_PRINCIPAL
WORKER = "agent:worker"


def _load_vector(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# An offline v6 chain: genesis, an acceptance, two ordinary events.
# ---------------------------------------------------------------------------


class _Chain:
    """A signed v6 chain built in memory, plus everything a statement needs."""

    def __init__(self, keyset: Any, *, may_sign_bundles: bool = True) -> None:
        self.keyset = keyset
        self.records: list[tuple[bytes, bytes]] = []
        self.hashes: list[str] = []

        genesis = genesis_envelope(keyset, principal_id=BOOTSTRAP)
        self.project_instance_id = str(genesis["project_instance_id"])
        self.trust_domain_id = str(genesis["trust_domain_id"])
        self.core_digest = str(genesis["payload"]["trust_domain_core_digest"])
        self.document_digest = str(genesis["payload"]["genesis_document_digest"])
        self._append(genesis, BOOTSTRAP)
        self.genesis_hash = self.hashes[0]

        worker = keyset.key_for(WORKER)
        acceptance = self._acceptance_envelope(worker, may_sign_bundles=may_sign_bundles)
        self._append(acceptance, BOOTSTRAP)
        self.acceptance_hash = self.hashes[-1]

        entity_id = str(uuid.uuid4())
        previous_entity: str | None = None
        for seq, transition in enumerate(("created", "updated"), start=1):
            envelope = self._work_item_envelope(
                entity_id=entity_id,
                entity_seq=seq,
                transition=transition,
                previous_entity_event_hash=previous_entity,
            )
            self._append(envelope, WORKER)
            previous_entity = self.hashes[-1]

    # -- construction -----------------------------------------------------

    def _append(self, envelope: dict[str, Any], principal_id: str) -> None:
        envelope = copy.deepcopy(envelope)
        envelope["chain"]["previous_project_event_hash"] = (
            self.hashes[-1] if self.hashes else None
        )
        signed = sign_v6_envelope(envelope, self.keyset.key_for(principal_id).seed)
        self.records.append((signed.canonical_envelope, signed.signature))
        self.hashes.append("sha256:" + signed.event_hash.hex())

    def _base(self, principal_id: str) -> dict[str, Any]:
        key = self.keyset.key_for(principal_id)
        return {
            "type": "regista.event",
            "version": 6,
            "project_instance_id": self.project_instance_id,
            "trust_domain_id": self.trust_domain_id,
            "event_id": str(uuid.uuid4()),
            "actor": {"principal_id": principal_id, "kind": "system", "metadata": {}},
            "signing": {
                "scheme_id": "ed25519",
                "key_id": key.key_id,
                "key_binding_event_hash": self.hashes[0] if self.hashes else None,
            },
            "authorization": {"mode": "direct", "credentials": []},
            "workflow": None,
            "occurred_at": "2026-08-23T12:00:00.000000Z",
            "producer": v6_producer().as_envelope_member(),
            "chain": {
                "hash_algorithm": "sha-256",
                "previous_entity_event_hash": None,
                "previous_project_event_hash": None,
            },
        }

    def _acceptance_envelope(self, worker: Any, *, may_sign_bundles: bool) -> dict[str, Any]:
        envelope = self._base(BOOTSTRAP)
        envelope["entity"] = {
            "kind": "principal",
            "id": str(uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + WORKER)),
        }
        envelope["entity_seq"] = 1
        envelope["transition"] = "principal_key_accepted"
        envelope["payload"] = {
            "type": "regista.key-acceptance",
            "version": 1,
            "trust_domain_id": self.trust_domain_id,
            "project_instance_id": self.project_instance_id,
            "principal_id": WORKER,
            "key_id": worker.key_id,
            "fingerprint": worker.fingerprint,
            "public_key": worker.public_key_b64,
            "trust_event_hash": digest_text(hashlib.sha256(b"enrolment").digest()),
            "trust_log_checkpoint": {
                "checkpoint_seq": 1,
                "head_event_hash": digest_text(hashlib.sha256(b"head").digest()),
                "document_digest": digest_text(hashlib.sha256(b"doc").digest()),
            },
            "scopes": {
                "entity_kinds": ["work_item", "principal", "workflow", "project"],
                "transitions": None,
                "may_sign_checkpoints": False,
                "may_sign_bundles": may_sign_bundles,
            },
            "accepted_by": {
                "principal_id": BOOTSTRAP,
                "key_id": self.keyset.key_for(BOOTSTRAP).key_id,
                "key_binding_event_hash": self.hashes[0],
            },
        }
        return envelope

    def _work_item_envelope(
        self,
        *,
        entity_id: str,
        entity_seq: int,
        transition: str,
        previous_entity_event_hash: str | None,
    ) -> dict[str, Any]:
        envelope = self._base(WORKER)
        envelope["entity"] = {"kind": "work_item", "id": entity_id}
        envelope["entity_seq"] = entity_seq
        envelope["transition"] = transition
        envelope["payload"] = {"note": f"event {entity_seq}"}
        envelope["signing"]["key_binding_event_hash"] = self.acceptance_hash
        envelope["chain"]["previous_entity_event_hash"] = previous_entity_event_hash
        return envelope

    # -- statement inputs -------------------------------------------------

    def trust_root(self, **overrides: Any) -> BundleV3TrustRoot:
        fields: dict[str, Any] = {
            "trust_domain_id": self.trust_domain_id,
            "trust_domain_core_digest": self.core_digest,
            "genesis_document_digest": self.document_digest,
            "governance_mode": "solo",
            "governance_threshold": 1,
            "governance_signer_count": 1,
        }
        fields.update(overrides)
        return BundleV3TrustRoot(**fields)

    def signer(self, **overrides: Any) -> BundleV3Signer:
        worker = self.keyset.key_for(WORKER)
        fields: dict[str, Any] = {
            "principal_id": WORKER,
            "key_id": worker.key_id,
            "fingerprint": worker.fingerprint,
            "authority_kind": "scoped",
            "authority_event_hash": self.acceptance_hash,
            "may_sign_bundles": True,
            "private_key": worker.seed,
        }
        fields.update(overrides)
        return BundleV3Signer(**fields)

    @property
    def signer_public_key(self) -> bytes:
        return self.keyset.key_for(WORKER).public_key

    def key_evidence(self) -> list[dict[str, Any]]:
        """The §4.3 evidence records for the two keys the chain's acceptances name."""
        records = []
        for principal_id in (BOOTSTRAP, WORKER):
            key = self.keyset.key_for(principal_id)
            records.append(
                {
                    "key_id": key.key_id,
                    "principal_id": principal_id,
                    "scheme_id": "ed25519",
                    "public_key": key.public_key_b64,
                    "fingerprint": key.fingerprint,
                }
            )
        return sorted(records, key=lambda r: str(r["key_id"]))

    def build(self, **overrides: Any) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "event_records": self.records,
            "project_instance_id": self.project_instance_id,
            "trust_root": self.trust_root(),
            "signer": self.signer(),
            "scope_kind": "complete-store",
            "bundled_key_evidence": self.key_evidence(),
            "regista_version": "0.7.2",
        }
        kwargs.update(overrides)
        return build_bundle_v3_document(**kwargs)


@pytest.fixture(scope="module")
def keyset(tmp_path_factory: pytest.TempPathFactory) -> Any:
    return make_v6_keyset(tmp_path_factory.mktemp("bundle_v3_keys"))


@pytest.fixture(scope="module")
def chain(keyset: Any) -> _Chain:
    return _Chain(keyset)


@pytest.fixture(scope="module")
def document(chain: _Chain) -> dict[str, Any]:
    return chain.build()


def _reparse(document: dict[str, Any]) -> Any:
    return parse_bundle_v3_document(canonical_bundle_bytes(document))


def _mutated(document: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(document)


# ---------------------------------------------------------------------------
# §3.3 — the frozen membership vectors, against the production functions
# ---------------------------------------------------------------------------


class TestFrozenMerkleVectors:
    """``tests/vectors/v6/bundle-merkle-*.json``, recomputed by ``regista._bundle_v3``.

    P0.3's vectors exist so "a future non-Python verifier" has frozen bytes to check
    against. Until something in ``src/`` is checked against them they only prove the
    generator agrees with itself, and a one-byte disagreement in a domain tag "produces
    two different roots and one very confusing incident" (§3.3 correction 2).
    """

    @pytest.mark.parametrize(
        "name",
        ["bundle-merkle-single", "bundle-merkle-two", "bundle-merkle-three",
         "bundle-merkle-five"],
        ids=lambda n: str(n),
    )
    def test_production_membership_root_matches_the_frozen_vector(self, name: str) -> None:
        case = _load_vector(name)
        hashes = [
            bytes.fromhex(h.removeprefix("sha256:")) for h in case["input"]["event_hashes"]
        ]
        assert digest_text(membership_root(hashes)) == case["expected"]["membership_root"]

    @pytest.mark.parametrize(
        "name",
        ["bundle-merkle-single", "bundle-merkle-two", "bundle-merkle-three",
         "bundle-merkle-five"],
        ids=lambda n: str(n),
    )
    def test_production_leaves_match_the_frozen_vector(self, name: str) -> None:
        case = _load_vector(name)
        hashes = [
            bytes.fromhex(h.removeprefix("sha256:")) for h in case["input"]["event_hashes"]
        ]
        computed = [digest_text(merkle_leaf(i, h)) for i, h in enumerate(hashes)]
        expected = case["expected"].get("leaves")
        if expected is None:
            expected = [case["expected"]["leaf_0"]]
        assert computed[: len(expected)] == expected

    def test_production_node_matches_the_frozen_two_leaf_vector(self) -> None:
        case = _load_vector("bundle-merkle-two")
        hashes = [
            bytes.fromhex(h.removeprefix("sha256:")) for h in case["input"]["event_hashes"]
        ]
        node = merkle_node(merkle_leaf(0, hashes[0]), merkle_leaf(1, hashes[1]))
        assert digest_text(node) == case["expected"]["node_0_1"]

    def test_production_empty_root_matches_the_frozen_vector(self) -> None:
        case = _load_vector("bundle-merkle-empty")
        assert digest_text(merkle_root([])) == case["expected"]["membership_root"]
        assert case["expected"]["reachable"] is False

    def test_the_domain_tags_are_the_frozen_manifest_tags(self) -> None:
        """The tags are frozen in the vector manifest; the module must not restate them
        differently. This is the one-byte disagreement §3.3 correction 2 is about."""
        manifest = json.loads((VECTORS / "manifest.json").read_text(encoding="utf-8"))
        tags = manifest["domain_tags"]
        assert MEMBER_LEAF_DOMAIN == tags["bundle_member"].encode("utf-8")
        assert MEMBER_NODE_DOMAIN == tags["bundle_node"].encode("utf-8")

    def test_the_leaf_has_no_extra_positional_byte(self) -> None:
        """§3.3 correction 2: "No leading ``0x00`` on the leaf". Asserted against the
        construction rather than against a vector, so the vector and the rule are two
        independent statements."""
        event_hash = bytes(range(32))
        expected = hashlib.sha256(
            MEMBER_LEAF_DOMAIN + (7).to_bytes(8, "big") + event_hash
        ).digest()
        assert merkle_leaf(7, event_hash) == expected

    def test_the_split_is_at_the_largest_power_of_two_not_a_duplicated_tail(self) -> None:
        """§3.3 reason 2: the Bitcoin-style duplicate-the-last-node rule "admits two
        distinct leaf sequences with the same root"."""
        leaves = [bytes([i]) * 32 for i in range(3)]
        rfc6962 = merkle_node(merkle_node(leaves[0], leaves[1]), leaves[2])
        bitcoin = merkle_node(
            merkle_node(leaves[0], leaves[1]), merkle_node(leaves[2], leaves[2])
        )
        assert merkle_root(leaves) == rfc6962
        assert merkle_root(leaves) != bitcoin

    def test_the_ordinal_is_in_the_leaf_so_a_permutation_changes_the_root(self) -> None:
        hashes = [bytes([i]) * 32 for i in range(5)]
        assert membership_root(hashes) != membership_root(list(reversed(hashes)))


# ---------------------------------------------------------------------------
# §3.7 — section digests
# ---------------------------------------------------------------------------


class TestSectionDigests:
    def test_the_section_name_is_inside_the_hash_input(self) -> None:
        """§3.7: "two sections cannot be swapped even if their contents happen to be
        structurally compatible"."""
        contents = [digest_text(b"\x01" * 32)]
        assert section_digest("workflows", contents) != section_digest(
            "review_verdicts", contents
        )

    def test_the_digest_is_the_specified_construction(self) -> None:
        from regista._bundle_v3 import SECTION_DIGEST_DOMAIN
        from regista._jcs import canonicalize

        contents: list[Any] = [{"a": 1}]
        expected = hashlib.sha256(
            SECTION_DIGEST_DOMAIN + b"events" + b"\x00" + canonicalize(contents)
        ).digest()
        assert section_digest("events", contents) == expected


# ---------------------------------------------------------------------------
# §2 / §6 — format acceptance and anti-downgrade
# ---------------------------------------------------------------------------


class TestFormatDecisionAndAntiDowngrade:
    def test_only_version_three_is_supported(self) -> None:
        assert SUPPORTED_FORMAT_VERSIONS == frozenset({3})
        assert BUNDLE_V3_FORMAT_VERSION == 3

    def test_the_module_constants_agree_with_the_bundle_module(self) -> None:
        """§2 cites ``_SUPPORTED_FORMAT_VERSIONS``; §6 cites it again. One object."""
        from regista import _bundle

        assert _bundle._SUPPORTED_FORMAT_VERSIONS is SUPPORTED_FORMAT_VERSIONS
        assert _bundle._BUNDLE_FORMAT_VERSION == BUNDLE_V3_FORMAT_VERSION

    @pytest.mark.parametrize("declared", [1, 2])
    def test_a_v2_shaped_artifact_is_refused_by_name(self, declared: int) -> None:
        """The v1/v2 document had a ``manifest``, not a signed ``statement``. It must be
        refused as a FORMAT decision, naming the version, not reported as malformed v3 —
        an operator who reads "malformed" re-exports nothing."""
        legacy = json.dumps(
            {
                "manifest": {"format_version": declared, "event_count": 1},
                "events": [],
                "public_keys": [],
            }
        )
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(legacy)
        assert exc.value.code is ErrorCode.BUNDLE_FORMAT_UNSUPPORTED
        assert f"bundle v{declared} artifact" in str(exc.value)
        assert exc.value.detail is not None
        assert exc.value.detail["declared_format_version"] == declared

    @pytest.mark.parametrize("declared", [1, 2, 4, 0, -1])
    def test_a_statement_declaring_another_version_is_refused_not_downgraded(
        self, document: dict[str, Any], declared: int
    ) -> None:
        doctored = _mutated(document)
        doctored["statement"]["version"] = declared
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert exc.value.code is ErrorCode.BUNDLE_FORMAT_UNSUPPORTED
        assert "REFUSED rather than" in str(exc.value)

    def test_a_boolean_version_does_not_read_as_version_one(
        self, document: dict[str, Any]
    ) -> None:
        """``bool`` is an ``int`` subclass, so ``True in {1}`` is True. A verifier that
        accepted it would accept ``"version": true`` as format 1 — and then refuse it, but
        for the wrong reason and with the wrong diagnosis."""
        doctored = _mutated(document)
        doctored["statement"]["version"] = True
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert exc.value.code is ErrorCode.BUNDLE_FORMAT_UNSUPPORTED
        assert "must be an integer" in str(exc.value)

    def test_a_document_with_no_statement_declares_no_format(self) -> None:
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(json.dumps({"sections": {}}))
        assert exc.value.code is ErrorCode.BUNDLE_FORMAT_UNSUPPORTED
        assert "no `statement` object" in str(exc.value)

    def test_malformed_json_is_an_argument_error_not_a_format_decision(self) -> None:
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document("not json {{{")
        assert exc.value.code is ErrorCode.INVALID_ARGUMENT


# ---------------------------------------------------------------------------
# §3.1 — document shape
# ---------------------------------------------------------------------------


class TestDocumentShape:
    def test_a_clean_document_parses_and_verifies(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        parsed = _reparse(document)
        report = verify_bundle_v3_core(
            parsed, statement_public_key=chain.signer_public_key
        )
        assert report.core_ok, report.findings
        assert report.findings == ()
        assert report.event_count == len(chain.records)
        assert report.statement_signature_checked is True
        assert report.statement_signature_valid is True
        assert report.signer_authority_checked is True
        assert report.signer_may_sign_bundles is True

    def test_the_document_has_exactly_the_specified_top_level_keys(
        self, document: dict[str, Any]
    ) -> None:
        assert set(document) == {"statement", "statement_signature", "sections"}

    def test_an_unknown_top_level_key_is_a_rejection_not_an_ignore(
        self, document: dict[str, Any]
    ) -> None:
        """§3.1 rule 3, with its own stated reason: "a v2 verifier's tolerance of extra
        keys is how ``public_keys`` quietly became a trust root"."""
        doctored = _mutated(document)
        doctored["public_keys"] = [{"key_id": "pk_x"}]
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert exc.value.code is ErrorCode.BUNDLE_STATEMENT_INVALID
        assert "public_keys" in str(exc.value)

    def test_the_sections_object_is_closed(self, document: dict[str, Any]) -> None:
        doctored = _mutated(document)
        doctored["sections"]["action_delegation_credentials"] = []
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert exc.value.code is ErrorCode.BUNDLE_STATEMENT_INVALID
        assert "action_delegation_credentials" in str(exc.value)

    def test_every_named_section_is_present_and_every_section_is_named(
        self, document: dict[str, Any]
    ) -> None:
        """§3.2's first hard rule: "A one-sided set is a rejection. This is what makes
        'delete a whole section' fail without enumerating fields"."""
        assert set(document["sections"]) == set(SECTION_NAMES)
        assert set(document["statement"]["section_digests"]) == set(SECTION_NAMES)
        doctored = _mutated(document)
        del doctored["sections"]["review_verdicts"]
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "review_verdicts" in str(exc.value)

    def test_the_index_is_advisory_and_never_consumed(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        """§3.1 rule 2: "Emitting it is optional; consuming it in the verification path is
        forbidden." Filled here with values that contradict every signed field, so a
        verifier that read any of them would produce a different verdict."""
        doctored = _mutated(document)
        doctored["index"] = {
            "event_count": 99999,
            "event_membership_root": digest_text(b"\xff" * 32),
            "section_digests": {name: digest_text(b"\x00" * 32) for name in SECTION_NAMES},
            "events": ["sha256:" + "0" * 64],
        }
        report = verify_bundle_v3_core(
            parse_bundle_v3_document(canonical_bundle_bytes(doctored)),
            statement_public_key=chain.signer_public_key,
        )
        assert report.core_ok, report.findings


# ---------------------------------------------------------------------------
# §3.2 — the statement schema, as amended
# ---------------------------------------------------------------------------


class TestStatementSchema:
    def test_the_statement_has_no_epoch_block(self, document: dict[str, Any]) -> None:
        """Decision E2. The block is not emitted."""
        assert "epoch" not in document["statement"]

    def test_a_statement_carrying_epoch_is_refused_by_name(
        self, document: dict[str, Any]
    ) -> None:
        """Decision E2 as confirmed at the Phase B review: **forbidden**, not ignored.

        The reasoning is in BUNDLE-V3.md §3.2's E2 marker, and the reason it must be a
        refusal rather than an ignore is that the statement is the *signed* object — a
        tolerated member is attacker-chosen content inside a valid signature that no
        verifier checks. The refusal names ``epoch`` and cites E2 so an operator holding a
        pre-decision artifact reads a diagnosis rather than "unknown key".
        """
        doctored = _mutated(document)
        doctored["statement"]["epoch"] = {
            "cutover_event_hash": None,
            "legacy_event_count": 0,
            "v6_event_count": 4,
            "scheme_counts": {"ed25519": 4},
        }
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert exc.value.code is ErrorCode.BUNDLE_STATEMENT_INVALID
        assert "epoch" in str(exc.value)
        assert "E2" in str(exc.value)
        assert "FORBIDDEN" in str(exc.value)

    @pytest.mark.parametrize(
        ("member", "value", "expected_in_message"),
        [
            ("governance", {"mode": "solo"}, "collision 12"),
            ("selection", ["sha256:" + "0" * 64], "declared-selection"),
        ],
    )
    def test_other_retired_statement_members_are_refused_by_name(
        self,
        document: dict[str, Any],
        member: str,
        value: Any,
        expected_in_message: str,
    ) -> None:
        doctored = _mutated(document)
        doctored["statement"][member] = value
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert exc.value.code is ErrorCode.BUNDLE_STATEMENT_INVALID
        assert expected_in_message in str(exc.value)

    def test_an_unknown_statement_member_is_refused(
        self, document: dict[str, Any]
    ) -> None:
        doctored = _mutated(document)
        doctored["statement"]["extra_claim"] = "anything"
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert exc.value.code is ErrorCode.BUNDLE_STATEMENT_INVALID
        assert "extra_claim" in str(exc.value)

    def test_root_signatures_is_recognised_and_refused_rather_than_tolerated(
        self, document: dict[str, Any]
    ) -> None:
        """§3.2 amendment item 2 allows a direct root-threshold statement. Checking one
        needs the current root signer set and threshold, which is §4 trust-root resolution
        (Phase C). Accepting the shape and not checking the signatures would be a signed
        object with no verifier — refuse instead."""
        doctored = _mutated(document)
        del doctored["statement"]["signer"]
        doctored["statement"]["root_signatures"] = [
            {"signer_id": "root-1", "fingerprint": "ed25519:sha256:" + "0" * 64,
             "signature": "AA=="}
        ]
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert exc.value.code is ErrorCode.BUNDLE_STATEMENT_INVALID
        assert "root_signatures" in str(exc.value)

    def test_both_signer_and_root_signatures_is_a_rejection(
        self, document: dict[str, Any]
    ) -> None:
        doctored = _mutated(document)
        doctored["statement"]["root_signatures"] = []
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "exactly one of" in str(exc.value)

    def test_neither_signer_nor_root_signatures_is_a_rejection(
        self, document: dict[str, Any]
    ) -> None:
        doctored = _mutated(document)
        del doctored["statement"]["signer"]
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "exactly one of" in str(exc.value)

    def test_declared_selection_scope_is_rejected_not_attested(
        self, document: dict[str, Any]
    ) -> None:
        """§3.5 CUT marker: "A bundle declaring it is rejected, not attested"."""
        doctored = _mutated(document)
        doctored["statement"]["scope"]["kind"] = "declared-selection"
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "declared-selection` is CUT" in str(exc.value)

    def test_a_complete_store_scope_must_declare_a_null_preceding_hash(
        self, document: dict[str, Any]
    ) -> None:
        doctored = _mutated(document)
        doctored["statement"]["scope"]["preceding_event_hash"] = digest_text(b"\x01" * 32)
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "preceding_event_hash: null" in str(exc.value)

    def test_a_zero_event_scope_is_rejected(self, document: dict[str, Any]) -> None:
        doctored = _mutated(document)
        doctored["statement"]["scope"]["event_count"] = 0
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "positive integer" in str(exc.value)

    def test_trust_root_and_statement_must_name_the_same_trust_domain(
        self, document: dict[str, Any]
    ) -> None:
        doctored = _mutated(document)
        doctored["statement"]["trust_root"]["trust_domain_id"] = str(uuid.uuid4())
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "two domains" in str(exc.value)

    @pytest.mark.parametrize(
        ("mode", "threshold", "signer_count"),
        [
            ("co_signed", 1, 3),   # several fingerprints at threshold 1 is solo_effective
            ("solo", 1, 2),        # two signers is not solo
            ("solo_effective", 2, 2),  # threshold 2 is co_signed
        ],
    )
    def test_a_governance_mode_contradicting_its_own_numbers_is_invalid(
        self, document: dict[str, Any], mode: str, threshold: int, signer_count: int
    ) -> None:
        """``TRUST-DOMAIN.md`` §3.4 derives the mode from threshold/signer_count, and §10
        says ``solo_effective`` "exists precisely to stop an estate listing several
        fingerprints at threshold 1 and calling itself ``co_signed``". A signed
        restatement that contradicts its own numbers is invalid."""
        doctored = _mutated(document)
        doctored["statement"]["trust_root"]["root_governance"] = {
            "mode": mode, "threshold": threshold, "signer_count": signer_count
        }
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "contradicts its own numbers" in str(exc.value)

    def test_the_retired_governance_spelling_is_refused(
        self, document: dict[str, Any]
    ) -> None:
        doctored = _mutated(document)
        doctored["statement"]["trust_root"]["root_governance"]["mode"] = "single_signer_lab"
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "single_signer_lab` is retired" in str(exc.value)

    def test_a_null_signer_authority_event_hash_is_refused(
        self, document: dict[str, Any]
    ) -> None:
        """Owner ruling O3: the authority is a signed event. A null there is a
        self-authorising signer."""
        doctored = _mutated(document)
        doctored["statement"]["signer"]["authority_event_hash"] = None
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "self-authorising signer" in str(exc.value)

    def test_an_hmac_statement_signature_scheme_is_refused(
        self, document: dict[str, Any]
    ) -> None:
        """§3.4: "There is no HMAC bundle signature — an HMAC statement signature would be
        verifiable only by the operator, which is the S5 circularity wearing a different
        hat"."""
        doctored = _mutated(document)
        doctored["statement"]["signer"]["scheme_id"] = "hmac-sha256"
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "ed25519" in str(exc.value)


# ---------------------------------------------------------------------------
# §3.6 — event records
# ---------------------------------------------------------------------------


class TestEventRecords:
    def test_a_record_is_base64_envelope_and_signature_and_nothing_else(
        self, document: dict[str, Any]
    ) -> None:
        """Decision E1 (base64, final) and §3.6's "Nothing else"."""
        for record in document["sections"]["events"]:
            assert set(record) == {"canonical_envelope", "signature"}
            # base64, not hex: a hex string of even length would decode as base64 only by
            # accident, so decoding strictly is the discriminator.
            base64.b64decode(record["canonical_envelope"], validate=True)
            base64.b64decode(record["signature"], validate=True)

    def test_a_record_carrying_a_row_column_is_refused(
        self, document: dict[str, Any]
    ) -> None:
        """The twenty columns v2 exported are "a second copy of signed data for a consumer
        to read instead of the signed one"."""
        doctored = _mutated(document)
        doctored["sections"]["events"][0]["global_seq"] = 1
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "global_seq" in str(exc.value)

    def test_hex_event_records_are_refused(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        """Decision E1 chose base64 over hex, and the two are NOT distinguishable at the
        decode step: a hex string whose length is a multiple of four is also valid base64
        (its alphabet is a subset). So the discrimination happens where it should — at the
        v6 envelope parse, which is a strict canonical-bytes check — and the refusal is a
        finding rather than a parse error. Stated here rather than left as a surprise for
        whoever writes the second implementation."""
        doctored = _mutated(document)
        raw = base64.b64decode(doctored["sections"]["events"][0]["canonical_envelope"])
        assert len(raw.hex()) % 4 == 0, "the accidental-base64 case is the interesting one"
        doctored["sections"]["events"][0]["canonical_envelope"] = raw.hex()
        report = verify_bundle_v3_core(
            parse_bundle_v3_document(canonical_bundle_bytes(doctored)),
            statement_public_key=chain.signer_public_key,
        )
        assert report.chain_ordered is False
        assert report.core_ok is False
        assert any("canonical v6 envelope" in f for f in report.findings), report.findings


# ---------------------------------------------------------------------------
# §3.3 — chain-derived ordering, and owner ruling O4
# ---------------------------------------------------------------------------


class TestChainDerivedOrdering:
    def test_the_order_is_the_chain_order_not_the_input_order(self, chain: _Chain) -> None:
        members = [parse_event_member(env, sig) for env, sig in reversed(chain.records)]
        ordered = derive_chain_order(members, preceding_event_hash=None)
        assert [m.event_hash_text for m in ordered] == chain.hashes
        assert [m.scope_ordinal for m in ordered] == list(range(len(chain.hashes)))

    def test_a_broken_link_refuses_fail_closed(self, chain: _Chain) -> None:
        """Owner ruling O4: "Export over a broken chain is refused, fail-closed." No
        diagnostic flag and no partial artifact — §12 L2's ``--diagnostic`` shape was
        offered and rejected, because "a flag on the evidentiary command is eventually
        load-bearing in someone's CI"."""
        members = [parse_event_member(env, sig) for env, sig in chain.records]
        del members[1]
        with pytest.raises(RegistaError) as exc:
            derive_chain_order(members, preceding_event_hash=None)
        assert exc.value.code is ErrorCode.BUNDLE_CHAIN_UNORDERABLE
        assert "not reachable" in str(exc.value)

    def test_a_fork_refuses(self, chain: _Chain, keyset: Any) -> None:
        members = [parse_event_member(env, sig) for env, sig in chain.records]
        # A second, differently-identified event declaring the same predecessor.
        forked = copy.deepcopy(dict(members[1].envelope))
        forked["event_id"] = str(uuid.uuid4())
        signed = sign_v6_envelope(forked, keyset.key_for(BOOTSTRAP).seed)
        members.append(parse_event_member(signed.canonical_envelope, signed.signature))
        with pytest.raises(RegistaError) as exc:
            derive_chain_order(members, preceding_event_hash=None)
        assert exc.value.code is ErrorCode.BUNDLE_CHAIN_UNORDERABLE
        assert "forks" in str(exc.value)

    def test_a_duplicated_event_refuses(self, chain: _Chain) -> None:
        members = [parse_event_member(env, sig) for env, sig in chain.records]
        members.append(members[0])
        with pytest.raises(RegistaError) as exc:
            derive_chain_order(members, preceding_event_hash=None)
        assert "share the event hash" in str(exc.value)

    def test_no_entry_point_refuses(self, chain: _Chain) -> None:
        members = [parse_event_member(env, sig) for env, sig in chain.records[1:]]
        with pytest.raises(RegistaError) as exc:
            derive_chain_order(members, preceding_event_hash=None)
        assert "no event in the set links from the declared scope entry point" in str(
            exc.value
        )

    def test_an_empty_set_refuses(self) -> None:
        with pytest.raises(RegistaError) as exc:
            derive_chain_order([], preceding_event_hash=None)
        assert exc.value.code is ErrorCode.BUNDLE_CHAIN_UNORDERABLE

    def test_a_contiguous_range_is_entered_at_its_declared_anchor(
        self, chain: _Chain
    ) -> None:
        members = [parse_event_member(env, sig) for env, sig in chain.records[2:]]
        ordered = derive_chain_order(members, preceding_event_hash=chain.hashes[1])
        assert [m.event_hash_text for m in ordered] == chain.hashes[2:]

    def test_ordering_never_consults_global_seq(self, document: dict[str, Any]) -> None:
        """§3.3: ordering on ``global_seq`` "would let a row-write attacker permute the
        tree without touching a signed byte". A v3 event record has no such field to
        consult, which is the structural form of the rule."""
        for record in document["sections"]["events"]:
            assert "global_seq" not in record


# ---------------------------------------------------------------------------
# §3.4 — the statement signature
# ---------------------------------------------------------------------------


class TestStatementSignature:
    def test_the_signing_input_carries_the_mandatory_domain_prefix(
        self, document: dict[str, Any]
    ) -> None:
        """§3.4: the prefix "MUST NOT be omitted 'because JCS output is unambiguous'. It
        is what stops a v3 statement being replayed as some other JCS-signed regista
        object under the same key"."""
        from regista._jcs import canonicalize

        signing_input = statement_signing_input(document["statement"])
        assert signing_input.startswith(STATEMENT_SIGNING_DOMAIN)
        assert signing_input == STATEMENT_SIGNING_DOMAIN + canonicalize(
            document["statement"]
        )
        assert signing_input != canonicalize(document["statement"])

    @pytest.mark.parametrize(
        ("path", "replacement"),
        [
            (("scope", "event_count"), 99),
            (("scope", "first_event_hash"), digest_text(b"\xab" * 32)),
            (("scope", "last_event_hash"), digest_text(b"\xcd" * 32)),
            (("event_membership_root",), digest_text(b"\xef" * 32)),
            (("bundle_id",), "00000000-0000-4000-8000-000000000000"),
            (("created_at",), "2020-01-01T00:00:00.000000+00:00"),
            (("trust_root", "trust_domain_core_digest"), digest_text(b"\x11" * 32)),
            (("signer", "authority_kind"), "root"),
        ],
        ids=lambda v: str(v)[:40],
    )
    def test_editing_any_signed_field_breaks_the_signature(
        self,
        chain: _Chain,
        document: dict[str, Any],
        path: tuple[str, ...],
        replacement: Any,
    ) -> None:
        """The whole thesis of §1: "Once ``scope``, ``event_count`` and the membership root
        are inside a signature, a tamperer must forge that signature; there is nothing left
        for a plausibility heuristic to do."

        Note what this does NOT need: a rehash. Bundle v2's tamper tests all had to
        recompute the unkeyed bundle hash the way an adversary would, because the hash
        agreed with whatever was there. There is no such field to restore.
        """
        doctored = _mutated(document)
        target: Any = doctored["statement"]
        for key in path[:-1]:
            target = target[key]
        assert target[path[-1]] != replacement, "the edit must actually change something"
        target[path[-1]] = replacement
        report = verify_bundle_v3_core(
            parse_bundle_v3_document(canonical_bundle_bytes(doctored)),
            statement_public_key=chain.signer_public_key,
        )
        assert report.statement_signature_checked is True
        assert report.statement_signature_valid is False
        assert report.core_ok is False
        assert any(
            "BUNDLE_STATEMENT_SIGNATURE_INVALID" in f for f in report.findings
        ), report.findings

    def test_no_supplied_key_is_reported_as_unchecked_not_as_a_pass(
        self, document: dict[str, Any]
    ) -> None:
        """"We did not check" and "the check failed" are the exact conflation S1 exists to
        eliminate, so they are two fields. ``core_ok`` is False either way — a verifier
        with no trust material has authenticated nothing (§4.1)."""
        report = verify_bundle_v3_core(_reparse(document), statement_public_key=None)
        assert report.statement_signature_checked is False
        assert report.statement_signature_valid is False
        assert report.core_ok is False
        # ...but the structural checks all ran and all passed, and the report says so
        # rather than collapsing everything into one failed boolean.
        assert report.structural_checks_ok is True
        assert report.findings == ()

    def test_a_different_key_does_not_verify(
        self, keyset: Any, document: dict[str, Any]
    ) -> None:
        other = keyset.key_for(BOOTSTRAP).public_key
        report = verify_bundle_v3_core(_reparse(document), statement_public_key=other)
        assert report.statement_signature_valid is False


# ---------------------------------------------------------------------------
# Recomputation: membership, sections, scope
# ---------------------------------------------------------------------------


class TestRecomputation:
    def test_deleting_an_event_is_caught_by_the_root_and_the_count(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        """§3.3's attack table, first row: "leaf count ≠ ``scope.event_count``; root ≠
        signed root"."""
        doctored = _mutated(document)
        del doctored["sections"]["events"][-1]
        report = verify_bundle_v3_core(
            parse_bundle_v3_document(canonical_bundle_bytes(doctored)),
            statement_public_key=chain.signer_public_key,
        )
        assert report.membership_root_ok is False
        assert report.scope_consistent is False
        assert report.section_digests_ok is False
        assert report.core_ok is False

    def test_reordering_events_does_not_change_the_root(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        """The ordinal is chain-derived, so shuffling the *array* cannot permute the tree —
        it can only break the section digest. That is the point of §3.3's "never by
        ``global_seq`` and never by event UUID": the artifact's array order is not a signed
        fact, so nothing security-relevant may depend on it."""
        doctored = _mutated(document)
        doctored["sections"]["events"].reverse()
        report = verify_bundle_v3_core(
            parse_bundle_v3_document(canonical_bundle_bytes(doctored)),
            statement_public_key=chain.signer_public_key,
        )
        assert report.membership_root_ok is True
        assert report.section_digests_ok is False
        assert report.core_ok is False

    def test_editing_a_section_breaks_its_digest_and_names_which_one(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        doctored = _mutated(document)
        doctored["sections"]["bundled_key_evidence"] = []
        report = verify_bundle_v3_core(
            parse_bundle_v3_document(canonical_bundle_bytes(doctored)),
            statement_public_key=chain.signer_public_key,
        )
        assert report.section_digests_ok is False
        assert "bundled_key_evidence" in report.section_digest_mismatches

    def test_the_reference_sections_are_recomputed_not_read(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        """A section a verifier recomputes cannot be edited. Emptying
        ``project_key_acceptance`` — which the chain's acceptance event classifies into —
        is caught even though the tamperer also fixed the digest."""
        doctored = _mutated(document)
        doctored["sections"]["project_key_acceptance"] = []
        doctored["statement"]["section_digests"]["project_key_acceptance"] = digest_text(
            section_digest("project_key_acceptance", [])
        )
        report = verify_bundle_v3_core(
            parse_bundle_v3_document(canonical_bundle_bytes(doctored)),
            statement_public_key=chain.signer_public_key,
        )
        assert report.reference_sections_ok is False
        assert any("reference_section_mismatch" in f for f in report.findings)

    def test_the_derived_reference_sections_classify_the_chain(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        sections = document["sections"]
        assert sections["checkpoints"] == [chain.genesis_hash]
        assert sections["project_key_acceptance"] == [chain.acceptance_hash]
        assert sections["workflows"] == []
        assert sections["review_verdicts"] == []
        assert sections["key_lifecycle"] == []
        for name in REFERENCE_SECTIONS:
            assert sections[name] == sorted(sections[name]), name

    def test_the_scope_names_the_chain_ends(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        scope = document["statement"]["scope"]
        assert scope["kind"] == "complete-store"
        assert scope["event_count"] == len(chain.hashes)
        assert scope["first_event_hash"] == chain.hashes[0]
        assert scope["last_event_hash"] == chain.hashes[-1]
        assert scope["preceding_event_hash"] is None

    def test_an_event_from_another_project_is_caught(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        doctored = _mutated(document)
        doctored["statement"]["project_instance_id"] = str(uuid.uuid4())
        report = verify_bundle_v3_core(
            parse_bundle_v3_document(canonical_bundle_bytes(doctored)),
            statement_public_key=chain.signer_public_key,
        )
        assert report.scope_consistent is False
        assert any("event_project_instance_mismatch" in f for f in report.findings)


# ---------------------------------------------------------------------------
# Owner ruling O3 — may_sign_bundles
# ---------------------------------------------------------------------------


class TestSignerAuthority:
    def test_a_key_without_the_scope_cannot_sign(self, chain: _Chain) -> None:
        """Owner ruling O3: "A writer key without the scope cannot sign a bundle
        statement." The refusal is at build time and by name."""
        with pytest.raises(RegistaError) as exc:
            chain.build(signer=chain.signer(may_sign_bundles=False))
        assert exc.value.code is ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED
        assert "may_sign_bundles" in str(exc.value)

    def test_the_verifier_rederives_the_scope_from_the_signed_acceptance(
        self, keyset: Any
    ) -> None:
        """The other half of O3, and the half that matters to an auditor: the scope is
        re-derived from the acceptance event inside the bundle, not taken from the
        statement's word. A builder that lied about ``may_sign_bundles`` is caught."""
        unscoped = _Chain(keyset, may_sign_bundles=False)
        document = unscoped.build()  # the builder's flag says True; the chain says False
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=unscoped.signer_public_key
        )
        assert report.signer_authority_checked is True
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False
        assert any("signer_may_not_sign_bundles" in f for f in report.findings)

    def test_an_authority_event_outside_a_complete_store_bundle_is_invalid(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        """``RECONCILIATION.md`` Resolution 4: "Missing closure in ``complete-store`` is
        invalid." The signing authority is the one dependency Phase B closes; the rest of
        the closure walk is Phase D's."""
        doctored = _mutated(document)
        doctored["statement"]["signer"]["authority_event_hash"] = digest_text(
            b"\x5c" * 32
        )
        report = verify_bundle_v3_core(
            parse_bundle_v3_document(canonical_bundle_bytes(doctored)),
            statement_public_key=chain.signer_public_key,
        )
        assert report.signer_authority_checked is False
        assert any(
            "signer_authority_outside_complete_store" in f for f in report.findings
        )


# ---------------------------------------------------------------------------
# The builder
# ---------------------------------------------------------------------------


class TestBuilder:
    def test_the_builder_round_trips_through_its_own_verifier(
        self, chain: _Chain
    ) -> None:
        """"An exporter that writes a version its own verifier rejects is the WI-240
        defect class." The builder parses what it produced before returning it."""
        document = chain.build()
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.core_ok, report.findings

    def test_a_complete_store_scope_may_not_be_given_a_preceding_hash(
        self, chain: _Chain
    ) -> None:
        with pytest.raises(RegistaError) as exc:
            chain.build(preceding_event_hash=chain.hashes[0])
        assert exc.value.code is ErrorCode.BUNDLE_STATEMENT_INVALID

    def test_a_contiguous_range_bundle_verifies(self, chain: _Chain) -> None:
        document = chain.build(
            event_records=chain.records[2:],
            scope_kind="contiguous-range",
            preceding_event_hash=chain.hashes[1],
        )
        parsed = _reparse(document)
        report = verify_bundle_v3_core(
            parsed, statement_public_key=chain.signer_public_key
        )
        # The signing authority is the acceptance event, which this window excludes. That
        # is `not_checkable`, not a pass and not a failure — and for a bounded range it is
        # the honest answer rather than the complete-store invalidity.
        assert report.signer_authority_checked is False
        assert report.membership_root_ok is True
        assert report.section_digests_ok is True
        assert report.scope_consistent is True
        assert report.statement_signature_valid is True
        assert parsed.statement["scope"]["preceding_event_hash"] == chain.hashes[1]

    def test_an_unknown_scope_kind_is_refused(self, chain: _Chain) -> None:
        with pytest.raises(RegistaError) as exc:
            chain.build(scope_kind="declared-selection")
        assert exc.value.code is ErrorCode.BUNDLE_STATEMENT_INVALID

    def test_the_bundled_key_evidence_fingerprint_must_match_its_material(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        """§4.3: a self-consistency check on *evidence*, explicitly not a trust decision.
        Authority still comes only from the auditor's pin."""
        doctored = _mutated(document)
        doctored["sections"]["bundled_key_evidence"] = [
            {
                "key_id": "pk_x",
                "principal_id": WORKER,
                "scheme_id": "ed25519",
                "public_key": base64.b64encode(b"\x00" * 32).decode("ascii"),
                "fingerprint": "ed25519:sha256:" + "0" * 64,
            }
        ]
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "does not match sha256 of the public_key" in str(exc.value)

    def test_external_evidence_must_be_classified(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        """§4.6 / D9: "Left unstated, someone will make a bundled copy of a checkpoint
        count as external evidence, which is BC-016 again"."""
        doctored = _mutated(document)
        doctored["sections"]["external_evidence"] = [
            {"class": "definitely_trustworthy", "source": "operator",
             "obtained_at": "2026-08-23T00:00:00+00:00", "content": {}}
        ]
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(doctored))
        assert "external_evidence[0].class must be one of" in str(exc.value)

    def test_classified_external_evidence_is_carried_and_digested(
        self, chain: _Chain
    ) -> None:
        entry = {
            "class": "independently_pinned_copy",
            "source": "publication-repo@abc123",
            "obtained_at": "2026-08-23T00:00:00+00:00",
            "content": {"checkpoint_digest": digest_text(b"\x09" * 32)},
        }
        document = chain.build(external_evidence=[entry])
        parsed = _reparse(document)
        assert parsed.sections["external_evidence"] == [entry]
        report = verify_bundle_v3_core(
            parsed, statement_public_key=chain.signer_public_key
        )
        assert report.core_ok, report.findings
