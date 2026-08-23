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
from collections.abc import Mapping, Sequence
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
    recompute_reference_sections,
    section_digest,
    section_digest_text,
    sign_statement,
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
OPERATOR = "human:operator"


def _load_vector(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# An offline v6 chain: genesis, an acceptance, two ordinary events.
# ---------------------------------------------------------------------------


class _Chain:
    """A signed v6 chain built in memory, plus everything a statement needs."""

    def __init__(
        self,
        keyset: Any,
        *,
        may_sign_bundles: bool = True,
        with_genesis: bool = True,
        head_transition: str | None = None,
        with_acceptance: bool = True,
        ordinary_events: int = 2,
    ) -> None:
        self.keyset = keyset
        self.records: list[tuple[bytes, bytes]] = []
        self.hashes: list[str] = []
        self._entity_seq: dict[str, int] = {}
        self._entity_head: dict[str, str | None] = {}
        self.work_item_id = str(uuid.uuid4())

        # The genesis envelope is built either way, because it is where the project and
        # trust-domain identifiers and the two trust-root digests come from. `with_genesis`
        # only decides whether it is APPENDED — a chain headed by a non-genesis event is
        # exactly what F3 (complete-store head identity) has to be tested against.
        genesis = genesis_envelope(keyset, principal_id=BOOTSTRAP)
        self.project_instance_id = str(genesis["project_instance_id"])
        self.trust_domain_id = str(genesis["trust_domain_id"])
        self.core_digest = str(genesis["payload"]["trust_domain_core_digest"])
        self.document_digest = str(genesis["payload"]["genesis_document_digest"])
        self.genesis_hash: str | None = None
        if with_genesis:
            self._append(genesis, BOOTSTRAP)
            self.genesis_hash = self.hashes[0]
        elif head_transition is not None:
            # A chain headed by something other than a project genesis. Only
            # `trust_domain_established` and `project_initialized` may carry a null
            # `chain.previous_project_event_hash` at all (the v6 envelope validator enforces
            # that), so this is the ONE non-genesis head a real signer can produce — which
            # is exactly why F3's check has to name the transition rather than the link.
            head = self._base(BOOTSTRAP)
            self._entity(head, "trust_domain", self.trust_domain_id)
            head["transition"] = head_transition
            head["payload"] = {"note": "trust-log genesis, not this project's"}
            head["signing"]["key_binding_event_hash"] = None
            self._append(head, BOOTSTRAP)

        self.acceptance_hash: str | None = None
        if with_acceptance:
            self.acceptance_hash = self.append(
                self.acceptance_envelope(WORKER, may_sign_bundles=may_sign_bundles),
                BOOTSTRAP,
            )

        for transition in ("created", "updated")[:ordinary_events]:
            self.append(self.work_item_envelope(transition=transition), WORKER)

    # -- construction -----------------------------------------------------

    def append(self, envelope: dict[str, Any], principal_id: str) -> str:
        """Sign and append *envelope*, linking it to the current head. Returns its hash."""

        self._append(envelope, principal_id)
        return self.hashes[-1]

    def _append(self, envelope: dict[str, Any], principal_id: str) -> None:
        envelope = copy.deepcopy(envelope)
        envelope["chain"]["previous_project_event_hash"] = (
            self.hashes[-1] if self.hashes else None
        )
        signed = sign_v6_envelope(envelope, self.keyset.key_for(principal_id).seed)
        self.records.append((signed.canonical_envelope, signed.signature))
        self.hashes.append("sha256:" + signed.event_hash.hex())
        entity_id = str(envelope["entity"]["id"])
        self._entity_head[entity_id] = self.hashes[-1]

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

    def _entity(self, envelope: dict[str, Any], kind: str, entity_id: str) -> None:
        """Fill entity, entity_seq and the per-entity chain link for *entity_id*."""

        seq = self._entity_seq.get(entity_id, 0) + 1
        self._entity_seq[entity_id] = seq
        envelope["entity"] = {"kind": kind, "id": entity_id}
        envelope["entity_seq"] = seq
        envelope["chain"]["previous_entity_event_hash"] = self._entity_head.get(entity_id)

    def acceptance_payload(
        self,
        principal_id: str,
        *,
        may_sign_bundles: bool,
        accepted_by: str = BOOTSTRAP,
        accepted_by_anchor: str | None = None,
        may_accept_keys: bool | None = None,
    ) -> dict[str, Any]:
        """A ``regista.key-acceptance/v1`` payload for *principal_id*'s key."""

        key = self.keyset.key_for(principal_id)
        scopes: dict[str, Any] = {
            "entity_kinds": ["work_item", "principal", "workflow", "project"],
            "transitions": None,
            "may_sign_checkpoints": False,
            "may_sign_bundles": may_sign_bundles,
        }
        if may_accept_keys is not None:
            scopes["may_accept_keys"] = may_accept_keys
        return {
            "type": "regista.key-acceptance",
            "version": 1,
            "trust_domain_id": self.trust_domain_id,
            "project_instance_id": self.project_instance_id,
            "principal_id": principal_id,
            "key_id": key.key_id,
            "fingerprint": key.fingerprint,
            "public_key": key.public_key_b64,
            "trust_event_hash": digest_text(hashlib.sha256(b"enrolment").digest()),
            "trust_log_checkpoint": {
                "checkpoint_seq": 1,
                "head_event_hash": digest_text(hashlib.sha256(b"head").digest()),
                "document_digest": digest_text(hashlib.sha256(b"doc").digest()),
            },
            "scopes": scopes,
            "accepted_by": {
                "principal_id": accepted_by,
                "key_id": self.keyset.key_for(accepted_by).key_id,
                "key_binding_event_hash": (
                    accepted_by_anchor
                    if accepted_by_anchor is not None
                    else (self.genesis_hash or digest_text(b"\x00" * 32))
                ),
            },
        }

    def acceptance_envelope(
        self,
        principal_id: str,
        *,
        may_sign_bundles: bool,
        signed_by: str = BOOTSTRAP,
        transition: str = "principal_key_accepted",
        entity_label: str = "",
        **payload_kwargs: Any,
    ) -> dict[str, Any]:
        envelope = self._base(signed_by)
        self._entity(
            envelope,
            "principal",
            str(uuid.uuid5(uuid.NAMESPACE_OID, f"regista.principal:{principal_id}{entity_label}")),
        )
        envelope["transition"] = transition
        envelope["payload"] = self.acceptance_payload(
            principal_id, may_sign_bundles=may_sign_bundles, **payload_kwargs
        )
        return envelope

    def revocation_envelope(
        self,
        *,
        principal_id: str,
        acceptance_event_hash: str,
        revoked_by: str = BOOTSTRAP,
    ) -> dict[str, Any]:
        envelope = self._base(revoked_by)
        self._entity(
            envelope,
            "principal",
            str(uuid.uuid5(uuid.NAMESPACE_OID, "regista.principal:" + principal_id)),
        )
        envelope["transition"] = "principal_key_acceptance_revoked"
        envelope["payload"] = {
            "type": "regista.key-acceptance-revocation",
            "version": 1,
            "trust_domain_id": self.trust_domain_id,
            "project_instance_id": self.project_instance_id,
            "principal_id": principal_id,
            "key_id": self.keyset.key_for(principal_id).key_id,
            "acceptance_event_hash": acceptance_event_hash,
            "reason": "superseded",
            "revoked_by": {
                "principal_id": revoked_by,
                "key_id": self.keyset.key_for(revoked_by).key_id,
                "key_binding_event_hash": self.genesis_hash or digest_text(b"\x00" * 32),
            },
        }
        return envelope

    def work_item_envelope(
        self,
        *,
        transition: str = "created",
        signed_by: str = WORKER,
        payload: dict[str, Any] | None = None,
        entity_id: str | None = None,
    ) -> dict[str, Any]:
        envelope = self._base(signed_by)
        self._entity(envelope, "work_item", entity_id or self.work_item_id)
        envelope["transition"] = transition
        envelope["payload"] = (
            payload if payload is not None else {"note": f"event {transition}"}
        )
        if self.acceptance_hash is not None:
            envelope["signing"]["key_binding_event_hash"] = self.acceptance_hash
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


def _forge_document(
    chain: _Chain,
    *,
    records: Sequence[tuple[bytes, bytes]] | None = None,
    scope_kind: str = "complete-store",
    preceding_event_hash: str | None = None,
    signer_principal: str = WORKER,
    signer_key_principal: str | None = None,
    signing_seed_principal: str | None = None,
    authority_event_hash: str | None = None,
    statement_overrides: Mapping[str, Any] | None = None,
    signature_overrides: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble a v3 document DIRECTLY, bypassing ``build_bundle_v3_document``.

    A conforming builder refuses to emit most of what these tests need — that is the
    point of the builder — but a verifier is judged on artifacts no conforming builder
    would produce. So the statement is assembled here from the same public primitives
    (:func:`membership_root`, :func:`section_digest_text`,
    :func:`recompute_reference_sections`, :func:`sign_statement`), which means this helper
    cannot drift from the format even though it can lie about anything in it.

    ``signer_key_principal`` sets the ``signer.key_id``/``signer.fingerprint`` identity;
    ``signing_seed_principal`` sets whose private key actually signs. Making those two
    independently settable is exactly what F2 needs.
    """

    from regista._bundle_v3 import derive_chain_order, parse_event_member

    event_records = list(records if records is not None else chain.records)
    ordered = derive_chain_order(
        [parse_event_member(env, sig) for env, sig in event_records],
        preceding_event_hash=preceding_event_hash,
    )

    sections: dict[str, list[Any]] = {name: [] for name in SECTION_NAMES}
    sections["events"] = [m.as_event_record() for m in ordered]
    sections.update(recompute_reference_sections(ordered))
    sections["bundled_key_evidence"] = chain.key_evidence()

    identity = chain.keyset.key_for(signer_key_principal or signer_principal)
    seed = chain.keyset.key_for(signing_seed_principal or signer_principal).seed

    statement: dict[str, Any] = {
        "type": "regista.audit-bundle",
        "version": 3,
        "bundle_id": str(uuid.uuid4()),
        "project_instance_id": chain.project_instance_id,
        "trust_domain_id": chain.trust_domain_id,
        "created_at": "2026-08-23T12:00:00+00:00",
        "scope": {
            "kind": scope_kind,
            "event_count": len(ordered),
            "first_event_hash": ordered[0].event_hash_text,
            "last_event_hash": ordered[-1].event_hash_text,
            "preceding_event_hash": preceding_event_hash,
        },
        "event_membership_root": digest_text(
            membership_root([m.event_hash for m in ordered])
        ),
        "section_digests": {
            name: section_digest_text(name, sections[name]) for name in SECTION_NAMES
        },
        "trust_root": chain.trust_root().as_statement_member(),
        "signer": {
            "principal_id": signer_principal,
            "key_id": identity.key_id,
            "scheme_id": "ed25519",
            "fingerprint": identity.fingerprint,
            "authority_kind": "scoped",
            "authority_event_hash": (
                authority_event_hash
                if authority_event_hash is not None
                else (chain.acceptance_hash or digest_text(b"\x11" * 32))
            ),
        },
        "exporter": {
            "regista_version": "0.7.2",
            "statement_schema": "regista.audit-bundle/3",
        },
    }
    if statement_overrides:
        statement.update(copy.deepcopy(dict(statement_overrides)))

    signature = sign_statement(statement, private_key=seed, key_id=identity.key_id)
    if signature_overrides:
        signature.update(dict(signature_overrides))
    return {"statement": statement, "statement_signature": signature, "sections": sections}


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
        assert report.notes == (), (
            "a complete-store bundle contains its own signing authority, so there is "
            "nothing to report as outside scope"
        )
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
    def test_a_key_without_the_scope_cannot_sign(self, keyset: Any) -> None:
        """Owner ruling O3: "A writer key without the scope cannot sign a bundle
        statement." The refusal is at build time and by name.

        Note what the builder is handed: a chain whose acceptance for this key sets
        ``may_sign_bundles: false``, and a signer that says nothing about the scope at all.
        There is no flag to lie with any more — the events decide.
        """
        denied = _Chain(keyset, may_sign_bundles=False)
        with pytest.raises(RegistaError) as exc:
            denied.build()
        assert exc.value.code is ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED
        assert "may_sign_bundles" in str(exc.value)

    def test_the_verifier_rederives_the_scope_from_the_signed_acceptance(
        self, keyset: Any
    ) -> None:
        """The other half of O3, and the half that matters to an auditor: the scope is
        re-derived from the acceptance event inside the bundle, not taken from the
        statement's word.

        The document is forged rather than built, because a conforming builder now refuses
        to produce it — and an artifact no conforming builder emits is precisely what a
        verifier must be judged on.
        """
        unscoped = _Chain(keyset, may_sign_bundles=False)
        document = _forge_document(unscoped)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=unscoped.signer_public_key
        )
        assert report.signer_authority_checked is True
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False
        assert any("signer_may_not_sign_bundles" in f for f in report.findings)

    def test_an_authority_event_absent_from_a_complete_store_bundle_is_invalid(
        self, keyset: Any
    ) -> None:
        """``RECONCILIATION.md`` Resolution 4: "Missing closure in ``complete-store`` is
        invalid." The signing authority is the one dependency Phase B closes; the rest of
        the closure walk is Phase D's."""
        no_anchor = _Chain(keyset, with_acceptance=False)
        document = _forge_document(no_anchor)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=no_anchor.signer_public_key
        )
        assert report.signer_authority_checked is False
        assert report.core_ok is False
        assert any(
            "signer_authority_absent_from_complete_store" in f for f in report.findings
        ), report.findings

    def test_naming_an_anchor_that_is_not_the_one_in_force_is_invalid(
        self, chain: _Chain, document: dict[str, Any]
    ) -> None:
        """Naming a hash that is not the current anchor is its own finding, distinct from
        naming nothing: the bundle DOES carry an anchor, and the statement points elsewhere.
        Keeping the two apart is what makes the superseded-acceptance case (S3) legible."""
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
            "signer_authority_is_not_the_current_anchor" in f for f in report.findings
        ), report.findings


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
        """A windowed chunk that excludes the signer's own acceptance still builds, because
        the builder resolves authority over ``authority_records`` — the whole chain the
        exporter observes — and not over the window it is emitting.

        Resolving over the window alone would make every chunk that does not happen to
        contain the acceptance unexportable, which would break §9's chunking workflow
        outright.
        """
        document = chain.build(
            event_records=chain.records[2:],
            authority_records=chain.records,
            scope_kind="contiguous-range",
            preceding_event_hash=chain.hashes[1],
        )
        parsed = _reparse(document)
        report = verify_bundle_v3_core(
            parsed, statement_public_key=chain.signer_public_key
        )
        # The signing authority is the acceptance event, which this window excludes. That
        # is `not_checkable`, not a pass and not a failure — and for a bounded range it is
        # the honest answer rather than the complete-store invalidity. RECONCILIATION.md
        # Resolution 4 requires it be NAMED rather than treated as satisfaction, so it
        # lands in `notes`: not a finding (the artifact is not defective) and not silence.
        assert report.signer_authority_checked is False
        assert report.signer_may_sign_bundles is False
        assert any("signer_authority_outside_scope" in n for n in report.notes), report.notes
        assert not any("signer_authority" in f for f in report.findings)
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


# ---------------------------------------------------------------------------
# F1 — owner ruling O3 cannot be satisfied by an acceptance-SHAPED payload
# ---------------------------------------------------------------------------


class TestSignerAuthorityLaundering:
    """The four laundering routes a probe-executing reviewer demonstrated end to end.

    The original Phase B gate asked one question — "is there a payload here that looks
    like an acceptance and names this key?" — and every scenario below answers yes while
    the store's own resolver answers no. That asymmetry is the defect: the store refused to
    export these bundles, and the offline verifier accepted them, so the artifact was
    stronger than the verdict on it.

    The fix mirrors ``_v6_writer``'s three rules, and each test names the one it depends
    on: the anchor-transition restriction (``_ANCHOR_TRANSITIONS``), newest-live selection,
    and revocation-kills-the-whole-resolution.
    """

    def test_a_grant_embedded_in_an_ordinary_event_is_not_an_anchor(
        self, keyset: Any
    ) -> None:
        """S1a. An ordinary work-item event, signed by the worker itself, whose payload
        carries a ``bootstrap_key_acceptance`` granting the worker ``may_sign_bundles``.

        Nothing about that payload is authority: the event's transition is not one the
        project's key-binding machinery reads anchors from, and the "grant" is
        self-authored. ``_v6_writer._ANCHOR_TRANSITIONS`` is a closed set of three for
        exactly this reason.
        """
        chain = _Chain(keyset, may_sign_bundles=False)
        forged = chain.append(
            chain.work_item_envelope(
                transition="updated",
                signed_by=WORKER,
                payload={
                    "note": "nothing to see here",
                    "bootstrap_key_acceptance": chain.acceptance_payload(
                        WORKER, may_sign_bundles=True
                    ),
                },
            ),
            WORKER,
        )
        document = _forge_document(chain, authority_event_hash=forged)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False
        assert any("signer_authority" in f for f in report.findings), report.findings

    def test_an_acceptance_typed_payload_on_an_ordinary_transition_is_not_an_anchor(
        self, keyset: Any
    ) -> None:
        """S1b. The same forgery one level more brazen: a full
        ``regista.key-acceptance/v1`` payload on transition ``updated``.

        The payload validates against §5.8's schema. It is still not an anchor, because a
        transition is a signed field and ``principal_key_accepted`` is what the project
        chain uses to mean "a key was accepted". Reading the payload type instead of the
        transition is what let this through.
        """
        chain = _Chain(keyset, may_sign_bundles=False)
        forged = chain.append(
            chain.work_item_envelope(
                transition="updated",
                signed_by=WORKER,
                payload=chain.acceptance_payload(WORKER, may_sign_bundles=True),
            ),
            WORKER,
        )
        document = _forge_document(chain, authority_event_hash=forged)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False

    def test_a_self_authored_acceptance_is_not_an_anchor(self, keyset: Any) -> None:
        """The worker accepts its own key, on the right transition, with a valid-looking
        payload.

        ``RECONCILIATION.md`` Resolution 1: "a key may not accept itself: ordinary
        acceptance runs with no exceptions and no self-authorisation anywhere". The store
        refuses this at write time (``self_authorisation``); an offline verifier that did
        not re-check it would accept the one document the writer exists to prevent.
        """
        chain = _Chain(keyset, may_sign_bundles=False)
        forged = chain.append(
            chain.acceptance_envelope(
                WORKER,
                may_sign_bundles=True,
                signed_by=WORKER,
                accepted_by=WORKER,
                entity_label="-self",
            ),
            WORKER,
        )
        document = _forge_document(chain, authority_event_hash=forged)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False

    def test_an_acceptance_whose_accepted_by_is_not_the_signer_is_not_an_anchor(
        self, keyset: Any
    ) -> None:
        """``_v6_writer._require_authority_matches_signer``, offline.

        The payload claims the bootstrap principal exercised the authority; the envelope is
        signed by the worker. "If those may differ, the payload asserts an authority that
        never touched the event — a free-text claim wearing a structured field's clothes."
        """
        chain = _Chain(keyset, may_sign_bundles=False)
        forged = chain.append(
            chain.acceptance_envelope(
                WORKER,
                may_sign_bundles=True,
                signed_by=WORKER,          # the worker signs...
                accepted_by=BOOTSTRAP,     # ...but claims bootstrap authorised it
                entity_label="-mismatch",
            ),
            WORKER,
        )
        document = _forge_document(chain, authority_event_hash=forged)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False

    def test_an_acceptance_anchored_on_another_keys_grant_is_not_an_anchor(
        self, keyset: Any
    ) -> None:
        """A hole found while reviewing the fix for this finding, one indirection further
        out than the ``accepted_by`` binding.

        ``human:operator`` signs an acceptance for the worker and anchors it on the genesis
        bootstrap acceptance — which does hold ``may_accept_keys``, but grants it to the
        BOOTSTRAP principal, not to the operator. Checking only "does the granting anchor
        hold may_accept_keys?" lets any principal inherit an authority it was never given by
        pointing at someone else's grant. An anchor authorises the key it names and no other.
        """
        chain = _Chain(keyset, may_sign_bundles=False)
        forged = chain.append(
            chain.acceptance_envelope(
                WORKER,
                may_sign_bundles=True,
                signed_by="human:operator",
                accepted_by="human:operator",
                accepted_by_anchor=chain.genesis_hash,
                entity_label="-borrowed",
            ),
            "human:operator",
        )
        document = _forge_document(chain, authority_event_hash=forged)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False

    def test_a_revocation_whose_payload_cannot_be_read_refuses_rather_than_skipping(
        self, keyset: Any
    ) -> None:
        """The other hole found while reviewing the fix, and the more dangerous one.

        Gating the revocation check on ``payload.type`` meant an attacker could neutralise a
        revocation by editing that one field: the event still carries transition
        ``principal_key_acceptance_revoked``, the check skipped it, and the revoked grant
        survived. The store raises in the same situation — "a revocation that cannot be
        parsed cannot be skipped, because skipping it would silently re-admit the acceptance
        it revoked" — so an unreadable revocation refuses the whole resolution.
        """
        chain = _Chain(keyset, may_sign_bundles=True)
        assert chain.acceptance_hash is not None
        envelope = chain.revocation_envelope(
            principal_id=WORKER, acceptance_event_hash=chain.acceptance_hash
        )
        envelope["payload"]["type"] = "regista.something-else"
        chain.append(envelope, BOOTSTRAP)
        document = _forge_document(chain, authority_event_hash=chain.acceptance_hash)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False
        assert any("revocation_unreadable" in f for f in report.findings), report.findings

    def test_a_revocation_for_a_different_key_does_not_refuse(self, keyset: Any) -> None:
        """The necessary counterweight to the two rules above: a revocation naming ANOTHER
        principal's key must not disturb this signer's authority. A fix that refused on any
        revocation anywhere would make a store unable to export after any key rotation."""
        chain = _Chain(keyset, may_sign_bundles=True)
        chain.append(
            chain.revocation_envelope(
                principal_id="human:operator",
                acceptance_event_hash=digest_text(b"\x7e" * 32),
            ),
            BOOTSTRAP,
        )
        document = _forge_document(chain, authority_event_hash=chain.acceptance_hash)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is True
        assert report.core_ok is True, report.findings

    def test_a_revocation_inside_the_same_bundle_kills_the_authority(
        self, keyset: Any
    ) -> None:
        """S2, and the sharpest of the four: the revocation is IN the artifact.

        ``resolve_key_binding_anchor`` refuses on any revocation for the principal/key,
        and says why: "Falling back turns a revocation into a *privilege escalation*: the
        operator's most recent word about this key was 'no longer usable'." A bundle that
        carries both the grant and its revocation and reports the grant is reporting the
        operator's superseded word as current.
        """
        chain = _Chain(keyset, may_sign_bundles=True)
        assert chain.acceptance_hash is not None
        chain.append(
            chain.revocation_envelope(
                principal_id=WORKER, acceptance_event_hash=chain.acceptance_hash
            ),
            BOOTSTRAP,
        )
        document = _forge_document(chain, authority_event_hash=chain.acceptance_hash)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False
        assert any("revoked" in f for f in report.findings), report.findings

    def test_a_superseded_acceptance_does_not_beat_the_current_one(
        self, keyset: Any
    ) -> None:
        """S3. Acceptance A grants ``may_sign_bundles``; a later acceptance B for the same
        key denies it; the statement names A.

        ``resolve_key_binding_anchor``'s rule is "the most recent live acceptance — the one
        carrying current scopes", and currentness is predecessor-link traversal. Honouring
        the older grant reads the operator's superseded word as current, which is the same
        defect as the revocation case in a quieter form.
        """
        chain = _Chain(keyset, may_sign_bundles=True)
        superseded = chain.acceptance_hash
        assert superseded is not None
        chain.append(
            chain.acceptance_envelope(
                WORKER, may_sign_bundles=False, entity_label="-current"
            ),
            BOOTSTRAP,
        )
        document = _forge_document(chain, authority_event_hash=superseded)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False

    def test_the_current_acceptance_is_the_one_that_decides(self, keyset: Any) -> None:
        """The positive direction, so the fix is not merely "refuse everything".

        Acceptance A denies the scope, a later acceptance B grants it, and the statement
        names B. Newest-live selection means this verifies — and a fix that broke it would
        have made the O3 gate unusable rather than sound.
        """
        chain = _Chain(keyset, may_sign_bundles=False)
        current = chain.append(
            chain.acceptance_envelope(
                WORKER, may_sign_bundles=True, entity_label="-current"
            ),
            BOOTSTRAP,
        )
        document = _forge_document(chain, authority_event_hash=current)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_authority_checked is True
        assert report.signer_may_sign_bundles is True
        assert report.core_ok is True, report.findings

    def test_the_builder_derives_authority_instead_of_trusting_its_caller(
        self, keyset: Any
    ) -> None:
        """The build side of F1: ``BundleV3Signer`` no longer carries a
        ``may_sign_bundles`` flag for the builder to believe.

        A caller-asserted boolean is not evidence — it is the same "free-text claim wearing
        a structured field's clothes" the writer refuses in ``accepted_by``. The builder now
        derives the scope from the event set it is about to sign over, so the only way to
        get a signed statement is for the events to support it.
        """
        import dataclasses

        assert "may_sign_bundles" not in {
            f.name for f in dataclasses.fields(BundleV3Signer)
        }, "a caller-asserted authority flag is exactly what F1 removed"
        assert "authority_event_hash" not in {
            f.name for f in dataclasses.fields(BundleV3Signer)
        }, "the authority event is derived from the chain, not named by the caller"

        denied = _Chain(keyset, may_sign_bundles=False)
        with pytest.raises(RegistaError) as exc:
            denied.build()
        assert exc.value.code is ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED
        assert "may_sign_bundles" in str(exc.value)

    def test_the_builder_refuses_when_the_authority_is_revoked_in_scope(
        self, keyset: Any
    ) -> None:
        chain = _Chain(keyset, may_sign_bundles=True)
        assert chain.acceptance_hash is not None
        chain.append(
            chain.revocation_envelope(
                principal_id=WORKER, acceptance_event_hash=chain.acceptance_hash
            ),
            BOOTSTRAP,
        )
        with pytest.raises(RegistaError) as exc:
            chain.build()
        assert exc.value.code is ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED


# ---------------------------------------------------------------------------
# F2 — the verifying key must be the key the statement names
# ---------------------------------------------------------------------------


class TestSignerAuthorityGrantorLaundering:
    """Round-2 blocker FR2-1 Face A: the GRANTOR of a standalone acceptance is validated.

    Round 1 validated the candidate acceptance but read the grantor's ``may_accept_keys``
    straight off its payload, so a forged grantor laundered authority one indirection out.
    The writer is the oracle that makes this decisive: ``_v6_writer._ACCEPTANCE_SCOPE_KEYS``
    does not contain ``may_accept_keys``, and ``validate_key_acceptance_payload`` returns it
    hardcoded ``False`` — so a standalone acceptance carrying the field is a *refusal*, and
    the only thing that can legitimately grant it is the project genesis. These tests build a
    two-hop authority chain (worker accepted by operator, operator's grant forged) and assert
    the forgery is caught.
    """

    def _operator_grants_worker(
        self,
        keyset: Any,
        *,
        grantor_envelope_factory: Any,
    ) -> tuple[_Chain, str]:
        """genesis → [grantor for operator] → worker-acceptance(accepted_by operator).

        ``grantor_envelope_factory(chain)`` returns the (envelope, signer_principal) for the
        event the worker's acceptance will anchor on. Returns the chain and the forged
        authority hash (the worker acceptance)."""
        chain = _Chain(keyset, with_acceptance=False, ordinary_events=0)
        grantor_env, grantor_signer = grantor_envelope_factory(chain)
        grantor_hash = chain.append(grantor_env, grantor_signer)
        worker_hash = chain.append(
            chain.acceptance_envelope(
                WORKER,
                may_sign_bundles=True,
                signed_by=OPERATOR,
                accepted_by=OPERATOR,
                accepted_by_anchor=grantor_hash,
                entity_label="-by-operator",
            ),
            OPERATOR,
        )
        return chain, worker_hash

    def test_a_standalone_grantor_carrying_may_accept_keys_is_refused(
        self, keyset: Any
    ) -> None:
        """Face A, decisive form. The grantor is a standalone ``principal_key_accepted`` for
        the operator with ``may_accept_keys: true`` forged into its scopes.

        Pre-fix the resolver read that ``True`` and let the worker's acceptance resolve. The
        writer's validator refuses the payload outright (``scopes_key_set``): the member is
        not part of a standalone acceptance's closed scope set at all.
        """
        chain, worker_hash = self._operator_grants_worker(
            keyset,
            grantor_envelope_factory=lambda c: (
                c.acceptance_envelope(
                    OPERATOR,
                    may_sign_bundles=False,
                    signed_by=BOOTSTRAP,
                    accepted_by=BOOTSTRAP,
                    accepted_by_anchor=c.genesis_hash,
                    may_accept_keys=True,  # the forgery: standalone scopes cannot carry this
                    entity_label="-grantor",
                ),
                BOOTSTRAP,
            ),
        )
        document = _forge_document(chain, authority_event_hash=worker_hash)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False
        assert any("anchor_grantor" in f for f in report.findings), report.findings

    def test_a_self_minted_epoch_started_grantor_is_refused(self, keyset: Any) -> None:
        """Face A: the grantor is a self-minted ``project_cryptographic_epoch_started``.

        Pre-fix a bootstrap-transition event was treated as an unconditional external
        bootstrap at any ordinal/signer. EPOCH-RESET deletes the legacy seam, so the only
        bootstrap anchor a clean-epoch bundle recognises is the project genesis; an
        epoch-started grantor is refused (``grantor_not_project_genesis``).
        """

        def _epoch_started(c: _Chain) -> tuple[dict[str, Any], str]:
            # A v6 project_cryptographic_epoch_started has fixed shape: entity kind
            # "project", entity id == project_instance_id, entity_seq 1 (null prev entity),
            # non-null project predecessor. Built to pass the envelope validator precisely so
            # the REFUSAL under test comes from the resolver — grantor_not_project_genesis —
            # and not from an ill-formed envelope that would never reach it.
            env = c._base(OPERATOR)
            env["entity"] = {"kind": "project", "id": c.project_instance_id}
            env["entity_seq"] = 1
            env["transition"] = "project_cryptographic_epoch_started"
            env["chain"]["previous_entity_event_hash"] = None
            env["payload"] = {
                "bootstrap_key_acceptance": c.acceptance_payload(
                    OPERATOR,
                    may_sign_bundles=False,
                    accepted_by=OPERATOR,
                    may_accept_keys=True,
                )
            }
            env["signing"]["key_binding_event_hash"] = None
            return env, OPERATOR

        chain, worker_hash = self._operator_grants_worker(
            keyset, grantor_envelope_factory=_epoch_started
        )
        document = _forge_document(chain, authority_event_hash=worker_hash)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False
        assert any("anchor_grantor" in f for f in report.findings), report.findings

    def test_a_revoked_grantor_is_refused(self, keyset: Any) -> None:
        """Face A: the grantor's own key is revoked. The standard chain (worker accepted by
        BOOTSTRAP, anchored on genesis) plus a revocation of the BOOTSTRAP key.

        The top-level revocation gate only refuses when the SIGNER's key is revoked; the
        grantor-revocation check is separate, and pre-fix it did not exist, so a worker whose
        grantor was revoked still resolved.
        """
        chain = _Chain(keyset, may_sign_bundles=True, ordinary_events=0)
        assert chain.acceptance_hash is not None
        chain.append(
            chain.revocation_envelope(
                principal_id=BOOTSTRAP,
                acceptance_event_hash=chain.genesis_hash or "",
                revoked_by=BOOTSTRAP,
            ),
            BOOTSTRAP,
        )
        document = _forge_document(chain, authority_event_hash=chain.acceptance_hash)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False
        assert any("anchor_grantor_revoked" in f for f in report.findings), report.findings


class TestSignerAuthorityNewestLiveFailsClosed:
    """Round-2 blocker FR2-1 Face B: a malformed NEWER competing anchor fails closed."""

    def test_a_malformed_newer_anchor_does_not_fall_back_to_stale_authority(
        self, keyset: Any
    ) -> None:
        """Acceptance A grants ``may_sign_bundles``; a newer ``principal_key_accepted`` for
        the same key has its payload type set wrong; the statement names A.

        Pre-fix the malformed newer anchor was silently skipped and the resolver fell back to
        A, preserving stale authority. The store fails parsing rather than selecting stale
        authority, and so must this: a competing anchor that does not validate refuses the
        whole resolution.
        """
        chain = _Chain(keyset, may_sign_bundles=True, ordinary_events=0)
        stale = chain.acceptance_hash
        assert stale is not None
        malformed = chain.acceptance_envelope(
            WORKER, may_sign_bundles=False, entity_label="-newer"
        )
        malformed["payload"]["type"] = "regista.not-an-acceptance"
        chain.append(malformed, BOOTSTRAP)
        document = _forge_document(chain, authority_event_hash=stale)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is False
        assert report.core_ok is False
        assert any("competing_anchor_invalid" in f for f in report.findings), report.findings

    def test_a_newer_anchor_with_scopes_removed_fails_closed(self, keyset: Any) -> None:
        """The other repro shape: scopes stripped from the newer competing anchor."""
        chain = _Chain(keyset, may_sign_bundles=True, ordinary_events=0)
        stale = chain.acceptance_hash
        assert stale is not None
        malformed = chain.acceptance_envelope(
            WORKER, may_sign_bundles=False, entity_label="-newer2"
        )
        del malformed["payload"]["scopes"]
        chain.append(malformed, BOOTSTRAP)
        document = _forge_document(chain, authority_event_hash=stale)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.core_ok is False
        assert any("competing_anchor_invalid" in f for f in report.findings), report.findings

    def test_a_valid_newer_anchor_supersedes_and_verifies(self, keyset: Any) -> None:
        """The counterweight: a WELL-FORMED newer anchor is honoured (newest-live), so the
        fail-closed rule does not break legitimate re-acceptance."""
        chain = _Chain(keyset, may_sign_bundles=False, ordinary_events=0)
        newer = chain.append(
            chain.acceptance_envelope(
                WORKER, may_sign_bundles=True, entity_label="-current"
            ),
            BOOTSTRAP,
        )
        document = _forge_document(chain, authority_event_hash=newer)
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.signer_may_sign_bundles is True
        assert report.core_ok is True, report.findings

    def test_the_writer_validator_is_the_one_actually_used(self) -> None:
        """The reuse, asserted structurally so a later refactor cannot quietly fork it. The
        module must call ``_v6_writer.validate_key_acceptance_payload``, not a paraphrase."""
        import inspect

        from regista import _bundle_v3

        src = inspect.getsource(_bundle_v3._validate_standalone_anchor)
        assert "validate_key_acceptance_payload" in src
        assert "from ._v6_writer import validate_key_acceptance_payload" in src


class TestBuilderAuthorityRecordsIntegrity:
    """Round-2 NB-b: build enforces authority_records ⊇ event_records and one project."""

    def test_authority_records_must_contain_every_exported_event(
        self, keyset: Any
    ) -> None:
        chain = _Chain(keyset, may_sign_bundles=True)
        with pytest.raises(RegistaError) as exc:
            chain.build(
                event_records=chain.records,
                authority_records=chain.records[:1],  # missing the rest
            )
        assert exc.value.code is ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED
        assert "every exported event" in str(exc.value)

    def test_authority_records_from_another_project_are_refused(
        self, keyset: Any
    ) -> None:
        chain = _Chain(keyset, may_sign_bundles=True)
        other = _Chain(keyset, may_sign_bundles=True)
        with pytest.raises(RegistaError) as exc:
            chain.build(
                event_records=chain.records,
                # a superset by count, but a different project's chain
                authority_records=chain.records + other.records,
            )
        # Two independent project chains cannot form one ordered authority chain — each has
        # its own null-predecessor genesis — so this is refused, and the *earliest* gate to
        # catch it wins: derive_chain_order sees two heads (BUNDLE_CHAIN_UNORDERABLE) before
        # the explicit same-project check (BUNDLE_SIGNER_NOT_PERMITTED) is reached. Either is
        # a correct fail-closed; the point is that a cross-project authority_records never
        # yields a signed statement.
        assert exc.value.code in {
            ErrorCode.BUNDLE_CHAIN_UNORDERABLE,
            ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED,
        }

    def test_authority_records_from_another_trust_domain_are_refused(
        self, keyset: Any
    ) -> None:
        """Round-3 blocker FR3-1: the cross-DOMAIN face of the round-2 laundering class.

        Round 2 required authority records to share ``project_instance_id`` but did not check
        ``trust_domain_id``. A single forged acceptance that keeps the project instance but
        carries a different domain chain-links as the newest anchor, is selected as the
        authority, and is named in a statement whose ``trust_root`` describes a *different*
        domain — so ``authority_event_hash`` points at an anchor from a domain the statement
        does not describe. A project instance belongs to one trust domain, so a record
        disagreeing on the domain is not part of this chain's authority, and the builder must
        refuse before authority resolution.
        """
        chain = _Chain(keyset, may_sign_bundles=True, ordinary_events=0)
        foreign_domain = str(uuid.uuid4())
        assert foreign_domain != chain.trust_domain_id
        foreign = chain.acceptance_envelope(
            WORKER, may_sign_bundles=True, entity_label="-foreign-domain"
        )
        # Same project instance, DIFFERENT trust domain — kept internally consistent so the
        # event is a well-formed v6 envelope that only the domain check should reject.
        foreign["trust_domain_id"] = foreign_domain
        foreign["payload"]["trust_domain_id"] = foreign_domain
        chain.append(foreign, BOOTSTRAP)

        with pytest.raises(RegistaError) as exc:
            chain.build(
                event_records=chain.records[:-1],   # the honest window
                authority_records=chain.records,     # + the foreign-domain anchor
            )
        assert exc.value.code is ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED
        assert "more than one trust domain" in str(exc.value)
        assert exc.value.detail is not None
        assert exc.value.detail["member_trust_domain_id"] == foreign_domain
        assert exc.value.detail["statement_trust_domain_id"] == chain.trust_domain_id

    def test_a_same_domain_superset_still_exports(self, keyset: Any) -> None:
        """The counterweight to FR3-1: a legitimate same-project, same-domain superset — the
        chunking case the superset argument exists for — still builds and verifies."""
        chain = _Chain(keyset, may_sign_bundles=True)
        document = chain.build(
            event_records=chain.records[2:],
            authority_records=chain.records,  # full chain, one project, one domain
            scope_kind="contiguous-range",
            preceding_event_hash=chain.hashes[1],
        )
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.statement_signature_valid is True
        assert report.membership_root_ok is True


class TestSignerKeyBinding:
    """§3.2 says ``signer.fingerprint`` is redundant with ``key_id`` **on purpose**: "the
    auditor pins fingerprints, not key ids, and a signed self-statement of the fingerprint
    means the pin comparison never has to route through the bundled registry."

    Both reviewers found independently that Phase B never made that comparison, in either
    direction — so the statement's whole account of who signed it was decoration. Three
    comparisons close it, and each has a test below.
    """

    def test_a_signature_from_a_key_the_statement_does_not_name_is_refused(
        self, keyset: Any
    ) -> None:
        """Reviewer A's probe. The bootstrap key signs the statement; the signer block names
        the worker; the verifier is handed the bootstrap public key.

        Before the fix the signature verified and the report said so, while the artifact's
        own account of its signer was a different principal entirely. An auditor comparing
        their pinned fingerprint against ``signer.fingerprint`` would have been comparing
        against a field nothing checked.
        """
        chain = _Chain(keyset)
        document = _forge_document(
            chain,
            signer_principal=WORKER,          # the statement names the worker...
            signing_seed_principal=BOOTSTRAP,  # ...but bootstrap's key signed it
        )
        report = verify_bundle_v3_core(
            _reparse(document),
            statement_public_key=keyset.key_for(BOOTSTRAP).public_key,
        )
        assert report.statement_signature_checked is True
        assert report.statement_signature_valid is False, (
            "the signature is cryptographically valid under the key supplied, and that is "
            "precisely why it must be refused: the key is not the one the statement names"
        )
        assert report.core_ok is False
        assert any(
            "statement_key_is_not_the_declared_signer" in f for f in report.findings
        ), report.findings

    def test_a_signature_block_naming_another_key_id_is_refused(
        self, keyset: Any
    ) -> None:
        """The cheaper half, and a pure internal contradiction: ``statement_signature.key_id``
        disagrees with ``statement.signer.key_id``. No supplied key is needed to see it, so
        it is a parse-time refusal rather than a finding."""
        chain = _Chain(keyset)
        document = _forge_document(
            chain, signature_overrides={"key_id": "pk_something_else"}
        )
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(canonical_bundle_bytes(document))
        assert exc.value.code is ErrorCode.BUNDLE_STATEMENT_INVALID
        assert "statement_signature.key_id" in str(exc.value)

    def test_a_signer_block_whose_fingerprint_contradicts_its_key_id_is_refused(
        self, keyset: Any
    ) -> None:
        """The signer block names the worker's ``key_id`` and the bootstrap key's
        fingerprint. §4.4 criterion 4: "a bundled key whose fingerprint contradicts a pinned
        fingerprint for the same key id is ``invalid``, not merely reported"."""
        chain = _Chain(keyset)
        document = _forge_document(chain)
        document["statement"]["signer"]["fingerprint"] = keyset.key_for(
            BOOTSTRAP
        ).fingerprint
        # Re-sign so the finding cannot be the signature's.
        document["statement_signature"] = sign_statement(
            document["statement"],
            private_key=keyset.key_for(WORKER).seed,
            key_id=keyset.key_for(WORKER).key_id,
        )
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.statement_signature_valid is False
        assert report.core_ok is False

    def test_the_builder_refuses_a_signer_whose_private_key_is_not_its_identity(
        self, keyset: Any
    ) -> None:
        """Reviewer B's probe, on the build side: a ``BundleV3Signer`` carrying the worker's
        declared identity and the bootstrap principal's private key produced a document that
        verified under the bootstrap public key with ``signer_may_sign_bundles=True``.

        The builder now refuses: a declared fingerprint the supplied private key cannot
        produce is a caller error that must not become a signed artifact.
        """
        chain = _Chain(keyset)
        with pytest.raises(RegistaError) as exc:
            chain.build(
                signer=chain.signer(private_key=keyset.key_for(BOOTSTRAP).seed)
            )
        assert exc.value.code is ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED
        assert "fingerprint" in str(exc.value)

    def test_a_matching_key_still_verifies(self, keyset: Any) -> None:
        """The positive control for all three comparisons."""
        chain = _Chain(keyset)
        report = verify_bundle_v3_core(
            _reparse(chain.build()), statement_public_key=chain.signer_public_key
        )
        assert report.core_ok is True, report.findings


# ---------------------------------------------------------------------------
# F3 — complete-store must be headed by the project genesis
# ---------------------------------------------------------------------------


class TestCompleteStoreHeadIsGenesis:
    def test_a_null_predecessor_non_genesis_head_cannot_claim_complete_store(
        self, keyset: Any
    ) -> None:
        """§3.5: ``complete-store`` requires ``first_event_hash`` = **project genesis**.

        Phase B checked only that the head had a null ``previous_project_event_hash``, which
        is a necessary and nowhere near sufficient condition: an ordinary signed event can
        carry a null project link and head a bundle claiming to be the whole chain. The
        difference matters because ``complete-store`` is the scope that licenses "an absent
        referent contradicts the claim" — a false one turns every absence into a lie in the
        safe-looking direction.
        """
        chain = _Chain(
            keyset,
            with_genesis=False,
            head_transition="trust_domain_established",
            with_acceptance=False,
        )
        document = _forge_document(chain, scope_kind="complete-store")
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.scope_consistent is False
        assert report.core_ok is False
        assert any(
            "complete_store_head_is_not_project_genesis" in f for f in report.findings
        ), report.findings

    def test_a_genuine_genesis_head_is_accepted(self, keyset: Any) -> None:
        chain = _Chain(keyset)
        report = verify_bundle_v3_core(
            _reparse(chain.build()), statement_public_key=chain.signer_public_key
        )
        assert report.scope_consistent is True
        assert report.core_ok is True, report.findings


# ---------------------------------------------------------------------------
# N1 / N2 — hostile JSON must produce a NAMED refusal, not a traceback
# ---------------------------------------------------------------------------


class TestHostileJson:
    """A verifier is an attacker-facing parser, so every rejection must be a named
    ``RegistaError``.

    An uncaught ``FloatDomainError`` or ``CanonicalizationError`` is a traceback at the CLI
    and a 500 at the sidecar — and a 500 is indistinguishable from "the verifier broke",
    which is the wrong thing for an auditor to conclude about a hostile artifact. Each case
    below reached the caller as a non-``RegistaError`` exception before the fix.
    """

    @pytest.mark.parametrize(
        ("label", "raw_content"),
        [
            ("infinity", "Infinity"),
            ("negative-infinity", "-Infinity"),
            ("nan", "NaN"),
            ("float-overflow", "1e400"),
            ("integer-overflow", "1" + "0" * 400),
        ],
        ids=lambda v: str(v)[:24],
    )
    def test_non_finite_and_out_of_range_numbers_are_named_refusals(
        self, chain: _Chain, document: dict[str, Any], label: str, raw_content: str
    ) -> None:
        """JSON's number grammar admits values RFC 8785 cannot canonicalize, and
        ``json.loads`` accepts three literals the grammar does not even contain
        (``NaN``/``Infinity``/``-Infinity``). Both routes must be refused by name."""
        # The hostile value goes inside an OTHERWISE VALID document, and that placement is
        # the whole point: a malformed skeleton is refused by the structural checks long
        # before anything canonicalizes, so a probe built that way proves nothing. Here every
        # structural check passes and the canonicalizer is genuinely reached.
        carrier = chain.build(
            external_evidence=[
                {
                    "class": "operator_asserted",
                    "source": "hostile",
                    "obtained_at": "2026-08-23T00:00:00+00:00",
                    "content": {"n": 0},
                }
            ]
        )
        raw = canonical_bundle_bytes(carrier).decode()
        hostile = raw.replace('"n":0', f'"n":{raw_content}')
        assert hostile != raw, "the substitution must actually land"
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(hostile)
        assert exc.value.code in {
            ErrorCode.INVALID_ARGUMENT,
            ErrorCode.BUNDLE_STATEMENT_INVALID,
        }

    def test_a_lone_surrogate_is_a_named_refusal(self, chain: _Chain) -> None:
        """RFC 8785 cannot serialise an unpaired surrogate, and the canonicalizer says so by
        raising. Reaching the caller as a canonicalizer error rather than a bundle error
        makes a hostile string look like an internal fault."""
        carrier = chain.build(
            external_evidence=[
                {
                    "class": "operator_asserted",
                    "source": "surrogate-carrier",
                    "obtained_at": "2026-08-23T00:00:00+00:00",
                    "content": {},
                }
            ]
        )
        raw = canonical_bundle_bytes(carrier).decode()
        hostile = raw.replace('"surrogate-carrier"', '"\\ud800"')
        assert hostile != raw
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(hostile)
        assert exc.value.code in {
            ErrorCode.INVALID_ARGUMENT,
            ErrorCode.BUNDLE_STATEMENT_INVALID,
            ErrorCode.BUNDLE_FORMAT_UNSUPPORTED,
        }

    def test_a_duplicate_json_key_is_refused(self, document: dict[str, Any]) -> None:
        """N2. ``json.loads`` keeps the LAST of two identical keys, so a decoy ``scope``
        placed before the real one is invisible to the parser and visible to a human reading
        the file — or the reverse, depending on which tool reads it. §3.1 rule 4 says the
        bundle is canonical JSON; canonical JSON has no duplicate keys."""
        raw = canonical_bundle_bytes(document).decode()
        decoy = '{"kind":"complete-store","event_count":1}'
        hostile = raw.replace('"scope":', f'"scope":{decoy},"scope":', 1)
        assert hostile != raw
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(hostile)
        assert exc.value.code in {
            ErrorCode.INVALID_ARGUMENT,
            ErrorCode.BUNDLE_STATEMENT_INVALID,
        }
        assert "duplicate" in str(exc.value).lower()

    def test_non_canonical_bytes_are_refused(self, document: dict[str, Any]) -> None:
        """§3.1 rule 4, enforced rather than asserted: the artifact's bytes must BE their
        RFC 8785 fixed point.

        This is the same discipline ``parse_v6_envelope_strict`` applies to an envelope, and
        it subsumes a whole family of presentation tricks — reordered keys, inserted
        whitespace, a duplicate key that survived the pair hook — into one comparison.
        """
        pretty = json.dumps(json.loads(canonical_bundle_bytes(document)), indent=2)
        with pytest.raises(RegistaError) as exc:
            parse_bundle_v3_document(pretty)
        assert exc.value.code is ErrorCode.BUNDLE_STATEMENT_INVALID
        assert "canonical" in str(exc.value).lower()


# ---------------------------------------------------------------------------
# N3 — a cycle must refuse, not hang
# ---------------------------------------------------------------------------


class TestChainOrderTerminates:
    """O4 demands a refusal on a chain that cannot be totally ordered. A hang is not a
    refusal: an export or verify that never returns is a denial-of-service on the tool an
    auditor is holding, and it is indistinguishable from a very large bundle.
    """

    def test_a_two_event_cycle_refuses_rather_than_hanging(self, keyset: Any) -> None:
        """Two events each declaring the other as predecessor, entered from outside.

        Constructed by hand because no chain builder can produce it: event A's hash depends
        on B's and vice versa. So instead both events declare the SAME external predecessor
        and one of them also appears as its own successor — the shape a relocated or
        replayed chunk produces.
        """
        chain = _Chain(keyset)
        members = [parse_event_member(env, sig) for env, sig in chain.records]
        # Re-enter at an event already in the walk: member[2]'s predecessor is member[1],
        # and we ask the walk to start at member[1]'s predecessor, which is member[0] —
        # then splice member[0] back in as a successor of the tail.
        entry = members[0].previous_project_event_hash
        looped = [*members, members[0]]
        with pytest.raises(RegistaError) as exc:
            derive_chain_order(looped, preceding_event_hash=entry)
        assert exc.value.code is ErrorCode.BUNDLE_CHAIN_UNORDERABLE

    def test_a_self_referencing_event_refuses(self, keyset: Any) -> None:
        """An event naming its own hash as its predecessor cannot exist honestly (the hash
        covers the field), but a hand-edited artifact can present one, and the walk must
        terminate on it."""
        from regista._bundle_v3 import OrderedMember

        chain = _Chain(keyset)
        member = parse_event_member(*chain.records[0])
        # A member whose declared predecessor IS its own hash. Built by substituting the
        # parsed envelope rather than by re-signing, because a real signer cannot produce
        # this and the verifier must still terminate.
        envelope = dict(member.envelope)
        envelope["chain"] = {
            **dict(member.envelope["chain"]),
            "previous_project_event_hash": member.event_hash_text,
        }
        looping = OrderedMember(
            scope_ordinal=-1,
            canonical_envelope=member.canonical_envelope,
            signature=member.signature,
            event_hash=member.event_hash,
            envelope=envelope,
        )
        with pytest.raises(RegistaError) as exc:
            derive_chain_order([looping], preceding_event_hash=member.event_hash_text)
        assert exc.value.code is ErrorCode.BUNDLE_CHAIN_UNORDERABLE


# ---------------------------------------------------------------------------
# N4 / N5 — the report must not claim checks it did not run
# ---------------------------------------------------------------------------


class TestReportHonesty:
    def test_core_ok_requires_the_signer_authority(self, keyset: Any) -> None:
        """N4. The module docstring points Phase C at ``verify_bundle_v3_core``, and
        ``core_ok`` is the summary a consumer reaches for first. If it can be True while
        O3 was never established, the seam invites exactly the misreading the axis model
        exists to prevent."""
        chain = _Chain(keyset)
        document = _forge_document(
            chain,
            records=chain.records[2:],
            scope_kind="contiguous-range",
            preceding_event_hash=chain.acceptance_hash,
        )
        report = verify_bundle_v3_core(
            _reparse(document), statement_public_key=chain.signer_public_key
        )
        assert report.structural_checks_ok is True
        assert report.statement_signature_valid is True
        assert report.signer_authority_checked is False
        assert report.core_ok is False, (
            "core_ok must not read as an acceptance when the signer's authority was never "
            "established"
        )
        assert any("signer_authority_outside_scope" in n for n in report.notes)

    def test_unrun_checks_are_reported_as_unrun_not_as_passes(self, keyset: Any) -> None:
        """N5. With the chain unorderable there is nothing to compare a scope against and no
        tree to root, so the fields that describe those checks must say "not run" rather
        than carry a default that reads as a pass.

        ``recomputed_membership_root`` was the worst of them: it reported
        ``sha256(<empty>)`` — the frozen empty-tree root — as though it had been computed
        over the presented events.
        """
        chain = _Chain(keyset)
        document = _forge_document(chain)
        # Drop a middle event so the walk cannot reach the tail.
        del document["sections"]["events"][1]
        document["statement"]["section_digests"]["events"] = section_digest_text(
            "events", document["sections"]["events"]
        )
        parsed = _reparse(document)
        report = verify_bundle_v3_core(
            parsed, statement_public_key=chain.signer_public_key
        )
        assert report.chain_ordered is False
        assert report.membership_root_ok is None
        assert report.scope_consistent is None
        assert report.reference_sections_ok is None
        assert report.recomputed_membership_root is None
        assert report.core_ok is False
        emitted = report.to_dict()
        for key in (
            "membership_root_ok",
            "scope_consistent",
            "reference_sections_ok",
            "recomputed_membership_root",
        ):
            assert emitted[key] is None, key
