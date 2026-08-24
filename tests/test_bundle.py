"""Bundle v3 export and offline verification against a real store.

``tests/test_bundle_v3.py`` covers the document — the statement schema, the membership
tree, the section digests, the signature — with no database. This module covers the parts
that need one: reading a project's chain, resolving the signer's ``may_sign_bundles`` scope
from its signed acceptance, the write ceremony, and the round trip back through the
verifier.

**The adversary model changed with the format, and it is the reason most of these tests
look different from their bundle v2 ancestors.** Every v2 tamper test had to recompute the
bundle hash "the way a tampering adversary would", because the hash was unkeyed and agreed
with whatever it was given — so the finding had to come from a check that survived the
rehash. Under v3 there is no such field. What an adversary can still do is **re-sign**, if
they hold the signing key, and :func:`_resign` is that adversary: it recomputes every
digest the statement commits to and produces a fresh, valid signature. Tests that use it
are asking "is this caught by something other than the signature?"; tests that do not are
asking "does the signature catch it?".
"""

from __future__ import annotations

import base64
import copy
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any, NamedTuple

import pytest

from regista import Regista
from regista._bundle import (
    AcceptBundledKeys,
    TrustPolicy,
    _archive_relation_present,
    verify_audit_bundle_offline,
    verify_audit_bundle_v3,
)
from regista._bundle_v3 import (
    SECTION_NAMES,
    canonical_bundle_bytes,
    compute_dependency_closure,
    section_digest_text,
    sign_statement,
)
from regista._errors import ErrorCode, RegistaError
from regista._testing import drop_project_schema
from regista._testing_v6 import (
    BOOTSTRAP_PRINCIPAL,
    V6TestKeyset,
    make_v6_keyset,
    open_v6_epoch,
    v6_producer,
)

DSN = os.environ.get(
    "REGISTA_TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)
KEY_PATH = "tests/test_keys.json"
WORKFLOW_PATH = "tests/test_workflow.yaml"

#: The principal whose signed project-local acceptance bears ``may_sign_bundles``, and
#: therefore the only one that may sign a statement (owner ruling O3).
BUNDLE_SIGNER = "agent:worker"

#: The replayed root governance state. Export has no default for this and cannot derive it:
#: ``BUNDLE-V3.md`` §3.2 requires the state obtained by replaying the signed trust-domain
#: governance log, and forbids copying it from genesis, configuration or a projection. A
#: test that wants a bundle therefore states it, exactly as an operator will until §4
#: trust-root resolution (Phase C) lands.
ROOT_GOVERNANCE = {"mode": "solo", "threshold": 1, "signer_count": 1}

# A genesis-only store's single event is a Bootstrap-B event whose authority is external by
# construction, and RECONCILIATION.md Resolution 1 is explicit: "Bootstrap without an
# external pin is not a bootstrap; it is an unauthenticated first event." So it is reported
# as one unverifiable signature naming the absent pin — not as an error, and not as a pass.
_V6_BOOTSTRAP_UNPINNED = "unauthenticated first event"

BUNDLE_WORKER = "agent:worker"
BUNDLE_REVIEWER = "human:reviewer"


def _can_run() -> bool:
    try:
        import psycopg

        conn = psycopg.connect(DSN, connect_timeout=2)
        conn.close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _can_run(),
    reason="Postgres not available at regista_test DSN",
)


class _Store(NamedTuple):
    store: Regista
    project: str
    keyset: V6TestKeyset
    genesis_event_hash: str
    entity_id: uuid.UUID

    @property
    def signer_public_key(self) -> bytes:
        return self.keyset.key_for(BUNDLE_SIGNER).public_key

    def export(self, output: Path, **kwargs: Any) -> dict[str, Any]:
        params: dict[str, Any] = {
            "root_governance": ROOT_GOVERNANCE,
            "signing_principal_id": BUNDLE_SIGNER,
        }
        params.update(kwargs)
        return self.store.export_audit_bundle(str(output), **params)

    def verify(self, output: Path, **kwargs: Any) -> Any:
        kwargs.setdefault("statement_public_key", self.signer_public_key)
        return verify_audit_bundle_offline(output, **kwargs)


def _open_store(name: str, keyset: V6TestKeyset) -> tuple[Regista, str, uuid.UUID]:
    """A project on a clean v6 epoch, with two events on one entity.

    TWO events on ONE entity, deliberately. Every event ``open_v6_epoch`` writes is
    ``entity_seq == 1`` for its own entity, so a store built only from it has no per-entity
    link for the entity-chain check to verify — and a chain check with nothing to check
    passes. Mutation M20 (reverting the event-hash formula) SURVIVED against such a
    fixture, which is how this was found.
    """
    from regista._v6_writer import append_v6_event

    store = Regista.create_project(DSN, name, keyset.path)
    genesis = open_v6_epoch(store, keyset, may_sign_bundles=True)
    entity_id = uuid.uuid4()
    for transition in ("created", "updated"):
        with store._mgr.transaction() as conn:
            append_v6_event(
                conn,
                store._keys,
                entity_kind="work_item",
                entity_id=entity_id,
                transition=transition,
                actor_id=BUNDLE_SIGNER,
                actor_kind="agent",
                producer=v6_producer(),
                payload={"initial_state": "open"},
            )
    return store, genesis.to_dict()["event_hash"], entity_id


@pytest.fixture(scope="module")
def bundle_store(tmp_path_factory: pytest.TempPathFactory) -> Any:
    keyset = make_v6_keyset(tmp_path_factory.mktemp("bundle_v3_store_keys"))
    name = f"bundle_v3_{uuid.uuid4().hex[:8]}"
    store, genesis_hash, entity_id = _open_store(name, keyset)
    try:
        # Export is read-only, so one module-scoped project serves every test here
        # (project creation replays the full migration set).
        yield _Store(
            store=store,
            project=name,
            keyset=keyset,
            genesis_event_hash=genesis_hash,
            entity_id=entity_id,
        )
    finally:
        store.close()
        drop_project_schema(DSN, name)


@pytest.fixture
def project() -> Any:
    name = f"bundle_test_{uuid.uuid4().hex[:8]}"
    yield name
    drop_project_schema(DSN, name)


@pytest.fixture
def sub(project: str) -> Any:
    """A project with NO v6 epoch open: an event-free store.

    Used only by the negative export paths that must refuse before any signing happens.
    """
    s = Regista.create_project(DSN, project, KEY_PATH)
    yield s
    s.close()


# ---------------------------------------------------------------------------
# Tamper helpers
# ---------------------------------------------------------------------------


def _project_identity(store: Any) -> Any:
    from regista._v6_writer import read_project_identity

    with store._mgr.transaction() as conn:
        identity = read_project_identity(conn)
    assert identity is not None
    return identity


def _acceptance_hash_for(rows: Any, principal_id: str, keyset: V6TestKeyset) -> str:
    """The event hash of the standalone acceptance granting *principal_id*'s key."""

    from regista._bundle_v3 import parse_event_member

    key_id = keyset.key_for(principal_id).key_id
    for row in rows:
        if row["transition"] != "principal_key_accepted":
            continue
        member = parse_event_member(
            bytes(row["canonical_envelope"]), bytes(row["signature"])
        )
        payload = member.payload or {}
        if payload.get("principal_id") == principal_id and payload.get("key_id") == key_id:
            return member.event_hash_text
    raise AssertionError(f"no acceptance for {principal_id} in the presented rows")


def _read(output: Path) -> dict[str, Any]:
    return json.loads(output.read_text())


def _write(output: Path, document: dict[str, Any]) -> None:
    output.write_bytes(canonical_bundle_bytes(document))


def _resign(document: dict[str, Any], keyset: V6TestKeyset) -> dict[str, Any]:
    """Recompute every derived commitment and re-sign — the strongest adversary available.

    This is what replaces bundle v2's ``_rehash``. It assumes the adversary holds the
    signing key, which is the worst case an artifact can be asked to survive: everything
    the statement commits to is recomputed to agree with the edited body, and the signature
    is genuinely valid. A test that uses this and still gets a finding has proved the
    finding does not depend on the signature at all.
    """
    doctored = copy.deepcopy(document)
    statement = doctored["statement"]
    for name in SECTION_NAMES:
        statement["section_digests"][name] = section_digest_text(
            name, doctored["sections"][name]
        )
    key = keyset.key_for(BUNDLE_SIGNER)
    doctored["statement_signature"] = sign_statement(
        statement, private_key=key.seed, key_id=key.key_id
    )
    return doctored


# ---------------------------------------------------------------------------
# WI-210 — output naming
# ---------------------------------------------------------------------------


class TestRejectArchiveOutputName:
    @pytest.mark.parametrize(
        "name",
        [
            "bundle.tar.gz",
            "bundle.tgz",
            "bundle.tar",
            "bundle.zip",
            "bundle.json.gz",
            "bundle.tar.bz2",
            "bundle.tar.xz",
            "BUNDLE.TGZ",
        ],
    )
    def test_helper_rejects_archive_names(self, name: str) -> None:
        from regista._bundle import _reject_archive_output_name

        with pytest.raises(RegistaError) as exc_info:
            _reject_archive_output_name(name)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    @pytest.mark.parametrize("name", ["bundle.json", "bundle", "bundle.ndjson", "a.json.bak"])
    def test_helper_accepts_non_archive_names(self, name: str) -> None:
        from regista._bundle import _reject_archive_output_name

        _reject_archive_output_name(name)

    def test_export_rejects_tar_gz(self, sub: Any, tmp_path: Path) -> None:
        with pytest.raises(RegistaError) as exc_info:
            sub.export_audit_bundle(str(tmp_path / "bundle.tar.gz"))
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT
        assert not (tmp_path / "bundle.tar.gz").exists()


# ---------------------------------------------------------------------------
# Export refusals that come before anything is signed
# ---------------------------------------------------------------------------


class TestExportRequiresItsInputs:
    """§3.4 and §3.2: a v3 bundle is a signed statement about a replayed governance state.

    Neither input has a fallback, and both refusals are the design rather than a gap. §4.1's
    argument applies to the export side as much as the verify side: "Every 'remember to pass
    the trust file' discipline fails eventually. Making it un-passable makes it
    un-forgettable."
    """

    def test_export_without_governance_refuses_by_name(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        output = tmp_path / "no_governance.json"
        with pytest.raises(RegistaError) as exc_info:
            bundle_store.store.export_audit_bundle(str(output))
        assert exc_info.value.code == ErrorCode.BUNDLE_STATEMENT_INVALID
        assert "replaying the signed trust-domain governance log" in str(exc_info.value)
        assert "Phase C" in str(exc_info.value)
        assert not output.exists(), "a refused export must leave no artifact"

    def test_a_key_without_may_sign_bundles_cannot_sign(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """Owner ruling O3, on a real store: the genesis/bootstrap key's *signed* acceptance
        (the ``bootstrap_key_acceptance`` inside ``project_initialized``) sets
        ``may_sign_bundles: false``, so it cannot sign a bundle statement even though it is
        the key that opened the epoch and can sign everything else.

        The scope comes from the signed acceptance, never from the key file — which is the
        whole content of O3: the authority "is an *explicit, signed* property of a key — not
        an implication of holding the writer key".
        """
        output = tmp_path / "unscoped.json"
        with pytest.raises(RegistaError) as exc_info:
            bundle_store.export(output, signing_principal_id=BOOTSTRAP_PRINCIPAL)
        assert exc_info.value.code == ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED
        assert "may_sign_bundles" in str(exc_info.value)
        assert not output.exists()


# ---------------------------------------------------------------------------
# The round trip
# ---------------------------------------------------------------------------


class TestVerifyAuditBundleOffline:
    def test_exported_bundle_round_trips_offline(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """The export → offline-verify round trip on a real artifact, with the v3 document
        shape asserted rather than assumed.

        §2's last line is the assertion that matters most here: "**A v3 bundle is not a
        superset of v2.** It is a different document with a different top-level shape."
        """
        output = tmp_path / "roundtrip.json"
        result = bundle_store.export(output)

        assert output.is_file()
        assert result["output_path"] == str(output)
        assert result["format_version"] == 3
        assert result["scope_kind"] == "complete-store"
        assert result["event_membership_root"].startswith("sha256:")
        assert result["bundle_bytes"] > 0
        assert result["since_seq"] is None and result["until_seq"] is None
        assert "bundle_hash" not in result, (
            "the unkeyed bundle hash is DELETED, not renamed (BUNDLE-V3.md §1, §8)"
        )

        document = _read(output)
        assert set(document) == {"statement", "statement_signature", "sections"}
        assert "manifest" not in document
        assert "public_keys" not in document
        assert "anchor_receipts" not in document and "segments" not in document

        statement = document["statement"]
        assert statement["type"] == "regista.audit-bundle"
        assert statement["version"] == 3
        assert "epoch" not in statement, "decision E2: the epoch block is dropped"
        assert statement["scope"]["event_count"] == result["event_count"]
        assert statement["scope"]["first_event_hash"] == bundle_store.genesis_event_hash
        assert statement["scope"]["preceding_event_hash"] is None
        assert statement["trust_root"]["root_governance"] == ROOT_GOVERNANCE
        assert statement["signer"]["principal_id"] == BUNDLE_SIGNER
        assert statement["signer"]["scheme_id"] == "ed25519"
        assert statement["exporter"]["statement_schema"] == "regista.audit-bundle/3"
        assert set(document["sections"]) == set(SECTION_NAMES)

        report = bundle_store.verify(output)
        assert report.format_version == 3
        assert report.statement_signature_checked is True
        assert report.statement_signature_valid is True
        assert report.membership_root_ok is True
        assert report.section_digests_ok is True
        assert report.reference_sections_ok is True
        assert report.scope_consistent is True
        assert report.global_chain_ok is True
        assert report.work_item_chain_ok is True
        assert report.signer_may_sign_bundles is True
        assert report.errors == [], report.errors
        assert report.self_verification_ok is True, (report.errors, report.unverifiable_details)
        assert "bundle_hash_ok" not in report.to_dict()
        assert "signature_check" not in report.to_dict()

    def test_the_signed_statement_restates_the_genesis_digests_it_carries(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """``trust_root``'s core and genesis-document digests are restatements of what this
        project's own genesis event signed, so a verifier holding the bundle can check the
        restatement against the artifact rather than taking the statement's word.

        ``root_governance`` is deliberately NOT checkable this way, and that asymmetry is
        §3.2's rule: the governance state "is not copied from genesis". A verifier that
        cannot replay the log reports ``unverified_restatement`` (§4.5) — an axis value,
        Phase C's to emit.
        """
        output = tmp_path / "restatement.json"
        bundle_store.export(output)
        document = _read(output)

        genesis_record = document["sections"]["events"][0]
        genesis_envelope = json.loads(
            base64.b64decode(genesis_record["canonical_envelope"])
        )
        trust_root = document["statement"]["trust_root"]
        assert (
            trust_root["trust_domain_core_digest"]
            == genesis_envelope["payload"]["trust_domain_core_digest"]
        )
        assert (
            trust_root["genesis_document_digest"]
            == genesis_envelope["payload"]["genesis_document_digest"]
        )

        # And the other direction: a restatement the genesis event contradicts is a
        # finding, even from an adversary who re-signed.
        doctored = copy.deepcopy(document)
        doctored["statement"]["trust_root"]["genesis_document_digest"] = (
            "sha256:" + "ab" * 32
        )
        _write(output, _resign(doctored, bundle_store.keyset))
        report = bundle_store.verify(output)
        assert report.statement_signature_valid is True, "the adversary re-signed"
        assert any("trust_root_contradicts_genesis" in e for e in report.errors), (
            report.errors
        )
        assert report.self_verification_ok is False

    def test_a_caller_supplied_trust_pin_reaches_the_offline_verifier(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """§8.4: the per-event trust policy is a caller input, and it cannot come from the
        artifact — a bundle that supplied its own pin would be vouching for itself.

        Asserting that the *reported* checkpoint binding changes is how this proves the
        input is plumbed rather than accepted and dropped.
        """
        from regista._verification import VerificationPolicy

        output = tmp_path / "pinned.json"
        bundle_store.export(output)

        unpinned = bundle_store.verify(output)
        assert unpinned.unverifiable_details, "the bootstrap event is the unpinned one"
        assert "checkpoint_binding=checkpoint_bound" in unpinned.unverifiable_details[0]

        pinned = bundle_store.verify(
            output,
            policy=VerificationPolicy(
                pinned_trust_domain_id=_read(output)["statement"]["trust_domain_id"],
                cutover_checkpoint_event_hash=bundle_store.genesis_event_hash,
            ),
        )
        assert "checkpoint_binding=externally_pinned" in pinned.unverifiable_details[0], (
            "the pinned checkpoint hash must reach the verdict, not be accepted and dropped"
        )
        assert "external_trust_pin" not in pinned.unverifiable_details[0]

    def test_a_pin_naming_another_domain_is_a_defect_not_a_gap(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """The other direction, and the one that makes the pin load-bearing: a pin the
        artifact contradicts is INVALID, which is an error and not an absence."""
        from regista._verification import VerificationPolicy

        output = tmp_path / "wrong_pin.json"
        bundle_store.export(output)
        report = bundle_store.verify(
            output, policy=VerificationPolicy(pinned_trust_domain_id=str(uuid.uuid4()))
        )
        assert report.self_verification_ok is False
        assert any("trust_domain_mismatch" in e for e in report.errors), report.errors

    def test_verify_detects_a_signed_field_edit(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """The bundle v3 counterpart of v2's ``test_verify_detects_bundle_hash_mismatch``,
        and the reason that test is retired rather than adapted.

        v2's check was an **unkeyed** SHA-256 over the document, so it detected accidental
        corruption and nothing else — "anyone can recompute [it] after editing anything"
        (§1), which is why every v2 tamper test had to rehash before it could prove
        anything. The v3 counterpart of "an edit inside the committed region is detected" is
        cryptographic: editing ``scope.event_count`` — the same field the v2 test edited —
        invalidates the statement signature, and there is no field an editor can restore.
        """
        output = tmp_path / "edited.json"
        bundle_store.export(output)

        document = _read(output)
        document["statement"]["scope"]["event_count"] = 999
        _write(output, document)

        report = bundle_store.verify(output)
        assert report.statement_signature_checked is True
        assert report.statement_signature_valid is False
        assert report.self_verification_ok is False
        assert any("BUNDLE_STATEMENT_SIGNATURE_INVALID" in e for e in report.errors), (
            report.errors
        )

    def test_verify_detects_tampered_event(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """A rewritten event is caught, and under v3 it is caught **structurally** rather
        than by field reconciliation.

        v2 exported twenty row columns beside the envelope and caught a rewrite by
        reconciling them (``row_field_mismatch``). v3 exports the envelope alone (§3.6), so
        there is no row to disagree — and the envelope's bytes are inside the event hash,
        inside the membership root, inside the signature. The adversary here re-signs, so
        the finding cannot be coming from the signature: it comes from the recomputed root.
        """
        output = tmp_path / "row_tamper.json"
        bundle_store.export(output)

        document = _read(output)
        record = document["sections"]["events"][-1]
        envelope = json.loads(base64.b64decode(record["canonical_envelope"]))
        assert envelope["transition"] == "updated"
        envelope["transition"] = "not_updated"
        record["canonical_envelope"] = base64.b64encode(
            json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode()
        ).decode("ascii")
        _write(output, _resign(document, bundle_store.keyset))

        report = bundle_store.verify(output)
        assert report.statement_signature_valid is True, "the adversary re-signed"
        assert report.self_verification_ok is False
        assert report.membership_root_ok is False or report.global_chain_ok is False, (
            "a rewritten envelope must change the event hash and therefore the tree"
        )

    def test_verify_nonexistent_file_raises(self) -> None:
        with pytest.raises(RegistaError) as exc_info:
            verify_audit_bundle_offline("/nonexistent/bundle.json")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_verify_malformed_json_raises(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")

        with pytest.raises(RegistaError) as exc_info:
            verify_audit_bundle_offline(str(bad))
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_verify_empty_bundle_fails_closed(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """An event-free bundle proves nothing and used to verify trivially: the empty chain
        is vacuously valid and there is nothing left to fail (PR #32 review N5).

        Under v3 it is rejected **twice**, which is what §8 "Retained" means by
        "strengthened": ``scope.event_count`` must be a positive integer, and an empty event
        set has no membership root to sign. The adversary re-signs and still cannot produce
        one, because the refusal is structural rather than a comparison.
        """
        output = tmp_path / "emptied.json"
        bundle_store.export(output)
        document = _read(output)
        document["sections"]["events"] = []
        document["statement"]["scope"]["event_count"] = 0
        _write(output, _resign(document, bundle_store.keyset))

        with pytest.raises(RegistaError) as exc_info:
            bundle_store.verify(output)
        assert exc_info.value.code == ErrorCode.BUNDLE_STATEMENT_INVALID
        assert "positive integer" in str(exc_info.value)

    def test_a_v2_artifact_is_refused_by_name_not_verified_leniently(
        self, tmp_path: Path
    ) -> None:
        """§2/§6 on the store-facing entry point. S3 was "signature enforcement is optional
        under format 1"; v3 removes the configuration rather than hardening it, so a v1/v2
        artifact never reaches a verifier at all."""
        legacy = tmp_path / "v2.json"
        legacy.write_text(
            json.dumps(
                {
                    "manifest": {"format_version": 2, "event_count": 1, "bundle_hash": ""},
                    "events": [],
                    "public_keys": [],
                }
            )
        )
        with pytest.raises(RegistaError) as exc_info:
            verify_audit_bundle_offline(str(legacy))
        assert exc_info.value.code == ErrorCode.BUNDLE_FORMAT_UNSUPPORTED
        assert "bundle v2 artifact" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Event authentication — the §8 "keystone"
# ---------------------------------------------------------------------------


class TestOfflineSignatureVerification:
    """Offline event authentication over a v3 bundle.

    The bundle carries key material in ``sections.bundled_key_evidence`` and inside the
    signed acceptance payloads, and the verifier hands each event to
    ``verify_event_strict`` — the one primitive that decides whether an event is
    authenticated. §8 calls that delegation "the keystone" and retains it wholesale.
    """

    def test_export_carries_key_evidence_from_the_signed_acceptance(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """The v3 counterpart of v2's ``test_export_includes_registered_public_key``, and a
        deliberate change of source rather than a rename.

        v2 exported the ``principal_keys`` projection as ``public_keys``, and §4.3 names
        three mechanisms for why that had to stop — the first being that the section is now
        called ``bundled_key_evidence`` so that "no code path can read it as a root by habit
        or by autocomplete". The bytes now come from the bundle's own **signed** acceptance
        objects, which §5.8 repeats ``public_key`` inside on purpose. Nothing reads
        ``principal_keys``: a projection row that exists *because* a verifier needs it is
        §5.9 rule 1's forbidden coupling.
        """
        output = tmp_path / "with_keys.json"
        result = bundle_store.export(output)
        document = _read(output)

        evidence = {r["key_id"]: r for r in document["sections"]["bundled_key_evidence"]}
        assert evidence, "the acceptance payloads in scope carry key material"
        assert result["public_key_count"] == len(evidence)

        signer_key = bundle_store.keyset.key_for(BUNDLE_SIGNER)
        entry = evidence[signer_key.key_id]
        assert entry["principal_id"] == BUNDLE_SIGNER
        assert entry["scheme_id"] == "ed25519"
        assert base64.b64decode(entry["public_key"]) == signer_key.public_key
        assert entry["fingerprint"] == signer_key.fingerprint
        assert set(entry) == {
            "key_id",
            "principal_id",
            "scheme_id",
            "public_key",
            "fingerprint",
        }

    def test_the_evidence_section_carries_no_validity_window(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """The v3 counterpart of v2's ``test_the_registry_wins_where_both_carry_the_key``,
        which no longer has a subject.

        v2's ``public_keys`` section carried ``valid_from`` / ``valid_to`` / ``revoked_at``
        copied from the ``principal_keys`` projection, and the rule was that the registry
        beat payload-derived evidence because it "knows strictly more". Under v3 the section
        is *evidence*, not a registry: §4.3's records are "exact public-key material
        records", and the acceptance object they mirror declares no window. So there is no
        precedence question left — and, more to the point, no operator-writable field in the
        bundle that could *narrow* what verifies. Enrollment-before-use is evaluated on
        chain ordinal and the signed timestamp (§4.4 criterion 2), not on a copied column.
        """
        output = tmp_path / "no_window.json"
        bundle_store.export(output)
        for entry in _read(output)["sections"]["bundled_key_evidence"]:
            assert "valid_from" not in entry
            assert "valid_to" not in entry
            assert "revoked_at" not in entry
            assert "status" not in entry

    def test_a_forged_event_signature_is_caught_by_the_membership_root_too(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """The v3 counterpart of v2's
        ``test_forged_signature_caught_only_by_signature_check``, retired because its name
        states something v3 makes false.

        Under v2 a forged signature "constrains no chain link the bundle can check, and the
        unkeyed bundle hash can be restored — so the signature check is the only thing
        standing between a forgery and a clean report". Under v3 the signature is an input
        to the event hash (``V6-ENVELOPE.md`` §5.3), the event hash is a membership leaf, and
        the root is signed. So a forgery is caught **twice**, and this asserts both: the
        cryptographic conviction (``signature_invalid``) and the structural one (the root),
        against an adversary who re-signed the statement.
        """
        output = tmp_path / "forged.json"
        bundle_store.export(output)

        document = _read(output)
        record = document["sections"]["events"][-1]
        real = base64.b64decode(record["signature"])
        record["signature"] = base64.b64encode(b"\xff" * len(real)).decode("ascii")
        _write(output, _resign(document, bundle_store.keyset))

        report = bundle_store.verify(output)
        assert report.statement_signature_valid is True, "the adversary re-signed"
        assert report.self_verification_ok is False
        assert report.membership_root_ok is False, (
            "the signature is inside the event hash, so a forgery moves the root"
        )
        assert any("signature_invalid" in e for e in report.errors), report.errors
        assert not any(_V6_BOOTSTRAP_UNPINNED in e for e in report.errors), (
            "the forgery must fail the CRYPTOGRAPHIC check, not merely surface the "
            "bootstrap-pin gap that a clean bundle also reports"
        )

    def test_missing_public_key_fails_closed(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """An asymmetric event whose key the bundle does not carry is unverifiable, and
        unverifiable is a finding — not a pass.

        Reaching that state needs a different construction under v3, and the reason is
        WI-296's key-evidence half: the acceptance payload repeats ``public_key`` inside
        **signed bytes**, so a bundle carrying the acceptance carries the key whatever
        happens to the evidence section. Emptying the section is therefore not enough (and
        would also break its digest).

        So the state is reached honestly instead: a ``contiguous-range`` window that starts
        *after* the acceptance event. The key's evidence is genuinely outside the presented
        scope, which is exactly §9 criterion 15's case, and the report must say so rather
        than pass.
        """
        with bundle_store.store._mgr.transaction() as conn:
            rows = conn.execute(
                "SELECT global_seq FROM events ORDER BY global_seq"
            ).fetchall()
        # Everything after the acceptance block: the ordinary events only.
        since = rows[-3]["global_seq"]

        output = tmp_path / "no_keys.json"
        bundle_store.export(output, since_seq=since)
        document = _read(output)
        assert document["statement"]["scope"]["kind"] == "contiguous-range"
        assert document["sections"]["bundled_key_evidence"] == [], (
            "no acceptance event is in this window, so there is no key evidence in it"
        )

        report = bundle_store.verify(output)
        assert report.self_verification_ok is False
        assert report.signatures_verified == 0
        assert any("No public key for key_id" in e for e in report.errors), report.errors


# ---------------------------------------------------------------------------
# WI-240 / WI-249 — the write ceremony
# ---------------------------------------------------------------------------


class TestExportBounds:
    """WI-240: bounded, capped, self-verifying export."""

    def test_the_grantor_of_a_real_standalone_acceptance_validates(
        self, bundle_store: Any
    ) -> None:
        """The round-2 grantor rule against GENUINE writer-produced events, not hand-built
        ones. ``open_v6_epoch`` accepts the worker with a standalone ``principal_key_accepted``
        signed by the genesis principal and anchored on the genesis event — the exact
        grantor path round 2 hardened. The offline resolver must validate that grantor (the
        project genesis) and resolve the worker's ``may_sign_bundles``.

        This is the faithful-mirror claim under test: the resolver reuses
        ``_v6_writer.validate_key_acceptance_payload``, so a real acceptance the writer
        produced must pass the very validator the writer applied when it wrote it.
        """
        from regista._bundle_v3 import (
            SigningAuthority,
            derive_chain_order,
            parse_event_member,
            resolve_bundle_signing_authority,
        )

        with bundle_store.store._mgr.transaction() as conn:
            rows = conn.execute(
                "SELECT canonical_envelope, signature FROM events ORDER BY global_seq"
            ).fetchall()
        ordered = derive_chain_order(
            [
                parse_event_member(bytes(r["canonical_envelope"]), bytes(r["signature"]))
                for r in rows
            ],
            preceding_event_hash=None,
        )
        authority, refusals = resolve_bundle_signing_authority(
            ordered,
            principal_id=BUNDLE_SIGNER,
            key_id=bundle_store.keyset.key_for(BUNDLE_SIGNER).key_id,
        )
        assert isinstance(authority, SigningAuthority), refusals
        assert authority.kind == "acceptance", (
            "the worker holds a standalone acceptance whose grantor is the genesis"
        )
        assert authority.may_sign_bundles is True
        # No grantor refusal: the genesis grantor validated as a real bootstrap anchor.
        assert not any("grantor" in r for r in refusals), refusals

    def test_a_revoked_signing_authority_refuses_at_both_gates(
        self, tmp_path_factory: pytest.TempPathFactory, tmp_path: Path
    ) -> None:
        """Owner ruling O3 against a real store, and the scenario a probe-executing reviewer
        used to show the two gates had drifted apart.

        The store admits a ``principal_key_acceptance_revoked`` event through the ordinary
        writer — that is what revocation IS — and from that moment
        ``resolve_key_binding_anchor`` refuses every anchor for the key, because "a
        revocation is not superseded by an older acceptance".

        Both gates are asserted, and only one of them was ever sound. The store-side
        pre-flight already refused before this fix, which is exactly what made the defect
        hard to see: export said no, so the *export* path looked correct, while an offline
        verifier handed the resulting events said yes. So this test also runs the offline
        resolver over the REAL store's events — not a hand-built chain — because that is the
        gate that was missing, and agreement between the two is the property worth pinning.
        """
        from regista._v6_writer import append_v6_event

        keyset = make_v6_keyset(tmp_path_factory.mktemp("bundle_v3_revoked_keys"))
        name = f"bundle_v3_rev_{uuid.uuid4().hex[:8]}"
        store, genesis_hash, _entity = _open_store(name, keyset)
        try:
            with store._mgr.transaction() as conn:
                rows = conn.execute(
                    "SELECT canonical_envelope, signature, transition FROM events "
                    "ORDER BY global_seq"
                ).fetchall()
            acceptance_hash = _acceptance_hash_for(rows, BUNDLE_SIGNER, keyset)

            with store._mgr.transaction() as conn:
                append_v6_event(
                    conn,
                    store._keys,
                    entity_kind="principal",
                    entity_id=uuid.uuid5(
                        uuid.NAMESPACE_OID, "regista.principal:" + BUNDLE_SIGNER
                    ),
                    transition="principal_key_acceptance_revoked",
                    actor_id=BOOTSTRAP_PRINCIPAL,
                    actor_kind="system",
                    producer=v6_producer(),
                    payload={
                        "type": "regista.key-acceptance-revocation",
                        "version": 1,
                        "trust_domain_id": str(
                            _project_identity(store).trust_domain_id
                        ),
                        "project_instance_id": str(
                            _project_identity(store).project_instance_id
                        ),
                        "principal_id": BUNDLE_SIGNER,
                        "key_id": keyset.key_for(BUNDLE_SIGNER).key_id,
                        "acceptance_event_hash": acceptance_hash,
                        "reason": "superseded",
                        "revoked_by": {
                            "principal_id": BOOTSTRAP_PRINCIPAL,
                            "key_id": keyset.key_for(BOOTSTRAP_PRINCIPAL).key_id,
                            "key_binding_event_hash": genesis_hash,
                        },
                    },
                )

            # Gate 1 — the store-side pre-flight. Sound before this fix, and asserted so a
            # later refactor cannot quietly drop it.
            output = tmp_path / "revoked.json"
            with pytest.raises(RegistaError) as exc_info:
                store.export_audit_bundle(
                    str(output),
                    root_governance=ROOT_GOVERNANCE,
                    signing_principal_id=BUNDLE_SIGNER,
                )
            assert exc_info.value.code in {
                ErrorCode.BUNDLE_SIGNER_NOT_PERMITTED,
                ErrorCode.KEY_ACCEPTANCE_REVOKED,
            }
            assert not output.exists()

            # Gate 2 — the offline derivation, over the same real events. This is the one
            # that was missing: the material carries the grant AND its revocation, and the
            # answer must be "no anchor", by name.
            from regista._bundle_v3 import (
                derive_chain_order,
                parse_event_member,
                resolve_bundle_signing_authority,
            )

            with store._mgr.transaction() as conn:
                all_rows = conn.execute(
                    "SELECT canonical_envelope, signature FROM events ORDER BY global_seq"
                ).fetchall()
            ordered = derive_chain_order(
                [
                    parse_event_member(
                        bytes(r["canonical_envelope"]), bytes(r["signature"])
                    )
                    for r in all_rows
                ],
                preceding_event_hash=None,
            )
            authority, refusals = resolve_bundle_signing_authority(
                ordered,
                principal_id=BUNDLE_SIGNER,
                key_id=keyset.key_for(BUNDLE_SIGNER).key_id,
            )
            assert authority is None, (
                "the revocation is in the material; no anchor for this key may be used"
            )
            # The round-2 resolver keys the revocation on (principal, key) — exactly as the
            # store's resolve_key_binding_anchor does ("a revocation ANYWHERE for this
            # principal/key refuses") — so the refusal names the principal and key rather
            # than one acceptance hash. `acceptance_hash` is retained above only to drive the
            # revocation event; the invariant under test is that ANY revocation for the pair
            # refuses the whole resolution.
            assert any("signer_authority_revoked" in r for r in refusals), refusals
            assert BUNDLE_SIGNER in " ".join(refusals), refusals
        finally:
            store.close()
            drop_project_schema(DSN, name)

    def test_empty_range_is_rejected(self, sub: Any, tmp_path: Path) -> None:
        with pytest.raises(RegistaError, match="Empty export range"):
            sub.export_audit_bundle(
                str(tmp_path / "empty.json"), since_seq=10, until_seq=10
            )

    def test_export_of_event_free_store_is_rejected(
        self, sub: Any, project: str, tmp_path: Path
    ) -> None:
        output = tmp_path / "empty_store.json"
        with pytest.raises(RegistaError, match="store has no events"):
            sub.export_audit_bundle(str(output), root_governance=ROOT_GOVERNANCE)
        assert not output.exists()

    @pytest.mark.parametrize(
        ("since_kind", "until_kind"),
        [
            ("max", None),  # since == corpus max: nothing after it
            ("beyond", None),  # since past the end
            (None, "zero"),  # until 0: nothing at or before it
            (None, "negative"),  # until negative
        ],
    )
    def test_window_selecting_no_events_is_rejected(
        self,
        bundle_store: Any,
        tmp_path: Path,
        since_kind: str | None,
        until_kind: str | None,
    ) -> None:
        """WI-240 review F1: a window that selects zero rows must not write a
        trivially-'verifiable' bundle and exit 0 — in the chunking workflow a bad boundary
        would silently lose events. Distinct from the ``until <= since`` range gate: each of
        these windows is well-formed and simply selects nothing, so only the post-query
        check can catch it."""
        with bundle_store.store._mgr.transaction() as conn:
            corpus_max = conn.execute(
                "SELECT max(global_seq) AS m FROM events"
            ).fetchone()["m"]
        since = {"max": corpus_max, "beyond": corpus_max + 500}.get(since_kind or "")
        until = {"zero": 0, "negative": -5}.get(until_kind or "")

        output = tmp_path / "void.json"
        with pytest.raises(RegistaError, match="selected no events") as exc_info:
            bundle_store.export(output, since_seq=since, until_seq=until)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT
        assert not output.exists()

    def test_oversized_export_refuses_and_writes_nothing(
        self, bundle_store: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from regista import _bundle

        monkeypatch.setattr(_bundle, "MAX_BUNDLE_BYTES", 512)
        output = tmp_path / "oversize.json"
        with pytest.raises(RegistaError, match="Refusing to write") as exc_info:
            bundle_store.export(output)
        assert not output.exists(), "a refused export must leave no artifact"
        assert "nothing was written" in str(exc_info.value)

    def test_export_reports_self_verification(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """An export is done when the artifact it wrote is verifiable, not when the write
        returns (WI-240). The public key is the one the export just signed with, so this
        proves the artifact verifies against **its own signer** — not that the signer is
        trusted, which is §4 and an auditor's pin."""
        output = tmp_path / "sv.json"
        result = bundle_store.export(output)

        sv = result["self_verification"]
        assert set(sv) == {
            "applicability",
            "membership_signature",
            "event_authentication",
            "event_trust_root",
            "findings",
            "notes",
        }
        assert "verified" not in sv, "§5.2 deleted the boolean; the verdict is applicability"
        assert "signature_check" not in sv, "§6 deleted the field and its magic strings"
        # §9 rule 7 / §5.2: the self-verification is a self-consistency verdict against the
        # bundle's OWN keys (AcceptBundledKeys, clamped by Rule C), never external
        # authentication. `bundle_rooted` is the honest ceiling for a project bundle offline
        # (WI-337); it is not `invalid`, so the artifact was written.
        assert sv["applicability"] == "bundle_rooted"
        assert sv["membership_signature"] == "valid_bundled_key"
        assert sv["findings"] == []
        assert result["bundle_bytes"] > 0

    def test_store_level_defects_are_reported_not_fatal(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """A defect of the STORE faithfully preserved must not block the only archival path
        a degraded store has. The export reports it, loudly, and still publishes the
        artifact; ``bundle verify`` is the enforcement point.

        Here the "defect" is the honest one every genesis-bearing bundle carries: the
        bootstrap event's authority is external and nothing pinned it. It reaches the
        report per event, and the artifact is written.
        """
        output = tmp_path / "degraded.json"
        result = bundle_store.export(output)  # must not raise

        assert output.is_file(), "a reported (not fatal) finding must still publish"
        sv = result["self_verification"]
        # The honest defect every genesis-bearing bundle carries: the bootstrap event's
        # authority is external and nothing pinned it, so event authentication is
        # `legacy_partial`, not full. That is reported per axis and is NOT `invalid`, so the
        # artifact still publishes — `bundle verify` against a pin is the enforcement point.
        assert sv["applicability"] == "bundle_rooted"
        assert sv["event_authentication"] == "legacy_partial"
        assert sv["applicability"] != "invalid", (
            "a faithfully-preserved store defect must not fail the only archival path"
        )

    def test_corruption_of_the_written_artifact_raises_and_keeps_it(
        self, bundle_store: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The v3 counterpart of v2's
        ``test_hash_mismatch_on_written_artifact_raises_and_keeps_it``, retired because its
        name states the mechanism and the mechanism is gone.

        The invariant is unchanged and is the boundary the export draws: a defect the STORE
        preserved is reported and still publishes; a defect **export introduced** fails the
        export. What detects it is no longer an unkeyed hash but the statement signature —
        and under §9 rule 5 / D11 the self-verification runs over the ``.partial`` BEFORE
        ``os.replace``, so the corrupt artifact is left at the ``.partial`` for inspection
        and the destination is never touched (stronger than v2, which left the bad bundle at
        the destination). The corruption is injected into the bytes written to the
        ``.partial`` so it is a real signature failure, not a stubbed report.
        """
        real_write_bytes = Path.write_bytes

        def corrupting_write(path: Path, data: bytes) -> int:
            if path.name.endswith(".partial"):
                doctored = json.loads(data)
                doctored["statement"]["scope"]["event_count"] = 999
                return real_write_bytes(path, canonical_bundle_bytes(doctored))
            return real_write_bytes(path, data)

        monkeypatch.setattr(Path, "write_bytes", corrupting_write)
        output = tmp_path / "corrupt.json"
        with pytest.raises(RegistaError) as exc_info:
            bundle_store.export(output)

        assert exc_info.value.code == ErrorCode.BUNDLE_WRITE_CORRUPT
        assert "does not self-verify" in str(exc_info.value)
        # §9 rule 5: the rejected artifact is kept at the unique temp (FR2-2) for inspection,
        # and the destination was NEVER touched — publication does not run on a failed check.
        partials = list(tmp_path.glob("corrupt.json.*.partial"))
        assert len(partials) == 1, f"expected one temp left for inspection: {partials}"
        assert json.loads(partials[0].read_text())["statement"]["scope"]["event_count"] == 999
        assert not output.exists(), "publication must not run when self-verification fails"

    def test_successful_export_leaves_no_partial_file(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """Write-then-rename (review F8): the ``.partial`` temp is the only thing a killed
        process may leave behind, and a SUCCESSFUL export leaves none."""
        output = tmp_path / "clean.json"
        bundle_store.export(output)

        assert output.is_file()
        assert sorted(p.name for p in tmp_path.iterdir()) == ["clean.json"]

    def test_write_failure_removes_the_partial_and_spares_the_destination(
        self, bundle_store: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If the write dies mid-way, unlink the ``.partial`` — only the partial, never the
        real destination (WI-249). Nothing reaches the destination that did not survive the
        write.

        ``overwrite=True`` is passed so the pre-existing destination gets past §9 rule 4's
        refusal — the point here is the WI-249 invariant, and it must hold even when the
        operator explicitly allowed a replacement: a write that dies still spares the file
        it was going to replace, because ``os.replace`` never runs.
        """
        output = tmp_path / "keepme.json"
        sentinel = b'{"previous": "bundle"}'
        output.write_bytes(sentinel)

        real_write_bytes = Path.write_bytes

        def dies_mid_write(path: Path, data: bytes) -> None:
            # A plausible-looking partial lands on disk, then the write fails.
            real_write_bytes(path, data[: len(data) // 2])
            raise OSError("injected: no space left on device")

        monkeypatch.setattr(Path, "write_bytes", dies_mid_write)
        with pytest.raises(OSError, match="injected"):
            bundle_store.export(output, overwrite=True)

        monkeypatch.undo()
        assert not (tmp_path / "keepme.json.partial").exists(), (
            "a failed write left a plausible-looking partial bundle behind"
        )
        assert output.read_bytes() == sentinel, (
            "a failed export clobbered the destination it never verified"
        )

    def test_chunked_exports_are_disjoint_and_jointly_complete(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """Two windows that partition the corpus produce two independently verifiable
        bundles whose membership is disjoint and whose union is the whole chain.

        The second chunk is a ``contiguous-range`` scope anchored to the event immediately
        before it, so §3.5's guarantee holds: "the range is anchored to the chain
        immediately before it, so a chunk cannot be silently relocated". The anchor is read
        off the chain, never off the window bounds.
        """
        with bundle_store.store._mgr.transaction() as conn:
            seqs = [
                row["global_seq"]
                for row in conn.execute(
                    "SELECT global_seq FROM events ORDER BY global_seq"
                ).fetchall()
            ]
        cut = seqs[len(seqs) // 2]

        head = tmp_path / "head.json"
        tail = tmp_path / "tail.json"
        bundle_store.export(head, until_seq=cut)
        bundle_store.export(tail, since_seq=cut)

        head_doc = _read(head)
        tail_doc = _read(tail)
        # Both chunks are `contiguous-range`: a windowed export cannot attest that it is
        # the whole chain, even when the window would have covered it. The head chunk's
        # range starts at genesis, so its `preceding_event_hash` is legitimately null
        # (§3.5, "or the range starts at genesis").
        assert head_doc["statement"]["scope"]["kind"] == "contiguous-range"
        assert tail_doc["statement"]["scope"]["kind"] == "contiguous-range"
        assert head_doc["statement"]["scope"]["preceding_event_hash"] is None
        assert (
            tail_doc["statement"]["scope"]["preceding_event_hash"]
            == head_doc["statement"]["scope"]["last_event_hash"]
        ), "the tail chunk is anchored to the head chunk's last event, from the chain"

        head_events = {r["canonical_envelope"] for r in head_doc["sections"]["events"]}
        tail_events = {r["canonical_envelope"] for r in tail_doc["sections"]["events"]}
        assert not (head_events & tail_events), "the chunks must be disjoint"
        assert len(head_events) + len(tail_events) == len(seqs)

        for path in (head, tail):
            report = bundle_store.verify(path)
            assert report.statement_signature_valid is True, path
            assert report.membership_root_ok is True, path
            assert report.scope_consistent is True, path
            assert report.global_chain_ok is True, path

        # The head chunk contains the acceptance that grants may_sign_bundles, so O3 is
        # re-derived and the chunk is `verified`. The tail chunk does NOT, and reports so
        # rather than passing: RECONCILIATION.md Resolution 4's "reports the named
        # dependency as outside scope — never silently valid", applied to the boolean.
        head_report = bundle_store.verify(head)
        tail_report = bundle_store.verify(tail)
        assert head_report.signer_authority_checked is True
        assert head_report.self_verification_ok is True, head_report.errors
        assert tail_report.signer_authority_checked is False
        assert tail_report.self_verification_ok is False
        assert any(
            "signer_authority_outside_scope" in n for n in tail_report.notes
        ), tail_report.notes

        # NOTE, flagged rather than fixed here: the tail chunk's per-event findings are
        # "No public key for key_id ..." — an *error*, because the acceptance events that
        # carry the key material fall outside the window. Under §9 criterion 15 and
        # `MaterialCompleteness.CONTIGUOUS_RANGE` a referent absent from a bounded scope
        # "is outside scope and must be NAMED as such", which is closer to A3
        # `not_checkable` than to a defect. Reclassifying it is the §5.1 axis model's job
        # (WI-289 Phase C), not Phase B's: `_verify_event_signatures` is shared with the
        # live-store path and its error/unverifiable split is what the axes aggregate. This
        # assertion pins the CURRENT behaviour so the reclassification is a visible diff.
        assert all(
            "No public key for key_id" in e for e in tail_report.errors
        ), tail_report.errors

    def test_a_windowed_export_that_is_not_contiguous_refuses(
        self, bundle_store: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Owner ruling O4 at the export boundary: a set of events with more than one entry
        point into the chain is not a range, and export refuses rather than producing a
        partial or diagnostic artifact.

        "A flag on the evidentiary command is eventually load-bearing in someone's CI, and
        the failure mode is a forensic dump that gets read as an audit bundle" — so there is
        no ``--diagnostic``, and this asserts the absence by asserting the refusal.
        """
        from regista import _bundle

        real_read = _bundle._read_export_rows

        def punch_a_hole(conn: Any, **kwargs: Any) -> Any:
            records = real_read(conn, **kwargs)
            # Drop a middle event: what remains has two entry points.
            return records[:1] + records[2:]

        monkeypatch.setattr(_bundle, "_read_export_rows", punch_a_hole)
        output = tmp_path / "holed.json"
        with pytest.raises(RegistaError) as exc_info:
            bundle_store.export(output)
        assert exc_info.value.code == ErrorCode.BUNDLE_CHAIN_UNORDERABLE
        assert "2 distinct entry point(s)" in str(exc_info.value)
        assert "nothing was written" in str(exc_info.value).lower()
        assert not output.exists()


# ---------------------------------------------------------------------------
# WI-296 — key evidence and self-verification, on a real epoch
# ---------------------------------------------------------------------------


class TestGenesisKeyEvidence:
    def test_a_healthy_post_genesis_export_self_verifies_true(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """WI-296's self-verification half. Note what is and is not claimed: every
        *ordinary* v6 event in the bundle is fully authenticated, while the genesis event
        remains unverifiable-pending-a-pin — counted and detailed rather than either hidden
        or promoted to an error."""
        output = tmp_path / "post_genesis.json"
        result = bundle_store.export(output)

        sv = result["self_verification"]
        # Self-verification reaches the honest ceiling (§9 rule 7): `bundle_rooted`, a
        # self-consistency verdict, not `invalid`. The genesis event is unverifiable-pending
        # a pin, which shows as `legacy_partial` event authentication rather than an error.
        assert sv["applicability"] == "bundle_rooted", sv["findings"]
        assert sv["findings"] == []
        assert sv["membership_signature"] == "valid_bundled_key"
        assert sv["event_authentication"] == "legacy_partial"

        report = bundle_store.verify(output)
        assert report.self_verification_ok is True, report.errors
        assert report.global_chain_ok is True
        assert report.work_item_chain_ok is True

    def test_the_v6_chain_links_verify_under_the_v6_hash_formula(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """A found defect, kept pinned. ``_hash_event`` once computed
        ``sha256(envelope || signature)`` — the v1-v5 formula — for every event, so for a v6
        chain **no link resolved at all**, and v2's ``_verify_global_chain`` returned
        ``ok=True`` *vacuously*: with every link unresolved, every event became a bridge
        point, every bridge point was immediately its own tail, and all events were visited.

        Two things changed and both are asserted. The formula is asserted at the primitive,
        because a behavioural assertion alone is satisfied by a chain check that checks
        nothing. And the vacuous pass is now structurally impossible: ``derive_chain_order``
        admits exactly ONE entry point, so a set in which nothing links up has no entry
        point and refuses instead of passing.
        """
        from regista._bundle_v3 import derive_chain_order, parse_event_member
        from regista._signing import compute_v6_event_hash

        output = tmp_path / "chain.json"
        bundle_store.export(output)
        document = _read(output)
        records = [
            (
                base64.b64decode(r["canonical_envelope"]),
                base64.b64decode(r["signature"]),
            )
            for r in document["sections"]["events"]
        ]
        assert len(records) >= 3, "the point of the test is a multi-event v6 chain"

        # At the primitive: the head an event contributes is its OWN version's hash, and
        # the next event's envelope declares exactly that.
        first_envelope, first_signature = records[0]
        v6 = compute_v6_event_hash(first_envelope, first_signature)
        second = json.loads(records[1][0])
        assert second["chain"]["previous_project_event_hash"] == "sha256:" + v6.hex()

        import hashlib as _hashlib

        v5 = _hashlib.sha256(first_envelope + first_signature).digest()
        assert v6 != v5, "the two formulas must differ, or this test proves nothing"

        # And the vacuous-pass shape: a set whose links do not resolve refuses.
        members = [parse_event_member(e, s) for e, s in records[1:]]
        with pytest.raises(RegistaError) as exc_info:
            derive_chain_order(members, preceding_event_hash=None)
        assert exc_info.value.code == ErrorCode.BUNDLE_CHAIN_UNORDERABLE

        report = bundle_store.verify(output)
        assert report.global_chain_ok is True
        # Non-vacuous: the fixture carries an entity with two events, so the per-entity
        # check has a real link to verify rather than nothing to verify.
        entity_counts: dict[str, int] = {}
        for envelope, _sig in records:
            entity = json.loads(envelope)["entity"]["id"]
            entity_counts[entity] = entity_counts.get(entity, 0) + 1
        assert max(entity_counts.values()) >= 2, (
            "a per-entity chain check with no multi-event entity checks nothing"
        )
        assert report.work_item_chain_ok is True

    def test_the_acceptance_payload_alone_is_sufficient_key_evidence(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """WI-296's other half, at its narrowest, and it survives v3 unchanged in force.

        ``bundled_key_evidence`` is emptied and the artifact re-signed, so the *only* key
        material left is the ``public_key`` inside the signed acceptance payloads. §5.8
        repeats it there on purpose — "it makes a project bundle self-sufficient for key
        material without making it self-sufficient for *trust*" — and if this failed, an
        out-of-the-box store would export a bundle nobody can check, which is the fact
        WI-296 opened with.
        """
        output = tmp_path / "payload_keys.json"
        bundle_store.export(output)
        document = _read(output)
        document["sections"]["bundled_key_evidence"] = []
        _write(output, _resign(document, bundle_store.keyset))

        report = bundle_store.verify(output)
        assert report.section_digests_ok is True, "the adversary recomputed the digests"
        assert not any("No public key" in e for e in report.errors), report.errors
        assert report.signatures_verified >= 1
        # Unverifiable for the bootstrap-pin reason ONLY — not for want of a key.
        assert report.signatures_unverifiable == 1
        assert _V6_BOOTSTRAP_UNPINNED in report.unverifiable_details[0]


# ---------------------------------------------------------------------------
# The Phase C / Phase D seam
# ---------------------------------------------------------------------------


class TestVerificationSeam:
    """What Phase C and Phase D consume, asserted so a later refactor notices.

    Phase C builds §4 trust-root resolution and the §5 axis model on top of the core
    report; Phase D builds the §9 export ceremony on top of the builder. Both seams are
    exercised here on a real artifact rather than described in a docstring.
    """

    def test_the_core_report_is_available_without_the_boolean_summary(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        from regista._bundle import verify_bundle_v3_report

        output = tmp_path / "seam.json"
        bundle_store.export(output)

        core = verify_bundle_v3_report(
            output, statement_public_key=bundle_store.signer_public_key
        )
        assert core.core_ok, core.findings
        assert core.format_version == 3
        assert core.recomputed_membership_root == (
            _read(output)["statement"]["event_membership_root"]
        )
        assert core.ordered_event_hashes[0] == bundle_store.genesis_event_hash
        assert "verified" not in core.to_dict(), (
            "the core report reaches no verdict: §5's lattice is Phase C's, and a boolean "
            "here would be the flattening WI-269 exists to prevent"
        )
        assert "applicability" not in core.to_dict()

    def test_a_verifier_with_no_trust_material_reports_unchecked_not_verified(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """§4.1's rule, as far as Phase B implements it: trust material is a caller input
        and its absence is reported, never assumed away. Phase C makes the argument
        *required* — "Making it un-passable makes it un-forgettable" — and until then the
        honest reported state is "checked: no"."""
        output = tmp_path / "unpinned.json"
        bundle_store.export(output)

        report = verify_audit_bundle_offline(output)
        assert report.statement_signature_checked is False
        assert report.statement_signature_valid is False
        assert report.self_verification_ok is False
        # ...while every structural check still ran and passed, and the report says which.
        assert report.membership_root_ok is True
        assert report.section_digests_ok is True
        assert report.scope_consistent is True
        assert report.global_chain_ok is True

    def test_the_bundled_evidence_is_never_used_to_check_the_statement_signature(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """§4.3 / §5.2 rule C, structurally. The signer's own public key is inside
        ``bundled_key_evidence`` — it is one of the accepted keys — so a verifier that
        resolved the statement key from the artifact would report a valid signature with no
        caller input at all, and §5.2's circularity clamp would be unreachable. It must
        not."""
        output = tmp_path / "self_rooted.json"
        bundle_store.export(output)

        signer_key_id = _read(output)["statement"]["signer"]["key_id"]
        evidence = {
            r["key_id"] for r in _read(output)["sections"]["bundled_key_evidence"]
        }
        assert signer_key_id in evidence, (
            "the premise: the artifact does carry the bytes that would verify it"
        )
        assert verify_audit_bundle_offline(output).statement_signature_checked is False


# ---------------------------------------------------------------------------
# WI-289 Phase D — the §9 export ceremony, pinned rule by rule
# ---------------------------------------------------------------------------


def _v3(output: Path) -> Any:
    """Verify an artifact through Phase C's verdict verifier, self-consistency form.

    ``AcceptBundledKeys`` is the honest trust choice for a self-contained project bundle —
    it authenticates against the keys the bundle carries and is clamped to ``bundle_rooted``
    (Rule C). It is what the export self-check uses and what these Phase D pins assert
    against, because the invariants here are about the export ceremony and the fail-closed
    boundary, not about an auditor's external pin.
    """

    return verify_audit_bundle_v3(
        str(output), AcceptBundledKeys(operator_acknowledges_no_external_trust=True)
    )


def _membership_hashes(output: Path) -> set[str]:
    """The event-hash SET of a bundle's membership — what the boundary tests assert on.

    Counts alone cannot tell exclusive-lower from inclusive-upper (opposite boundary
    semantics can produce the same count); membership + boundary inclusion can (F4).
    """
    from regista._bundle_v3 import parse_event_member

    return {
        parse_event_member(
            base64.b64decode(r["canonical_envelope"]), base64.b64decode(r["signature"])
        ).event_hash_text
        for r in _read(output)["sections"]["events"]
    }


def _seq_hashes(store: Any) -> list[tuple[int, str]]:
    """Ordered ``[(global_seq, event_hash_text)]`` over the live stream, for boundary tests."""
    from regista._bundle_v3 import parse_event_member

    with store._mgr.transaction() as conn:
        rows = conn.execute(
            "SELECT global_seq, canonical_envelope, signature FROM events ORDER BY global_seq"
        ).fetchall()
    return [
        (
            r["global_seq"],
            parse_event_member(
                bytes(r["canonical_envelope"]), bytes(r["signature"])
            ).event_hash_text,
        )
        for r in rows
    ]


class TestPhaseDExportCeremony:
    """§9 rules 1-5, 7 on a real epoch. Each test pins one rule's fail-closed behavior."""

    def test_rule4_refuses_an_existing_destination_unless_overwrite(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """§9 rule 4 (WI-261): an audit bundle is evidence, so export never replaces one
        silently. The refusal is up front — nothing is read or signed — and ``overwrite``
        is the only key that lets a replacement through."""
        output = tmp_path / "rule4.json"
        bundle_store.export(output)
        original = output.read_bytes()

        with pytest.raises(RegistaError) as exc:
            bundle_store.export(output)
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT
        assert "refusing to overwrite" in str(exc.value)
        assert output.read_bytes() == original, "the existing artifact must be untouched"

        # The only way through is the explicit opt-in.
        bundle_store.export(output, overwrite=True)
        assert output.is_file()

    def test_rule2_preflight_mismatch_aborts_and_writes_nothing(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """§9 rule 2 / D1: a preflight whose event_count/head disagrees with the derived
        scope aborts — a moved head is an error, not a silently narrower bundle. Nothing is
        written, and a MATCHING preflight is accepted."""
        output = tmp_path / "rule2.json"
        # A matching preflight is accepted (the artifact is written).
        clean = tmp_path / "rule2_ok.json"
        good = bundle_store.export(clean)
        matching = {
            "event_count": good["event_count"],
            "first_event_hash": bundle_store.genesis_event_hash,
            "last_event_hash": _read(clean)["statement"]["scope"]["last_event_hash"],
        }
        bundle_store.export(output, preflight=matching)
        assert output.is_file()

        # A count that disagrees aborts, and the destination is never created.
        aborted = tmp_path / "rule2_abort.json"
        bad = dict(matching, event_count=matching["event_count"] + 1)
        with pytest.raises(RegistaError) as exc:
            bundle_store.export(aborted, preflight=bad)
        assert exc.value.code == ErrorCode.BUNDLE_STATEMENT_INVALID
        assert "preflight comparison failed" in str(exc.value)
        assert not aborted.exists(), "a preflight mismatch must write nothing"

    def test_rule5_self_verifies_the_partial_before_replace(
        self, bundle_store: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """§9 rule 5 / D11: the self-verification runs over the ``.partial`` BEFORE
        ``os.replace``. If ``os.replace`` were reached on a corrupt artifact this test would
        see the destination created; instead the corrupt bytes never leave the ``.partial``.
        """
        real_replace = os.replace
        replaced: list[Any] = []

        def spy_replace(src: Any, dst: Any, **kwargs: Any) -> None:
            replaced.append((src, dst))
            real_replace(src, dst, **kwargs)

        real_write_bytes = Path.write_bytes

        def corrupting_write(path: Path, data: bytes) -> int:
            if path.name.endswith(".partial"):
                doctored = json.loads(data)
                doctored["statement"]["scope"]["event_count"] = 4242
                return real_write_bytes(path, canonical_bundle_bytes(doctored))
            return real_write_bytes(path, data)

        monkeypatch.setattr(os, "replace", spy_replace)
        monkeypatch.setattr(Path, "write_bytes", corrupting_write)
        output = tmp_path / "rule5.json"
        with pytest.raises(RegistaError) as exc:
            bundle_store.export(output)
        assert exc.value.code == ErrorCode.BUNDLE_WRITE_CORRUPT
        assert replaced == [], "os.replace must NOT run when the temp fails self-verify"
        assert not output.exists()
        assert len(list(tmp_path.glob("rule5.json.*.partial"))) == 1


class _ArchiveStore:
    """A fresh v6 epoch with events that can be archived — the harness rules 1 and 3 need.

    ``bundle_store`` is module-scoped and read-only; rules 1 (an invalid event injected) and
    3 (rows moved to ``events_archive``) mutate the store, so they get their own throwaway
    project each.
    """

    def __init__(self, store: Any, keyset: Any, terminal_entity: uuid.UUID) -> None:
        self.store = store
        self.keyset = keyset
        self.terminal_entity = terminal_entity

    def export(self, output: Path, **kwargs: Any) -> dict[str, Any]:
        params: dict[str, Any] = {
            "root_governance": ROOT_GOVERNANCE,
            "signing_principal_id": BUNDLE_SIGNER,
        }
        params.update(kwargs)
        return self.store.export_audit_bundle(str(output), **params)


@pytest.fixture
def archive_store(tmp_path: Path) -> Any:
    """A fresh epoch whose terminal work item can be archived into ``events_archive``."""
    from regista._v6_writer import append_v6_event

    keyset = make_v6_keyset(tmp_path)
    name = f"bundle_arch_{uuid.uuid4().hex[:8]}"
    store = Regista.create_project(DSN, name, keyset.path)
    open_v6_epoch(store, keyset, may_sign_bundles=True)
    entity_id = uuid.uuid4()
    for transition in ("created", "completed"):
        with store._mgr.transaction() as conn:
            append_v6_event(
                conn,
                store._keys,
                entity_kind="work_item",
                entity_id=entity_id,
                transition=transition,
                actor_id=BUNDLE_SIGNER,
                actor_kind="agent",
                producer=v6_producer(),
                payload={"state": transition},
            )
    try:
        yield _ArchiveStore(store, keyset, entity_id)
    finally:
        store.close()
        drop_project_schema(DSN, name)


class TestPhaseDExportCeremonyOnAFreshEpoch:
    """Rules 1 and 3, which mutate the store and so need their own epoch."""

    def test_rule1_refuses_to_sign_over_an_invalid_event(
        self, archive_store: Any, tmp_path: Path
    ) -> None:
        """§9 rule 1: strict-verify every event before signing; refuse a corpus containing
        an ``Applicability.INVALID`` event. Signing a membership root over a known-bad event
        would make regista attest to it. The invalid event is created by a direct row
        rewrite — the attacker's UPDATE, never the API."""
        # Rewrite a signed row column so its verdict is INVALID (the row no longer reconciles
        # against its own signed envelope).
        with archive_store.store._mgr.transaction() as conn:
            conn.execute(
                "UPDATE events SET actor_id = %s WHERE transition = %s",
                ["agent:impostor", "completed"],
            )
        output = tmp_path / "rule1.json"
        with pytest.raises(RegistaError) as exc:
            archive_store.export(output)
        assert exc.value.code == ErrorCode.BUNDLE_STATEMENT_INVALID
        assert "invalid events" in str(exc.value)
        assert not output.exists(), "nothing is written when the source has an invalid event"

    def test_rule3_consolidates_events_archive_into_a_complete_store(
        self, archive_store: Any, tmp_path: Path
    ) -> None:
        """§9 rule 3 (WI-259): a complete-store export reads ``events`` consolidated with
        ``events_archive`` — the complete logical stream Stage 4 restores. A complete-store
        that silently omitted archived rows would be a signed FALSE statement, strictly worse
        than today's unsigned one.

        The terminal event is moved into ``events_archive`` exactly as Stage-4 archival does
        (``_archive.py``: INSERT … SELECT then DELETE, referrers first), without the
        workflow terminal-state gating that a full ``archive_events`` run needs — the point
        here is the export READ, not the archival policy."""
        # Baseline: the whole chain before archiving.
        before = tmp_path / "before.json"
        base = archive_store.export(before)
        full_count = base["event_count"]

        # Simulate Stage-4 archival of the terminal ("completed") event.
        store = archive_store.store
        with store._mgr.transaction() as conn:
            row = conn.execute(
                "SELECT event_id FROM events WHERE transition = %s ORDER BY global_seq DESC "
                "LIMIT 1",
                ["completed"],
            ).fetchone()
            assert row is not None, "the terminal event must exist"
            eid = row["event_id"]
            assert _archive_relation_present(conn), "events_archive relation must exist"
            conn.execute(
                "INSERT INTO events_archive SELECT * FROM events WHERE event_id = %s", [eid]
            )
            conn.execute("DELETE FROM hook_queue WHERE event_id = %s", [eid])
            conn.execute("DELETE FROM witness_receipts WHERE event_id = %s", [eid])
            conn.execute("DELETE FROM events WHERE event_id = %s", [eid])
            live = conn.execute("SELECT count(*) AS c FROM events").fetchone()["c"]
            arch = conn.execute("SELECT count(*) AS c FROM events_archive").fetchone()["c"]
        assert arch == 1 and live == full_count - 1, "the row moved to events_archive"

        # A complete-store export must still cover the WHOLE logical stream.
        after = tmp_path / "after.json"
        result = archive_store.export(after)
        assert result["scope_kind"] == "complete-store"
        assert result["event_count"] == full_count, (
            "a complete-store omitting archived rows is a signed false statement (§9 rule 3)"
        )
        after_hashes = {
            r["canonical_envelope"] for r in _read(after)["sections"]["events"]
        }
        before_hashes = {
            r["canonical_envelope"] for r in _read(before)["sections"]["events"]
        }
        assert after_hashes == before_hashes, "the archived event is back in the stream"
        assert _v3(after).applicability != "invalid"


# ---------------------------------------------------------------------------
# WI-289 Phase D fix round — F1 (concurrent append) and F2 (destination TOCTOU)
# ---------------------------------------------------------------------------


class TestPhaseDConcurrencyAndTOCTOU:
    """The two production blockers Sol's concurrent probes found (WI-340 F1/F2).

    A single-threaded run cannot see either: F1 needs an append racing the export read, F2
    needs a destination appearing in the window between the up-front ``exists()`` check and
    the final publication. Both are pinned here with the race made deterministic.
    """

    def test_f1_a_scope_disagreeing_with_the_locked_head_aborts(
        self, archive_store: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """§9 rule 1 (F1): a complete-store whose scope does not equal the store head observed
        under the export lock is refused, never signed. Simulates the torn/advanced-head read
        by returning an advanced head from the locked snapshot; the assertion aborts before
        any write. Red-on-pre-fix: before F1 there was no head captured and no assertion, so
        the stale prefix was signed as a complete-store."""
        import regista._bundle as bundle_mod

        real = bundle_mod._lock_export_snapshot_head

        def advanced(conn: Any) -> tuple[str | None, int]:
            _, count = real(conn)
            return "sha256:" + "ff" * 32, count + 1  # pretend an (N+1)th committed

        monkeypatch.setattr(bundle_mod, "_lock_export_snapshot_head", advanced)
        out = tmp_path / "stale.json"
        with pytest.raises(RegistaError) as exc:
            archive_store.export(out)
        assert exc.value.code == ErrorCode.BUNDLE_STATEMENT_INVALID
        assert "stale complete-store" in str(exc.value)
        assert not out.exists(), "a stale complete-store must never be written"

    def test_f1_a_concurrent_append_is_serialised_behind_the_export_lock(
        self, archive_store: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """§9 rule 1 (F1): the export holds the event_chain_head lock across its read, so a
        concurrent append CANNOT commit mid-export — it serialises behind the export. The
        deterministic proof is inside the read hook: after the appender has had time to run,
        it is still blocked (its event has not committed), because the export holds the head
        lock. Red-on-pre-fix: without the lock the append commits during the sleep and the
        blocked-assertion fails.
        """
        import regista._bundle as bundle_mod
        from regista._v6_writer import append_v6_event

        store = archive_store.store
        with store._mgr.transaction() as conn:
            n_before = int(conn.execute("SELECT count(*) AS c FROM events").fetchone()["c"])

        committed = threading.Event()

        def appender() -> None:
            with store._mgr.transaction() as conn:
                append_v6_event(
                    conn, store._keys, entity_kind="work_item", entity_id=uuid.uuid4(),
                    transition="created", actor_id=BUNDLE_SIGNER, actor_kind="agent",
                    producer=v6_producer(), payload={"concurrent": True},
                )
            committed.set()

        real_read = bundle_mod._read_export_rows
        state: dict[str, Any] = {}

        def read_hook(conn: Any, **kw: Any) -> Any:
            if "t" not in state:
                t = threading.Thread(target=appender)
                t.start()
                state["t"] = t
                # Give the appender ample time to reach append_v6_event's FOR UPDATE on the
                # head sentinel and block there. The export holds that lock, so it must NOT
                # have committed.
                time.sleep(1.5)
                assert not committed.is_set(), (
                    "the concurrent append committed during the export read — the head lock "
                    "is not serialising appends (F1 regression)"
                )
            return real_read(conn, **kw)

        monkeypatch.setattr(bundle_mod, "_read_export_rows", read_hook)
        out = tmp_path / "snapshot.json"
        result = archive_store.export(out)
        state["t"].join(timeout=15)
        assert committed.is_set(), "the append must complete once the export released the lock"

        # Export signed the consistent snapshot as it stood under the lock; the append landed
        # after. The complete-store is never a stale prefix.
        assert result["scope_kind"] == "complete-store"
        assert result["event_count"] == n_before
        with store._mgr.transaction() as conn:
            n_after = int(conn.execute("SELECT count(*) AS c FROM events").fetchone()["c"])
        assert n_after == n_before + 1, "the serialised append is now in the store"

    def test_f2_a_destination_created_after_the_check_is_not_clobbered(
        self, archive_store: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """§9 rule 4 (F2): the no-clobber rule is enforced at PUBLICATION, not just by the
        up-front exists() check. A destination created in the TOCTOU window (here, during the
        self-verification, after the up-front check passed) is refused, not silently
        replaced. Red-on-pre-fix: the old os.replace clobbered the racer's file."""
        import regista._bundle as bundle_mod

        out = tmp_path / "toctou.json"
        sentinel = b'{"prior": "artifact that must survive"}'
        real_verify = bundle_mod.verify_audit_bundle_v3

        def verify_hook(path: Any, trust: Any, **kw: Any) -> Any:
            # A racer publishes to the destination AFTER export's up-front exists() check.
            if not out.exists():
                out.write_bytes(sentinel)
            return real_verify(path, trust, **kw)

        monkeypatch.setattr(bundle_mod, "verify_audit_bundle_v3", verify_hook)
        with pytest.raises(RegistaError) as exc:
            archive_store.export(out)  # overwrite=False
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT
        assert "overwrite" in str(exc.value)
        assert out.read_bytes() == sentinel, "the racer's destination must not be clobbered"

    def test_fr2_1_the_head_lock_is_held_through_signing(
        self, archive_store: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """§9 rule 1 (WI-340 FR2-1): the head lock is held through SIGNING, not only the read.
        The hook fires at the sign step (``build_bundle_v3_document``, now inside the lock); a
        concurrent append is still blocked there, so no event can commit between the read and
        the signed ``created_at`` and make a complete-store false. Red-on-pre-fix: with produce
        /sign dedented outside the lock, the append commits at signing time and the
        blocked-assertion fails."""
        import regista._bundle as bundle_mod
        from regista._v6_writer import append_v6_event

        store = archive_store.store
        committed = threading.Event()

        def appender() -> None:
            with store._mgr.transaction() as conn:
                append_v6_event(
                    conn, store._keys, entity_kind="work_item", entity_id=uuid.uuid4(),
                    transition="created", actor_id=BUNDLE_SIGNER, actor_kind="agent",
                    producer=v6_producer(), payload={"racing_the_signature": True},
                )
            committed.set()

        real_build = bundle_mod.build_bundle_v3_document
        state: dict[str, Any] = {}

        def build_hook(**kw: Any) -> Any:
            if "t" not in state:
                t = threading.Thread(target=appender)
                t.start()
                state["t"] = t
                time.sleep(1.5)
                assert not committed.is_set(), (
                    "an append committed at SIGNING time — the head lock is released before "
                    "signing (FR2-1 regression: produce/sign is outside the critical section)"
                )
            return real_build(**kw)

        monkeypatch.setattr(bundle_mod, "build_bundle_v3_document", build_hook)
        out = tmp_path / "sign_locked.json"
        result = archive_store.export(out)
        state["t"].join(timeout=15)
        assert committed.is_set(), "the append completes once the export released the lock"
        assert result["scope_kind"] == "complete-store"
        assert result["self_verification"]["applicability"] == "bundle_rooted"

    def test_fr2_2_a_unique_temp_defeats_a_shared_path_substitution(
        self, archive_store: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """§9 rule 5 (WI-340 FR2-2): the export publishes bytes it verified, over a UNIQUE
        exclusively-created temp inode — not a fixed shared ``<name>.partial`` path a second
        exporter could rewrite between self-verify and publish. The racer here rewrites the
        predictable shared path AFTER self-verification; because the real temp name is
        unpredictable, the published artifact is still the verified bytes. Red-on-pre-fix: the
        old fixed ``<name>.partial`` path is exactly what the racer overwrites, so the publish
        used unverified bytes."""
        import regista._bundle as bundle_mod

        out = tmp_path / "sub.json"
        corrupt = b'{"corrupt": "substituted-after-verification"}'
        real_verify = bundle_mod.verify_audit_bundle_v3

        def verify_hook(path: Any, trust: Any, **kw: Any) -> Any:
            report = real_verify(path, trust, **kw)
            # A racer overwrites the PREDICTABLE shared path a pre-FR2-2 exporter would use.
            (tmp_path / "sub.json.partial").write_bytes(corrupt)
            return report

        monkeypatch.setattr(bundle_mod, "verify_audit_bundle_v3", verify_hook)
        result = archive_store.export(out)
        assert out.is_file()
        assert out.read_bytes() != corrupt, "publish used the racer's substituted bytes (FR2-2)"
        # And what was published is the verified artifact (self-verifies clean).
        assert result["self_verification"]["applicability"] == "bundle_rooted"
        assert _v3(out).applicability != "invalid"


# ---------------------------------------------------------------------------
# WI-289 rule 6 — dependency closure beyond the signer's authority
# ---------------------------------------------------------------------------


class TestRule6DependencyClosure:
    """§9 rule 6 / RECONCILIATION.md Resolution 4, on a real artifact.

    A complete-store missing a dependency it names is INVALID; a contiguous-range names each
    out-of-scope dependency rather than treating its absence as satisfaction. The closure
    walked here is the one BEYOND Phase B/C's signer authority — key lifecycle, project
    acceptance, workflow registration, checkpoints, verdict subjects.
    """

    def _ordered(self, output: Path, *, preceding: str | None) -> Any:
        from regista._bundle_v3 import derive_chain_order, parse_event_member

        members = [
            parse_event_member(
                base64.b64decode(r["canonical_envelope"]), base64.b64decode(r["signature"])
            )
            for r in _read(output)["sections"]["events"]
        ]
        return derive_chain_order(members, preceding_event_hash=preceding)

    def test_a_clean_complete_store_is_closure_complete(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        output = tmp_path / "closed.json"
        bundle_store.export(output)
        assert compute_dependency_closure(self._ordered(output, preceding=None)) == [], (
            "a healthy whole-chain export names no dependency it does not contain"
        )
        assert _v3(output).applicability != "invalid"

    def test_compute_dependency_closure_detects_a_missing_named_dependency(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """The walk itself, isolated. Dropping the acceptance every ordinary event's
        ``key_binding_event_hash`` anchors to makes it a named-but-absent dependency; the
        closure walk reports it with its kind. (In a linear complete-store this ALSO breaks
        chain ordering, which is why the invalid-verdict face of rule 6 is exercised through a
        contiguous-range below — but the walk that Resolution 4 rests on is asserted here
        directly.)"""
        output = tmp_path / "walk.json"
        bundle_store.export(output)
        ordered = list(self._ordered(output, preceding=None))
        anchors = {
            m.envelope["signing"]["key_binding_event_hash"]
            for m in ordered
            if m.transition not in ("project_initialized", "principal_key_accepted")
            and m.envelope["signing"].get("key_binding_event_hash")
        }
        assert anchors, "an ordinary event must anchor to an acceptance"
        kept = [m for m in ordered if m.event_hash_text not in anchors]
        missing = compute_dependency_closure(kept)
        assert any(kind == "key_binding" and ref in anchors for kind, ref, _ in missing), (
            missing
        )

    def test_a_contiguous_range_names_its_out_of_scope_dependencies(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """RECONCILIATION.md Resolution 4's observable half: a bounded range legitimately
        excludes an event's key-binding anchor (an earlier acceptance), and the verifier
        NAMES it as outside scope in the report notes — never treats its absence as
        satisfaction. This is the invalid-vs-outside-scope distinction that separates a
        complete-store from a contiguous-range."""
        with bundle_store.store._mgr.transaction() as conn:
            seqs = [
                r["global_seq"]
                for r in conn.execute(
                    "SELECT global_seq FROM events ORDER BY global_seq"
                ).fetchall()
            ]
        # A tail window that starts AFTER the acceptances, so the ordinary events' key-binding
        # anchors fall outside the window.
        cut = seqs[-2]
        output = tmp_path / "range.json"
        result = bundle_store.export(output, since_seq=cut)
        assert result["scope_kind"] == "contiguous-range"
        report = _v3(output)
        assert report.applicability != "invalid", report.to_dict()
        assert any("dependency_outside_scope" in n for n in report.notes), report.notes


# ---------------------------------------------------------------------------
# WI-289 cluster-4 counterparts — the 11 retired bundle-v3 offline-verification
# invariants, re-asserted against a real v6 epoch under the v3 verdict model.
# ---------------------------------------------------------------------------


class TestWI289Cluster4Counterparts:
    """Each retired ``tests/test_bundle.py`` (bundle-v2) node's surviving invariant, carried
    forward onto bundle v3. The retirement ledger's ``covered_by`` pointers name these tests;
    ``TestWI289Cluster4LedgerMapping`` machine-checks that mapping.

    The formula and the report shape changed — the unkeyed bundle hash is gone, replaced by
    the statement signature and the §5 axis model — but each invariant survives the epoch
    reset, which is the whole content of the ledger's carry-forward strings.
    """

    # -- test_verify_clean_bundle_passes --
    def test_a_clean_v3_bundle_verifies_offline(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """A clean exported bundle verifies offline with no findings (statement-signature
        model). Retires ``TestVerifyAuditBundleOffline::test_verify_clean_bundle_passes``."""
        output = tmp_path / "clean.json"
        bundle_store.export(output)
        report = _v3(output)
        assert report.applicability == "bundle_rooted"
        assert report.membership_signature == "valid_bundled_key"
        assert list(report.findings) == [], report.findings

    # -- test_export_with_since_seq --
    def test_since_seq_is_an_exclusive_lower_bound(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """``since_seq`` is an EXCLUSIVE lower bound: the boundary event is NOT in the
        membership, the next one IS, and the membership is exactly the tail set (F4:
        membership + boundary, not a count that opposite semantics could also produce).
        Retires ``TestExportAuditBundle::test_export_with_since_seq``."""
        sh = _seq_hashes(bundle_store.store)
        cut, boundary_hash = sh[0]
        next_hash = sh[1][1]
        output = tmp_path / "since.json"
        result = bundle_store.export(output, since_seq=cut)
        assert result["scope_kind"] == "contiguous-range"
        membership = _membership_hashes(output)
        assert boundary_hash not in membership, "since_seq is EXCLUSIVE — boundary excluded"
        assert next_hash in membership
        assert membership == {h for s, h in sh if s > cut}

    # -- test_until_seq_is_an_inclusive_upper_bound --
    def test_until_seq_is_an_inclusive_upper_bound(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """``until_seq`` is an INCLUSIVE upper bound: the boundary event IS in the membership,
        the one after is NOT, and the membership is exactly the prefix set (F4). Retires
        ``TestExportBounds::test_until_seq_is_an_inclusive_upper_bound``."""
        sh = _seq_hashes(bundle_store.store)
        mid = len(sh) // 2
        cut, boundary_hash = sh[mid]
        after_hash = sh[mid + 1][1]
        output = tmp_path / "until.json"
        bundle_store.export(output, until_seq=cut)
        membership = _membership_hashes(output)
        assert boundary_hash in membership, "until_seq is INCLUSIVE — boundary included"
        assert after_hash not in membership
        assert membership == {h for s, h in sh if s <= cut}

    # -- test_since_and_until_form_a_window --
    def test_since_and_until_form_a_window(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """``since``/``until`` bound the window exactly — exclusive lower, inclusive upper —
        asserted by MEMBERSHIP at both boundaries (F4). Retires
        ``TestExportBounds::test_since_and_until_form_a_window``."""
        sh = _seq_hashes(bundle_store.store)
        lo, lo_hash = sh[0]
        hi, hi_hash = sh[-2]
        after_hi_hash = sh[-1][1]
        output = tmp_path / "window.json"
        result = bundle_store.export(output, since_seq=lo, until_seq=hi)
        assert result["scope_kind"] == "contiguous-range"
        membership = _membership_hashes(output)
        assert lo_hash not in membership, "lower bound is EXCLUSIVE"
        assert hi_hash in membership, "upper bound is INCLUSIVE"
        assert after_hi_hash not in membership
        assert membership == {h for s, h in sh if lo < s <= hi}

    # -- test_chunked_exports_both_verify_offline --
    def test_chunked_exports_both_verify_and_a_preflight_matches(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """A corpus split into chunks yields a DISJOINT UNION that partitions the whole stream
        (no overlap, no gap — not merely a count that sums), each chunk independently
        verifiable; a matching preflight is accepted on each chunk (§9.2). Retires
        ``TestExportBounds::test_chunked_exports_both_verify_offline``."""
        sh = _seq_hashes(bundle_store.store)
        whole = {h for _, h in sh}
        cut = sh[len(sh) // 2][0]
        head, tail = tmp_path / "head.json", tmp_path / "tail.json"
        bundle_store.export(head, until_seq=cut)
        bundle_store.export(tail, since_seq=cut)
        head_m, tail_m = _membership_hashes(head), _membership_hashes(tail)
        assert head_m.isdisjoint(tail_m), "chunks must not overlap"
        assert head_m | tail_m == whole, "chunks must partition the whole stream (no gap)"
        for path in (head, tail):
            assert _v3(path).applicability != "invalid", path
        # The preflight for the head chunk matches its own derived scope.
        head_scope = _read(head)["statement"]["scope"]
        rematch = tmp_path / "head2.json"
        bundle_store.export(
            rematch,
            until_seq=cut,
            preflight={
                "event_count": head_scope["event_count"],
                "first_event_hash": head_scope["first_event_hash"],
                "last_event_hash": head_scope["last_event_hash"],
            },
        )
        assert rematch.is_file(), "a matching preflight is accepted"

    # -- test_binding_mismatch_fails_closed --
    def test_a_principal_key_binding_mismatch_fails_closed(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """v6 principal↔key binding verification in bundle verification: relabelling which
        principal a bundled key belongs to is a registry-chain inconsistency the verifier
        surfaces (§4.3). Exercised under an EXTERNAL trust form (a pinned fingerprint) where a
        clean bundle is ``consistent`` with no such finding — so the tamper produces a
        DISTINGUISHING verdict, not one a clean bundle already satisfies (F3: the prior
        ``!= externally_authenticated`` + ``event_trust_root in (bundled_only, absent)`` were
        all true of a clean bundle too). Retires
        ``TestOfflineSignatureVerification::test_binding_mismatch_fails_closed``."""
        output = tmp_path / "binding.json"
        bundle_store.export(output)
        document = _read(output)
        signer_fp = next(
            r["fingerprint"]
            for r in document["sections"]["bundled_key_evidence"]
            if r["principal_id"] == BUNDLE_SIGNER
        )
        trust = TrustPolicy.from_fingerprints([signer_fp])
        # Baseline under the SAME external trust form: registry is consistent, no finding.
        clean = verify_audit_bundle_v3(str(output), trust).to_dict()
        assert clean["registry_chain_consistency"] == "consistent", clean
        assert not any("registry_chain_consistency" in f for f in clean["findings"]), clean

        # Swap the principal_id on the signer's own key evidence and re-sign as the strongest
        # adversary; the evidence now disagrees with the principal its SIGNED acceptance binds.
        for record in document["sections"]["bundled_key_evidence"]:
            if record["principal_id"] == BUNDLE_SIGNER:
                record["principal_id"] = "agent:someone-else"
        _write(output, _resign(document, bundle_store.keyset))
        tampered = verify_audit_bundle_v3(str(output), trust).to_dict()
        assert tampered["registry_chain_consistency"] == "inconsistent", tampered
        assert any("registry_chain_consistency" in f for f in tampered["findings"]), tampered
        assert tampered["applicability"] != "externally_authenticated", tampered

    # -- test_clean_mixed_bundle_verifies_signatures --
    def test_offline_event_signature_verification_reports_via_the_axes(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """Offline event-signature verification is reported through the A-axes (the mixed
        HMAC population dies with the epoch, so only the v6 half of the retired invariant
        survives): a clean bundle's ordinary events authenticate, the genesis bootstrap is
        counted as not-yet-pinned rather than failed. Retires
        ``TestOfflineSignatureVerification::test_clean_mixed_bundle_verifies_signatures``."""
        output = tmp_path / "axes.json"
        bundle_store.export(output)
        d = _v3(output).to_dict()
        assert d["event_verification_ran"] is True
        assert d["event_authentication"] == "legacy_partial", (
            "ordinary v6 events authenticate; the unpinned genesis keeps it below FULL"
        )
        # F4: assert EVERY event is individually attributed (ed25519), not merely ≥1. A v6
        # epoch has no shared-secret (HMAC) attribution, so the individual count is the WHOLE
        # stream and shared_secret/none are zero. (Attribution — is the actor individually
        # named — is distinct from whether the signature chained to a pinned key: the genesis
        # bootstrap is individually attributed here even though its authority is unpinned,
        # which is what keeps A4 at legacy_partial rather than FULL.)
        ac = d["event_attribution_counts"]
        assert ac is not None
        assert ac.get("shared_secret", 0) == 0, "a v6 epoch has no HMAC attribution"
        assert ac.get("none", 0) == 0
        assert ac["individual"] == d["event_count"], (
            "every event's ed25519 signature must be individually attributed"
        )

    # -- test_registry_absent_is_recorded_and_fails_closed --
    def test_absent_key_evidence_is_recorded_and_fails_closed(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """With the key evidence stripped, offline verification of the asymmetric events
        cannot authenticate them and never silently passes — the absence is recorded, not
        promoted to a pass. Retires
        ``TestOfflineSignatureVerification::test_registry_absent_is_recorded_and_fails_closed``.
        """
        output = tmp_path / "no_registry.json"
        bundle_store.export(output)
        document = _read(output)
        document["sections"]["bundled_key_evidence"] = []
        _write(output, _resign(document, bundle_store.keyset))
        report = _v3(output)
        assert report.applicability != "externally_authenticated"
        # No key material means no event key resolves; the trust root is absent, never a pass.
        assert report.event_trust_root == "absent", report.to_dict()

    # -- test_unknown_scheme_fails_closed --
    def test_relabelling_an_event_scheme_id_fails_closed(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """v6 signs ``scheme_id`` and requires equality with the trusted key's scheme (§3.1);
        relabelling it in a bundled key evidence record is a scheme mismatch, not a verifier
        selector, and fails closed to ``invalid`` — not merely "not externally authenticated"
        (which every project bundle is anyway; that was the vacuous assertion this replaces,
        F3). Retires ``TestOfflineSignatureVerification::test_unknown_scheme_fails_closed``."""
        output = tmp_path / "scheme.json"
        bundle_store.export(output)
        document = _read(output)
        for record in document["sections"]["bundled_key_evidence"]:
            record["scheme_id"] = "ed448-not-a-real-selector"
        _write(output, _resign(document, bundle_store.keyset))
        report = _v3(output)
        assert report.applicability == "invalid", report.to_dict()
        assert any("scheme_id must be 'ed25519'" in f for f in report.findings), (
            report.findings
        )

    # -- test_v1_bundle_signature_check_skipped --
    def test_a_format_version_downgrade_is_rejected_outright(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """A format-version downgrade cannot silently pass: the v3 verifier rejects a
        non-v3 ``format_version`` outright (downgrade fails closed; BUNDLE-V3.md §6). Retires
        ``TestOfflineSignatureVerification::test_v1_bundle_signature_check_skipped``."""
        output = tmp_path / "downgrade.json"
        bundle_store.export(output)
        document = _read(output)
        document["statement"]["version"] = 1
        _write(output, _resign(document, bundle_store.keyset))
        report = _v3(output)
        assert report.applicability == "invalid", report.to_dict()
        assert report.structure == "malformed", report.to_dict()

    # -- test_unverifiable_store_exits_3_by_default --
    def test_cli_export_exit_code_is_the_self_verification_applicability(
        self, bundle_store: Any, tmp_path: Path
    ) -> None:
        """The v3 CLI export exit code is driven by the self-verification applicability
        (§9.7): exit 0 requires externally_authenticated, which a project bundle cannot reach
        offline (WI-337), so a healthy project export self-verifies at ``bundle_rooted`` and
        the CLI exits 2. F4: this invokes the REAL ``regista`` process and asserts the PROCESS
        exit code — a CLI regression that exited 0 would pass a mapping-constant check but is
        caught here. Retires
        ``TestCliExportExitCodes::test_unverifiable_store_exits_3_by_default``."""
        import subprocess
        import sys

        env = {k: v for k, v in os.environ.items() if k != "REGISTA_DSN"}
        env["REGISTA_KEY_PATH"] = bundle_store.keyset.path
        out = tmp_path / "cli_exit.json"
        cli = [sys.executable, "-m", "regista._cli"]
        export = subprocess.run(
            [
                *cli,
                "--dsn", DSN, "--project", bundle_store.project,
                "bundle", "export", "--output", str(out),
                "--signing-principal-id", BUNDLE_SIGNER,
                "--root-governance-mode", "solo",
                "--root-governance-threshold", "1",
                "--root-governance-signer-count", "1",
            ],
            env=env, capture_output=True, text=True,
        )
        # bundle_rooted is the honest offline ceiling for a project bundle → exit 2, NOT 0.
        assert export.returncode == 2, (export.returncode, export.stderr[-800:])
        assert out.is_file(), export.stderr[-800:]

        verify = subprocess.run(
            [*cli, "bundle", "verify", str(out), "--accept-bundled-keys"],
            env=env, capture_output=True, text=True,
        )
        assert verify.returncode == 2, (verify.returncode, verify.stderr[-800:])

        no_trust = subprocess.run(
            [*cli, "bundle", "verify", str(out)], env=env, capture_output=True, text=True,
        )
        assert no_trust.returncode == 1, (no_trust.returncode, no_trust.stderr[-800:])
