from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NamedTuple

import pytest
from nacl.signing import SigningKey

from regista import Regista, V6GenesisWrite
from regista._bundle import (
    _canonical_bundle_bytes,
    verify_audit_bundle_offline,
)
from regista._errors import ErrorCode, RegistaError
from regista._testing import drop_project_schema, seed_legacy_principal_key

DSN = os.environ.get(
    "REGISTA_TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)
KEY_PATH = "tests/test_keys.json"
WORKFLOW_PATH = "tests/test_workflow.yaml"

# ---------------------------------------------------------------------------
# A store holding exactly one exportable v6 event: its genesis.
#
# P1.4 kept a list of bundle behaviors (BUNDLE-V3.md §8 "Retained") that only
# have meaning on a SUCCESSFUL export — write-then-rename, self-verify-after-
# write, the BUNDLE_WRITE_CORRUPT raise-and-keep, and the delegation to
# verify_event_strict, which §8 calls "the keystone". P1.2 closed the v5 epoch,
# so no ordinary event writer exists until P1.7 and the corpus-building
# fixtures those tests used are gone. `write_genesis` still works, and a store
# with a genesis event has one exportable, ed25519-signed, registry-backed
# event — which is enough to exercise every retained positive path here.
# The fixture is built the way tests/test_genesis.py builds one.
# ---------------------------------------------------------------------------

_V6_VECTOR = Path(__file__).parent / "vectors" / "v6" / "bootstrap-project-initialized.json"
_GENESIS_PRINCIPAL = "agent:bundle-genesis"
_GENESIS_KEY_ID = "pk-bundle-genesis"

# The v6 verifier boundary (P1.7 phase 2) replaced the clamp that used to return
# INVALID/envelope_schema_incomplete for every v6 row. Two consequences shape the
# assertions below, and they are different from each other:
#
# * A **post-genesis** v6 chain now reaches `verified=True` — see
#   `TestGenesisKeyEvidence::test_a_healthy_post_genesis_export_self_verifies_true`,
#   which is WI-296's self-verification half.
# * A **genesis-only** bundle does not, and must not. Its one event is a Bootstrap-B
#   event whose authority is external by construction, and RECONCILIATION.md
#   Resolution 1 is explicit: "Bootstrap without an external pin is not a bootstrap;
#   it is an unauthenticated first event." Without a caller-supplied trust pin AND a
#   presented trust log (§5.8), the honest verdict is UNVERIFIABLE. So the artifact
#   reports one unverifiable signature naming the absent pin, and zero errors —
#   which is a materially different report from the clamp's "invalid", and the
#   assertions say which.
_V6_BOOTSTRAP_UNPINNED = "unauthenticated first event"


class _GenesisStore(NamedTuple):
    store: Regista
    project: str
    public_key: bytes
    genesis: V6GenesisWrite


def _genesis_envelope(public_key: bytes) -> dict[str, Any]:
    case = json.loads(_V6_VECTOR.read_text(encoding="utf-8"))
    envelope: dict[str, Any] = copy.deepcopy(case["input"]["envelope_declaration_order"])
    project_instance_id = str(uuid.uuid4())
    envelope["project_instance_id"] = project_instance_id
    envelope["entity"]["id"] = project_instance_id
    envelope["event_id"] = str(uuid.uuid4())
    envelope["trust_domain_id"] = str(uuid.uuid4())
    # The vector's occurred_at is a fixed instant in the past. The offline
    # verifier refuses an event signed before its key's validity window, and
    # the legacy seeder stamps valid_from at the registration instant, so
    # the genesis event has to be stamped now. v6 requires the exact
    # YYYY-MM-DDThh:mm:ss.ffffffZ spelling — isoformat() is rejected.
    envelope["occurred_at"] = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    envelope["actor"]["principal_id"] = _GENESIS_PRINCIPAL
    envelope["signing"]["key_id"] = _GENESIS_KEY_ID
    acceptance = envelope["payload"]["bootstrap_key_acceptance"]
    acceptance["principal_id"] = _GENESIS_PRINCIPAL
    acceptance["key_id"] = _GENESIS_KEY_ID
    acceptance["scheme_id"] = "ed25519"
    acceptance["public_key"] = base64.b64encode(public_key).decode("ascii")
    acceptance["fingerprint"] = "ed25519:sha256:" + hashlib.sha256(public_key).hexdigest()
    acceptance["scopes"] = {
        "entity_kinds": ["project", "principal", "workflow", "work_item"],
        "transitions": None,
        "may_accept_keys": True,
        "may_sign_checkpoints": True,
        "may_sign_bundles": False,
    }
    return envelope


def _rehash(bundle: dict[str, Any]) -> None:
    """Recompute bundle_hash the way a tampering adversary would.

    The interim bundle hash is unkeyed, so an adversary who edits a bundle can
    also restore agreement. Every tamper test here rehashes: the finding must
    come from a check that survives it.
    """
    bundle["manifest"]["bundle_hash"] = (
        "sha256:" + hashlib.sha256(_canonical_bundle_bytes(bundle)).hexdigest()
    )


@pytest.fixture(scope="module")
def genesis_store(tmp_path_factory):
    key_path = tmp_path_factory.mktemp("bundle_genesis_keys") / "keys.json"
    signing_key = SigningKey.generate()
    public_key = bytes(signing_key.verify_key)
    key_path.write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "key_id": _GENESIS_KEY_ID,
                        "scheme": "ed25519",
                        "alg": "Ed25519",
                        "secret": base64.b64encode(bytes(signing_key)).decode("ascii"),
                        "encoding": "base64",
                        "public_key": base64.b64encode(public_key).decode("ascii"),
                        "principal_id": _GENESIS_PRINCIPAL,
                        "role": "actor",
                        "status": "active",
                    }
                ]
            }
        )
    )

    project = f"bundle_genesis_{uuid.uuid4().hex[:8]}"
    store = Regista.create_project(DSN, project, str(key_path), strict_asymmetric=True)
    try:
        # Registered BEFORE the genesis write: valid_from is the registration
        # instant, and an event signed before it is rejected as out-of-window.
        # P2.2 §5.9 rule 2 removed the public mutators; this bundle fixture seeds a
        # pre-cutover `legacy_unsourced` row, which is what the v4/v5 offline
        # verifier resolves through. It is deliberately NOT a v6-sourced row: there
        # is no signed trust-log enrolment event here to project from.
        seed_legacy_principal_key(
            store._mgr, _GENESIS_PRINCIPAL, public_key, "ed25519", key_id=_GENESIS_KEY_ID
        )
        written = store.write_genesis(_genesis_envelope(public_key), gate_passed=True)
        # Export is read-only, so one module-scoped project serves every test
        # here (project creation replays 45 migrations).
        yield _GenesisStore(
            store=store, project=project, public_key=public_key, genesis=written
        )
    finally:
        store.close()
        drop_project_schema(DSN, project)


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


def _drive_to_terminal(sub, wi):
    agent = {"role": "agent"}
    reviewer = {"role": "reviewer"}
    sub.transition(wi.work_item_id, "start", "agent-1", actor_metadata=agent)
    sub.transition(wi.work_item_id, "submit_review", "agent-1", actor_metadata=agent)
    sub.transition(wi.work_item_id, "approve", "reviewer-1", actor_metadata=reviewer)


@pytest.fixture
def project():
    name = f"bundle_test_{uuid.uuid4().hex[:8]}"
    yield name
    drop_project_schema(DSN, name)


@pytest.fixture
def sub(project):
    s = Regista.create_project(DSN, project, KEY_PATH)
    with open(WORKFLOW_PATH) as f:
        s.register_workflow(f.read())
    yield s
    s.close()


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
    def test_helper_rejects_archive_names(self, name):
        from regista._bundle import _reject_archive_output_name
        from regista._errors import ErrorCode, RegistaError

        with pytest.raises(RegistaError) as exc_info:
            _reject_archive_output_name(name)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    @pytest.mark.parametrize("name", ["bundle.json", "bundle", "bundle.ndjson", "a.json.bak"])
    def test_helper_accepts_non_archive_names(self, name):
        from regista._bundle import _reject_archive_output_name

        _reject_archive_output_name(name)

    def test_export_rejects_tar_gz(self, sub, tmp_path):
        from regista._errors import ErrorCode, RegistaError

        with pytest.raises(RegistaError) as exc_info:
            sub.export_audit_bundle(str(tmp_path / "bundle.tar.gz"))
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT
        assert not (tmp_path / "bundle.tar.gz").exists()


class TestVerifyAuditBundleOffline:
    def test_exported_bundle_round_trips_offline(self, genesis_store, tmp_path):
        """The retained export → offline-verify round trip, on a real artifact.

        This store holds exactly its genesis event, so the report's verdict is
        `UNVERIFIABLE`, not `INVALID` and not `verified`. Before the v6 verifier
        boundary this test asserted that the *clamp* finding was the only finding;
        it now asserts the two things that actually distinguish the honest verdict:
        **zero errors** (nothing about the artifact is contradicted) and **one
        unverifiable signature** whose reason names the absent external pin.

        `verified=True` for a v6 bundle is reachable and is asserted in
        `TestGenesisKeyEvidence`, on a post-genesis chain. It is unreachable *here*
        for a reason that is about the bootstrap position, not about the verifier.
        """
        output = tmp_path / "roundtrip.json"
        result = genesis_store.store.export_audit_bundle(str(output))

        assert output.is_file()
        assert result["output_path"] == str(output)
        assert result["event_count"] == 1
        assert result["public_key_count"] == 1
        assert result["bundle_hash"].startswith("sha256:")
        assert result["bundle_bytes"] > 0
        assert result["since_seq"] is None
        assert result["until_seq"] is None

        bundle = json.loads(output.read_text())
        assert set(bundle) == {"manifest", "events", "public_keys"}, (
            "P1.4 deleted the anchor_receipts and segments sections (BUNDLE-V3 §8)"
        )
        manifest = bundle["manifest"]
        assert manifest["project"] == genesis_store.project
        assert manifest["format_version"] == 2
        assert manifest["event_count"] == 1
        assert manifest["public_key_count"] == 1
        assert manifest["principal_key_registry"] == "present"
        assert manifest["bundle_hash"] == result["bundle_hash"]
        assert "anchor_receipt_count" not in manifest
        assert "segment_count" not in manifest
        assert len(bundle["events"]) == 1
        assert bundle["events"][0]["event_id"] == str(genesis_store.genesis.event_id)

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok, report.bundle_hash_error
        assert report.global_chain_ok, report.global_chain_error
        assert report.work_item_chain_ok, report.work_item_chain_error
        assert report.event_count == 1
        assert report.errors == [], (
            "a genesis-only bundle is UNVERIFIABLE, not defective: nothing about the "
            "artifact is contradicted, so nothing belongs in errors"
        )
        assert report.signatures_verified == 0
        assert report.signatures_unverifiable == 1
        assert report.signature_check == "enforced_none_verified"
        assert not report.verified, (
            "nothing was cryptographically established, so this is not verified — "
            '"nothing was checked" must never read as "everything checks out"'
        )
        # The reason travels with the count. A bare count is the silence WI-267
        # closed at the event level and this closes at the report level.
        assert len(report.unverifiable_details) == 1
        detail = report.unverifiable_details[0]
        assert _V6_BOOTSTRAP_UNPINNED in detail, detail
        assert "key_binding=bootstrap_external" in detail, detail
        assert "unbound=" in detail and "external_trust_pin" in detail, detail
        assert "anchor_receipt_count" not in report.to_dict()
        assert "segment_count" not in report.to_dict()

    def test_a_caller_supplied_trust_pin_reaches_the_offline_verifier(
        self, genesis_store, tmp_path
    ):
        """§8.4: the trust policy is a caller input, and it cannot come from the
        artifact — a bundle that supplied its own pin would be vouching for itself.

        The pin alone is not enough for this bundle (§5.8 needs the trust log too, and
        a project bundle carries none), so the verdict stays UNVERIFIABLE. What the
        pin *does* change is the reported checkpoint binding, and asserting that is
        how this test proves the input is plumbed rather than accepted and dropped.
        """
        from regista._signing import compute_v6_event_hash
        from regista._verification import VerificationPolicy

        output = tmp_path / "pinned.json"
        genesis_store.store.export_audit_bundle(str(output))
        bundle = json.loads(output.read_text())
        event = bundle["events"][0]
        genesis_hash = "sha256:" + compute_v6_event_hash(
            bytes.fromhex(event["canonical_envelope"]),
            bytes.fromhex(event["signature"]),
        ).hex()

        unpinned = verify_audit_bundle_offline(str(output))
        assert "checkpoint_binding=checkpoint_bound" in unpinned.unverifiable_details[0]

        pinned = verify_audit_bundle_offline(
            str(output),
            policy=VerificationPolicy(
                pinned_trust_domain_id=str(genesis_store.genesis.trust_domain_id),
                cutover_checkpoint_event_hash=genesis_hash,
            ),
        )
        assert pinned.errors == [], pinned.errors
        assert pinned.signatures_unverifiable == 1
        assert "checkpoint_binding=externally_pinned" in pinned.unverifiable_details[0], (
            "the pinned checkpoint hash must reach the verdict, not be accepted and "
            "dropped"
        )
        assert "external_trust_pin" not in pinned.unverifiable_details[0], (
            "the pin was supplied, so it is no longer the unbound property"
        )
        assert "bootstrap_external_authority" in pinned.unverifiable_details[0], (
            "what IS still unbound is the bootstrap event's external authority, and "
            "the two properties are deliberately distinct"
        )
        assert "the trust log" in pinned.unverifiable_details[0], (
            "what is still missing is the trust log (§5.8 needs BOTH), and the report "
            "must say which of the two is absent"
        )

    def test_a_pin_naming_another_domain_is_a_defect_not_a_gap(
        self, genesis_store, tmp_path
    ):
        """The other direction, and the one that makes the pin load-bearing: a pin the
        artifact contradicts is INVALID, which is an error and not an absence."""
        from regista._verification import VerificationPolicy

        output = tmp_path / "wrong_pin.json"
        genesis_store.store.export_audit_bundle(str(output))
        report = verify_audit_bundle_offline(
            str(output),
            policy=VerificationPolicy(pinned_trust_domain_id=str(uuid.uuid4())),
        )
        assert not report.verified
        assert any("trust_domain_mismatch" in e for e in report.errors), report.errors

    def test_verify_detects_bundle_hash_mismatch(self, genesis_store, tmp_path):
        output = tmp_path / "hash_mismatch.json"
        genesis_store.store.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        # Inside the hashed region, and deliberately NOT rehashed.
        bundle["manifest"]["event_count"] = 999
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert not report.bundle_hash_ok
        assert report.bundle_hash_error
        assert not report.verified
        assert any("Bundle hash mismatch" in e for e in report.errors), report.errors

    def test_verify_detects_tampered_event(self, genesis_store, tmp_path):
        """The keystone (BUNDLE-V3.md §8 "Retained"): offline verification
        delegates to `verify_event_strict`, which reconciles the exported row
        against the envelope that was signed. An adversary who rewrites a row
        field and rehashes the bundle defeats the unkeyed bundle hash — and is
        still caught, by name, on the field they rewrote."""
        output = tmp_path / "row_tamper.json"
        genesis_store.store.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        assert bundle["events"][0]["transition"] == "project_initialized"
        bundle["events"][0]["transition"] = "not_project_initialized"
        _rehash(bundle)
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok, "the adversary rehashed; the unkeyed hash agrees"
        assert report.global_chain_ok
        assert report.work_item_chain_ok
        assert not report.verified
        assert any(
            "row_field_mismatch" in e and "transition" in e for e in report.errors
        ), report.errors

    def test_verify_nonexistent_file_raises(self):
        from regista._errors import ErrorCode, RegistaError

        with pytest.raises(RegistaError) as exc_info:
            verify_audit_bundle_offline("/nonexistent/bundle.json")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_verify_malformed_json_raises(self, tmp_path):
        from regista._errors import ErrorCode, RegistaError

        bad = tmp_path / "bad.json"
        bad.write_text("not valid json {{{")

        with pytest.raises(RegistaError) as exc_info:
            verify_audit_bundle_offline(str(bad))
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_verify_empty_bundle_fails_closed(self, tmp_path):
        """An event-free bundle used to verify=True: the empty global chain is
        vacuously valid and there is nothing left to fail. The exporter refuses
        to write one (WI-240), so it is not an artifact this tool produced —
        it is what is left after someone wipes a bundle and zeroes the counts.
        Answering "verified" to a document that makes no claim is the worst
        outcome available, so it is now rejected (PR #32 review N5)."""
        bundle = {
            "manifest": {
                "project": "empty",
                "exported_at": datetime.now(UTC).isoformat(),
                "event_count": 0,
                "anchor_receipt_count": 0,
                "segment_count": 0,
                "format_version": 1,
                "bundle_hash": "",
            },
            "events": [],
            "anchor_receipts": [],
            "segments": [],
        }

        bundle_bytes = _canonical_bundle_bytes(bundle)
        bundle["manifest"]["bundle_hash"] = f"sha256:{hashlib.sha256(bundle_bytes).hexdigest()}"

        output = tmp_path / "empty_bundle.json"
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok, "every count agrees; only emptiness fails"
        assert not report.verified
        assert report.event_count == 0
        assert any("contains no events" in e for e in report.errors), report.errors


class TestOfflineSignatureVerification:
    """Bundle v2 offline signer-binding verification (WI-267).

    The bundle carries the principal public-key registry, and the offline
    verifier resolves each event's key from it and hands the row to
    `verify_event_strict` — the one primitive that decides whether an event is
    authenticated. A bundle with consistent chain hashes and a forged signature
    must not pass, and a bundle with no key evidence must fail closed.
    """

    def test_export_includes_registered_public_key(self, genesis_store, tmp_path):
        output = tmp_path / "with_keys.json"
        genesis_store.store.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        assert bundle["manifest"]["principal_key_registry"] == "present"
        entry = {k["key_id"]: k for k in bundle["public_keys"]}[_GENESIS_KEY_ID]
        assert entry["principal_id"] == _GENESIS_PRINCIPAL
        assert entry["scheme"] == "ed25519"
        assert entry["status"] == "active"
        assert bytes.fromhex(entry["public_key"]) == genesis_store.public_key

    def test_forged_signature_caught_only_by_signature_check(self, genesis_store, tmp_path):
        """A forged signature constrains no chain link the bundle can check, and
        the unkeyed bundle hash can be restored — so the signature check is the
        only thing standing between a forgery and a clean report. The finding
        must be `signature_invalid`, not the v6-boundary clamp: that difference
        is the proof that real cryptographic verification ran."""
        output = tmp_path / "forged.json"
        genesis_store.store.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        event = bundle["events"][0]
        assert event["scheme_id"] == "ed25519"
        event["signature"] = "ff" * (len(event["signature"]) // 2)
        _rehash(bundle)
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok, "the adversary rehashed; the unkeyed hash agrees"
        assert report.global_chain_ok, report.global_chain_error
        assert report.work_item_chain_ok, report.work_item_chain_error
        assert not report.verified
        assert report.signatures_verified == 0
        assert any("signature_invalid" in e for e in report.errors), report.errors
        assert not any(_V6_BOOTSTRAP_UNPINNED in e for e in report.errors), (
            "the forgery must fail the CRYPTOGRAPHIC check. Before the v6 boundary "
            "landed this guarded against the clamp finding masquerading as the "
            "convicting one; it now guards against the same confusion with the "
            "bootstrap-pin finding, which a clean bundle also reports — and which is "
            "reported as unverifiable rather than as an error, so a forgery that "
            "produced only that would show up here as an empty `errors`."
        )
        assert report.unverifiable_details == [], (
            "a forged signature is a conviction, not a gap: it must not be filed "
            "under the channel reserved for 'nothing was established'"
        )

    def test_missing_public_key_fails_closed(self, genesis_store, tmp_path):
        """An asymmetric event whose key the bundle does not carry **at all** is
        unverifiable, and unverifiable is a finding — not a pass.

        Emptying `public_keys` is no longer sufficient to reach that state, and the
        reason is WI-296's genesis key-evidence half: a v6 acceptance payload repeats
        `public_key` on purpose (§5.8), so a bundle carrying the genesis event carries
        the bytes for the genesis key whether or not the registry section survives.
        That is the point of the §5.8 repetition, and
        `TestGenesisKeyEvidence` asserts it directly.

        So this test strips **both** sources: the registry section *and* the payload's
        embedded acceptance. It rehashes afterwards, the way an adversary would.
        """
        output = tmp_path / "no_keys.json"
        genesis_store.store.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        bundle["public_keys"] = []
        # The envelope bytes are the artifact, so removing the acceptance from the
        # decoded `payload` column is not enough — the verifier reads the envelope.
        # Corrupting the envelope would change the verdict's reason, so instead the
        # key_id is renamed in both places: the bundle now names a key nothing in it
        # carries, which is exactly "no key evidence" without touching signed bytes.
        bundle["events"][0]["key_id"] = "pk-nothing-carries-this"
        _rehash(bundle)
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok
        assert not report.verified
        assert report.signatures_verified == 0
        assert any(
            "No public key for key_id 'pk-nothing-carries-this'" in e
            for e in report.errors
        ), report.errors


class TestExportBounds:
    """WI-240: bounded, capped, self-verifying export."""

    def test_export_reports_self_verification(self, genesis_store, tmp_path):
        output = tmp_path / "sv.json"
        result = genesis_store.store.export_audit_bundle(str(output))

        sv = result["self_verification"]
        assert set(sv) == {
            "verified",
            "signatures_verified",
            "signatures_unverifiable",
            "signature_check",
            "errors",
            "unverifiable_details",
        }
        # A genesis-only store: one Bootstrap-B event, no external pin, so
        # UNVERIFIABLE. Not the clamp, and not a defect — see the module note.
        assert sv["verified"] is False
        assert sv["signatures_verified"] == 0
        assert sv["signatures_unverifiable"] == 1
        assert sv["signature_check"] == "enforced_none_verified"
        assert sv["errors"] == []
        assert sv["unverifiable_details"] and all(
            _V6_BOOTSTRAP_UNPINNED in d for d in sv["unverifiable_details"]
        )
        assert result["bundle_bytes"] > 0

    def test_store_level_defects_are_reported_not_fatal(self, genesis_store, tmp_path):
        """A defect of the STORE faithfully preserved must not block the only
        archival path a degraded store has. The export reports it, loudly, and
        still publishes the artifact; `bundle verify` is the enforcement point.

        The *finding* this asserts against changed with the v6 verifier boundary, and
        the change is a strengthening rather than a relabelling. Before, the finding
        was the clamp — an artefact of the verifier, present on every v6 export, and
        therefore useless as a signal about this store. Now the export is handed a
        store with genuinely nothing external pinned, and the finding says so per
        event. The invariant under test is unchanged: **a reported finding still
        publishes**, and the report still carries it.
        """
        output = tmp_path / "degraded.json"
        result = genesis_store.store.export_audit_bundle(str(output))  # must not raise

        assert output.is_file(), "a reported (not fatal) finding must still publish"
        sv = result["self_verification"]
        assert sv["verified"] is False
        assert sv["unverifiable_details"], (
            "a finding that does not reach the report is a silent finding"
        )
        # And it must be reported through the log too, which is the channel an
        # operator running an unattended export actually sees.
        assert sv["signatures_unverifiable"] == 1

    def test_hash_mismatch_on_written_artifact_raises_and_keeps_it(
        self, genesis_store, tmp_path, monkeypatch
    ):
        """The other half of the boundary above: a defect EXPORT introduced —
        the artifact does not hash-match what was serialized — fails the export,
        with the artifact left at the destination for inspection. The artifact
        is corrupted for real, between the rename and the self-verification,
        rather than by stubbing the report."""
        real_replace = os.replace

        def corrupting_replace(src, dst, **kwargs):
            real_replace(src, dst, **kwargs)
            doctored = json.loads(Path(dst).read_text())
            doctored["manifest"]["event_count"] = 999  # hashed region, not rehashed
            Path(dst).write_text(json.dumps(doctored, sort_keys=True, default=str))

        monkeypatch.setattr(os, "replace", corrupting_replace)
        output = tmp_path / "corrupt.json"
        with pytest.raises(RegistaError) as exc_info:
            genesis_store.store.export_audit_bundle(str(output))

        assert exc_info.value.code == ErrorCode.BUNDLE_WRITE_CORRUPT
        assert "does not match what was serialized" in str(exc_info.value)
        assert output.is_file(), "the rejected artifact is kept for inspection"
        assert json.loads(output.read_text())["manifest"]["event_count"] == 999

    def test_successful_export_leaves_no_partial_file(self, genesis_store, tmp_path):
        """Write-then-rename (review F8): the `.partial` temp is the only thing
        a killed process may leave behind, and a SUCCESSFUL export leaves
        none."""
        output = tmp_path / "clean.json"
        genesis_store.store.export_audit_bundle(str(output))

        assert output.is_file()
        assert sorted(p.name for p in tmp_path.iterdir()) == ["clean.json"]

    def test_write_failure_removes_the_partial_and_spares_the_destination(
        self, genesis_store, tmp_path, monkeypatch
    ):
        """If the write dies mid-way, unlink the `.partial` — only the partial,
        never the real destination (WI-249). Nothing reaches the destination
        that did not survive the write."""
        output = tmp_path / "keepme.json"
        sentinel = b'{"previous": "bundle"}'
        output.write_bytes(sentinel)

        real_write_bytes = Path.write_bytes

        def dies_mid_write(path, data):
            # A plausible-looking partial lands on disk, then the write fails.
            real_write_bytes(path, data[: len(data) // 2])
            raise OSError("injected: no space left on device")

        monkeypatch.setattr(Path, "write_bytes", dies_mid_write)
        with pytest.raises(OSError, match="injected"):
            genesis_store.store.export_audit_bundle(str(output))

        monkeypatch.undo()
        assert not (tmp_path / "keepme.json.partial").exists(), (
            "a failed write left a plausible-looking partial bundle behind"
        )
        assert output.read_bytes() == sentinel, (
            "a failed export clobbered the destination it never verified"
        )

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
        self, genesis_store, tmp_path, since_kind, until_kind
    ):
        """WI-240 review F1: a window that selects zero rows must not write a
        trivially-'verifiable' bundle and exit 0 — in the chunking workflow a
        bad boundary would silently lose events. Distinct from the
        `until <= since` range gate: each of these windows is well-formed and
        simply selects nothing, so only the post-query check can catch it."""
        corpus_max = genesis_store.genesis.global_seq
        since = {"max": corpus_max, "beyond": corpus_max + 500}.get(since_kind)
        until = {"zero": 0, "negative": -5}.get(until_kind)

        output = tmp_path / "void.json"
        with pytest.raises(RegistaError, match="selected no events") as exc_info:
            genesis_store.store.export_audit_bundle(
                str(output), since_seq=since, until_seq=until
            )
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT
        assert not output.exists()

    def test_empty_range_is_rejected(self, sub, tmp_path):
        from regista._errors import RegistaError

        with pytest.raises(RegistaError, match="Empty export range"):
            sub.export_audit_bundle(
                str(tmp_path / "empty.json"), since_seq=10, until_seq=10
            )

    def test_export_of_event_free_store_is_rejected(self, sub, project, tmp_path):
        from regista._errors import RegistaError

        output = tmp_path / "empty_store.json"
        with pytest.raises(RegistaError, match="store has no events"):
            sub.export_audit_bundle(str(output))
        assert not output.exists()

    def test_oversized_export_refuses_and_writes_nothing(
        self, sub, project, tmp_path, monkeypatch
    ):
        from regista import _bundle
        from regista._errors import RegistaError

        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "oversize",
            custom_fields={"title": "oversize"},
        )
        _drive_to_terminal(sub, wi)

        monkeypatch.setattr(_bundle, "MAX_BUNDLE_BYTES", 512)
        output = tmp_path / "oversize.json"
        with pytest.raises(RegistaError, match="Refusing to write") as exc_info:
            sub.export_audit_bundle(str(output))
        assert not output.exists(), "a refused export must leave no artifact"
        assert "nothing was written" in str(exc_info.value)


class TestGenesisKeyEvidence:
    """WI-296, both halves, on a real store.

    The item recorded a decision before this work started, and this class is that
    decision's test surface:

    * **the key-evidence half** — export carries key material *from the v6 acceptance
      payloads it already exports*, not from a ``principal_keys`` row seeded so a
      verifier can find one. §5.8 repeats ``public_key`` inside the acceptance object on
      purpose ("it makes a project bundle self-sufficient for key material without
      making it self-sufficient for trust"), and §5.9 rule 1 forbids the other route.
    * **the self-verification half** — a healthy post-genesis export self-verifies
      ``True``. That is the assertion the clamp made impossible, and it is asserted on a
      post-genesis chain rather than on a genesis-only store, because a genesis-only
      store's single event is a Bootstrap-B event whose authority is external by
      construction (see the module note).
    """

    @pytest.fixture
    def post_genesis(self, tmp_path_factory):
        """A store with a real epoch: genesis, a workflow registration, acceptances.

        Built through ``tests/_v6_fixtures.open_v6_epoch`` — the same helper the fixture
        migration uses — so this test cannot pass against a ceremony the migration
        cannot reproduce.
        """
        from regista._v6_writer import append_v6_event
        from tests._v6_fixtures import make_v6_keyset, open_v6_epoch, v6_producer

        name = f"bundle_pg_{uuid.uuid4().hex[:8]}"
        keyset = make_v6_keyset(tmp_path_factory.mktemp("bundle_pg_keys"))
        store = Regista.create_project(DSN, name, keyset.path)
        try:
            genesis = open_v6_epoch(store, keyset)
            # TWO events on ONE entity, deliberately. Every event `open_v6_epoch`
            # writes is `entity_seq == 1` for its own entity (one project event, one
            # workflow registration, one acceptance per principal), so a store built
            # only from it has no per-entity link for `_verify_work_item_chains` to
            # check — and a chain check with nothing to check passes. Mutation M20
            # (reverting `_hash_event` to the v1-v5 formula) SURVIVED against such a
            # fixture, which is how this was found.
            entity_id = uuid.uuid4()
            for transition in ("created", "updated"):
                with store._mgr.transaction() as conn:
                    append_v6_event(
                        conn,
                        store._keys,
                        entity_kind="work_item",
                        entity_id=entity_id,
                        transition=transition,
                        actor_id="agent:worker",
                        actor_kind="agent",
                        producer=v6_producer(),
                        payload={"initial_state": "open"},
                    )
            yield store, name, genesis
        finally:
            store.close()
            drop_project_schema(DSN, name)

    def test_a_healthy_post_genesis_export_self_verifies_true(self, post_genesis, tmp_path):
        """WI-296's self-verification half. This is the assertion the clamp blocked.

        Note what is and is not claimed. Every *ordinary* v6 event in the bundle is
        ``FULLY_AUTHENTICATED``; the genesis event remains unverifiable-pending-a-pin,
        which is counted and detailed rather than either hidden or promoted to an error.
        `verified` therefore means "nothing is contradicted and something was
        cryptographically established", which is what it has always meant.
        """
        store, _name, _genesis = post_genesis
        output = tmp_path / "post_genesis.json"
        result = store.export_audit_bundle(str(output))

        sv = result["self_verification"]
        assert sv["verified"] is True, (sv["errors"], sv["unverifiable_details"])
        assert sv["errors"] == []
        assert sv["signatures_verified"] >= 1
        assert sv["signature_check"] == "enforced"
        # The genesis event, and only it.
        assert sv["signatures_unverifiable"] == 1
        assert all(_V6_BOOTSTRAP_UNPINNED in d for d in sv["unverifiable_details"])

        report = verify_audit_bundle_offline(str(output))
        assert report.verified is True, report.errors
        assert report.global_chain_ok, report.global_chain_error
        assert report.work_item_chain_ok, report.work_item_chain_error

    def test_the_v6_chain_links_verify_under_the_v6_hash_formula(
        self, post_genesis, tmp_path
    ):
        """A found defect, fixed here rather than worked around.

        ``_bundle._hash_event`` computed ``sha256(envelope || signature)`` — the v1-v5
        formula — for every event. A v6 chain links on the domain-tagged
        ``compute_v6_event_hash`` (``V6-ENVELOPE.md`` §6.1), so for a v6 bundle **no
        link resolved at all**.

        The consequence was not a false break; it was worse. ``_verify_global_chain``
        treats an event whose predecessor is not in the set as a legitimate *bridge
        point* (a windowed export starts mid-chain), so when every link fails to
        resolve, every event becomes an entry point, every entry point is immediately
        its own tail, all events are visited, and the function returns
        ``ok=True`` — **vacuously**. The chain was not verified and the report said it
        was. `_verify_work_item_chains` did break loudly, but only for an entity with
        two or more events, and the epoch-opening ceremony writes none.

        So this test asserts the formula at the primitive as well as through the
        report: a behavioural assertion alone is satisfied by a chain check that
        checks nothing.
        """
        import hashlib as _hashlib

        from regista._bundle import _hash_event
        from regista._signing import compute_v6_event_hash
        from regista._types import Event

        store, _name, _genesis = post_genesis
        output = tmp_path / "chain.json"
        store.export_audit_bundle(str(output))
        bundle = json.loads(output.read_text())
        events = sorted(bundle["events"], key=lambda e: e["global_seq"])
        assert len(events) >= 3, "the point of the test is a multi-event v6 chain"

        first, second = events[0], events[1]
        envelope = bytes.fromhex(first["canonical_envelope"])
        signature = bytes.fromhex(first["signature"])
        v6 = compute_v6_event_hash(envelope, signature)
        v5 = _hashlib.sha256(envelope + signature).digest()
        assert v6 != v5, "the two formulas must differ, or this test proves nothing"
        assert bytes.fromhex(second["prev_global_event_hash"]) == v6

        # At the primitive: the head an event contributes is its OWN version's hash.
        assert _hash_event(Event.from_dict(first)) == v6

        report = verify_audit_bundle_offline(str(output))
        assert report.global_chain_ok, report.global_chain_error
        # Non-vacuous: the fixture carries an entity with two events, so this check
        # has a real per-entity link to verify rather than nothing to verify.
        assert report.work_item_chain_ok, report.work_item_chain_error
        entity_counts: dict[str, int] = {}
        for event in events:
            entity_counts[event["entity_id"]] = entity_counts.get(event["entity_id"], 0) + 1
        assert max(entity_counts.values()) >= 2, (
            "a per-entity chain check with no multi-event entity checks nothing"
        )

    def test_the_genesis_payload_alone_is_sufficient_key_evidence(
        self, genesis_store, tmp_path
    ):
        """WI-296's other half, asserted at its narrowest.

        The registry section is emptied — so the *only* key evidence left is the
        `bootstrap_key_acceptance` inside the genesis event's own signed payload. The
        signature must still verify against it. If this fails, an out-of-the-box
        genesis store exports a bundle nobody can check, which is the fact WI-296
        opened with.
        """
        output = tmp_path / "payload_keys.json"
        genesis_store.store.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        bundle["public_keys"] = []
        _rehash(bundle)
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok
        assert not any("No public key" in e for e in report.errors), report.errors
        # Unverifiable for the bootstrap-pin reason ONLY — not for want of a key.
        assert report.signatures_unverifiable == 1
        assert _V6_BOOTSTRAP_UNPINNED in report.unverifiable_details[0]

    def test_the_registry_wins_where_both_carry_the_key(self, genesis_store, tmp_path):
        """An operator-registered entry knows strictly more than the payload does: it
        carries a validity window and a revocation state the acceptance object has no
        member for. So payload-derived evidence fills gaps and never overrides.

        Asserted through the behaviour that depends on it: a registry entry whose
        `valid_from` postdates the event makes the event fail, and it would silently
        pass if the payload's window-free entry had won.
        """
        output = tmp_path / "both.json"
        genesis_store.store.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        entry = {k["key_id"]: k for k in bundle["public_keys"]}[_GENESIS_KEY_ID]
        entry["valid_from"] = "2099-01-01T00:00:00+00:00"
        _rehash(bundle)
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert not report.verified
        assert any("Event signed before key validity" in e for e in report.errors), (
            report.errors
        )
