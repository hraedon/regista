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
from regista._principal_keys import register_principal_key
from regista._testing import drop_project_schema

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

# verify_event_strict clamps EVERY v6 event to applicability=invalid until the
# v6 verifier boundary lands: the bytes and the duplicated row fields verify,
# but the project/trust/key-binding/workflow/delegation referents cannot yet be
# resolved offline. So `verified=True` is unreachable for a v6-only bundle in
# this tree, and the tests below assert the honest verdict rather than a
# pretended one. This is the finding that says so.
_V6_BOUNDARY_FINDING = "require the v6 verifier boundary"


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
    # register_principal_key stamps valid_from at the registration instant, so
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
        register_principal_key(
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

        `verified=True` is not reachable in this tree and this test does not
        pretend otherwise (see _V6_BOUNDARY_FINDING): the v6 boundary finding is
        asserted to be the ONLY finding, which is the honest form of "a clean
        bundle verifies" available before the v6 verifier lands. Everything
        else the artifact and the report still owe an auditor is asserted.
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
        assert report.signatures_unverifiable == 0, "the genesis event is ed25519, not HMAC"
        assert not report.verified
        assert all(_V6_BOUNDARY_FINDING in e for e in report.errors), report.errors
        assert report.errors, "the v6 boundary finding must be reported, not silent"
        assert "anchor_receipt_count" not in report.to_dict()
        assert "segment_count" not in report.to_dict()

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
        assert not any(_V6_BOUNDARY_FINDING in e for e in report.errors), (
            "the forgery must fail the cryptographic check, not merely the "
            "v6-boundary clamp that a clean bundle also reports"
        )

    def test_missing_public_key_fails_closed(self, genesis_store, tmp_path):
        """An asymmetric event whose key the bundle does not carry is
        unverifiable, and unverifiable is a finding — not a pass."""
        output = tmp_path / "no_keys.json"
        genesis_store.store.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        bundle["public_keys"] = []
        _rehash(bundle)
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok
        assert not report.verified
        assert report.signatures_verified == 0
        assert any(
            f"No public key for key_id '{_GENESIS_KEY_ID}'" in e for e in report.errors
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
        }
        assert sv["verified"] is False  # the v6 verifier boundary, not a bundle defect
        assert sv["signatures_verified"] == 0
        assert sv["signature_check"] == "enforced_none_verified"
        assert sv["errors"] and all(_V6_BOUNDARY_FINDING in e for e in sv["errors"])
        assert result["bundle_bytes"] > 0

    def test_store_level_defects_are_reported_not_fatal(self, genesis_store, tmp_path):
        """A defect of the STORE faithfully preserved must not block the only
        archival path a degraded store has. The export reports it, loudly, and
        still publishes the artifact; `bundle verify` is the enforcement
        point."""
        output = tmp_path / "degraded.json"
        result = genesis_store.store.export_audit_bundle(str(output))  # must not raise

        assert output.is_file(), "a reported (not fatal) finding must still publish"
        assert result["self_verification"]["verified"] is False
        assert result["self_verification"]["errors"]

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
