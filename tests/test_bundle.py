from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from regista import Regista
from regista._anchoring import FileAnchorProvider
from regista._bundle import BundleVerificationReport, verify_audit_bundle_offline
from regista._testing import drop_project_schema, raw_transaction

DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = "tests/test_keys.json"
WORKFLOW_PATH = "tests/test_workflow.yaml"


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


class TestExportAuditBundle:
    def test_export_creates_valid_json(self, sub, project, tmp_path):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "export-test",
            custom_fields={"title": "export-test"},
        )
        _drive_to_terminal(sub, wi)

        output = tmp_path / "bundle.json"
        result = sub.export_audit_bundle(str(output))

        assert output.is_file()
        assert result["event_count"] > 0
        assert result["bundle_hash"].startswith("sha256:")

        bundle = json.loads(output.read_text())
        assert "manifest" in bundle
        assert "events" in bundle
        assert "anchor_receipts" in bundle
        assert "segments" in bundle
        assert bundle["manifest"]["project"] == project
        assert bundle["manifest"]["event_count"] == result["event_count"]
        assert bundle["manifest"]["format_version"] == 2
        assert "public_keys" in bundle
        assert bundle["manifest"]["principal_key_registry"] == "present"

    def test_export_with_since_seq(self, sub, project, tmp_path):
        wi1, _ = sub.create_work_item(
            "test_workflow", "feature", "seq-1",
            custom_fields={"title": "seq-1"},
        )
        _drive_to_terminal(sub, wi1)

        with raw_transaction(sub) as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(global_seq), 0) AS max_seq FROM events"
            ).fetchone()
            baseline = row["max_seq"]

        wi2, _ = sub.create_work_item(
            "test_workflow", "feature", "seq-2",
            custom_fields={"title": "seq-2"},
        )
        _drive_to_terminal(sub, wi2)

        output = tmp_path / "bundle_partial.json"
        result = sub.export_audit_bundle(str(output), since_seq=baseline)

        assert result["event_count"] > 0

        bundle = json.loads(output.read_text())
        for evt in bundle["events"]:
            assert evt["global_seq"] > baseline

    def test_export_includes_anchor_receipts(self, sub, project, tmp_path):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "anchor-test",
            custom_fields={"title": "anchor-test"},
        )
        _drive_to_terminal(sub, wi)

        sub.anchoring.set_provider(FileAnchorProvider(directory=str(tmp_path / "anchors")))
        sub.trigger_anchoring(batch_size=100)

        output = tmp_path / "bundle_with_anchors.json"
        result = sub.export_audit_bundle(str(output))

        assert result["anchor_receipt_count"] > 0

        bundle = json.loads(output.read_text())
        assert len(bundle["anchor_receipts"]) > 0
        receipt = bundle["anchor_receipts"][0]
        assert "merkle_root" in receipt
        assert "target_global_seq" in receipt


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
    def test_verify_clean_bundle_passes(self, sub, project, tmp_path):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "verify-clean",
            custom_fields={"title": "verify-clean"},
        )
        _drive_to_terminal(sub, wi)

        output = tmp_path / "clean_bundle.json"
        sub.export_audit_bundle(str(output))

        report = verify_audit_bundle_offline(str(output))

        assert report.verified
        assert report.event_count > 0
        assert report.global_chain_ok
        assert report.work_item_chain_ok
        assert report.bundle_hash_ok

    def test_verify_detects_tampered_event(self, sub, project, tmp_path):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "verify-tamper",
            custom_fields={"title": "verify-tamper"},
        )
        _drive_to_terminal(sub, wi)

        output = tmp_path / "tampered_bundle.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        if len(bundle["events"]) >= 2:
            evt = bundle["events"][1]
            if "prev_global_event_hash" in evt:
                evt["prev_global_event_hash"] = "00" * 32
            elif "signature" in evt:
                evt["signature"] = "ff" * len(evt["signature"])
        Path(output).write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))

        assert not report.verified
        assert len(report.errors) > 0

    def test_verify_detects_bundle_hash_mismatch(self, sub, project, tmp_path):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "verify-hash",
            custom_fields={"title": "verify-hash"},
        )
        _drive_to_terminal(sub, wi)

        output = tmp_path / "hash_mismatch.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        bundle["manifest"]["bundle_hash"] = "sha256:0000000000000000"
        Path(output).write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))

        assert not report.verified
        assert not report.bundle_hash_ok

    def test_verify_detects_anchor_mismatch(self, sub, project, tmp_path):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "verify-anchor",
            custom_fields={"title": "verify-anchor"},
        )
        _drive_to_terminal(sub, wi)

        sub.anchoring.set_provider(FileAnchorProvider(directory=str(tmp_path / "anchors")))
        sub.trigger_anchoring(batch_size=100)

        output = tmp_path / "anchor_mismatch.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        if bundle["anchor_receipts"]:
            receipt = bundle["anchor_receipts"][0]
            receipt["merkle_root"] = "00" * 32

            Path(output).write_text(
                json.dumps(bundle, sort_keys=True, default=str)
            )

            report = verify_audit_bundle_offline(str(output))

            assert not report.verified
            anchor_results = [a for a in report.anchor_verifications if not a["verified"]]
            assert len(anchor_results) > 0
        else:
            pytest.skip("No anchor receipts to tamper")

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

    def test_verify_empty_bundle_passes(self, tmp_path):
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
        from regista._bundle import _canonical_bundle_bytes

        bundle_bytes = _canonical_bundle_bytes(bundle)
        bundle["manifest"]["bundle_hash"] = f"sha256:{hashlib.sha256(bundle_bytes).hexdigest()}"

        output = tmp_path / "empty_bundle.json"
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert report.verified
        assert report.event_count == 0


class TestVerifyArchiveChain:
    def test_verify_chain_no_segments(self, sub):
        result = sub.verify_archive_chain()
        assert result["verified"]
        assert result["segment_count"] == 0

    def test_verify_chain_with_segments(self, sub):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "chain-test",
            custom_fields={"title": "chain-test"},
        )
        _drive_to_terminal(sub, wi)

        before = datetime.now(UTC) + timedelta(days=365)
        sub.archive.seal(before_timestamp=before)

        result = sub.verify_archive_chain()

        assert result["verified"]
        assert result["segment_count"] >= 1
        assert len(result["chain_breaks"]) == 0

    def test_verify_chain_detects_broken_link(self, sub):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "broken-chain",
            custom_fields={"title": "broken-chain"},
        )
        _drive_to_terminal(sub, wi)

        before = datetime.now(UTC) + timedelta(days=365)
        sub.archive.seal(before_timestamp=before)

        with raw_transaction(sub) as conn:
            conn.execute(
                "UPDATE event_segments SET first_event_prev_hash = %s "
                "WHERE segment_id = (SELECT segment_id FROM event_segments "
                "ORDER BY first_global_seq DESC LIMIT 1)",
                [b"\x00" * 32],
            )

        result = sub.verify_archive_chain()

        if result["segment_count"] > 1:
            assert not result["verified"]
            assert len(result["chain_breaks"]) > 0
        else:
            pass


class TestOfflineSignatureVerification:
    """Bundle v2 offline signer-binding verification (Plan 008 WI-1.1 close-out).

    v1 bundles verified chain hashes and anchor roots but never event
    signatures — a bundle with consistent hashes and forged signatures
    passed. v2 exports the principal public-key registry and verifies
    asymmetric-scheme signatures offline, including the principal↔signer
    binding and key validity window. Symmetric (HMAC) events are counted
    as unverifiable, never silently passed.
    """

    @pytest.fixture
    def ed25519_setup(self, tmp_path):
        import base64

        import nacl.signing

        from regista._principal_keys import register_principal_key
        from regista._testing import drop_project_schema as _drop

        project = f"bundle_sig_{uuid.uuid4().hex[:8]}"
        principal_id = f"bundle_principal_{uuid.uuid4().hex[:8]}"

        sk = nacl.signing.SigningKey.generate()
        seed, vk = bytes(sk), bytes(sk.verify_key)
        priv_path = tmp_path / f"{principal_id}_priv.key"
        priv_path.write_bytes(seed)
        priv_path.chmod(0o600)
        key_file = tmp_path / "sig_keys.json"
        key_file.write_text(json.dumps({"keys": [
            {
                "key_id": "bootstrap-hmac",
                "secret": "dGVzdA==",
                "encoding": "base64",
                "status": "active",
            },
            {
                "key_id": f"ed25519-{principal_id}",
                "scheme": "ed25519",
                "principal_id": principal_id,
                "secret_ref": f"file:{priv_path}",
                "public_key": base64.b64encode(vk).decode("ascii"),
                "role": "actor",
                "status": "active",
            },
        ]}))

        sub = Regista.create_project(DSN, project, str(key_file))
        try:
            with open(WORKFLOW_PATH) as f:
                sub.register_workflow(f.read())
            register_principal_key(
                sub._mgr, principal_id, vk, "ed25519",
                key_id=f"ed25519-{principal_id}",
            )
            yield sub, principal_id
        finally:
            sub.close()
            _drop(DSN, project)

    @staticmethod
    def _rehash(bundle: dict) -> None:
        """Recompute bundle_hash the way a tampering adversary would."""
        from regista._bundle import _canonical_bundle_bytes

        bundle["manifest"]["bundle_hash"] = (
            "sha256:" + hashlib.sha256(_canonical_bundle_bytes(bundle)).hexdigest()
        )

    def _export_mixed_bundle(self, sub, principal_id, tmp_path) -> Path:
        """HMAC events first, then an ed25519-signed event LAST in the chain."""
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "hmac-actor",
            custom_fields={"title": "hmac-signed"},
        )
        _drive_to_terminal(sub, wi)
        sub.create_work_item(
            "test_workflow", "feature", principal_id,
            custom_fields={"title": "ed25519-signed"},
        )
        output = tmp_path / "sig_bundle.json"
        sub.export_audit_bundle(str(output))
        return output

    def test_export_includes_registered_public_key(
        self, ed25519_setup, tmp_path
    ):
        sub, principal_id = ed25519_setup
        output = self._export_mixed_bundle(sub, principal_id, tmp_path)

        bundle = json.loads(output.read_text())
        assert bundle["manifest"]["principal_key_registry"] == "present"
        keys = {k["key_id"]: k for k in bundle["public_keys"]}
        entry = keys[f"ed25519-{principal_id}"]
        assert entry["principal_id"] == principal_id
        assert entry["scheme"] == "ed25519"
        assert entry["public_key"]

    def test_clean_mixed_bundle_verifies_signatures(
        self, ed25519_setup, tmp_path
    ):
        sub, principal_id = ed25519_setup
        output = self._export_mixed_bundle(sub, principal_id, tmp_path)

        report = verify_audit_bundle_offline(str(output))
        assert report.verified
        assert report.signature_check == "enforced"
        assert report.signatures_verified >= 1
        assert report.signatures_unverifiable >= 1
        assert (
            report.signatures_verified + report.signatures_unverifiable
            == report.event_count
        )

    def test_forged_signature_caught_only_by_signature_check(
        self, ed25519_setup, tmp_path
    ):
        """The last event's signature constrains no chain link — before v2,
        forging it (and rehashing the bundle) passed offline verification."""
        sub, principal_id = ed25519_setup
        output = self._export_mixed_bundle(sub, principal_id, tmp_path)

        bundle = json.loads(output.read_text())
        last = bundle["events"][-1]
        assert last["scheme_id"] == "ed25519"
        last["signature"] = "ff" * (len(last["signature"]) // 2)
        self._rehash(bundle)
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert not report.verified
        # The chain checks cannot see this tampering — only the signature
        # check catches it. This is the added value of bundle v2.
        assert report.bundle_hash_ok
        assert report.global_chain_ok
        assert any("Signature verification failed" in e for e in report.errors)

    def test_hmac_only_bundle_counts_all_unverifiable(self, sub, tmp_path):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "hmac-only",
            custom_fields={"title": "hmac-only"},
        )
        _drive_to_terminal(sub, wi)
        output = tmp_path / "hmac_bundle.json"
        sub.export_audit_bundle(str(output))

        report = verify_audit_bundle_offline(str(output))
        assert report.verified
        assert report.signature_check == "enforced_none_verified"
        assert report.signatures_verified == 0
        assert report.signatures_unverifiable == report.event_count

    def test_v1_bundle_signature_check_skipped(self, tmp_path):
        from regista._bundle import _canonical_bundle_bytes

        bundle = {
            "manifest": {
                "project": "v1-compat",
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
        bundle["manifest"]["bundle_hash"] = (
            f"sha256:{hashlib.sha256(bundle_bytes).hexdigest()}"
        )
        output = tmp_path / "v1_bundle.json"
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert report.verified
        assert report.signature_check == "skipped_v1_bundle"

    def test_missing_public_key_fails_closed(self, ed25519_setup, tmp_path):
        sub, principal_id = ed25519_setup
        output = self._export_mixed_bundle(sub, principal_id, tmp_path)

        bundle = json.loads(output.read_text())
        bundle["public_keys"] = []
        self._rehash(bundle)
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert not report.verified
        assert any("No public key for key_id" in e for e in report.errors)

    def test_binding_mismatch_fails_closed(self, ed25519_setup, tmp_path):
        sub, principal_id = ed25519_setup
        output = self._export_mixed_bundle(sub, principal_id, tmp_path)

        bundle = json.loads(output.read_text())
        for k in bundle["public_keys"]:
            if k["key_id"] == f"ed25519-{principal_id}":
                k["principal_id"] = "someone-else"
        self._rehash(bundle)
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert not report.verified
        assert any("Actor-signer mismatch" in e for e in report.errors)

    def test_unknown_scheme_fails_closed(self, ed25519_setup, tmp_path):
        sub, principal_id = ed25519_setup
        output = self._export_mixed_bundle(sub, principal_id, tmp_path)

        bundle = json.loads(output.read_text())
        bundle["events"][-1]["scheme_id"] = "mystery-scheme"
        self._rehash(bundle)
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert not report.verified
        assert any("Unknown signing scheme" in e for e in report.errors)

    def test_registry_absent_is_recorded_and_fails_closed(
        self, ed25519_setup, tmp_path
    ):
        """Dropping principal_keys exercises the savepoint path: export
        still succeeds, records the registry as absent, and offline
        verification of asymmetric events fails closed (no silent pass)."""
        sub, principal_id = ed25519_setup
        sub.create_work_item(
            "test_workflow", "feature", principal_id,
            custom_fields={"title": "ed25519-signed"},
        )
        with raw_transaction(sub) as conn:
            conn.execute("DROP TABLE principal_keys")

        output = tmp_path / "no_registry.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        assert bundle["manifest"]["principal_key_registry"] == "absent"
        assert bundle["public_keys"] == []

        report = verify_audit_bundle_offline(str(output))
        assert not report.verified
        assert any("No public key for key_id" in e for e in report.errors)


class TestOfflineAnchorHashAgility:
    """WI-207: offline bundle anchor verification must handle non-SHA-256
    events. ``_verify_anchor_offline`` recomputes ``payload_canonical_hash``
    with the event's own ``hash_alg`` (``resolve_hash_function``); the rest of
    the suite only creates sha-256 events, so pin the hash-agility path
    end-to-end through export + offline verification."""

    def test_offline_anchor_verifies_with_sha384_events(self, sub, project, tmp_path):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "anchor-hash-agility",
            custom_fields={"title": "anchor-hash-agility"},
        )
        for i in range(2):
            sub.append_event(
                wi.work_item_id, "agent-1",
                hash_alg="sha-384",
                transition=f"hash_agility_{i}",
                payload={"alg": "sha-384", "i": i},
            )

        sub.anchoring.set_provider(FileAnchorProvider(directory=str(tmp_path / "anchors")))
        receipt = sub.trigger_anchoring(batch_size=100)
        assert receipt is not None

        output = tmp_path / "sha384_anchor.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        assert bundle["anchor_receipts"], "expected an anchor receipt in the bundle"
        hash_algs = {e["hash_alg"] for e in bundle["events"]}
        assert "sha-384" in hash_algs, "test must exercise a non-SHA-256 event"

        report = verify_audit_bundle_offline(str(output))
        assert report.verified, f"offline verification failed: {report.errors}"
        assert report.anchor_receipt_count > 0
        assert all(av["verified"] for av in report.anchor_verifications)


class TestExportBounds:
    """WI-240: bounded, capped, self-verifying export."""

    def _two_item_corpus(self, sub):
        """Two terminal work items; returns the boundary global_seq between them."""
        wi1, _ = sub.create_work_item(
            "test_workflow", "feature", "bounds-1",
            custom_fields={"title": "bounds-1"},
        )
        _drive_to_terminal(sub, wi1)
        with raw_transaction(sub) as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(global_seq), 0) AS max_seq FROM events"
            ).fetchone()
            boundary = row["max_seq"]
        wi2, _ = sub.create_work_item(
            "test_workflow", "feature", "bounds-2",
            custom_fields={"title": "bounds-2"},
        )
        _drive_to_terminal(sub, wi2)
        return boundary

    def test_until_seq_is_an_inclusive_upper_bound(self, sub, project, tmp_path):
        boundary = self._two_item_corpus(sub)
        output = tmp_path / "prefix.json"
        result = sub.export_audit_bundle(str(output), until_seq=boundary)

        assert result["event_count"] > 0
        assert result["until_seq"] == boundary
        bundle = json.loads(output.read_text())
        assert bundle["manifest"]["until_seq"] == boundary
        seqs = [e["global_seq"] for e in bundle["events"]]
        assert max(seqs) <= boundary

    def test_since_and_until_form_a_window(self, sub, project, tmp_path):
        boundary = self._two_item_corpus(sub)
        with raw_transaction(sub) as conn:
            row = conn.execute(
                "SELECT MAX(global_seq) AS max_seq FROM events"
            ).fetchone()
            corpus_max = row["max_seq"]

        output = tmp_path / "window.json"
        result = sub.export_audit_bundle(
            str(output), since_seq=boundary, until_seq=corpus_max
        )
        bundle = json.loads(output.read_text())
        seqs = [e["global_seq"] for e in bundle["events"]]
        assert min(seqs) > boundary
        assert max(seqs) <= corpus_max
        assert result["event_count"] == len(seqs)

    def test_empty_range_is_rejected(self, sub, tmp_path):
        from regista._errors import RegistaError

        with pytest.raises(RegistaError, match="Empty export range"):
            sub.export_audit_bundle(
                str(tmp_path / "empty.json"), since_seq=10, until_seq=10
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
        self, sub, project, tmp_path, since_kind, until_kind
    ):
        """WI-240 review F1: a window that selects zero rows must not write a
        trivially-'verifiable' bundle and exit 0 — in the chunking workflow a
        bad boundary would silently lose events."""
        from regista._errors import RegistaError

        self._two_item_corpus(sub)
        with raw_transaction(sub) as conn:
            corpus_max = conn.execute(
                "SELECT MAX(global_seq) AS m FROM events"
            ).fetchone()["m"]

        since = {"max": corpus_max, "beyond": corpus_max + 500}.get(since_kind)
        until = {"zero": 0, "negative": -5}.get(until_kind)
        output = tmp_path / "void.json"
        with pytest.raises(RegistaError, match="selected no events"):
            sub.export_audit_bundle(str(output), since_seq=since, until_seq=until)
        assert not output.exists()

    def test_export_of_event_free_store_is_rejected(self, sub, project, tmp_path):
        from regista._errors import RegistaError

        output = tmp_path / "empty_store.json"
        with pytest.raises(RegistaError, match="store has no events"):
            sub.export_audit_bundle(str(output))
        assert not output.exists()

    def test_chunked_exports_both_verify_offline(self, sub, project, tmp_path):
        """The WI-240 acceptance case: a corpus split into a prefix chunk and a
        mid-chain chunk, each independently verifiable offline."""
        boundary = self._two_item_corpus(sub)

        chunk1 = tmp_path / "chunk1.json"
        chunk2 = tmp_path / "chunk2.json"
        sub.export_audit_bundle(str(chunk1), until_seq=boundary)
        sub.export_audit_bundle(str(chunk2), since_seq=boundary)

        for chunk in (chunk1, chunk2):
            report = verify_audit_bundle_offline(str(chunk))
            assert report.verified, f"{chunk.name}: {report.errors}"

        # Completeness is judged against the STORE, not the chunks' own
        # manifests (WI-240 review F3): the union of the chunk pair must be
        # exactly the corpus, disjointly.
        with raw_transaction(sub) as conn:
            corpus_ids = {
                str(r["event_id"])
                for r in conn.execute("SELECT event_id FROM events").fetchall()
            }
        c1 = json.loads(chunk1.read_text())
        c2 = json.loads(chunk2.read_text())
        ids1 = {e["event_id"] for e in c1["events"]}
        ids2 = {e["event_id"] for e in c2["events"]}
        assert ids1 & ids2 == set()
        assert ids1 | ids2 == corpus_ids

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

    def test_export_reports_self_verification(self, sub, project, tmp_path):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "selfverify",
            custom_fields={"title": "selfverify"},
        )
        _drive_to_terminal(sub, wi)

        result = sub.export_audit_bundle(str(tmp_path / "sv.json"))
        assert result["self_verification"]["verified"] is True
        assert result["bundle_bytes"] > 0

    def test_hash_mismatch_on_written_artifact_raises_and_keeps_it(
        self, sub, project, tmp_path, monkeypatch
    ):
        """A defect export itself introduced (the artifact does not hash-match
        what was serialized) fails the export."""
        from regista import _bundle
        from regista._errors import RegistaError

        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "sv-fail",
            custom_fields={"title": "sv-fail"},
        )
        _drive_to_terminal(sub, wi)

        broken = BundleVerificationReport(
            verified=False,
            event_count=0,
            anchor_receipt_count=0,
            segment_count=0,
            global_chain_ok=True,
            bundle_hash_ok=False,
            bundle_hash_error="synthetic mismatch",
            errors=["synthetic mismatch"],
        )
        monkeypatch.setattr(
            _bundle, "verify_audit_bundle_offline", lambda _path: broken
        )
        output = tmp_path / "sv-fail.json"
        with pytest.raises(RegistaError, match="does not match what was serialized"):
            sub.export_audit_bundle(str(output))
        assert output.exists(), "the rejected artifact is kept for inspection"

    def test_store_level_defects_are_reported_not_fatal(
        self, sub, project, tmp_path, monkeypatch
    ):
        """A defect of the store faithfully preserved (hash-consistent artifact,
        failing verification) must not block a degraded store's only archival
        path — it is reported in the result instead."""
        from regista import _bundle

        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "sv-store",
            custom_fields={"title": "sv-store"},
        )
        _drive_to_terminal(sub, wi)

        degraded = BundleVerificationReport(
            verified=False,
            event_count=1,
            anchor_receipt_count=0,
            segment_count=0,
            global_chain_ok=True,
            bundle_hash_ok=True,
            errors=["No public key for key_id 'x' in bundle registry"],
        )
        monkeypatch.setattr(
            _bundle, "verify_audit_bundle_offline", lambda _path: degraded
        )
        result = sub.export_audit_bundle(str(tmp_path / "sv-store.json"))
        assert result["self_verification"]["verified"] is False
        assert result["self_verification"]["errors"]

    def test_mid_chain_chunk_excludes_receipts_and_verifies(
        self, sub, project, tmp_path
    ):
        """A mid-chain chunk contains no genesis, so no anchor receipt is
        provable in it; export excludes them (counted in the manifest) instead
        of shipping receipts the verifier would fail."""
        boundary = self._two_item_corpus(sub)
        sub.anchoring.set_provider(
            FileAnchorProvider(directory=str(tmp_path / "anchors"))
        )
        sub.trigger_anchoring(batch_size=100)

        chunk = tmp_path / "midchain.json"
        result = sub.export_audit_bundle(str(chunk), since_seq=boundary)

        assert result["anchor_receipt_count"] == 0
        assert result["anchor_receipts_excluded"] > 0
        bundle = json.loads(chunk.read_text())
        assert bundle["anchor_receipts"] == []
        assert bundle["manifest"]["anchor_receipts_excluded"] > 0

        report = verify_audit_bundle_offline(str(chunk))
        assert report.verified, f"mid-chain chunk failed: {report.errors}"

    def test_prefix_chunk_keeps_only_receipts_it_can_prove(
        self, sub, project, tmp_path
    ):
        """A receipt targeting a seq beyond the exported prefix cannot be
        proven by this bundle and is excluded rather than shipped broken."""
        wi1, _ = sub.create_work_item(
            "test_workflow", "feature", "prefix-1",
            custom_fields={"title": "prefix-1"},
        )
        _drive_to_terminal(sub, wi1)
        sub.anchoring.set_provider(
            FileAnchorProvider(directory=str(tmp_path / "anchors"))
        )
        sub.trigger_anchoring(batch_size=100)
        with raw_transaction(sub) as conn:
            row = conn.execute(
                "SELECT MAX(global_seq) AS max_seq FROM events"
            ).fetchone()
            first_max = row["max_seq"]

        wi2, _ = sub.create_work_item(
            "test_workflow", "feature", "prefix-2",
            custom_fields={"title": "prefix-2"},
        )
        _drive_to_terminal(sub, wi2)
        sub.trigger_anchoring(batch_size=100)

        prefix = tmp_path / "prefix_receipts.json"
        result = sub.export_audit_bundle(str(prefix), until_seq=first_max)

        assert result["anchor_receipt_count"] >= 1
        assert result["anchor_receipts_excluded"] >= 1
        report = verify_audit_bundle_offline(str(prefix))
        assert report.verified, f"prefix chunk failed: {report.errors}"
        assert all(av["verified"] for av in report.anchor_verifications)


class TestSegmentAndReceiptWindowing:
    """WI-240 review F4/F5: bounded fetches and slices must not overclaim."""

    def test_slice_segments_keeps_overlap_drops_outside(self):
        from regista._bundle import _slice_segments_to_window

        segs = [
            {"segment_id": "a", "first_global_seq": 1, "last_global_seq": 8},
            {"segment_id": "b", "first_global_seq": 9, "last_global_seq": 13},
            {"segment_id": "c", "first_global_seq": 14, "last_global_seq": 20},
        ]
        kept, excluded = _slice_segments_to_window(segs, 9, 13)
        assert [s["segment_id"] for s in kept] == ["b"]
        assert excluded == 2

        kept, excluded = _slice_segments_to_window(segs, 5, 15)
        assert [s["segment_id"] for s in kept] == ["a", "b", "c"]
        assert excluded == 0

    def test_slice_segments_keeps_unbounded_rows(self):
        from regista._bundle import _slice_segments_to_window

        segs = [{"segment_id": "open", "first_global_seq": None, "last_global_seq": None}]
        kept, excluded = _slice_segments_to_window(segs, 100, 200)
        assert kept == segs and excluded == 0

    def test_receipt_listing_orders_oldest_target_first(self, sub, project, tmp_path):
        """The bundle fetch is bounded, so it must hold the receipts a prefix
        bundle can prove — the OLDEST targets, not the newest submissions."""
        from regista._anchoring import list_anchor_receipts
        from regista._testing import raw_transaction as _raw

        for n in ("recA", "recB"):
            wi, _ = sub.create_work_item(
                "test_workflow", "feature", n, custom_fields={"title": n}
            )
            _drive_to_terminal(sub, wi)
            sub.anchoring.set_provider(
                FileAnchorProvider(directory=str(tmp_path / "anchors"))
            )
            sub.trigger_anchoring(batch_size=100)

        with _raw(sub) as conn:
            receipts = list_anchor_receipts(conn, limit=10, order="target_seq")
        targets = [r.target_global_seq for r in receipts]
        assert targets == sorted(targets)
        assert len(targets) >= 2


class TestCliExportExitCodes:
    """WI-240 review F2: exit codes are the API pipelines read — 0 must mean
    exported AND verifiable; a store-level verification failure exits 3
    unless --allow-unverified opts in."""

    def _cli_env(self, monkeypatch, sub, project):
        monkeypatch.setenv("REGISTA_DSN", DSN)
        monkeypatch.setenv("REGISTA_PROJECT", project)
        monkeypatch.setenv("REGISTA_HMAC_KEY_PATH", KEY_PATH)

    def _degraded_report(self):
        return BundleVerificationReport(
            verified=False,
            event_count=1,
            anchor_receipt_count=0,
            segment_count=0,
            global_chain_ok=True,
            bundle_hash_ok=True,
            errors=["No public key for key_id 'x' in bundle registry"],
        )

    def test_unverifiable_store_exits_3_by_default(
        self, sub, project, tmp_path, monkeypatch, capsys
    ):
        from regista import _bundle, _cli

        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "cli-exit",
            custom_fields={"title": "cli-exit"},
        )
        _drive_to_terminal(sub, wi)
        self._cli_env(monkeypatch, sub, project)
        monkeypatch.setattr(
            _bundle, "verify_audit_bundle_offline",
            lambda _path: self._degraded_report(),
        )

        output = tmp_path / "cli_degraded.json"
        with pytest.raises(SystemExit) as exc_info:
            _cli.main(["bundle", "export", "--output", str(output)])
        assert exc_info.value.code == 3
        assert output.exists(), "the artifact is still written"
        assert "offline verifier rejects" in capsys.readouterr().err

    def test_allow_unverified_opts_into_exit_0(
        self, sub, project, tmp_path, monkeypatch
    ):
        from regista import _bundle, _cli

        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "cli-allow",
            custom_fields={"title": "cli-allow"},
        )
        _drive_to_terminal(sub, wi)
        self._cli_env(monkeypatch, sub, project)
        monkeypatch.setattr(
            _bundle, "verify_audit_bundle_offline",
            lambda _path: self._degraded_report(),
        )

        output = tmp_path / "cli_allowed.json"
        rc = _cli.main(
            ["bundle", "export", "--output", str(output), "--allow-unverified"]
        )
        assert rc in (0, None)
        assert output.exists()
