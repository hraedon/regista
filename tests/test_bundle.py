from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from regista import Regista
from regista._anchoring import FileAnchorProvider
from regista._bundle import (
    BundleVerificationReport,
    _canonical_bundle_bytes,
    verify_audit_bundle_offline,
)
from regista._testing import drop_project_schema, raw_transaction

DSN = os.environ.get(
    "REGISTA_TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)
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
        from regista._bundle import _canonical_bundle_bytes

        bundle_bytes = _canonical_bundle_bytes(bundle)
        bundle["manifest"]["bundle_hash"] = f"sha256:{hashlib.sha256(bundle_bytes).hexdigest()}"

        output = tmp_path / "empty_bundle.json"
        output.write_text(json.dumps(bundle, sort_keys=True, default=str))

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok, "every count agrees; only emptiness fails"
        assert not report.verified
        assert report.event_count == 0
        assert any("contains no events" in e for e in report.errors), report.errors


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

    def test_v1_bundle_signature_check_skipped(self, sub, tmp_path):
        """A v1 bundle carries no key registry, so its signature check is
        reported as skipped rather than silently passed.

        Built by downgrading a real export (drop ``public_keys`` and the v2-only
        ``public_key_count``, set ``format_version`` to 1, recompute the
        unkeyed hash) instead of hand-rolling an EMPTY document: an event-free
        bundle no longer verifies at all (review N5), and an empty one could
        never have exercised the signature path anyway.
        """
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "v1-compat",
            custom_fields={"title": "v1-compat"},
        )
        _drive_to_terminal(sub, wi)

        output = tmp_path / "v1_bundle.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        assert bundle["events"], "the v1 downgrade must keep real events"
        bundle.pop("public_keys", None)
        bundle["manifest"].pop("public_key_count", None)
        bundle["manifest"]["format_version"] = 1
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert report.verified, report.errors
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


def _build_two_segment_corpus(sub):
    """Seal two batches of terminal work items so the store ends up with
    two sealed segments separated by the first segment's seal event."""
    wi1, _ = sub.create_work_item(
        "test_workflow", "feature", "wi-first-seg",
        custom_fields={"title": "wi-first-seg"},
    )
    _drive_to_terminal(sub, wi1)
    # Seal the first batch only (cutoff just in the future so the
    # not-yet-created second batch is excluded).
    sub.archive.seal(
        before_timestamp=datetime.now(UTC) + timedelta(seconds=1)
    )

    wi2, _ = sub.create_work_item(
        "test_workflow", "feature", "wi-second-seg",
        custom_fields={"title": "wi-second-seg"},
    )
    _drive_to_terminal(sub, wi2)
    # Seal everything remaining.
    result = sub.archive.seal(
        before_timestamp=datetime.now(UTC) + timedelta(days=365)
    )
    return result


def _segment_and_gap_seqs(sub):
    """Return the two segments (ordered) and the global_seq of the
    inter-segment seal event, discovered dynamically from the store."""
    with raw_transaction(sub) as conn:
        segs = conn.execute(
            "SELECT segment_id, first_global_seq, last_global_seq "
            "FROM event_segments ORDER BY first_global_seq"
        ).fetchall()
        assert len(segs) >= 2, f"need 2+ segments, got {len(segs)}"
        a, b = segs[0], segs[1]
        # The seal event of the earlier segment sits in the gap.
        seal_rows = conn.execute(
            "SELECT global_seq FROM events WHERE entity_kind = 'segment' "
            "AND global_seq > %s AND global_seq < %s "
            "ORDER BY global_seq",
            [a["last_global_seq"], b["first_global_seq"]],
        ).fetchall()
    assert seal_rows, "expected a seal event in the gap"
    return a, b, seal_rows[0]["global_seq"]


def _rehash_and_write(bundle, output):
    """Recompute the (unkeyed) bundle hash and write the tampered artifact.

    The bundle hash is a plain SHA-256 over the canonical bytes with
    ``bundle_hash`` stripped, so any tamperer can restore it. Every negative
    test here does exactly that: the point is that the bundle-hash check is
    NOT what catches the tamper.
    """
    bundle["manifest"]["bundle_hash"] = (
        "sha256:" + hashlib.sha256(_canonical_bundle_bytes(bundle)).hexdigest()
    )
    Path(output).write_text(
        json.dumps(bundle, sort_keys=True, separators=(",", ":"), default=str)
    )


class TestSegmentChainOfflineVerification:
    """WI-249: offline segment-chain verification must link consecutive
    segments through the inter-segment seal event instead of assuming strict
    adjacency."""

    def _build_two_segment_corpus(self, sub):
        return _build_two_segment_corpus(sub)

    def test_two_segment_bundle_verifies_segment_chain(self, sub, tmp_path):
        """A 2-segment corpus full-exports and offline-verifies with the
        segment chain intact (links through the inter-segment seal event)."""
        self._build_two_segment_corpus(sub)

        segments = sub.archive.list_segments()
        assert len(segments) >= 2, f"expected 2+ segments, got {len(segments)}"

        output = tmp_path / "two_seg_bundle.json"
        result = sub.export_audit_bundle(str(output))

        # The export self-verifies; with the bug the segment chain reports
        # verified=False and export_audit_bundle would have logged a
        # verification error (and the CLI would exit 3).
        assert result["self_verification"]["verified"] is True, (
            result["self_verification"]["errors"]
        )
        assert result["segment_count"] >= 2

        report = verify_audit_bundle_offline(str(output))
        assert report.verified, report.errors
        assert report.segment_chain_ok, report.segment_chain_error

    def test_tampered_head_hash_fails_segment_chain(self, sub, tmp_path):
        """A genuinely broken linkage (tampered head_hash) must still fail
        the segment-chain check — the fix must not pass everything."""
        self._build_two_segment_corpus(sub)

        output = tmp_path / "tampered_bundle.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        segs = bundle["segments"]
        assert len(segs) >= 2
        # Tamper the first segment's head_hash so no exported event chains
        # from it.
        segs[0]["head_hash"] = "ff" * 32
        # Recompute the bundle hash so the bundle-hash check passes and the
        # segment-chain check is the one that fails.
        bundle["manifest"]["bundle_hash"] = (
            "sha256:"
            + hashlib.sha256(_canonical_bundle_bytes(bundle)).hexdigest()
        )
        Path(output).write_text(
            json.dumps(bundle, sort_keys=True, separators=(",", ":"), default=str)
        )

        report = verify_audit_bundle_offline(str(output))
        assert not report.segment_chain_ok
        assert not report.verified

    def _segment_and_gap_seqs(self, sub):
        return _segment_and_gap_seqs(sub)

    def test_windowed_export_straddling_seal_gap_self_verifies(
        self, sub, tmp_path
    ):
        """WI-249 review F2 (empirical): a --since-seq/--until-seq window that
        cuts through the seal gap must still self-verify. Try several windows
        straddling the inter-segment seal event."""
        self._build_two_segment_corpus(sub)
        a, b, seal_seq = self._segment_and_gap_seqs(sub)

        # Windows to try (since_exclusive, until_inclusive): each straddles
        # the seal event differently, some clipping a segment's edge.
        candidates = [
            (a["last_global_seq"] - 1, b["first_global_seq"]),
            (a["last_global_seq"], b["first_global_seq"]),
            (a["last_global_seq"], seal_seq),
            (seal_seq - 1, b["first_global_seq"] + 1),
            (a["first_global_seq"], b["last_global_seq"]),
        ]
        for since_seq, until_seq in candidates:
            if until_seq <= since_seq:
                continue
            output = tmp_path / f"win_{since_seq}_{until_seq}.json"
            result = sub.export_audit_bundle(
                str(output), since_seq=since_seq, until_seq=until_seq
            )
            assert result["self_verification"]["verified"] is True, (
                f"window ({since_seq},{until_seq}] failed self-verification: "
                f"{result['self_verification']['errors']}"
            )
            # Offline re-verification must agree.
            report = verify_audit_bundle_offline(str(output))
            assert report.verified, (
                f"window ({since_seq},{until_seq}] offline failed: "
                f"{report.errors}"
            )

    def test_windowed_export_window_starting_inside_first_segment_keeps_both_linked(
        self, sub, tmp_path
    ):
        """WI-249 review F2: a window that starts inside segment A and runs
        past segment B overlaps BOTH segments, so the overlap-based slice
        keeps both. The inter-segment seal sits between them and is therefore
        in-window, so the kept pair links and the chunk self-verifies. This
        is the positive case the misnamed ``..._drops_unlinked_leading``
        test actually exercised."""
        self._build_two_segment_corpus(sub)
        a, b, _ = self._segment_and_gap_seqs(sub)

        # Window that starts inside segment A and runs past segment B: both
        # segments overlap the window, so both are kept and must link.
        since_seq = a["first_global_seq"] + 1
        until_seq = b["last_global_seq"]
        output = tmp_path / "win_linked_pair.json"
        result = sub.export_audit_bundle(
            str(output), since_seq=since_seq, until_seq=until_seq
        )
        assert result["self_verification"]["verified"] is True, (
            result["self_verification"]["errors"]
        )
        # Both overlapping segments are kept, none excluded.
        assert result["segment_count"] >= 2
        assert result["segments_excluded"] == 0

    def test_windowed_export_isolating_segment_b_keeps_it_without_incoming_seal(
        self, sub, tmp_path
    ):
        """WI-249 review F2 (isolating window): a window of
        ``since_seq = b.first - 1, until_seq = b.last`` overlaps ONLY segment
        B, so the overlap-based slice keeps exactly one segment record. The
        inter-segment seal linking A -> B is at global_seq < b.first, hence
        NOT in-window; segment B's incoming link is therefore unprovable in
        this chunk. That is correct and verifiable: with a single segment in
        the bundle the segment-chain walk has no predecessor to link from, so
        the chunk self-verifies. The leading segment is KEPT (not dropped):
        dropping it would orphan its events for no verification gain. The
        manifest reports one kept segment and one excluded (segment A, which
        does not overlap the window)."""
        self._build_two_segment_corpus(sub)
        _, b, seal_seq = self._segment_and_gap_seqs(sub)

        # Sanity: the seal linking A -> B is before b.first, so the isolating
        # window (which starts at b.first - 1, i.e. includes only
        # global_seq >= b.first) excludes it.
        assert seal_seq < b["first_global_seq"]

        since_seq = b["first_global_seq"] - 1
        until_seq = b["last_global_seq"]
        output = tmp_path / "win_isolated_b.json"
        result = sub.export_audit_bundle(
            str(output), since_seq=since_seq, until_seq=until_seq
        )
        assert result["self_verification"]["verified"] is True, (
            result["self_verification"]["errors"]
        )
        # Only segment B overlaps the window; segment A does not.
        assert result["segment_count"] == 1
        assert result["segments_excluded"] == 1
        # Offline re-verification must agree.
        report = verify_audit_bundle_offline(str(output))
        assert report.verified, report.errors

    def test_windowed_export_sweep_self_verifies(self, sub, tmp_path):
        """WI-249 review F2 (exhaustive sweep): every ``since_seq``/
        ``until_seq`` window across a 2-segment corpus must export a bundle
        that self-verifies. This is the parametrized version of the empirical
        65-window sweep claimed in the round-1 report — now committed so the
        property is regression-protected. Each window is also re-verified
        offline to lock in agreement between the export-time and offline
        verifiers."""
        self._build_two_segment_corpus(sub)
        self._segment_and_gap_seqs(sub)  # ensure the 2-segment corpus exists

        # The full set of event global_seqs in the corpus, plus sentinels
        # just outside the range so we exercise windows that clip the edges.
        with raw_transaction(sub) as conn:
            seq_rows = conn.execute(
                "SELECT global_seq FROM events ORDER BY global_seq"
            ).fetchall()
        seqs = [r["global_seq"] for r in seq_rows]
        assert len(seqs) >= 4, f"need 4+ events for a meaningful sweep, got {len(seqs)}"

        min_seq, max_seq = seqs[0], seqs[-1]
        # Candidate boundaries: just below the min, every event seq, and just
        # above the max. Windows are (since_exclusive, until_inclusive].
        boundaries = [min_seq - 1, *seqs, max_seq + 1]

        windows: list[tuple[int, int]] = []
        for i, since in enumerate(boundaries):
            for until in boundaries[i + 1:]:
                # Skip degenerate/empty windows (until <= since) and windows
                # that would select no events (consecutive equal boundaries
                # already filtered; a window with no events raises inside
                # export, which is the correct behaviour, not a verification
                # concern — so we skip windows whose event set is empty).
                if until <= since:
                    continue
                # A window selects events with since < global_seq <= until.
                # Skip if no event seq falls in (since, until].
                has_event = any(since < s <= until for s in seqs)
                if not has_event:
                    continue
                windows.append((since, until))

        assert windows, "sweep produced no windows to test"
        # Pin the count so the claim made about this sweep cannot drift again.
        # The corpus is 10 events (2 work items x 4, plus 2 seal events), so
        # boundaries is [0, 1..10, 11] = 12 values and the loop above yields
        # C(12, 2) = 66 ordered pairs. Exactly one of them — (10, 11] — selects
        # no event and is skipped, leaving 65. Earlier prose called this a
        # "66-window sweep"; it is 65 (Sol round-2 NB).
        assert len(seqs) == 10, f"corpus changed: {len(seqs)} events"
        assert len(windows) == 65, f"expected 65 non-empty windows, got {len(windows)}"
        # Keep the sweep bounded: cap at a dense grid if the corpus is large.
        # For the typical 2-segment corpus (~10-20 events) this is the full
        # Cartesian set, well under a hundred windows.
        if len(windows) > 200:
            step = len(windows) // 200 + 1
            windows = windows[::step]

        for since_seq, until_seq in windows:
            output = tmp_path / f"win_sweep_{since_seq}_{until_seq}.json"
            result = sub.export_audit_bundle(
                str(output), since_seq=since_seq, until_seq=until_seq
            )
            assert result["self_verification"]["verified"] is True, (
                f"window ({since_seq},{until_seq}] failed self-verification: "
                f"{result['self_verification']['errors']}"
            )
            report = verify_audit_bundle_offline(str(output))
            assert report.verified, (
                f"window ({since_seq},{until_seq}] offline failed: "
                f"{report.errors}"
            )
            # Segment accounting must be consistent: kept + excluded == total
            # segments in the store for this project.
            with raw_transaction(sub) as conn:
                seg_total = conn.execute(
                    "SELECT COUNT(*) AS n FROM event_segments"
                ).fetchone()["n"]
            assert result["segment_count"] + result["segments_excluded"] == seg_total, (
                f"window ({since_seq},{until_seq}] segment accounting mismatch: "
                f"kept={result['segment_count']} + "
                f"excluded={result['segments_excluded']} != total={seg_total}"
            )

    def test_tampered_seal_event_removed_fails_segment_chain(self, sub, tmp_path):
        """WI-249 review F4(1): a bundle with the inter-segment SEAL EVENT
        removed must fail offline verification (verified=False). The seal is
        the only event linking the two segments; without it the chain walk
        cannot bridge them."""
        self._build_two_segment_corpus(sub)
        _, _, seal_seq = self._segment_and_gap_seqs(sub)

        output = tmp_path / "no_seal_bundle.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        # Drop the inter-segment seal event from the exported events.
        bundle["events"] = [
            e for e in bundle["events"] if e.get("global_seq") != seal_seq
        ]
        # Recompute the bundle hash so the bundle-hash check passes and the
        # segment-chain check is the one that fails.
        bundle["manifest"]["bundle_hash"] = (
            "sha256:"
            + hashlib.sha256(_canonical_bundle_bytes(bundle)).hexdigest()
        )
        Path(output).write_text(
            json.dumps(bundle, sort_keys=True, separators=(",", ":"), default=str)
        )

        report = verify_audit_bundle_offline(str(output))
        assert not report.segment_chain_ok, (
            "removing the inter-segment seal must break the segment chain"
        )
        assert not report.verified

    def test_tampered_intermediate_hash_fails_segment_chain(self, sub, tmp_path):
        """WI-249 review F4(2): a bundle where an intermediate (gap) event's
        prev_global_event_hash is mutated must fail offline verification. The
        chain walk relies on that hash to step from the earlier segment's head
        into the gap; corrupting it severs the walk."""
        self._build_two_segment_corpus(sub)
        _, _, seal_seq = self._segment_and_gap_seqs(sub)

        output = tmp_path / "tampered_gap_bundle.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        # The seal event is the intermediate event in the gap. Mutate its
        # prev_global_event_hash so it no longer chains from segment A's head.
        for e in bundle["events"]:
            if e.get("global_seq") == seal_seq:
                e["prev_global_event_hash"] = "ee" * 32
                break
        bundle["manifest"]["bundle_hash"] = (
            "sha256:"
            + hashlib.sha256(_canonical_bundle_bytes(bundle)).hexdigest()
        )
        Path(output).write_text(
            json.dumps(bundle, sort_keys=True, separators=(",", ":"), default=str)
        )

        report = verify_audit_bundle_offline(str(output))
        assert not report.segment_chain_ok, (
            "mutating the gap event's prev_global_event_hash must break the chain"
        )
        assert not report.verified


class TestSegmentRecordAnchoring:
    """WI-254: every segment record must be checked against the events it
    spans — not just as the *predecessor* half of an inter-segment link.

    The offline verifier used to return ``(True, None)`` for a single segment
    with zero checks, and for multiple segments it read ``head_hash`` only
    from ``sorted_segs[i - 1]``, so the terminal segment's ``head_hash`` /
    ``event_count`` / boundaries were never verified against anything. The
    bundle hash is unkeyed, so a tamperer restores it trivially — these tests
    therefore always recompute it and assert the *segment* check is what
    fails.
    """

    def _seal_one_segment(self, sub):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "wi-sole-seg",
            custom_fields={"title": "wi-sole-seg"},
        )
        _drive_to_terminal(sub, wi)
        sub.archive.seal(before_timestamp=datetime.now(UTC) + timedelta(days=365))

    def test_tampered_terminal_segment_fails_multi_segment(self, sub, tmp_path):
        """The LAST segment of a 2-segment bundle is the one the old loop never
        read as a predecessor. Tampering its head_hash and event_count and
        recomputing the bundle hash used to yield verified=True."""
        _build_two_segment_corpus(sub)

        output = tmp_path / "terminal_tamper.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        segs = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])
        assert len(segs) >= 2
        terminal = segs[-1]
        terminal["head_hash"] = "ff" * 32
        terminal["event_count"] = 99999
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok, "the tamperer restored the unkeyed hash"
        assert not report.segment_chain_ok
        # The signed seal event is now the first anchor to fire, and it reports
        # the first field it finds disagreeing — this test tampers two, so
        # assert on the substance rather than pinning which one is named.
        assert any(
            f in (report.segment_chain_error or "")
            for f in ("head_hash", "event_count")
        ), report.segment_chain_error
        assert not report.verified

    def test_tampered_sole_segment_fails(self, sub, tmp_path):
        """A single-segment bundle used to short-circuit to (True, None) with
        zero checks — the sole segment IS the terminal segment."""
        self._seal_one_segment(sub)

        output = tmp_path / "sole_tamper.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        assert len(bundle["segments"]) == 1
        bundle["segments"][0]["head_hash"] = "ff" * 32
        bundle["segments"][0]["event_count"] = 99999
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok
        assert not report.segment_chain_ok
        assert not report.verified

    def test_tampered_terminal_event_count_alone_fails(self, sub, tmp_path):
        """event_count is checked independently of head_hash: inflating the
        count while leaving the anchor intact must still fail closed."""
        _build_two_segment_corpus(sub)

        output = tmp_path / "count_tamper.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        segs = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])
        segs[-1]["event_count"] = segs[-1]["event_count"] + 7
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.segment_chain_ok
        assert "event_count" in (report.segment_chain_error or "")
        assert not report.verified

    def test_terminal_segment_boundary_inflation_fails(self, sub, tmp_path):
        """Pushing last_global_seq past the exported events does not buy the
        tamperer a skipped check: in a bundle that declares NO window there is
        no truncation to hide behind, so the missing terminal event fails
        closed."""
        _build_two_segment_corpus(sub)

        output = tmp_path / "boundary_tamper.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        max_seq = max(e["global_seq"] for e in bundle["events"])
        segs = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])
        segs[-1]["last_global_seq"] = max_seq + 50
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.segment_chain_ok
        assert "last_global_seq" in (report.segment_chain_error or "")
        assert not report.verified

    def test_overlapping_segment_ranges_fail(self, sub, tmp_path):
        """Segments partition the chain; two records claiming the same events
        (and so the same tail) is a refusal, not a pair of confirmations."""
        _build_two_segment_corpus(sub)

        output = tmp_path / "overlap_tamper.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        segs = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])
        segs[1]["first_global_seq"] = segs[0]["last_global_seq"]
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.segment_chain_ok
        assert "overlap" in (report.segment_chain_error or "")
        assert not report.verified

    def test_segment_fully_inside_a_window_is_still_checked(self, sub, tmp_path):
        """A chunked export does not disable the check for the segments the
        window fully contains."""
        _build_two_segment_corpus(sub)
        a, b, _ = _segment_and_gap_seqs(sub)

        output = tmp_path / "win_full_seg_tamper.json"
        sub.export_audit_bundle(
            str(output), until_seq=b["first_global_seq"]
        )

        bundle = json.loads(output.read_text())
        # Segment A is wholly inside (0, b.first]; tamper it.
        target = [
            s for s in bundle["segments"]
            if s["first_global_seq"] == a["first_global_seq"]
        ]
        assert target, "segment A must be kept by the overlap slice"
        # event_count, not head_hash: head_hash was already read as the
        # predecessor half of the inter-segment link, so tampering it would
        # have been caught before this fix too. event_count was never read.
        target[0]["event_count"] = target[0]["event_count"] + 4
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.segment_chain_ok
        assert "event_count" in (report.segment_chain_error or "")
        assert not report.verified

    def test_window_truncated_segment_metadata_is_not_checkable(
        self, sub, tmp_path
    ):
        """THE WINDOWED-EXPORT RULE, stated as a test.

        ``_slice_segments_to_window`` keeps every segment that OVERLAPS the
        window, so a kept segment can be only partly inside it. For such a
        segment ``head_hash`` and ``event_count`` describe events the chunk
        deliberately does not contain, and no offline check can settle them —
        so they are skipped, explicitly, rather than assumed.

        This test pins that limit rather than papering over it: in a chunk
        whose declared ``until_seq`` cuts segment B, B's metadata can be
        rewritten and the chunk still verifies. That is the price of chunked
        export, and it is why the manifest's ``since_seq``/``until_seq``
        belong in the auditor's chunk plan — a bundle that declares no window
        (``test_terminal_segment_boundary_inflation_fails``) has no such
        latitude. The complementary direction is covered by
        ``test_segment_fully_inside_a_window_is_still_checked`` and by the
        65-window sweep, which must keep verifying untampered chunks.
        """
        _build_two_segment_corpus(sub)
        _, b, _ = _segment_and_gap_seqs(sub)
        assert b["first_global_seq"] < b["last_global_seq"], (
            "need a segment the window can cut"
        )

        output = tmp_path / "win_partial_seg.json"
        # until_seq lands inside segment B, so B is kept but truncated.
        sub.export_audit_bundle(str(output), until_seq=b["first_global_seq"])

        clean = verify_audit_bundle_offline(str(output))
        assert clean.verified, clean.errors

        bundle = json.loads(output.read_text())
        partial = [
            s for s in bundle["segments"]
            if s["first_global_seq"] == b["first_global_seq"]
        ]
        assert partial, "segment B overlaps the window and must be kept"
        partial[0]["head_hash"] = "ff" * 32
        partial[0]["event_count"] = 99999
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert report.segment_chain_ok, (
            "a window-truncated segment's head_hash/event_count describe "
            "events outside the chunk and are documented as unverifiable here"
        )


class TestSegmentSealReconciliation:
    """Sol round-2 finding 1 (WI-254 re-opened): anchoring the segment record
    to the EVENTS left the record's own fields unanchored, and made the count
    check circular — membership is computed from the record's own
    ``work_item_ids``, so editing it together with ``event_count`` kept the two
    agreeing. Two full-export attacks verified clean.

    The unforgeable statement was already travelling in the bundle: the
    ``segment_sealed`` event the sealer signs. Its payload names every
    structural field of the segment, and its envelope is committed by the
    global hash chain, so reconciling the record against it means a tamperer
    must forge a signature rather than edit a JSON field.
    """

    def _seal_payload_for(self, bundle, segment_id):
        """The signed seal payload for *segment_id*, read from the envelope."""
        for e in bundle["events"]:
            if e.get("entity_kind") != "segment":
                continue
            env = json.loads(bytes.fromhex(e["canonical_envelope"]).decode())
            payload = env.get("payload") or {}
            if payload.get("segment_id") == segment_id:
                return e, env, payload
        raise AssertionError(f"no seal event for segment {segment_id}")

    def test_seal_payload_carries_the_structural_fields(self, sub, tmp_path):
        """Pin what the seal actually anchors, so a future change to the seal
        payload cannot quietly hollow out the reconciliation."""
        _build_two_segment_corpus(sub)

        output = tmp_path / "seal_shape.json"
        sub.export_audit_bundle(str(output))
        bundle = json.loads(output.read_text())
        seg = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])[-1]
        evt, env, payload = self._seal_payload_for(bundle, seg["segment_id"])

        assert env["transition"] == "segment_sealed"
        assert set(payload) == {
            "segment_id", "first_global_seq", "last_global_seq",
            "first_event_id", "last_event_id", "event_count",
            "min_timestamp", "max_timestamp", "head_hash",
            "first_event_prev_hash", "archive_path", "work_item_ids",
        }
        for name in (
            "first_global_seq", "last_global_seq", "event_count", "head_hash",
            "first_event_prev_hash", "first_event_id", "last_event_id",
            "work_item_ids", "min_timestamp", "max_timestamp", "archive_path",
        ):
            assert seg[name] == payload[name], name
        # Not in the payload, and documented as unanchorable: `archived` is
        # flipped after sealing, `created_at` is the row's insert time, and
        # `seal_event_id` is the seal event's own id (reconciled separately).
        assert {"archived", "created_at", "seal_event_id"} - set(payload) == {
            "archived", "created_at", "seal_event_id"
        }
        assert seg["seal_event_id"] == evt["event_id"]

    def test_sole_segment_first_global_seq_shifted_to_zero_fails(
        self, sub, tmp_path
    ):
        """Sol attack (a): change a sole segment's first_global_seq from 1 to 0
        on a FULL export and recompute the unkeyed hash."""
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "wi-sole",
            custom_fields={"title": "wi-sole"},
        )
        _drive_to_terminal(sub, wi)
        sub.archive.seal(before_timestamp=datetime.now(UTC) + timedelta(days=365))

        output = tmp_path / "attack_a.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        assert len(bundle["segments"]) == 1
        assert bundle["segments"][0]["first_global_seq"] == 1
        bundle["segments"][0]["first_global_seq"] = 0
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok, "the tamperer restored the unkeyed hash"
        assert not report.segment_chain_ok, report.segment_chain_error
        assert "first_global_seq" in (report.segment_chain_error or "")
        assert not report.verified

    @pytest.mark.parametrize("shifted", [0, -7], ids=["zero", "negative"])
    def test_first_global_seq_shift_fails_multi_segment(
        self, sub, tmp_path, shifted
    ):
        _build_two_segment_corpus(sub)

        output = tmp_path / f"attack_a_multi_{shifted}.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        segs = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])
        segs[0]["first_global_seq"] = shifted
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.segment_chain_ok
        assert not report.verified

    def test_work_item_ids_and_count_rewritten_together_fails(
        self, sub, tmp_path
    ):
        """Sol attack (b): replace work_item_ids with an unrelated UUID AND set
        event_count to 0, so the circular membership count agrees with itself
        (0 == 0)."""
        _build_two_segment_corpus(sub)

        output = tmp_path / "attack_b.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        segs = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])
        terminal = segs[-1]
        assert terminal["event_count"] == 4
        terminal["work_item_ids"] = [str(uuid.uuid4())]
        terminal["event_count"] = 0
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok
        assert not report.segment_chain_ok, report.segment_chain_error
        assert not report.verified

    def test_count_band_rejects_zero_without_the_seal(self, sub, tmp_path):
        """The non-circular half of attack (b)'s defence, exercised where the
        seal cannot help: a window whose until_seq excludes the seal event.
        ``event_count`` must still be at least 1."""
        _build_two_segment_corpus(sub)
        a, _, _ = _segment_and_gap_seqs(sub)

        # until_seq = a.last: segment A is fully in-window, its seal (which
        # sits above a.last) is not.
        output = tmp_path / "band_zero.json"
        sub.export_audit_bundle(str(output), until_seq=a["last_global_seq"])

        bundle = json.loads(output.read_text())
        seg = bundle["segments"][0]
        with pytest.raises(AssertionError):
            self._seal_payload_for(bundle, seg["segment_id"])
        seg["work_item_ids"] = [str(uuid.uuid4())]
        seg["event_count"] = 0
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.segment_chain_ok
        assert "at least one event" in (report.segment_chain_error or "")
        assert not report.verified

    def test_count_band_rejects_inflation_without_the_seal(self, sub, tmp_path):
        _build_two_segment_corpus(sub)
        a, _, _ = _segment_and_gap_seqs(sub)

        output = tmp_path / "band_inflated.json"
        sub.export_audit_bundle(str(output), until_seq=a["last_global_seq"])

        bundle = json.loads(output.read_text())
        seg = bundle["segments"][0]
        seg["work_item_ids"] = []  # force the range-based fallback count
        seg["event_count"] = 999
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.segment_chain_ok
        assert "non-seal event" in (report.segment_chain_error or "")
        assert not report.verified

    def test_first_event_id_rewrite_fails(self, sub, tmp_path):
        """The first-boundary anchor: moving first_global_seq onto a real event
        lands on the wrong event_id."""
        _build_two_segment_corpus(sub)

        output = tmp_path / "first_event_id.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        segs = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])
        segs[-1]["first_event_id"] = str(uuid.uuid4())
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.segment_chain_ok
        assert "first_event_id" in (report.segment_chain_error or "")
        assert not report.verified

    def test_seal_event_deleted_from_full_export_fails(self, sub, tmp_path):
        """A seal always follows the segment it seals, so a bundle declaring no
        upper bound must contain it. Deleting it is how a tamperer would try to
        remove the anchor before editing the record."""
        _build_two_segment_corpus(sub)

        output = tmp_path / "seal_deleted.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        seg = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])[-1]
        evt, _, _ = self._seal_payload_for(bundle, seg["segment_id"])
        bundle["events"] = [
            e for e in bundle["events"] if e["event_id"] != evt["event_id"]
        ]
        bundle["manifest"]["event_count"] = len(bundle["events"])
        seg["event_count"] = 99999
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.segment_chain_ok
        assert "no chain-linked segment_sealed event" in (
            report.segment_chain_error or ""
        )
        assert not report.verified

    def test_injected_free_floating_seal_is_not_an_anchor(self, sub, tmp_path):
        """Deleting the real seal and injecting a forged one that chains from
        nothing must not supply the anchor: ``_verify_global_chain`` tolerates
        chain-fragment starts, so an unlinked event is not evidence of
        anything. (An injected seal that DOES chain from a present event forks
        that event and is rejected by the chain check already.)"""
        _build_two_segment_corpus(sub)

        output = tmp_path / "seal_injected.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        seg = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])[-1]
        evt, env, payload = self._seal_payload_for(bundle, seg["segment_id"])

        # Forge a seal whose payload matches the doctored record, and cut it
        # loose from the chain so it is accepted as a bridge fragment. The
        # doctoring is Sol attack (b), which the circular count check alone
        # cannot see: 0 declared events, 0 events matching the record's own
        # work_item_ids.
        stolen = [str(uuid.uuid4())]
        payload["event_count"] = 0
        payload["work_item_ids"] = stolen
        env["payload"] = payload
        env["prev_global_event_hash"] = "ab" * 32
        forged = dict(evt)
        forged["canonical_envelope"] = json.dumps(
            env, sort_keys=True, separators=(",", ":")
        ).encode().hex()
        forged["prev_global_event_hash"] = "ab" * 32
        seg["event_count"] = 0
        seg["work_item_ids"] = stolen

        bundle["events"] = [
            e for e in bundle["events"] if e["event_id"] != evt["event_id"]
        ] + [forged]
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.verified
        assert not report.segment_chain_ok, report.segment_chain_error

    def test_clean_multi_segment_bundle_still_reconciles(self, sub, tmp_path):
        """The reconciliation must be satisfied by construction on real
        exports — full and windowed."""
        _build_two_segment_corpus(sub)
        a, b, _ = _segment_and_gap_seqs(sub)

        full = tmp_path / "recon_full.json"
        sub.export_audit_bundle(str(full))
        assert verify_audit_bundle_offline(str(full)).verified

        for since_seq, until_seq in [
            (None, b["last_global_seq"]),
            (a["first_global_seq"], b["last_global_seq"] + 5),
            (a["last_global_seq"], b["last_global_seq"]),
        ]:
            out = tmp_path / f"recon_win_{since_seq}_{until_seq}.json"
            sub.export_audit_bundle(
                str(out), since_seq=since_seq, until_seq=until_seq
            )
            report = verify_audit_bundle_offline(str(out))
            assert report.verified, (
                f"window ({since_seq},{until_seq}] failed: {report.errors}"
            )


class TestDeclaredWindowIntegrity:
    """PR #32 review B1/N1: the declared window gates the segment checks, so
    the window itself has to be a claim an export could have made.

    ``export_audit_bundle`` refuses ``until_seq <= since_seq`` and refuses any
    window that selects no events, and ``global_seq`` is 1-based — so a
    non-positive ``until_seq``, a negative ``since_seq`` or an inverted pair
    cannot appear in a bundle this exporter wrote. The first cut of this fix
    honoured them as real bounds: ``until_seq = 0`` made every segment
    ``last_global_seq > 0`` and so skipped EVERY check, reopening WI-254 and
    WI-255 with a one-key manifest edit.
    """

    @pytest.mark.parametrize(
        "since_seq,until_seq",
        [
            (None, 0),
            (None, -5),
            (100, 50),
            (-1, None),
        ],
        ids=["until-zero", "until-negative", "inverted", "since-negative"],
    )
    def test_impossible_window_does_not_disable_segment_checks(
        self, sub, tmp_path, since_seq, until_seq
    ):
        """The B1 attack: a FULL export, one manifest key rewritten to an
        impossible window, the terminal segment doctored, the unkeyed hash
        recomputed. The window must read as unbounded (so the segment checks
        run) AND be reported as tamper evidence in its own right."""
        _build_two_segment_corpus(sub)

        output = tmp_path / f"impossible_win_{since_seq}_{until_seq}.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        bundle["manifest"]["since_seq"] = since_seq
        bundle["manifest"]["until_seq"] = until_seq
        segs = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])
        segs[-1]["head_hash"] = "ff" * 32
        segs[-1]["event_count"] = 99999
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok, "the tamperer restored the unkeyed hash"
        assert not report.segment_chain_ok, (
            "an impossible window must not switch the segment checks off"
        )
        assert any(
            "Manifest window is not one this exporter could have written" in e
            for e in report.errors
        ), report.errors
        assert not report.verified

    def test_impossible_window_does_not_hide_tail_truncation(self, sub, tmp_path):
        """The same key edit combined with the WI-255 tamper: delete the
        terminal segment's tail event, doctor manifest.event_count to agree,
        and try to buy a skipped segment check with until_seq=0."""
        _build_two_segment_corpus(sub)
        _, b, _ = _segment_and_gap_seqs(sub)

        output = tmp_path / "impossible_win_truncated.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        bundle["events"] = [
            e for e in bundle["events"]
            if e["global_seq"] != b["last_global_seq"]
        ]
        bundle["manifest"]["event_count"] = len(bundle["events"])
        bundle["manifest"]["until_seq"] = 0
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not any(
            "Manifest count mismatch" in e for e in report.errors
        ), "the manifest was doctored to agree"
        assert not report.segment_chain_ok
        assert not report.verified

    def test_non_integer_window_reads_as_unbounded(self, sub, tmp_path):
        """Non-integer nonsense was already handled; pin it so the B1 fix
        cannot regress it while tightening the integer cases."""
        _build_two_segment_corpus(sub)

        output = tmp_path / "garbled_win.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        bundle["manifest"]["until_seq"] = "nope"
        segs = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])
        segs[-1]["head_hash"] = "ff" * 32
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.segment_chain_ok
        assert not report.verified

    def test_invented_window_must_also_drop_the_events(self, sub, tmp_path):
        """Review N1. A tamperer who invents a window to disclaim completeness
        for the terminal segment has to delete the out-of-window events too —
        editing one manifest key leaves events sitting outside the window the
        bundle declares."""
        _build_two_segment_corpus(sub)
        _, b, _ = _segment_and_gap_seqs(sub)

        output = tmp_path / "invented_win.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        # A window that genuinely cuts segment B — but the events of the full
        # export are still all here, which no real chunk export could produce.
        bundle["manifest"]["until_seq"] = b["first_global_seq"]
        segs = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])
        segs[-1]["head_hash"] = "ff" * 32
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert any(
            "above the declared window" in e for e in report.errors
        ), report.errors
        assert not report.verified

    def test_real_windowed_export_satisfies_its_own_window(self, sub, tmp_path):
        """The extents check must be satisfied by construction on every real
        chunk — including one whose until_seq runs past the corpus."""
        _build_two_segment_corpus(sub)
        a, b, _ = _segment_and_gap_seqs(sub)

        for since_seq, until_seq in [
            (None, b["first_global_seq"]),
            (a["first_global_seq"], b["last_global_seq"]),
            (0, b["last_global_seq"] + 500),
        ]:
            output = tmp_path / f"real_win_{since_seq}_{until_seq}.json"
            sub.export_audit_bundle(
                str(output), since_seq=since_seq, until_seq=until_seq
            )
            report = verify_audit_bundle_offline(str(output))
            assert report.verified, (
                f"window ({since_seq},{until_seq}] failed: {report.errors}"
            )


class TestManifestCountAgreement:
    """WI-255: the manifest's declared counts must agree with the sections
    they describe.

    ``report.event_count`` is taken from the parsed section, so a bundle with
    its tail event deleted and its manifest left alone used to normalise the
    divergence away and verify clean.
    """

    def test_tail_truncation_with_stale_manifest_fails(self, sub, tmp_path):
        """Truncation alone: delete the highest-global_seq event, leave the
        manifest counts as exported, recompute the bundle hash."""
        _build_two_segment_corpus(sub)

        output = tmp_path / "truncated.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        declared = bundle["manifest"]["event_count"]
        max_seq = max(e["global_seq"] for e in bundle["events"])
        bundle["events"] = [
            e for e in bundle["events"] if e["global_seq"] != max_seq
        ]
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok, "the tamperer restored the unkeyed hash"
        assert report.global_chain_ok, (
            "removing the chain tail leaves the remaining chain intact — the "
            "count check is what must catch this"
        )
        assert report.event_count == declared - 1
        assert not report.verified
        assert any(
            "Manifest count mismatch: manifest.event_count" in e
            for e in report.errors
        ), report.errors

    def test_truncation_with_doctored_manifest_fails_on_segment_anchor(
        self, sub, tmp_path
    ):
        """WI-254 + WI-255 composed. Deleting a segment's terminal event AND
        doctoring the manifest count to match defeats the count check — the
        terminal-segment anchor is what still fails closed."""
        _build_two_segment_corpus(sub)
        _, b, _ = _segment_and_gap_seqs(sub)

        output = tmp_path / "truncated_doctored.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        victim = b["last_global_seq"]
        bundle["events"] = [
            e for e in bundle["events"] if e["global_seq"] != victim
        ]
        bundle["manifest"]["event_count"] = len(bundle["events"])
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert report.bundle_hash_ok
        assert not any(
            "Manifest count mismatch" in e for e in report.errors
        ), "the manifest was doctored to agree — the count check cannot fire"
        assert not report.segment_chain_ok, (
            "the terminal segment's head_hash anchors the deleted event"
        )
        assert not report.verified

    def test_segment_count_divergence_fails(self, sub, tmp_path):
        """Not only event_count: every count the manifest declares is checked."""
        _build_two_segment_corpus(sub)

        output = tmp_path / "seg_count_divergence.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        assert len(bundle["segments"]) >= 2
        segs = sorted(bundle["segments"], key=lambda s: s["first_global_seq"])
        # Drop the LEADING segment and keep the manifest's count: the
        # remaining record still self-checks, so only the count check can
        # catch the removal.
        bundle["segments"] = segs[1:]
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.verified
        assert any(
            "Manifest count mismatch: manifest.segment_count" in e
            for e in report.errors
        ), report.errors

    def test_public_key_count_divergence_fails(self, sub, tmp_path):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "key-count",
            custom_fields={"title": "key-count"},
        )
        _drive_to_terminal(sub, wi)

        output = tmp_path / "key_count_divergence.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        bundle["manifest"]["public_key_count"] = (
            len(bundle.get("public_keys", [])) + 3
        )
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.verified
        assert any(
            "Manifest count mismatch: manifest.public_key_count" in e
            for e in report.errors
        ), report.errors

    def test_non_integer_manifest_count_fails_closed(self, sub, tmp_path):
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "count-type",
            custom_fields={"title": "count-type"},
        )
        _drive_to_terminal(sub, wi)

        output = tmp_path / "count_type.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        bundle["manifest"]["event_count"] = "many"
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.verified
        assert any("is not an integer" in e for e in report.errors), report.errors

    def test_v2_bundle_missing_a_count_fails_closed(self, sub, tmp_path):
        """Review N2: format_version 2 is always written with all four counts,
        so DELETING one is tamper evidence — otherwise dropping the key is a
        way to opt out of the check."""
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "count-missing",
            custom_fields={"title": "count-missing"},
        )
        _drive_to_terminal(sub, wi)

        output = tmp_path / "count_missing.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        assert bundle["manifest"]["format_version"] == 2
        del bundle["manifest"]["event_count"]
        # Truncate as well, to show what the deletion would have laundered.
        max_seq = max(e["global_seq"] for e in bundle["events"])
        bundle["events"] = [
            e for e in bundle["events"] if e["global_seq"] != max_seq
        ]
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert not report.verified
        assert any(
            "Manifest count missing" in e for e in report.errors
        ), report.errors

    def test_v1_bundle_may_omit_the_v2_only_count(self, sub, tmp_path):
        """The version gate must not punish a genuine v1 bundle, which predates
        the key registry and carries no public_key_count."""
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "count-v1",
            custom_fields={"title": "count-v1"},
        )
        _drive_to_terminal(sub, wi)

        output = tmp_path / "count_v1.json"
        sub.export_audit_bundle(str(output))

        bundle = json.loads(output.read_text())
        bundle.pop("public_keys", None)
        bundle["manifest"].pop("public_key_count", None)
        bundle["manifest"]["format_version"] = 1
        _rehash_and_write(bundle, output)

        report = verify_audit_bundle_offline(str(output))
        assert report.verified, report.errors
        assert not any("Manifest count" in e for e in report.errors)

    def test_clean_bundle_has_no_count_errors(self, sub, tmp_path):
        """The check must not fire on an untampered bundle — including one
        whose optional sections are empty."""
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "count-clean",
            custom_fields={"title": "count-clean"},
        )
        _drive_to_terminal(sub, wi)

        output = tmp_path / "count_clean.json"
        sub.export_audit_bundle(str(output))

        report = verify_audit_bundle_offline(str(output))
        assert report.verified, report.errors
        assert not any("Manifest count mismatch" in e for e in report.errors)


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
        # Proves exit code 0 via subprocess — calling _cli.main in-process only
        # proves no SystemExit was raised (WI-249).
        import subprocess
        import sys

        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "cli-allow",
            custom_fields={"title": "cli-allow"},
        )
        _drive_to_terminal(sub, wi)

        # Driver that patches the verifier in its own process and runs the
        # CLI main; sys.exit propagates the real exit code.
        driver = tmp_path / "cli_allow_driver.py"
        driver.write_text(
            "import sys\n"
            "from regista import _bundle, _cli\n"
            "from regista._bundle import BundleVerificationReport\n"
            "_bundle.verify_audit_bundle_offline = lambda _path: (\n"
            "    BundleVerificationReport(\n"
            "        verified=False, event_count=1, anchor_receipt_count=0,\n"
            "        segment_count=0, global_chain_ok=True, bundle_hash_ok=True,\n"
            "        errors=[\"No public key for key_id 'x' in bundle registry\"],\n"
            "    ))\n"
            "sys.exit(_cli.main([\n"
            "    'bundle', 'export', '--output', sys.argv[1],\n"
            "    '--allow-unverified',\n"
            "]))\n"
        )

        output = tmp_path / "cli_allowed.json"
        result = subprocess.run(
            [sys.executable, str(driver), str(output)],
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "REGISTA_DSN": DSN,
                "REGISTA_PROJECT": project,
                "REGISTA_HMAC_KEY_PATH": KEY_PATH,
            },
        )
        assert result.returncode == 0, (
            f"expected exit 0, got {result.returncode}\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
        assert output.exists()
