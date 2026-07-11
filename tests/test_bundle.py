from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from regista import Regista
from regista._anchoring import FileAnchorProvider
from regista._bundle import verify_audit_bundle_offline
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
        assert bundle["manifest"]["format_version"] == 1

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
