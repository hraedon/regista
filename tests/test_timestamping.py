from __future__ import annotations

import uuid
from datetime import UTC
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from substrate._timestamping import (
    TimestampBatch,
    TSAConfig,
    compute_merkle_root,
    merkle_proof,
    submit_to_tsa,
    verify_merkle_proof,
    verify_tsa_token,
)
from substrate.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


class TestMerkleTree:
    def test_root_deterministic(self):
        ids = [uuid.uuid4() for _ in range(4)]
        root1 = compute_merkle_root(ids)
        root2 = compute_merkle_root(ids)
        assert root1 == root2

    def test_single_event(self):
        uid = uuid.uuid4()
        root = compute_merkle_root([uid])
        assert isinstance(root, bytes)
        assert len(root) == 32

    def test_empty_raises(self):
        with pytest.raises(ValueError, match="event_ids must not be empty"):
            compute_merkle_root([])

    def test_inclusion_proof(self):
        ids = [uuid.uuid4() for _ in range(8)]
        root = compute_merkle_root(ids)
        target = ids[3]
        proof = merkle_proof(ids, target)
        assert verify_merkle_proof(root, target, proof)

    def test_exclusion_fails(self):
        ids = [uuid.uuid4() for _ in range(8)]
        root = compute_merkle_root(ids)
        bad = uuid.uuid4()
        proof = merkle_proof(ids, ids[0])
        assert not verify_merkle_proof(root, bad, proof)

    def test_odd_count(self):
        ids = [uuid.uuid4() for _ in range(5)]
        root = compute_merkle_root(ids)
        for uid in ids:
            proof = merkle_proof(ids, uid)
            assert verify_merkle_proof(root, uid, proof)

    def test_power_of_two(self):
        ids = [uuid.uuid4() for _ in range(16)]
        root = compute_merkle_root(ids)
        proof = merkle_proof(ids, ids[7])
        assert verify_merkle_proof(root, ids[7], proof)


class TestTSAConfig:
    def test_defaults(self):
        cfg = TSAConfig(tsa_url="https://example.com/tsr")
        assert cfg.tsa_url == "https://example.com/tsr"
        assert cfg.batch_size == 1000
        assert cfg.interval_seconds == 3600.0

    def test_custom_batch_size(self):
        cfg = TSAConfig(tsa_url="https://example.com/tsr", batch_size=500)
        assert cfg.batch_size == 500


class TestTSASubmission:
    def test_submit_posts_to_tsa_url(self):
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"\x30\x03\x02\x01\x01"
        data = b"\x00" * 32
        with patch("substrate._timestamping.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_resp)
            mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
            result = submit_to_tsa(data, cfg)
        assert result == b"\x30\x03\x02\x01\x01"

    def test_submit_raises_on_http_error(self):
        from substrate._errors import ErrorCode, SubstrateError

        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        mock_resp = MagicMock()
        mock_resp.status = 500
        data = b"\x00" * 32
        with patch("substrate._timestamping.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_resp)
            mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(SubstrateError) as exc_info:
                submit_to_tsa(data, cfg)
            assert exc_info.value.code == ErrorCode.TSA_SUBMISSION_FAILED


class TestVerifyTsaToken:
    def test_verify_empty_token_returns_false(self):
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        assert verify_tsa_token(b"", b"\x00" * 32, cfg) is False

    def test_verify_short_token_returns_false(self):
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        assert verify_tsa_token(b"\x00" * 8, b"\x00" * 32, cfg) is False

    def test_verify_embedded_digest_returns_true(self):
        import hashlib

        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        data = b"test data for tsa"
        digest = hashlib.sha256(data).digest()
        token = b"\x00" * 32 + digest + b"\x00" * 32
        assert verify_tsa_token(token, data, cfg) is True


class TestTimestampBatchToDict:
    def test_to_dict_serializes_all_fields(self):
        import hashlib
        from datetime import datetime

        b = TimestampBatch(
            batch_id=uuid.uuid4(),
            event_ids=[uuid.uuid4()],
            merkle_root=hashlib.sha256(b"test").digest(),
            tsa_token=None,
            tsa_timestamp=None,
            submitted_at=datetime(2026, 1, 1, tzinfo=UTC),
            confirmed_at=None,
            status="pending",
            error_message=None,
        )
        d = b.to_dict()
        assert d["status"] == "pending"
        assert d["tsa_token"] is None
        assert len(d["event_ids"]) == 1
        assert d["submitted_at"] == "2026-01-01T00:00:00+00:00"


@pytest.fixture
def timestamp_substrate():
    from substrate import Substrate

    project = f"test_ts_{uuid.uuid4().hex[:8]}"
    sub = Substrate.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestReplayVerifyTimestamps:
    def test_verify_timestamps_false_no_warnings(self, timestamp_substrate):
        timestamp_substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "ts test"},
        )
        report = timestamp_substrate.replay(verify_timestamps=False)
        assert report.halted == 0
        assert report.warnings == 0

    def test_verify_timestamps_true_uncovered_events_warns(self, timestamp_substrate):
        timestamp_substrate.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "ts uncovered"},
        )
        report = timestamp_substrate.replay(verify_timestamps=True)
        assert report.halted == 0
        assert report.warnings >= 1
