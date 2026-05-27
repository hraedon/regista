from __future__ import annotations

import hashlib
import uuid
from datetime import UTC
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from regista._timestamping import (
    TimestampBatch,
    TSAConfig,
    compute_merkle_root,
    merkle_proof,
    submit_to_tsa,
    verify_merkle_proof,
    verify_tsa_token,
)
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
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

    def test_tsa_cert_path_reserved_docstring(self):
        # BC-229: field must exist and carry a docstring warning callers it is
        # not yet implemented.
        import dataclasses

        fields = {f.name: f for f in dataclasses.fields(TSAConfig)}
        assert "tsa_cert_path" in fields, "tsa_cert_path field must remain in TSAConfig"
        # Confirm the class docstring / field docstring mentions "future"
        import inspect

        src = inspect.getsource(TSAConfig)
        assert "RESERVED FOR FUTURE USE" in src or "future" in src.lower(), (
            "tsa_cert_path should have a docstring noting it is not yet implemented"
        )


class TestTSASubmission:
    def test_submit_posts_to_tsa_url(self):
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"\x30\x03\x02\x01\x01"
        data = b"\x00" * 32
        with patch("regista._timestamping.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_resp)
            mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
            result = submit_to_tsa(data, cfg)
        assert result == b"\x30\x03\x02\x01\x01"

    def test_submit_raises_on_http_error(self):
        from regista._errors import ErrorCode, RegistaError

        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        mock_resp = MagicMock()
        mock_resp.status = 500
        data = b"\x00" * 32
        with patch("regista._timestamping.urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_resp)
            mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
            with pytest.raises(RegistaError) as exc_info:
                submit_to_tsa(data, cfg)
            assert exc_info.value.code == ErrorCode.TSA_SUBMISSION_FAILED


def _build_fake_tsa_token(data: bytes, algo: str = "sha256") -> bytes:
    # Build a real CMS ContentInfo wrapping a TSTInfo whose message_imprint
    # matches `data` under the given hash algorithm. Signature/cert fields are
    # left empty — verify_tsa_token does not validate them (see BC-229).
    from asn1crypto import cms, core, tsp

    digest = hashlib.new(algo, data).digest()
    tst_info = tsp.TSTInfo(
        {
            "version": "v1",
            "policy": "1.2.3.4.5",
            "message_imprint": tsp.MessageImprint(
                {
                    "hash_algorithm": {"algorithm": algo},
                    "hashed_message": digest,
                }
            ),
            "serial_number": 1,
            "gen_time": "20260524000000Z",
        }
    )
    encap = cms.EncapsulatedContentInfo({"content_type": "tst_info"})
    encap["content"] = core.ParsableOctetString(tst_info.dump())
    signed = cms.SignedData(
        {
            "version": "v3",
            "digest_algorithms": [{"algorithm": algo}],
            "encap_content_info": encap,
            "certificates": [],
            "signer_infos": [],
        }
    )
    ci = cms.ContentInfo({"content_type": "signed_data", "content": signed})
    return ci.dump()


class TestVerifyTsaToken:
    def test_verify_empty_token_returns_false(self):
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        assert verify_tsa_token(b"", b"\x00" * 32, cfg) is False

    def test_verify_short_token_returns_false(self):
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        assert verify_tsa_token(b"\x00" * 8, b"\x00" * 32, cfg) is False

    def test_verify_matching_imprint_returns_true(self):
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        data = b"test data for tsa"
        token = _build_fake_tsa_token(data)
        assert verify_tsa_token(token, data, cfg) is True

    def test_verify_mismatched_imprint_returns_false(self):
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        token = _build_fake_tsa_token(b"original data")
        assert verify_tsa_token(token, b"tampered data", cfg) is False

    def test_verify_substring_false_positive_blocked(self):
        # The legacy substring check would return True here because the data
        # digest appears verbatim in the token bytes. Real CMS parsing rejects it.
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        data = b"test data for tsa"
        digest = hashlib.sha256(data).digest()
        token = b"\x00" * 32 + digest + b"\x00" * 32
        assert verify_tsa_token(token, data, cfg) is False

    def test_verify_sha384_imprint(self):
        cfg = TSAConfig(
            tsa_url="https://tsa.example.com/tsr", hash_algorithm="sha384"
        )
        data = b"sha384 payload"
        token = _build_fake_tsa_token(data, algo="sha384")
        assert verify_tsa_token(token, data, cfg) is True


class TestBuildTsr:
    def test_build_tsr_uses_configured_hash(self):
        from asn1crypto import tsp

        cfg = TSAConfig(
            tsa_url="https://tsa.example.com/tsr", hash_algorithm="sha384"
        )
        from regista._timestamping import _build_tsr

        tsr_bytes = _build_tsr(b"payload", cfg, nonce=12345)
        req = tsp.TimeStampReq.load(tsr_bytes)
        assert req["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha384"
        assert bytes(req["message_imprint"]["hashed_message"]) == hashlib.sha384(
            b"payload"
        ).digest()
        assert int(req["nonce"]) == 12345
        assert bool(req["cert_req"]) is True

    def test_build_tsr_includes_nonce_by_default(self):
        from asn1crypto import tsp

        from regista._timestamping import _build_tsr

        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        a = tsp.TimeStampReq.load(_build_tsr(b"x", cfg))
        b = tsp.TimeStampReq.load(_build_tsr(b"x", cfg))
        # Two randomly-generated nonces will collide with vanishing probability.
        assert int(a["nonce"]) != int(b["nonce"])


class TestBC228UTCTimestamps:
    """BC-228: trigger_timestamping must use tz-aware UTC datetimes, not naive local ones."""

    def test_trigger_timestamping_failed_batch_has_tz_aware_submitted_at(self):
        # Simulate the failed branch by patching submit_to_tsa to raise.
        # We need a DB connection — use a minimal mock that satisfies the query
        # interface used before submit_to_tsa is called.
        from unittest.mock import MagicMock, patch

        from regista._timestamping import TSAConfig, trigger_timestamping

        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")

        mock_row = MagicMock()
        mock_row.__getitem__ = lambda self, k: 0  # max_seq = 0 for both queries

        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = mock_row

        # Make the second execute return rows so we get past the early-exit checks.
        # We need to distinguish the two fetchone calls and the fetchall call.
        # Simplest: return None to trigger the early return (no new events).
        # That's fine: if max_seq == last_confirmed_seq we return None — so
        # make last_confirmed_seq < max_seq by returning different values.
        call_results = [
            MagicMock(**{"fetchone.return_value": {"max_seq": 0}}),  # tsp_batches confirmed
            MagicMock(**{"fetchall.return_value": [
                {"event_id": uuid.uuid4(), "global_seq": 1, "timestamp": None},
            ]}),  # events query
            MagicMock(),  # INSERT
            MagicMock(),  # UPDATE (failed)
        ]
        mock_conn.execute.side_effect = call_results

        with patch("regista._timestamping.submit_to_tsa", side_effect=RuntimeError("tsa down")):
            result = trigger_timestamping(mock_conn, cfg)

        assert result is not None
        assert result.status == "failed"
        assert result.submitted_at is not None
        assert result.submitted_at.tzinfo is not None, (
            "submitted_at must be timezone-aware (UTC); got naive datetime"
        )

    def test_trigger_timestamping_confirmed_branch_tz_aware(self):
        from unittest.mock import MagicMock, patch

        from regista._timestamping import TSAConfig, trigger_timestamping

        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")

        fake_event_id = uuid.uuid4()
        token = _build_fake_tsa_token(b"x")  # valid-ish token for parsing

        call_results = [
            MagicMock(**{"fetchone.return_value": {"max_seq": 0}}),
            MagicMock(**{"fetchall.return_value": [
                {"event_id": fake_event_id, "global_seq": 1, "timestamp": None},
            ]}),
            MagicMock(),  # INSERT
            MagicMock(),  # UPDATE confirmed
        ]
        mock_conn = MagicMock()
        mock_conn.execute.side_effect = call_results

        with patch("regista._timestamping.submit_to_tsa", return_value=token):
            result = trigger_timestamping(mock_conn, cfg)

        assert result is not None
        assert result.status == "confirmed"
        assert result.submitted_at is not None
        assert result.submitted_at.tzinfo is not None, (
            "submitted_at must be timezone-aware"
        )
        assert result.confirmed_at is not None
        assert result.confirmed_at.tzinfo is not None, (
            "confirmed_at must be timezone-aware"
        )
        assert result.tsa_timestamp is not None
        assert result.tsa_timestamp.tzinfo is not None, (
            "tsa_timestamp must be timezone-aware"
        )


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
def timestamp_regista():
    from regista import Regista

    project = f"test_ts_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestReplayVerifyTimestamps:
    def test_verify_timestamps_false_no_warnings(self, timestamp_regista):
        timestamp_regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "ts test"},
        )
        report = timestamp_regista.replay(verify_timestamps=False)
        assert report.halted == 0
        assert report.warnings == 0

    def test_verify_timestamps_true_uncovered_events_warns(self, timestamp_regista):
        timestamp_regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "ts uncovered"},
        )
        report = timestamp_regista.replay(verify_timestamps=True)
        assert report.halted == 0
        assert report.warnings >= 1

    def test_verify_timestamps_invalid_token_warns(self, timestamp_regista):
        # BC-226: replay(verify_timestamps=True) must validate the TSA token, not
        # just check coverage.  Insert a confirmed tsp_batch row whose tsa_token is
        # garbage (all-zeros), covering all event seqs.  The replay should warn
        # because the token fails cryptographic verification.
        import psycopg
        from psycopg.rows import dict_row

        _, _ = timestamp_regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "invalid token test"},
        )

        # Discover the event global_seq range for the events just created.
        with psycopg.connect(DSN, row_factory=dict_row) as raw_conn:
            schema = timestamp_regista._mgr.schema
            raw_conn.execute(f"SET search_path TO {schema}")
            evt_rows = raw_conn.execute(
                "SELECT MIN(global_seq) AS min_seq, MAX(global_seq) AS max_seq FROM events"
            ).fetchone()
            min_seq = evt_rows["min_seq"]
            max_seq = evt_rows["max_seq"]

            # Compute a valid-looking merkle root so coverage passes, but use a
            # garbage tsa_token so verify_tsa_token returns False.
            event_id_rows = raw_conn.execute(
                "SELECT event_id FROM events ORDER BY global_seq"
            ).fetchall()
            from regista._timestamping import compute_merkle_root
            event_ids = [r["event_id"] for r in event_id_rows]
            merkle_root = compute_merkle_root(event_ids)

            bad_token = b"\x00" * 32  # not a valid CMS token

            raw_conn.execute(
                "INSERT INTO tsp_batches "
                "(batch_id, merkle_root, first_global_seq, last_global_seq, "
                "first_event_at, last_event_at, event_count, status, tsa_token, confirmed_at) "
                "VALUES (gen_random_uuid(), %s, %s, %s, now(), now(), %s, 'confirmed', %s, now())",
                [merkle_root, min_seq, max_seq, max_seq - min_seq + 1, bad_token],
            )

        report = timestamp_regista.replay(verify_timestamps=True)
        # The bad token should produce a warning even though all events are covered.
        assert report.warnings >= 1

    def test_verify_timestamps_valid_token_no_extra_warnings(self, timestamp_regista):
        # BC-226: when a confirmed batch has a proper TSA token that validates,
        # no additional warning should be emitted for the token itself.
        import psycopg
        from psycopg.rows import dict_row

        timestamp_regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "valid token test"},
        )

        with psycopg.connect(DSN, row_factory=dict_row) as raw_conn:
            schema = timestamp_regista._mgr.schema
            raw_conn.execute(f"SET search_path TO {schema}")
            evt_rows = raw_conn.execute(
                "SELECT MIN(global_seq) AS min_seq, MAX(global_seq) AS max_seq FROM events"
            ).fetchone()
            min_seq = evt_rows["min_seq"]
            max_seq = evt_rows["max_seq"]

            event_id_rows = raw_conn.execute(
                "SELECT event_id FROM events ORDER BY global_seq"
            ).fetchall()
            from regista._timestamping import compute_merkle_root
            event_ids = [r["event_id"] for r in event_id_rows]
            merkle_root = compute_merkle_root(event_ids)

            # Build a valid fake token whose imprint matches the merkle_root.
            good_token = _build_fake_tsa_token(merkle_root)

            raw_conn.execute(
                "INSERT INTO tsp_batches "
                "(batch_id, merkle_root, first_global_seq, last_global_seq, "
                "first_event_at, last_event_at, event_count, status, tsa_token, confirmed_at) "
                "VALUES (gen_random_uuid(), %s, %s, %s, now(), now(), %s, 'confirmed', %s, now())",
                [merkle_root, min_seq, max_seq, max_seq - min_seq + 1, good_token],
            )

        report = timestamp_regista.replay(verify_timestamps=True)
        # With all events covered by a valid token, warnings should be 0.
        assert report.warnings == 0

    def test_verify_timestamps_merkle_root_mismatch_warns(self, timestamp_regista):
        # BC-230: a stored merkle_root that no longer matches the current event
        # log must produce a warning, even when the TSA token validates that
        # stored root. Simulates an operator tampering with events while
        # leaving tsp_batches.merkle_root intact.
        import psycopg
        from psycopg.rows import dict_row

        timestamp_regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "merkle mismatch test"},
        )

        with psycopg.connect(DSN, row_factory=dict_row) as raw_conn:
            schema = timestamp_regista._mgr.schema
            raw_conn.execute(f"SET search_path TO {schema}")
            evt_rows = raw_conn.execute(
                "SELECT MIN(global_seq) AS min_seq, MAX(global_seq) AS max_seq FROM events"
            ).fetchone()
            min_seq = evt_rows["min_seq"]
            max_seq = evt_rows["max_seq"]

            # Use a merkle_root derived from a DIFFERENT, fake event set —
            # the TSA signed *that* root, but the current event log will
            # re-derive to something else.
            fake_ids = [uuid.uuid4() for _ in range(3)]
            from regista._timestamping import compute_merkle_root
            stale_root = compute_merkle_root(fake_ids)
            valid_token = _build_fake_tsa_token(stale_root)

            raw_conn.execute(
                "INSERT INTO tsp_batches "
                "(batch_id, merkle_root, first_global_seq, last_global_seq, "
                "first_event_at, last_event_at, event_count, status, tsa_token, confirmed_at) "
                "VALUES (gen_random_uuid(), %s, %s, %s, now(), now(), %s, 'confirmed', %s, now())",
                [stale_root, min_seq, max_seq, max_seq - min_seq + 1, valid_token],
            )

        report = timestamp_regista.replay(verify_timestamps=True)
        # The re-derived root from current events won't match the stale stored root.
        assert report.warnings >= 1


class TestPlan014GlobalSeq:
    """Plan 014: global_seq is monotonic and coherent across multi-WI batches."""

    def test_global_seq_monotonic_across_work_items(self, timestamp_regista):
        import psycopg
        from psycopg.rows import dict_row

        # Create two work items.
        wi1, _ = timestamp_regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "wi1"},
        )
        wi2, _ = timestamp_regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "wi2"},
        )

        # Insert a third event to wi1 after wi2 created, interleaving global_seq.
        timestamp_regista.transition(
            wi1.work_item_id, "start", "agent-1",
            actor_metadata={"role": "agent"},
        )

        with psycopg.connect(DSN, row_factory=dict_row) as raw_conn:
            schema = timestamp_regista._mgr.schema
            raw_conn.execute(f"SET search_path TO {schema}")
            rows = raw_conn.execute(
                "SELECT work_item_id, event_seq, global_seq FROM events ORDER BY global_seq"
            ).fetchall()

        global_seqs = [r["global_seq"] for r in rows]
        # global_seq must be monotonic (allowing gaps from CACHE 100 on the
        # sequence) and unique across all events.
        assert global_seqs == sorted(global_seqs)
        assert len(set(global_seqs)) == len(global_seqs)

        # Per-work-item ordering: each event for a given WI has higher global_seq
        # than the previous event for that WI.
        wi1_rows = [r for r in rows if r["work_item_id"] == wi1.work_item_id]
        wi2_rows = [r for r in rows if r["work_item_id"] == wi2.work_item_id]
        assert wi1_rows[1]["global_seq"] > wi1_rows[0]["global_seq"]
        assert wi2_rows[0]["global_seq"] > wi1_rows[0]["global_seq"]

    def test_trigger_timestamping_selects_by_global_seq(self, timestamp_regista):
        from unittest.mock import patch

        from regista._timestamping import (
            TSAConfig,
            compute_merkle_root,
            trigger_timestamping,
        )

        # Create three work items.
        _wi1, _ = timestamp_regista.create_work_item(
            workflow_name="test_workflow", work_item_type="feature",
            actor_id="agent-1", custom_fields={"title": "a"},
        )
        _wi2, _ = timestamp_regista.create_work_item(
            workflow_name="test_workflow", work_item_type="feature",
            actor_id="agent-1", custom_fields={"title": "b"},
        )
        _wi3, _ = timestamp_regista.create_work_item(
            workflow_name="test_workflow", work_item_type="feature",
            actor_id="agent-1", custom_fields={"title": "c"},
        )

        import psycopg
        from psycopg.rows import dict_row

        with psycopg.connect(DSN, row_factory=dict_row) as raw_conn:
            schema = timestamp_regista._mgr.schema
            raw_conn.execute(f"SET search_path TO {schema}")
            row = raw_conn.execute(
                "SELECT MIN(global_seq) AS min_gs, MAX(global_seq) AS max_gs FROM events"
            ).fetchone()
            min_gs = row["min_gs"]
            max_gs = row["max_gs"]

            # All events should be selected in one batch by trigger_timestamping
            cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr", batch_size=1000)
            fake_token = _build_fake_tsa_token(b"merkle_root_placeholder")

            # Patch submit_to_tsa to return a fake token that passes verify.
            with patch("regista._timestamping.submit_to_tsa", return_value=fake_token):
                batch = trigger_timestamping(raw_conn, cfg)

            assert batch is not None
            assert batch.status == "confirmed"

            # Verify the stored row has correct global_seq bounds.
            batch_row = raw_conn.execute(
                "SELECT first_global_seq, last_global_seq FROM tsp_batches WHERE batch_id = %s",
                [batch.batch_id],
            ).fetchone()
            assert batch_row["first_global_seq"] == min_gs
            assert batch_row["last_global_seq"] == max_gs

            # Verify merkle root matches.
            event_id_rows = raw_conn.execute(
                "SELECT event_id FROM events WHERE global_seq >= %s "
                "AND global_seq <= %s ORDER BY global_seq",
                [min_gs, max_gs],
            ).fetchall()
            expected_ids = [r["event_id"] for r in event_id_rows]
            assert len(batch.event_ids) == len(expected_ids)
            expected_root = compute_merkle_root(expected_ids)
            assert batch.merkle_root == expected_root

    def test_replay_verify_timestamps_multi_wi(self, timestamp_regista):
        import psycopg
        from psycopg.rows import dict_row

        for i in range(3):
            timestamp_regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": f"wi{i}"},
            )

        with psycopg.connect(DSN, row_factory=dict_row) as raw_conn:
            schema = timestamp_regista._mgr.schema
            raw_conn.execute(f"SET search_path TO {schema}")
            evt_rows = raw_conn.execute(
                "SELECT MIN(global_seq) AS min_seq, MAX(global_seq) AS max_seq FROM events"
            ).fetchone()
            min_seq = evt_rows["min_seq"]
            max_seq = evt_rows["max_seq"]

            event_id_rows = raw_conn.execute(
                "SELECT event_id FROM events ORDER BY global_seq"
            ).fetchall()
            event_ids = [r["event_id"] for r in event_id_rows]
            from regista._timestamping import compute_merkle_root
            merkle_root = compute_merkle_root(event_ids)

            good_token = _build_fake_tsa_token(merkle_root)

            raw_conn.execute(
                "INSERT INTO tsp_batches "
                "(batch_id, merkle_root, first_global_seq, last_global_seq, "
                "first_event_at, last_event_at, event_count, status, tsa_token, confirmed_at) "
                "VALUES (gen_random_uuid(), %s, %s, %s, now(), now(), %s, 'confirmed', %s, now())",
                [merkle_root, min_seq, max_seq, max_seq - min_seq + 1, good_token],
            )

        report = timestamp_regista.replay(verify_timestamps=True)
        assert report.warnings == 0
        assert report.halted == 0

    def test_replay_merkle_root_mismatch_multi_wi(self, timestamp_regista):
        import psycopg
        from psycopg.rows import dict_row

        for i in range(3):
            timestamp_regista.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent-1",
                custom_fields={"title": f"wi{i}"},
            )

        with psycopg.connect(DSN, row_factory=dict_row) as raw_conn:
            schema = timestamp_regista._mgr.schema
            raw_conn.execute(f"SET search_path TO {schema}")
            evt_rows = raw_conn.execute(
                "SELECT MIN(global_seq) AS min_seq, MAX(global_seq) AS max_seq FROM events"
            ).fetchone()
            min_seq = evt_rows["min_seq"]
            max_seq = evt_rows["max_seq"]

            fake_ids = [uuid.uuid4() for _ in range(3)]
            from regista._timestamping import compute_merkle_root
            stale_root = compute_merkle_root(fake_ids)
            valid_token = _build_fake_tsa_token(stale_root)

            raw_conn.execute(
                "INSERT INTO tsp_batches "
                "(batch_id, merkle_root, first_global_seq, last_global_seq, "
                "first_event_at, last_event_at, event_count, status, tsa_token, confirmed_at) "
                "VALUES (gen_random_uuid(), %s, %s, %s, now(), now(), %s, 'confirmed', %s, now())",
                [stale_root, min_seq, max_seq, max_seq - min_seq + 1, valid_token],
            )

        report = timestamp_regista.replay(verify_timestamps=True)
        assert report.warnings >= 1
        assert report.halted == 0
