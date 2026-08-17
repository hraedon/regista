from __future__ import annotations

import hashlib
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import psycopg
import pytest
from psycopg.rows import dict_row

from regista._anchoring import (
    AnchorReceipt,
    AnchorStatus,
    FileAnchorProvider,
    OpenTimestampsProvider,
    RFC3161AnchorProvider,
    compute_content_anchor,
    create_anchor_receipt,
    get_anchor_receipt,
    latest_confirmed_seq,
    list_anchor_receipts,
    retry_failed_anchors,
    trigger_anchoring,
    update_anchor_receipt,
    verify_content_anchor,
)
from regista._errors import ErrorCode, RegistaError
from regista._timestamping import TSAConfig
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")
PYTHON = sys.executable


def _build_fake_tsa_token(data: bytes, algo: str = "sha256") -> bytes:
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
            "gen_time": "20260622000000Z",
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


class TestAnchorReceiptRoundTrip:
    def test_to_dict_and_from_dict_round_trips(self):
        receipt_id = uuid.uuid4()
        root = hashlib.sha256(b"test").digest()
        token = b"\x01\x02\x03"
        submitted = datetime(2026, 6, 22, 12, 0, tzinfo=UTC)
        confirmed = datetime(2026, 6, 22, 13, 0, tzinfo=UTC)
        receipt = AnchorReceipt(
            receipt_id=receipt_id,
            provider="file",
            merkle_root=root,
            status=AnchorStatus.CONFIRMED,
            receipt_bytes=token,
            submitted_at=submitted,
            confirmed_at=confirmed,
            target_global_seq=42,
            failure_count=0,
            last_error=None,
        )
        d = receipt.to_dict()
        assert d["receipt_id"] == str(receipt_id)
        assert d["merkle_root"] == root.hex()
        assert d["receipt_bytes"] == token.hex()
        assert d["submitted_at"] == submitted.isoformat()
        assert d["confirmed_at"] == confirmed.isoformat()
        assert d["target_global_seq"] == 42
        restored = AnchorReceipt.from_dict(d)
        assert restored.receipt_id == receipt_id
        assert restored.merkle_root == root
        assert restored.receipt_bytes == token
        assert restored.status == AnchorStatus.CONFIRMED
        assert restored.target_global_seq == 42

    def test_round_trip_with_none_fields(self):
        receipt = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="file",
            merkle_root=b"\x00" * 32,
            status=AnchorStatus.PENDING,
            submitted_at=datetime.now(UTC),
        )
        d = receipt.to_dict()
        assert d["receipt_bytes"] is None
        assert d["confirmed_at"] is None
        assert d["target_global_seq"] is None
        restored = AnchorReceipt.from_dict(d)
        assert restored.receipt_bytes is None
        assert restored.confirmed_at is None
        assert restored.target_global_seq is None


class TestFileAnchorProvider:
    def test_submit_writes_log_line_and_returns_confirmed(self, tmp_path):
        provider = FileAnchorProvider(directory=str(tmp_path))
        root = hashlib.sha256(b"event-batch").digest()
        receipt = provider.submit(root)
        assert receipt.status == AnchorStatus.CONFIRMED
        assert receipt.provider == "file"
        assert receipt.merkle_root == root
        assert receipt.confirmed_at is not None
        log_path = tmp_path / "anchors.log"
        assert log_path.exists()
        content = log_path.read_text(encoding="utf-8")
        assert root.hex() in content
        assert str(receipt.receipt_id) in content

    def test_verify_returns_confirmed_for_real_submission(self, tmp_path):
        provider = FileAnchorProvider(directory=str(tmp_path))
        root = hashlib.sha256(b"real-root").digest()
        receipt = provider.submit(root)
        status = provider.verify(root, receipt)
        assert status == AnchorStatus.CONFIRMED

    def test_verify_returns_failed_for_tampered_root(self, tmp_path):
        provider = FileAnchorProvider(directory=str(tmp_path))
        real_root = hashlib.sha256(b"real").digest()
        receipt = provider.submit(real_root)
        tampered = hashlib.sha256(b"forged").digest()
        status = provider.verify(tampered, receipt)
        assert status == AnchorStatus.FAILED

    def test_verify_returns_failed_when_log_missing(self, tmp_path):
        provider = FileAnchorProvider(directory=str(tmp_path))
        receipt = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="file",
            merkle_root=b"\x00" * 32,
            status=AnchorStatus.CONFIRMED,
            submitted_at=datetime.now(UTC),
        )
        assert not (tmp_path / "anchors.log").exists()
        status = provider.verify(b"\x00" * 32, receipt)
        assert status == AnchorStatus.FAILED

    def test_upgrade_is_noop(self, tmp_path):
        provider = FileAnchorProvider(directory=str(tmp_path))
        root = hashlib.sha256(b"root").digest()
        receipt = provider.submit(root)
        upgraded = provider.upgrade(receipt)
        assert upgraded is receipt

    def test_creates_directory_if_missing(self, tmp_path):
        subdir = tmp_path / "deep" / "nested"
        provider = FileAnchorProvider(directory=str(subdir))
        assert subdir.exists()
        provider.submit(hashlib.sha256(b"x").digest())


class TestRFC3161AnchorProvider:
    def test_submit_returns_confirmed_with_token(self):
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        root = hashlib.sha256(b"batch-root").digest()
        fake_token = _build_fake_tsa_token(root)
        with patch("regista._anchoring.submit_to_tsa", return_value=fake_token):
            provider = RFC3161AnchorProvider(cfg)
            receipt = provider.submit(root)
        assert receipt.status == AnchorStatus.CONFIRMED
        assert receipt.receipt_bytes == fake_token
        assert receipt.confirmed_at is not None

    def test_verify_passes_for_matching_root(self):
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        root = hashlib.sha256(b"matching").digest()
        token = _build_fake_tsa_token(root)
        receipt = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="rfc3161",
            merkle_root=root,
            status=AnchorStatus.CONFIRMED,
            receipt_bytes=token,
            submitted_at=datetime.now(UTC),
        )
        provider = RFC3161AnchorProvider(cfg)
        assert provider.verify(root, receipt) == AnchorStatus.CONFIRMED

    def test_verify_fails_for_tampered_root(self):
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        real_root = hashlib.sha256(b"original").digest()
        token = _build_fake_tsa_token(real_root)
        receipt = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="rfc3161",
            merkle_root=real_root,
            status=AnchorStatus.CONFIRMED,
            receipt_bytes=token,
            submitted_at=datetime.now(UTC),
        )
        provider = RFC3161AnchorProvider(cfg)
        tampered = hashlib.sha256(b"forged").digest()
        assert provider.verify(tampered, receipt) == AnchorStatus.FAILED

    def test_verify_fails_when_receipt_bytes_none(self):
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        receipt = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="rfc3161",
            merkle_root=b"\x00" * 32,
            status=AnchorStatus.CONFIRMED,
            submitted_at=datetime.now(UTC),
        )
        provider = RFC3161AnchorProvider(cfg)
        assert provider.verify(b"\x00" * 32, receipt) == AnchorStatus.FAILED

    def test_upgrade_is_noop(self):
        cfg = TSAConfig(tsa_url="https://tsa.example.com/tsr")
        provider = RFC3161AnchorProvider(cfg)
        receipt = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="rfc3161",
            merkle_root=b"\x00" * 32,
            status=AnchorStatus.CONFIRMED,
            submitted_at=datetime.now(UTC),
        )
        assert provider.upgrade(receipt) is receipt


class _FakeTimestamp:
    def __init__(self, digest, proof_bytes, ops=None, confirmed=False):
        self.digest = digest
        self._proof_bytes = proof_bytes
        self.ops = ops if ops is not None else {"attestation": True}
        self._confirmed = confirmed

    def serialize(self):
        return self._proof_bytes

    def upgrade(self, calendar):
        if calendar._upgrade_confirms:
            self._proof_bytes = b"confirmed_proof"
            self._confirmed = True


class _FakeCalendar:
    def __init__(self, url, upgrade_confirms=False):
        self.url = url
        self._upgrade_confirms = upgrade_confirms

    def stamp(self, digest):
        return _FakeTimestamp(digest, b"partial_proof")


def _make_fake_ots(*, confirm_on_verify=False, upgrade_confirms=False):
    import types

    def fake_deserialize(file_obj):
        data = file_obj.read()
        if data not in (b"partial_proof", b"confirmed_proof"):
            raise ValueError("invalid proof")
        return _FakeTimestamp(
            b"\x00" * 32, data,
            confirmed=(data == b"confirmed_proof"),
        )

    def fake_verify_timestamp(timestamp, digest):
        if timestamp._confirmed or confirm_on_verify:
            return datetime.now(UTC)
        return None

    ots = types.ModuleType("opentimestamps")
    calendar_mod = types.ModuleType("opentimestamps.calendar")

    class _CalendarFactory:
        def __call__(self, url):
            return _FakeCalendar(url, upgrade_confirms=upgrade_confirms)

    calendar_mod.RemoteCalendar = _CalendarFactory()
    core_mod = types.ModuleType("opentimestamps.core")
    ts_mod = types.ModuleType("opentimestamps.core.timestamp")
    ts_mod.deserialize = fake_deserialize
    ts_mod.Timestamp = _FakeTimestamp
    bitcoin_mod = types.ModuleType("opentimestamps.bitcoin")
    bitcoin_mod.verify_timestamp = fake_verify_timestamp

    ots.calendar = calendar_mod
    ots.core = core_mod
    ots.bitcoin = bitcoin_mod
    core_mod.timestamp = ts_mod

    modules = {
        "opentimestamps": ots,
        "opentimestamps.calendar": calendar_mod,
        "opentimestamps.core": core_mod,
        "opentimestamps.core.timestamp": ts_mod,
        "opentimestamps.bitcoin": bitcoin_mod,
    }
    return ots, modules


class TestOpenTimestampsProvider:
    def test_soft_import_raises_when_missing(self):
        with patch.dict(sys.modules, {"opentimestamps": None}):
            with pytest.raises(RegistaError) as exc_info:
                OpenTimestampsProvider()
            assert exc_info.value.code == ErrorCode.ANCHOR_PROVIDER_UNAVAILABLE
            assert "pip install regista[anchoring]" in exc_info.value.message

    def test_submit_returns_pending_receipt(self):
        _ots, modules = _make_fake_ots()
        with patch.dict(sys.modules, modules):
            provider = OpenTimestampsProvider()
            root = hashlib.sha256(b"ots-root").digest()
            receipt = provider.submit(root)
        assert receipt.status == AnchorStatus.PENDING
        assert receipt.provider == "opentimestamps"
        assert receipt.receipt_bytes == b"partial_proof"
        assert receipt.confirmed_at is None

    def test_upgrade_returns_confirmed_when_calendar_confirms(self):
        _ots, modules = _make_fake_ots(upgrade_confirms=True)
        with patch.dict(sys.modules, modules):
            provider = OpenTimestampsProvider()
            root = hashlib.sha256(b"upgrade-root").digest()
            receipt = provider.submit(root)
            assert receipt.status == AnchorStatus.PENDING
            upgraded = provider.upgrade(receipt)
        assert upgraded.status == AnchorStatus.CONFIRMED
        assert upgraded.confirmed_at is not None
        assert upgraded.receipt_bytes == b"confirmed_proof"

    def test_upgrade_stays_pending_when_not_confirmed(self):
        _ots, modules = _make_fake_ots(upgrade_confirms=False)
        with patch.dict(sys.modules, modules):
            provider = OpenTimestampsProvider()
            root = hashlib.sha256(b"pending-root").digest()
            receipt = provider.submit(root)
            upgraded = provider.upgrade(receipt)
        assert upgraded.status == AnchorStatus.PENDING
        assert upgraded.confirmed_at is None

    def test_verify_returns_confirmed_for_attested_proof(self):
        _ots, modules = _make_fake_ots()
        with patch.dict(sys.modules, modules):
            provider = OpenTimestampsProvider()
            root = hashlib.sha256(b"verified-root").digest()
            receipt = AnchorReceipt(
                receipt_id=uuid.uuid4(),
                provider="opentimestamps",
                merkle_root=root,
                status=AnchorStatus.CONFIRMED,
                receipt_bytes=b"confirmed_proof",
                submitted_at=datetime.now(UTC),
            )
            status = provider.verify(root, receipt)
        assert status == AnchorStatus.CONFIRMED

    def test_verify_returns_pending_for_partial_proof(self):
        _ots, modules = _make_fake_ots()
        with patch.dict(sys.modules, modules):
            provider = OpenTimestampsProvider()
            root = hashlib.sha256(b"partial-root").digest()
            receipt = AnchorReceipt(
                receipt_id=uuid.uuid4(),
                provider="opentimestamps",
                merkle_root=root,
                status=AnchorStatus.PENDING,
                receipt_bytes=b"partial_proof",
                submitted_at=datetime.now(UTC),
            )
            status = provider.verify(root, receipt)
        assert status == AnchorStatus.PENDING

    def test_verify_returns_failed_for_garbage_proof(self):
        _ots, modules = _make_fake_ots()
        with patch.dict(sys.modules, modules):
            provider = OpenTimestampsProvider()
            root = hashlib.sha256(b"garbage-root").digest()
            receipt = AnchorReceipt(
                receipt_id=uuid.uuid4(),
                provider="opentimestamps",
                merkle_root=root,
                status=AnchorStatus.PENDING,
                receipt_bytes=b"\xff\xff",
                submitted_at=datetime.now(UTC),
            )
            status = provider.verify(root, receipt)
        assert status == AnchorStatus.FAILED

    def test_verify_returns_failed_when_receipt_bytes_none(self):
        _ots, modules = _make_fake_ots()
        with patch.dict(sys.modules, modules):
            provider = OpenTimestampsProvider()
            receipt = AnchorReceipt(
                receipt_id=uuid.uuid4(),
                provider="opentimestamps",
                merkle_root=b"\x00" * 32,
                status=AnchorStatus.PENDING,
                submitted_at=datetime.now(UTC),
            )
            status = provider.verify(b"\x00" * 32, receipt)
        assert status == AnchorStatus.FAILED

    def test_default_calendar_url_used(self):
        _ots, modules = _make_fake_ots()
        with patch.dict(sys.modules, modules):
            provider = OpenTimestampsProvider()
            assert provider._calendar_urls == ["https://bitcoin.calendar.catallaxy.com/"]

    def test_accepts_list_of_calendar_urls(self):
        _ots, modules = _make_fake_ots()
        urls = ["https://a.calendar/", "https://b.calendar/"]
        with patch.dict(sys.modules, modules):
            provider = OpenTimestampsProvider(calendar_urls=urls)
            assert provider._calendar_urls == urls


class TestAnchorReceiptsMigration:
    @pytest.fixture(scope="module")
    def project(self):
        from regista import Regista

        name = f"mig_041_{uuid.uuid4().hex[:8]}"
        Regista.create_project(DSN, name, KEY_PATH)
        yield name
        drop_project_schema(DSN, name)

    def test_anchor_receipts_table_exists(self, project):
        with psycopg.connect(DSN, row_factory=dict_row) as conn:
            row = conn.execute(
                "SELECT 1 FROM information_schema.tables "
                "WHERE table_schema = %s AND table_name = 'anchor_receipts'",
                [project],
            ).fetchone()
        assert row is not None

    def test_anchor_receipts_columns(self, project):
        with psycopg.connect(DSN, row_factory=dict_row) as conn:
            rows = conn.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = %s AND table_name = 'anchor_receipts'",
                [project],
            ).fetchall()
        columns = {r["column_name"] for r in rows}
        expected = {
            "receipt_id", "provider", "merkle_root", "status",
            "receipt_bytes", "target_global_seq", "submitted_at",
            "confirmed_at", "failure_count", "last_error",
            "project_name", "envelope_version", "hash_algorithm",
        }
        assert expected <= columns

    def test_status_check_constraint(self, project):
        with psycopg.connect(DSN, row_factory=dict_row) as conn:
            with pytest.raises(psycopg.errors.CheckViolation):
                conn.execute(
                    f"INSERT INTO {project}.anchor_receipts "
                    "(receipt_id, provider, merkle_root, status, submitted_at) "
                    "VALUES (gen_random_uuid(), 'test', %s, 'bogus', now())",
                    [b"\x00" * 32],
                )
                conn.commit()
            conn.rollback()

    def test_retryable_status_accepted(self, project):
        with psycopg.connect(DSN, row_factory=dict_row) as conn:
            conn.execute(
                f"INSERT INTO {project}.anchor_receipts "
                "(receipt_id, provider, merkle_root, status, submitted_at) "
                "VALUES (gen_random_uuid(), 'test', %s, 'retryable', now())",
                [b"\x00" * 32],
            )
            conn.commit()

    def test_indexes_exist(self, project):
        with psycopg.connect(DSN, row_factory=dict_row) as conn:
            rows = conn.execute(
                "SELECT indexname FROM pg_indexes WHERE schemaname = %s",
                [project],
            ).fetchall()
        index_names = {r["indexname"] for r in rows}
        assert "idx_anchor_receipts_status" in index_names
        assert "idx_anchor_receipts_root" in index_names
        assert "idx_anchor_receipts_seq" in index_names


@pytest.fixture
def anchor_regista(tmp_path):
    from regista import Regista

    project = f"test_anchor_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    provider = FileAnchorProvider(directory=str(tmp_path / "anchors"))
    sub.anchoring.set_provider(provider)
    yield sub, provider
    sub.close()
    drop_project_schema(DSN, project)


def _create_event(sub) -> int:
    wi, _evt = sub.create_work_item(
        workflow_name="test_workflow",
        work_item_type="feature",
        actor_id="agent-1",
        custom_fields={"title": "anchor test"},
    )
    return wi.work_item_id


class TestAnchoringHashAgility:
    """WI-207: anchoring must verify chains whose events use a non-SHA-256
    hash_alg. verify_content_anchor recomputes payload_canonical_hash with the
    event's own hash_alg via resolve_hash_function; the rest of the suite only
    creates sha-256 events, so pin the agile path here."""

    def test_anchor_verifies_with_sha384_events(self, anchor_regista):
        sub, _provider = anchor_regista
        wi = _create_event(sub)  # genesis event is sha-256
        for i in range(2):
            sub.append_event(
                wi, "agent-1",
                hash_alg="sha-384",
                transition=f"hash_agility_{i}",
                payload={"alg": "sha-384", "i": i},
            )

        # Guard: the chain really does carry non-SHA-256 events, so this test
        # exercises the hash-agility recompute rather than passing vacuously.
        with psycopg.connect(DSN, row_factory=dict_row) as conn:
            conn.execute(f"SET search_path TO {sub._mgr.schema}")
            algs = {
                r["hash_alg"]
                for r in conn.execute("SELECT hash_alg FROM events").fetchall()
            }
        assert "sha-384" in algs

        receipt = sub.trigger_anchoring()
        assert receipt is not None
        assert receipt.status == AnchorStatus.CONFIRMED

        status = sub.verify_anchor_receipt(receipt.receipt_id)
        assert status == AnchorStatus.CONFIRMED

    def test_anchor_verify_fails_if_sha384_hash_recomputed_as_sha256(self, anchor_regista):
        # Negative control for the hash-agility path: if a sha-384 event's
        # payload_canonical_hash is overwritten with a sha-256 digest of the
        # same envelope (simulating a verifier that hardcodes sha-256), the
        # recompute no longer matches and verification must fail.
        sub, _provider = anchor_regista
        wi = _create_event(sub)
        sub.append_event(
            wi, "agent-1", hash_alg="sha-384",
            transition="hash_agility_neg", payload={"alg": "sha-384"},
        )
        receipt = sub.trigger_anchoring()
        assert receipt is not None

        with psycopg.connect(DSN, row_factory=dict_row, autocommit=True) as conn:
            conn.execute(f"SET search_path TO {sub._mgr.schema}")
            row = conn.execute(
                "SELECT canonical_envelope FROM events WHERE hash_alg = 'sha-384' LIMIT 1"
            ).fetchone()
            wrong_pch = hashlib.sha256(bytes(row["canonical_envelope"])).digest()
            conn.execute(
                "UPDATE events SET payload_canonical_hash = %s WHERE hash_alg = 'sha-384'",
                [wrong_pch],
            )

        assert sub.verify_anchor_receipt(receipt.receipt_id) == AnchorStatus.FAILED


class TestAnchoringIntegration:
    def test_trigger_anchoring_creates_confirmed_receipt(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)
        _create_event(sub)
        receipt = sub.trigger_anchoring()
        assert receipt is not None
        assert receipt.status == AnchorStatus.CONFIRMED
        assert receipt.target_global_seq is not None
        assert receipt.target_global_seq > 0

    def test_trigger_anchoring_returns_none_when_no_new_events(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)
        first = sub.trigger_anchoring()
        assert first is not None
        second = sub.trigger_anchoring()
        assert second is None

    def test_trigger_anchoring_advances_latest_confirmed_seq(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)
        sub.trigger_anchoring()
        with psycopg.connect(DSN, row_factory=dict_row) as conn:
            conn.execute(f"SET search_path TO {sub._mgr.schema}")
            seq = latest_confirmed_seq(conn)
        assert seq > 0

    def test_upgrade_pending_anchors_noop_for_file(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)
        sub.trigger_anchoring()
        count = sub.upgrade_pending_anchors()
        assert count == 0

    def test_verify_anchor_receipt_confirmed(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)
        receipt = sub.trigger_anchoring()
        status = sub.verify_anchor_receipt(receipt.receipt_id)
        assert status == AnchorStatus.CONFIRMED

    def test_verify_anchor_receipt_failed_for_tampered(self, anchor_regista, tmp_path):
        sub, _provider = anchor_regista
        _create_event(sub)
        receipt = sub.trigger_anchoring()
        with psycopg.connect(DSN, row_factory=dict_row, autocommit=True) as conn:
            conn.execute(f"SET search_path TO {sub._mgr.schema}")
            conn.execute(
                "UPDATE anchor_receipts SET merkle_root = %s WHERE receipt_id = %s",
                [b"\xff" * 32, receipt.receipt_id],
            )
        status = sub.verify_anchor_receipt(receipt.receipt_id)
        assert status == AnchorStatus.FAILED

    def test_verify_anchor_receipt_failed_for_tampered_payload(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)
        receipt = sub.trigger_anchoring()
        assert receipt is not None
        with psycopg.connect(DSN, row_factory=dict_row, autocommit=True) as conn:
            conn.execute(f"SET search_path TO {sub._mgr.schema}")
            conn.execute(
                "UPDATE events SET payload = '{\"tampered\": true}'::jsonb, "
                "canonical_envelope = %s WHERE global_seq = %s",
                [b'{"tampered": "payload"}', receipt.target_global_seq],
            )
        status = sub.verify_anchor_receipt(receipt.receipt_id)
        assert status == AnchorStatus.FAILED

    def test_verify_anchor_receipt_failed_for_tampered_signature(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)
        receipt = sub.trigger_anchoring()
        assert receipt is not None
        with psycopg.connect(DSN, row_factory=dict_row, autocommit=True) as conn:
            conn.execute(f"SET search_path TO {sub._mgr.schema}")
            conn.execute(
                "UPDATE events SET signature = %s WHERE global_seq = %s",
                [b"\xff" * 32, receipt.target_global_seq],
            )
        status = sub.verify_anchor_receipt(receipt.receipt_id)
        assert status == AnchorStatus.FAILED

    def test_verify_anchor_receipt_failed_for_tampered_actor(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)
        receipt = sub.trigger_anchoring()
        assert receipt is not None
        with psycopg.connect(DSN, row_factory=dict_row, autocommit=True) as conn:
            conn.execute(f"SET search_path TO {sub._mgr.schema}")
            conn.execute(
                "UPDATE events SET actor_id = 'tampered-actor', "
                "canonical_envelope = %s WHERE global_seq = %s",
                [b'{"tampered": "actor"}', receipt.target_global_seq],
            )
        status = sub.verify_anchor_receipt(receipt.receipt_id)
        assert status == AnchorStatus.FAILED

    def test_verify_anchor_receipt_failed_for_tampered_prev_global_hash(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)
        _create_event(sub)
        receipt = sub.trigger_anchoring()
        assert receipt is not None
        with psycopg.connect(DSN, row_factory=dict_row, autocommit=True) as conn:
            conn.execute(f"SET search_path TO {sub._mgr.schema}")
            conn.execute(
                "UPDATE events SET prev_global_event_hash = %s "
                "WHERE global_seq = %s",
                [b"\xff" * 32, receipt.target_global_seq],
            )
        status = sub.verify_anchor_receipt(receipt.receipt_id)
        assert status == AnchorStatus.FAILED

    def test_verify_anchor_receipt_failed_for_tampered_envelope(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)
        receipt = sub.trigger_anchoring()
        assert receipt is not None
        with psycopg.connect(DSN, row_factory=dict_row, autocommit=True) as conn:
            conn.execute(f"SET search_path TO {sub._mgr.schema}")
            conn.execute(
                "UPDATE events SET canonical_envelope = %s WHERE global_seq = %s",
                [b'{"tampered": true}', receipt.target_global_seq],
            )
        status = sub.verify_anchor_receipt(receipt.receipt_id)
        assert status == AnchorStatus.FAILED

    def test_get_anchor_receipt_not_found_raises(self, anchor_regista):
        sub, _provider = anchor_regista
        with pytest.raises(RegistaError) as exc_info:
            sub.get_anchor_receipt(uuid.uuid4())
        assert exc_info.value.code == ErrorCode.ANCHOR_RECEIPT_NOT_FOUND

    def test_list_anchor_receipts_filters_by_status(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)
        sub.trigger_anchoring()
        confirmed = sub.list_anchor_receipts(status="confirmed")
        assert len(confirmed) >= 1
        pending = sub.list_anchor_receipts(status="pending")
        assert len(pending) == 0

    def test_trigger_anchoring_without_provider_raises(self):
        from regista import Regista

        project = f"test_noprovider_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        try:
            with pytest.raises(RegistaError) as exc_info:
                sub.trigger_anchoring()
            assert exc_info.value.code == ErrorCode.ANCHOR_PROVIDER_UNAVAILABLE
        finally:
            sub.close()
            drop_project_schema(DSN, project)


class TestAnchoringPayloadMutationIntegration:
    """BLOCKING-2: document the known limitation that mutating only the
    ``payload`` jsonb column (not canonical_envelope) is NOT detected by
    the anchor.  Signature verification during replay would catch it."""

    def test_payload_only_mutation_not_detected_by_anchor(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)
        receipt = sub.trigger_anchoring()
        assert receipt is not None
        with psycopg.connect(DSN, row_factory=dict_row, autocommit=True) as conn:
            conn.execute(f"SET search_path TO {sub._mgr.schema}")
            # Mutate ONLY the payload jsonb column — leave canonical_envelope
            # and payload_canonical_hash untouched.
            conn.execute(
                "UPDATE events SET payload = '{\"sneaky\": true}'::jsonb "
                "WHERE global_seq = %s",
                [receipt.target_global_seq],
            )
        status = sub.verify_anchor_receipt(receipt.receipt_id)
        # Known limitation: the anchor does NOT detect payload-only mutation.
        # The anchor commits to sha256(canonical_envelope + signature), and
        # payload_canonical_hash is sha256(canonical_envelope).  Neither changes
        # when only the denormalised payload jsonb column is mutated.
        # Signature verification during replay would catch this.
        assert status == AnchorStatus.CONFIRMED

    def test_payload_canonical_hash_mismatch_detected(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)
        receipt = sub.trigger_anchoring()
        assert receipt is not None
        with psycopg.connect(DSN, row_factory=dict_row, autocommit=True) as conn:
            conn.execute(f"SET search_path TO {sub._mgr.schema}")
            # Tamper with payload_canonical_hash but not canonical_envelope.
            conn.execute(
                "UPDATE events SET payload_canonical_hash = %s "
                "WHERE global_seq = %s",
                [b"\xff" * 32, receipt.target_global_seq],
            )
        status = sub.verify_anchor_receipt(receipt.receipt_id)
        assert status == AnchorStatus.FAILED


class TestTriggerAnchoringPendingReceiptIntegration:
    """BLOCKING-3: a pending receipt must be persisted before the provider
    is called, so a crash between submit and update never loses the anchor."""

    def test_pending_receipt_exists_during_submit(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)

        seen_pending = {"value": False}

        class _CheckingProvider:
            name = "file"

            def submit(self, merkle_root: bytes) -> AnchorReceipt:
                # While the provider is processing, a pending receipt should
                # already be in the database.
                with sub._mgr.transaction() as conn:
                    row = conn.execute(
                        "SELECT status FROM anchor_receipts "
                        "WHERE merkle_root = %s",
                        [merkle_root],
                    ).fetchone()
                if row is not None and row["status"] == "pending":
                    seen_pending["value"] = True
                return AnchorReceipt(
                    receipt_id=uuid.uuid4(),
                    provider="file",
                    merkle_root=merkle_root,
                    status=AnchorStatus.CONFIRMED,
                    receipt_bytes=b"proof",
                    submitted_at=datetime.now(UTC),
                    confirmed_at=datetime.now(UTC),
                )

            def upgrade(self, receipt: AnchorReceipt) -> AnchorReceipt:
                return receipt

            def verify(self, merkle_root: bytes, receipt: AnchorReceipt) -> str:
                return AnchorStatus.CONFIRMED

        provider = _CheckingProvider()
        receipt = trigger_anchoring(
            sub._mgr, provider, project_name=sub._project
        )
        assert receipt is not None
        assert receipt.status == AnchorStatus.CONFIRMED
        assert seen_pending["value"] is True

    def test_failed_submit_leaves_retryable_receipt(self, anchor_regista):
        sub, _provider = anchor_regista
        _create_event(sub)

        failing = MagicMock()
        failing.name = "failing"
        failing.submit.side_effect = RuntimeError("network down")

        receipt = trigger_anchoring(sub._mgr, failing, project_name=sub._project)
        assert receipt is not None
        assert receipt.status == AnchorStatus.RETRYABLE
        assert receipt.failure_count == 1
        # The retryable receipt must be persisted (not lost).
        with sub._mgr.transaction() as conn:
            fetched = get_anchor_receipt(conn, receipt.receipt_id)
        assert fetched is not None
        assert fetched.status == AnchorStatus.RETRYABLE


class TestCreateAnchorReceiptConflictPersistence:
    """MAJOR-1 & MAJOR-2: create_anchor_receipt must return the existing row
    on conflict and upgrade retryable rows when a better status arrives."""

    @pytest.fixture
    def conflict_regista(self):
        from regista import Regista

        project = f"test_conflict_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        yield sub
        sub.close()
        drop_project_schema(DSN, project)

    def test_returns_existing_row_on_conflict(self, conflict_regista):
        """MAJOR-1: the returned receipt reflects the existing DB row."""
        sub = conflict_regista
        original = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="file",
            merkle_root=b"\xdd" * 32,
            status=AnchorStatus.CONFIRMED,
            receipt_bytes=b"original",
            submitted_at=datetime.now(UTC),
            confirmed_at=datetime.now(UTC),
            target_global_seq=10,
        )
        with sub._mgr.transaction() as conn:
            create_anchor_receipt(conn, original)

            # Second insert with same (provider, merkle_root) — should conflict.
            duplicate = AnchorReceipt(
                receipt_id=uuid.uuid4(),
                provider="file",
                merkle_root=b"\xdd" * 32,
                status=AnchorStatus.PENDING,
                submitted_at=datetime.now(UTC),
            )
            result = create_anchor_receipt(conn, duplicate)

        # MAJOR-1: result is the existing row, not None.
        assert result is not None
        assert result.receipt_id == original.receipt_id
        assert result.status == AnchorStatus.CONFIRMED

    def test_upgrades_retryable_to_confirmed(self, conflict_regista):
        """MAJOR-2: a retryable receipt is upgraded when a confirmed
        receipt arrives for the same (provider, merkle_root)."""
        sub = conflict_regista
        retryable = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="file",
            merkle_root=b"\xee" * 32,
            status=AnchorStatus.RETRYABLE,
            submitted_at=datetime.now(UTC),
            target_global_seq=7,
            failure_count=2,
            last_error="timeout",
        )
        with sub._mgr.transaction() as conn:
            create_anchor_receipt(conn, retryable)

            # Now a confirmed receipt arrives for the same anchor.
            confirmed = AnchorReceipt(
                receipt_id=uuid.uuid4(),
                provider="file",
                merkle_root=b"\xee" * 32,
                status=AnchorStatus.CONFIRMED,
                receipt_bytes=b"proof",
                submitted_at=datetime.now(UTC),
                confirmed_at=datetime.now(UTC),
                target_global_seq=7,
            )
            result = create_anchor_receipt(conn, confirmed)

        assert result is not None
        assert result.status == AnchorStatus.CONFIRMED
        assert result.receipt_bytes == b"proof"
        # The existing receipt_id is retained (upgraded in place).
        assert result.receipt_id == retryable.receipt_id

    def test_does_not_downgrade_confirmed_to_retryable(self, conflict_regista):
        """MAJOR-2: a confirmed receipt is NOT downgraded to retryable."""
        sub = conflict_regista
        confirmed = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="file",
            merkle_root=b"\xff" * 32,
            status=AnchorStatus.CONFIRMED,
            receipt_bytes=b"proof",
            submitted_at=datetime.now(UTC),
            confirmed_at=datetime.now(UTC),
            target_global_seq=3,
        )
        with sub._mgr.transaction() as conn:
            create_anchor_receipt(conn, confirmed)

            retryable = AnchorReceipt(
                receipt_id=uuid.uuid4(),
                provider="file",
                merkle_root=b"\xff" * 32,
                status=AnchorStatus.RETRYABLE,
                submitted_at=datetime.now(UTC),
                failure_count=1,
                last_error="oops",
            )
            result = create_anchor_receipt(conn, retryable)

        assert result is not None
        assert result.status == AnchorStatus.CONFIRMED
        assert result.failure_count == 0


class TestAnchoringPersistenceHelpers:
    @pytest.fixture
    def regista_with_table(self):
        from regista import Regista

        project = f"test_persist_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        yield sub
        sub.close()
        drop_project_schema(DSN, project)

    def test_create_and_get_anchor_receipt(self, regista_with_table):
        sub = regista_with_table
        receipt = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="file",
            merkle_root=b"\xaa" * 32,
            status=AnchorStatus.CONFIRMED,
            receipt_bytes=b"proof",
            submitted_at=datetime.now(UTC),
            confirmed_at=datetime.now(UTC),
            target_global_seq=5,
        )
        with sub._mgr.transaction() as conn:
            create_anchor_receipt(conn, receipt)
            fetched = get_anchor_receipt(conn, receipt.receipt_id)
        assert fetched is not None
        assert fetched.provider == "file"
        assert fetched.merkle_root == b"\xaa" * 32
        assert fetched.status == AnchorStatus.CONFIRMED
        assert fetched.target_global_seq == 5

    def test_update_anchor_receipt_fields(self, regista_with_table):
        sub = regista_with_table
        receipt = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="file",
            merkle_root=b"\xbb" * 32,
            status=AnchorStatus.PENDING,
            submitted_at=datetime.now(UTC),
        )
        with sub._mgr.transaction() as conn:
            create_anchor_receipt(conn, receipt)
            update_anchor_receipt(
                conn, receipt.receipt_id,
                status=AnchorStatus.CONFIRMED,
                confirmed_at=datetime.now(UTC),
            )
            fetched = get_anchor_receipt(conn, receipt.receipt_id)
        assert fetched.status == AnchorStatus.CONFIRMED
        assert fetched.confirmed_at is not None

    def test_update_anchor_receipt_rejects_unknown_fields(self, regista_with_table):
        sub = regista_with_table
        receipt = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="file",
            merkle_root=b"\xcc" * 32,
            status=AnchorStatus.PENDING,
            submitted_at=datetime.now(UTC),
        )
        with sub._mgr.transaction() as conn:
            create_anchor_receipt(conn, receipt)
            with pytest.raises(RegistaError):
                update_anchor_receipt(conn, receipt.receipt_id, bogus_field="x")

    def test_list_anchor_receipts_with_filters(self, regista_with_table):
        sub = regista_with_table
        r1 = AnchorReceipt(
            receipt_id=uuid.uuid4(), provider="file",
            merkle_root=b"\x01" * 32, status=AnchorStatus.CONFIRMED,
            submitted_at=datetime.now(UTC),
        )
        r2 = AnchorReceipt(
            receipt_id=uuid.uuid4(), provider="rfc3161",
            merkle_root=b"\x02" * 32, status=AnchorStatus.PENDING,
            submitted_at=datetime.now(UTC),
        )
        with sub._mgr.transaction() as conn:
            create_anchor_receipt(conn, r1)
            create_anchor_receipt(conn, r2)
            file_receipts = list_anchor_receipts(conn, provider="file")
            pending = list_anchor_receipts(conn, status="pending")
        assert any(r.receipt_id == r1.receipt_id for r in file_receipts)
        assert any(r.receipt_id == r2.receipt_id for r in pending)

    def test_latest_confirmed_seq_returns_zero_when_empty(self, regista_with_table):
        sub = regista_with_table
        with sub._mgr.transaction() as conn:
            seq = latest_confirmed_seq(conn)
        assert seq == 0


class TestMaintenanceAnchoring:
    def test_maintenance_creates_anchor_receipt(self, tmp_path):
        import time

        from regista import Regista
        from regista._maintenance import MaintenanceThread

        project = f"test_maint_anchor_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        # try covers everything from creation (epoch-blocked mid-body refusal
        # must not leak the schema — WI-243 guard).
        try:
            sub.register_workflow_file(WORKFLOW_PATH)
            provider = FileAnchorProvider(directory=str(tmp_path / "anchors"))
            sub.anchoring.set_provider(provider)
            _create_event(sub)
            mt = MaintenanceThread(
                sub,
                sweep_interval=0.05,
                anchor_provider=provider,
                anchor_interval=0.01,
                anchor_upgrade_interval=999.0,
            )
            mt.start()
            time.sleep(0.3)
            mt.stop()
            receipts = sub.list_anchor_receipts()
            assert len(receipts) >= 1
            assert receipts[0].status == AnchorStatus.CONFIRMED
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_maintenance_skips_anchoring_without_provider(self):
        import time

        from regista import Regista
        from regista._maintenance import MaintenanceThread

        project = f"test_maint_noprovider_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        try:
            mt = MaintenanceThread(
                sub,
                sweep_interval=0.05,
                anchor_provider=None,
                anchor_interval=0.01,
            )
            mt.start()
            time.sleep(0.15)
            mt.stop()
            assert mt.last_cycle_ok
        finally:
            sub.close()
            drop_project_schema(DSN, project)


class TestAnchorCLI:
    @pytest.fixture
    def cli_project(self, tmp_path):
        name = f"cli_anchor_{uuid.uuid4().hex[:8]}"
        yield name
        drop_project_schema(DSN, name)

    @pytest.fixture
    def populated_cli_project(self, cli_project, tmp_path):
        from regista import Regista

        result = _run_cli("--project", cli_project, "schema", "init")
        assert result.returncode == 0, result.stderr
        sub = Regista(DSN, cli_project, KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        _wi, _ = sub.create_work_item(
            "test_workflow", "feature", "worker-1",
            custom_fields={"title": "anchor-cli"},
        )
        sub.close()
        return cli_project, str(tmp_path / "anchors")

    def test_anchor_submit_file_provider(self, populated_cli_project):
        project, anchor_dir = populated_cli_project
        config = json.dumps({"path": anchor_dir})
        result = _run_cli(
            "--project", project,
            "anchor", "submit",
            "--provider", "file",
            "--provider-config", config,
        )
        assert result.returncode == 0, result.stderr
        assert "Anchored" in result.stdout or "No new events" in result.stdout

    def test_anchor_status_lists_receipts(self, populated_cli_project):
        project, anchor_dir = populated_cli_project
        config = json.dumps({"path": anchor_dir})
        _run_cli(
            "--project", project,
            "anchor", "submit",
            "--provider", "file",
            "--provider-config", config,
        )
        result = _run_cli("--project", project, "--json", "anchor", "status")
        assert result.returncode == 0, result.stderr
        data = _extract_cli_json(result.stdout)
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_anchor_verify_confirmed_receipt(self, populated_cli_project):
        project, anchor_dir = populated_cli_project
        config = json.dumps({"path": anchor_dir})
        submit_result = _run_cli(
            "--project", project,
            "anchor", "submit",
            "--provider", "file",
            "--provider-config", config,
        )
        assert submit_result.returncode == 0, submit_result.stderr
        if "No new events" in submit_result.stdout:
            pytest.skip("No events to anchor")
        status_result = _run_cli("--project", project, "--json", "anchor", "status")
        assert status_result.returncode == 0, status_result.stderr
        receipts = _extract_cli_json(status_result.stdout)
        assert len(receipts) >= 1
        receipt_id = receipts[0]["receipt_id"]
        verify_result = _run_cli(
            "--project", project,
            "anchor", "verify", receipt_id,
            "--provider", "file",
            "--provider-config", config,
        )
        assert verify_result.returncode == 0
        assert "confirmed" in verify_result.stdout

    def test_anchor_verify_unknown_receipt_exits_nonzero(self, populated_cli_project):
        project, anchor_dir = populated_cli_project
        config = json.dumps({"path": anchor_dir})
        fake_id = str(uuid.uuid4())
        result = _run_cli(
            "--project", project,
            "anchor", "verify", fake_id,
            "--provider", "file",
            "--provider-config", config,
        )
        assert result.returncode != 0


def _run_cli(*args, env=None):
    base_env = {
        "REGISTA_DSN": DSN,
        "REGISTA_HMAC_KEY_PATH": KEY_PATH,
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    if env:
        base_env.update(env)
    import subprocess

    result = subprocess.run(
        [PYTHON, "-m", "regista._cli", *args],
        capture_output=True,
        text=True,
        env=base_env,
        timeout=30,
    )
    return result


def _extract_cli_json(stdout):
    import re

    lines = stdout.strip().split("\n")
    filtered = "\n".join(
        line for line in lines
        if not re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
    )
    return json.loads(filtered)


class TestTriggerAnchoringFailurePersistence:
    def test_submit_failure_persists_retryable_receipt(self, tmp_path):
        from regista import Regista

        project = f"test_fail_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        # Cleanup must cover everything from creation: the epoch admission
        # gate refuses _create_event mid-body (absorbed as XFAIL), and a
        # narrower try would leak the schema — the WI-243 guard fails CI on
        # exactly that.
        try:
            sub.register_workflow_file(WORKFLOW_PATH)
            _create_event(sub)
            failing_provider = MagicMock()
            failing_provider.name = "failing"
            failing_provider.submit.side_effect = RuntimeError("network down")
            receipt = trigger_anchoring(
                sub._mgr, failing_provider, project_name=sub._project,
            )
            assert receipt.status == AnchorStatus.RETRYABLE
            assert receipt.failure_count == 1
            assert "network down" in (receipt.last_error or "")
            with sub._mgr.transaction() as conn:
                fetched = get_anchor_receipt(conn, receipt.receipt_id)
            assert fetched is not None
            assert fetched.status == AnchorStatus.RETRYABLE
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_retry_failed_anchors_resucceeds(self, tmp_path):
        from regista import Regista

        project = f"test_retry_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        # try covers everything from creation (epoch-blocked mid-body refusal
        # must not leak the schema — WI-243 guard).
        try:
            sub.register_workflow_file(WORKFLOW_PATH)
            _create_event(sub)
            failing_provider = MagicMock()
            failing_provider.name = "failing"
            failing_provider.submit.side_effect = RuntimeError("network down")
            receipt = trigger_anchoring(
                sub._mgr, failing_provider, project_name=sub._project,
            )
            assert receipt.status == AnchorStatus.RETRYABLE

            good_provider = FileAnchorProvider(directory=str(tmp_path / "anchors"))
            good_provider.name = "failing"
            count = retry_failed_anchors(sub._mgr, good_provider)
            assert count == 1

            with sub._mgr.transaction() as conn:
                fetched = get_anchor_receipt(conn, receipt.receipt_id)
            assert fetched is not None
            assert fetched.status == AnchorStatus.CONFIRMED
        finally:
            sub.close()
            drop_project_schema(DSN, project)

    def test_retry_exceeds_max_failures_marks_failed(self, tmp_path):
        from regista import Regista

        project = f"test_maxfail_{uuid.uuid4().hex[:8]}"
        sub = Regista.create_project(DSN, project, KEY_PATH)
        # try covers everything from creation (epoch-blocked mid-body refusal
        # must not leak the schema — WI-243 guard).
        try:
            sub.register_workflow_file(WORKFLOW_PATH)
            _create_event(sub)
            failing_provider = MagicMock()
            failing_provider.name = "failing"
            failing_provider.submit.side_effect = RuntimeError("persistent error")
            receipt = trigger_anchoring(
                sub._mgr, failing_provider, project_name=sub._project,
            )
            assert receipt.status == AnchorStatus.RETRYABLE
            assert receipt.failure_count == 1

            retry_failed_anchors(sub._mgr, failing_provider, max_failures=2)
            with sub._mgr.transaction() as conn:
                fetched = get_anchor_receipt(conn, receipt.receipt_id)
            assert fetched is not None
            assert fetched.failure_count == 2
            assert fetched.status == AnchorStatus.FAILED
        finally:
            sub.close()
            drop_project_schema(DSN, project)


class TestComputeContentAnchor:
    def test_compute_content_anchor_is_deterministic(self):
        chain_head = hashlib.sha256(b"envelope+signature").digest()
        anchor1 = compute_content_anchor(
            chain_head_hash=chain_head,
            project_name="test-project",
            target_global_seq=42,
            envelope_version=4,
            hash_algorithm="sha-256",
        )
        anchor2 = compute_content_anchor(
            chain_head_hash=chain_head,
            project_name="test-project",
            target_global_seq=42,
            envelope_version=4,
            hash_algorithm="sha-256",
        )
        assert anchor1 == anchor2

    def test_compute_content_anchor_changes_with_chain_head(self):
        head1 = hashlib.sha256(b"envelope1+signature").digest()
        head2 = hashlib.sha256(b"envelope2+signature").digest()
        a1 = compute_content_anchor(head1, "p", 1, 4, "sha-256")
        a2 = compute_content_anchor(head2, "p", 1, 4, "sha-256")
        assert a1 != a2

    def test_compute_content_anchor_changes_with_project(self):
        head = hashlib.sha256(b"env+sig").digest()
        a1 = compute_content_anchor(head, "project-a", 1, 4, "sha-256")
        a2 = compute_content_anchor(head, "project-b", 1, 4, "sha-256")
        assert a1 != a2

    def test_compute_content_anchor_changes_with_seq(self):
        head = hashlib.sha256(b"env+sig").digest()
        a1 = compute_content_anchor(head, "p", 1, 4, "sha-256")
        a2 = compute_content_anchor(head, "p", 2, 4, "sha-256")
        assert a1 != a2

    def test_compute_content_anchor_changes_with_envelope_version(self):
        head = hashlib.sha256(b"env+sig").digest()
        a1 = compute_content_anchor(head, "p", 1, 3, "sha-256")
        a2 = compute_content_anchor(head, "p", 1, 4, "sha-256")
        assert a1 != a2

    def test_compute_content_anchor_changes_with_hash_algorithm(self):
        head = hashlib.sha256(b"env+sig").digest()
        a1 = compute_content_anchor(head, "p", 1, 4, "sha-256")
        a2 = compute_content_anchor(head, "p", 1, 4, "sha-384")
        assert a1 != a2

    def test_compute_content_anchor_no_binding_collision(self):
        """Adversarial: distinct (project, seq, version) tuples must not
        produce the same anchor even when the tail bytes would collide
        under naive concatenation (e.g. 'p1'+2+3 vs 'p'+1+23)."""
        head = hashlib.sha256(b"env+sig").digest()
        a1 = compute_content_anchor(head, "p1", 2, 3, "sha-256")
        a2 = compute_content_anchor(head, "p", 1, 23, "sha-256")
        assert a1 != a2

    def test_compute_content_anchor_no_binding_collision_digits(self):
        """Adversarial: project names with digits must not collide."""
        head = hashlib.sha256(b"env+sig").digest()
        a1 = compute_content_anchor(head, "proj12", 3, 4, "sha-256")
        a2 = compute_content_anchor(head, "proj1", 23, 4, "sha-256")
        assert a1 != a2


class TestVerifyContentAnchor:
    def test_verify_content_anchor_rejects_missing_binding_fields(self):
        receipt = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="file",
            merkle_root=b"\x00" * 32,
            status=AnchorStatus.CONFIRMED,
            submitted_at=datetime.now(UTC),
            target_global_seq=1,
            project_name=None,
            envelope_version=4,
            hash_algorithm="sha-256",
        )
        assert verify_content_anchor(MagicMock(), receipt) is False

    def test_verify_content_anchor_rejects_missing_target_seq(self):
        receipt = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="file",
            merkle_root=b"\x00" * 32,
            status=AnchorStatus.CONFIRMED,
            submitted_at=datetime.now(UTC),
            target_global_seq=None,
            project_name="p",
            envelope_version=4,
            hash_algorithm="sha-256",
        )
        assert verify_content_anchor(MagicMock(), receipt) is False


def _mock_conn_with_rows(rows: list[dict]):
    """Build a mock connection whose single execute returns *rows* from fetchall."""
    conn = MagicMock()
    result = MagicMock()
    result.fetchall.return_value = rows
    conn.execute.return_value = result
    return conn


def _make_chain_rows(
    tamper_prev_hash: bool = False,
    tamper_pch: bool = False,
) -> list[dict]:
    """Two event rows forming a valid global chain (genesis → event 2).

    Flags selectively corrupt one field to test detection.
    """
    env1 = b'{"event_id":"e1"}'
    sig1 = b"\x01" * 32
    head1 = hashlib.sha256(env1 + sig1).digest()

    env2 = b'{"event_id":"e2"}'
    sig2 = b"\x02" * 32

    row1 = {
        "event_id": uuid.uuid4(),
        "global_seq": 1,
        "canonical_envelope": env1,
        "signature": sig1,
        "prev_global_event_hash": None,
        "payload_canonical_hash": hashlib.sha256(env1).digest(),
        "hash_alg": "sha-256",
    }
    row2 = {
        "event_id": uuid.uuid4(),
        "global_seq": 2,
        "canonical_envelope": env2,
        "signature": sig2,
        "prev_global_event_hash": b"\xff" * 32 if tamper_prev_hash else head1,
        "payload_canonical_hash": (
            b"\xff" * 32 if tamper_pch else hashlib.sha256(env2).digest()
        ),
        "hash_alg": "sha-256",
    }
    return [row1, row2]


def _receipt_for_chain(rows: list[dict], target_seq: int = 2) -> AnchorReceipt:
    """Build a receipt whose merkle_root matches the chain head of the target row."""
    target = next(r for r in rows if r["global_seq"] == target_seq)
    chain_head = hashlib.sha256(
        target["canonical_envelope"] + target["signature"]
    ).digest()
    anchor = compute_content_anchor(
        chain_head_hash=chain_head,
        project_name="test",
        target_global_seq=target_seq,
        envelope_version=4,
        hash_algorithm="sha-256",
    )
    return AnchorReceipt(
        receipt_id=uuid.uuid4(),
        provider="file",
        merkle_root=anchor,
        status=AnchorStatus.CONFIRMED,
        submitted_at=datetime.now(UTC),
        target_global_seq=target_seq,
        project_name="test",
        envelope_version=4,
        hash_algorithm="sha-256",
    )


class TestVerifyContentAnchorChainIntegrity:
    """BLOCKING-1: verify_content_anchor must validate chain links, not just
    navigate them."""

    def test_valid_chain_passes(self):
        rows = _make_chain_rows()
        receipt = _receipt_for_chain(rows)
        assert verify_content_anchor(_mock_conn_with_rows(rows), receipt) is True

    def test_tampered_prev_global_event_hash_detected(self):
        rows = _make_chain_rows(tamper_prev_hash=True)
        receipt = _receipt_for_chain(rows)
        assert verify_content_anchor(_mock_conn_with_rows(rows), receipt) is False

    def test_genesis_single_event_passes(self):
        """A single genesis event (no predecessor) should pass link check."""
        env = b'{"event_id":"genesis"}'
        sig = b"\xaa" * 32
        row = {
            "event_id": uuid.uuid4(),
            "global_seq": 1,
            "canonical_envelope": env,
            "signature": sig,
            "prev_global_event_hash": None,
            "payload_canonical_hash": hashlib.sha256(env).digest(),
            "hash_alg": "sha-256",
        }
        chain_head = hashlib.sha256(env + sig).digest()
        anchor = compute_content_anchor(
            chain_head_hash=chain_head,
            project_name="p",
            target_global_seq=1,
            envelope_version=4,
            hash_algorithm="sha-256",
        )
        receipt = AnchorReceipt(
            receipt_id=uuid.uuid4(),
            provider="file",
            merkle_root=anchor,
            status=AnchorStatus.CONFIRMED,
            submitted_at=datetime.now(UTC),
            target_global_seq=1,
            project_name="p",
            envelope_version=4,
            hash_algorithm="sha-256",
        )
        assert verify_content_anchor(_mock_conn_with_rows([row]), receipt) is True


class TestVerifyContentAnchorPayloadHash:
    """BLOCKING-2: verify_content_anchor must check payload_canonical_hash
    consistency with canonical_envelope."""

    def test_payload_canonical_hash_mismatch_detected(self):
        rows = _make_chain_rows(tamper_pch=True)
        receipt = _receipt_for_chain(rows)
        assert verify_content_anchor(_mock_conn_with_rows(rows), receipt) is False

    def test_valid_payload_canonical_hash_passes(self):
        rows = _make_chain_rows()
        receipt = _receipt_for_chain(rows)
        assert verify_content_anchor(_mock_conn_with_rows(rows), receipt) is True
