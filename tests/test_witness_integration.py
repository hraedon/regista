from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from regista._errors import RegistaError
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def regista():
    from regista import Regista

    project = f"test_wit_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestWitnessRegistration:
    def test_register_witness(self, regista):
        wid = regista.register_witness("https://example.com/webhook")
        assert isinstance(wid, uuid.UUID)
        witnesses = regista.list_witnesses()
        assert len(witnesses) == 1
        assert witnesses[0]["url"] == "https://example.com/webhook"
        assert witnesses[0]["status"] == "active"

    def test_register_witness_with_filter(self, regista):
        regista.register_witness(
            "https://example.com/webhook",
            event_filter={"transitions": ["close"]},
        )
        witnesses = regista.list_witnesses()
        assert witnesses[0]["event_filter"] == {"transitions": ["close"]}

    def test_register_witness_with_headers(self, regista):
        regista.register_witness(
            "https://example.com/webhook",
            headers={"Authorization": "Bearer token123"},
        )
        witnesses = regista.list_witnesses()
        assert witnesses[0]["headers"] == {"Authorization": "Bearer token123"}

    def test_unregister_witness(self, regista):
        wid = regista.register_witness("https://example.com/webhook")
        regista.unregister_witness(wid)
        assert len(regista.list_witnesses()) == 0

    def test_unregister_nonexistent_raises(self, regista):
        with pytest.raises(RegistaError, match="WITNESS_NOT_FOUND"):
            regista.unregister_witness(uuid.uuid4())

    def test_pause_witness(self, regista):
        wid = regista.register_witness("https://example.com/webhook")
        regista.pause_witness(wid)
        witnesses = regista.list_witnesses()
        assert witnesses[0]["status"] == "paused"

    def test_reactivate_witness(self, regista):
        wid = regista.register_witness("https://example.com/webhook")
        regista.pause_witness(wid)
        regista.reactivate_witness(wid)
        witnesses = regista.list_witnesses()
        assert witnesses[0]["status"] == "active"

    def test_list_witnesses_filtered(self, regista):
        regista.register_witness("https://example.com/webhook1")
        wid2 = regista.register_witness("https://example.com/webhook2")
        regista.pause_witness(wid2)
        active = regista.list_witnesses(status="active")
        assert len(active) == 1
        paused = regista.list_witnesses(status="paused")
        assert len(paused) == 1

    def test_pause_nonexistent_raises(self, regista):
        with pytest.raises(RegistaError, match="WITNESS_NOT_FOUND"):
            regista.pause_witness(uuid.uuid4())


class TestWitnessReceipts:
    def test_receipt_created_on_create_work_item(self, regista):
        wid = regista.register_witness(
            "https://example.com/webhook",
            event_filter=None,
        )
        _wi, evt = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        receipts = regista.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 1
        assert receipts[0]["witness_id"] == str(wid)
        assert receipts[0]["status"] == "pending"

    def test_filter_skips_event(self, regista):
        regista.register_witness(
            "https://example.com/webhook",
            event_filter={"transitions": ["close"]},
        )
        _wi, evt = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        receipts = regista.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 0

    def test_multiple_witnesses(self, regista):
        wid1 = regista.register_witness(
            "https://example.com/webhook1",
        )
        regista.register_witness(
            "https://example.com/webhook2",
            event_filter={"transitions": ["start"]},
        )
        _wi, evt = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        receipts = regista.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 1
        assert receipts[0]["witness_id"] == str(wid1)

    def test_receipt_created_on_transition(self, regista):
        regista.register_witness("https://example.com/webhook")
        wi, _evt_create = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        evt_transition = regista.transition(
            wi.work_item_id, "start", "actor-1",
            actor_metadata={"role": "agent"},
        )
        receipts = regista.list_witness_receipts(event_id=evt_transition.event_id)
        assert len(receipts) == 1

    def test_receipt_created_on_append_event(self, regista):
        regista.register_witness("https://example.com/webhook")
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        evt = regista.append_event(
            wi.work_item_id, "actor-1",
            transition="note",
        )
        receipts = regista.list_witness_receipts(event_id=evt.event_id)
        assert len(receipts) == 1

    def test_list_receipts_by_witness(self, regista):
        wid = regista.register_witness("https://example.com/webhook")
        _wi, _evt = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        receipts = regista.list_witness_receipts(witness_id=wid)
        assert len(receipts) == 1

    def test_deliver_pending_receipts_returns_zero(self, regista):
        regista.register_witness("https://unreachable.example.com/webhook")
        _wi, _evt = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        count = regista.deliver_pending_witness_receipts()
        assert count == 0

    def test_unregister_abandons_pending_receipts(self, regista):
        wid = regista.register_witness("https://example.com/webhook")
        _wi, _evt = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "test"},
        )
        regista.unregister_witness(wid)
        receipts = regista.list_witness_receipts()
        assert len(receipts) == 0


class TestBC297AsymmetricWitnessKeys:
    def test_register_witness_with_ed25519_public_key(self, regista):
        pubkey = b"\x01" * 32
        regista.register_witness(
            "https://example.com/witness",
            public_key=pubkey,
            key_scheme="ed25519",
        )
        witnesses = regista.list_witnesses()
        assert witnesses[0]["key_scheme"] == "ed25519"

    def test_ed25519_public_key_wrong_length_rejected(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.register_witness(
                "https://example.com/witness",
                key_scheme="ed25519",
                public_key=b"\x01" * 31,
            )
        assert exc_info.value.code.value == "INVALID_ARGUMENT"

    def test_ed25519_without_public_key_rejected(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.register_witness(
                "https://example.com/witness",
                key_scheme="ed25519",
            )
        assert exc_info.value.code.value == "INVALID_ARGUMENT"

    def test_invalid_key_scheme_rejected(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.register_witness(
                "https://example.com/witness",
                key_scheme="rsa",
                public_key=b"\x01" * 32,
            )
        assert exc_info.value.code.value == "INVALID_ARGUMENT"

    def test_hmac_witness_without_public_key_accepted(self, regista):
        wid = regista.register_witness(
            "https://example.com/witness",
            key_scheme="hmac-sha256",
        )
        assert isinstance(wid, uuid.UUID)

    def test_delivery_verifies_valid_ed25519_signature(self, regista):
        try:
            import nacl.signing
        except ImportError:
            pytest.skip("PyNaCl not installed")

        from unittest.mock import MagicMock, patch

        sk = nacl.signing.SigningKey.generate()
        pk = bytes(sk.verify_key)

        regista.register_witness(
            "http://localhost:19999/witness",
            public_key=pk,
            key_scheme="ed25519",
        )
        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "bc297"},
        )
        events = regista.read_events(work_item_id=wi.work_item_id)
        created_evt = events[-1]
        canonical_env = bytes(created_evt.canonical_envelope)
        witness_sig = sk.sign(canonical_env).signature

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = (
            '{"witness_signature": "' + witness_sig.hex() + '"}'
        ).encode()
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_resp

        with patch("http.client.HTTPConnection", return_value=mock_conn):
            count = regista.deliver_pending_witness_receipts()

        assert count == 1
        receipts = regista.list_witness_receipts()
        confirmed = [r for r in receipts if r["status"] == "confirmed"]
        assert len(confirmed) == 1

    def test_delivery_rejects_missing_ed25519_signature(self, regista):
        try:
            import nacl.signing
        except ImportError:
            pytest.skip("PyNaCl not installed")

        from unittest.mock import MagicMock, patch

        sk = nacl.signing.SigningKey.generate()
        pk = bytes(sk.verify_key)

        regista.register_witness(
            "http://localhost:19999/witness",
            public_key=pk,
            key_scheme="ed25519",
        )
        _wi, _ = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "bc297-missing"},
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{}'
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_resp

        with patch("http.client.HTTPConnection", return_value=mock_conn):
            count = regista.deliver_pending_witness_receipts()

        assert count == 0
        receipts = regista.list_witness_receipts()
        pending = [r for r in receipts if r["status"] == "pending"]
        assert len(pending) == 1
        assert pending[0]["error_message"] == "witness signature verification failed"

    def test_delivery_rejects_invalid_ed25519_signature(self, regista):
        try:
            import nacl.signing
        except ImportError:
            pytest.skip("PyNaCl not installed")

        from unittest.mock import MagicMock, patch

        sk = nacl.signing.SigningKey.generate()
        pk = bytes(sk.verify_key)

        regista.register_witness(
            "http://localhost:19999/witness",
            public_key=pk,
            key_scheme="ed25519",
        )
        _wi, _ = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "bc297-bad"},
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = (
            '{"witness_signature": "' + (b"\xff" * 64).hex() + '"}'
        ).encode()
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_resp

        with patch("http.client.HTTPConnection", return_value=mock_conn):
            count = regista.deliver_pending_witness_receipts()

        assert count == 0
        receipts = regista.list_witness_receipts()
        pending = [r for r in receipts if r["status"] == "pending"]
        assert len(pending) == 1
        assert pending[0]["error_message"] == "witness signature verification failed"

    def test_delivery_pauses_witness_and_receipt_after_invalid_ed25519_retries(self, regista):
        try:
            import nacl.signing
        except ImportError:
            pytest.skip("PyNaCl not installed")

        from unittest.mock import MagicMock, patch

        sk = nacl.signing.SigningKey.generate()
        pk = bytes(sk.verify_key)

        regista.register_witness(
            "http://localhost:19999/witness",
            public_key=pk,
            key_scheme="ed25519",
            max_failures=2,
            max_retries=2,
        )
        _wi, _ = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "bc297-retries"},
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = (
            '{"witness_signature": "' + (b"\xff" * 64).hex() + '"}'
        ).encode()
        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_resp

        with patch("http.client.HTTPConnection", return_value=mock_conn):
            regista.deliver_pending_witness_receipts()
            regista.deliver_pending_witness_receipts()

        receipts = regista.list_witness_receipts()
        assert len(receipts) == 1
        assert receipts[0]["status"] == "paused"
        assert receipts[0]["retry_count"] == 2
        assert receipts[0]["witness_scheme"] == "ed25519"
        witnesses = regista.list_witnesses()
        assert witnesses[0]["status"] == "paused"
