from __future__ import annotations

import hashlib
import uuid
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._witness import witness_principal_id
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


def _ed25519_keypair():
    try:
        import nacl.signing

        sk = nacl.signing.SigningKey.generate()
        return sk, bytes(sk.verify_key)
    except ImportError:
        return None, b"\x01" * 32


@pytest.fixture
def regista():
    from regista import Regista

    project = f"test_wke_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestWitnessPrincipalId:
    def test_format(self):
        wid = uuid.UUID("550e8400-e29b-41d4-a716-446655440000")
        assert witness_principal_id(wid) == "witness:550e8400-e29b-41d4-a716-446655440000"

    def test_accepts_str(self):
        assert witness_principal_id("abc").startswith("witness:")


class TestEnrollOnRegister:
    def test_ed25519_witness_enrolls_into_registry(self, regista):
        _sk, pub = _ed25519_keypair()
        wid = regista.register_witness(
            "https://example.com/witness",
            public_key=pub,
            key_scheme="ed25519",
        )
        entry = regista.enrolled_witness_key(wid)
        assert entry is not None
        assert entry["principal_id"] == witness_principal_id(wid)
        assert entry["scheme"] == "ed25519"
        assert entry["status"] == "active"
        assert bytes.fromhex(entry["public_key"]) == pub

    def test_enrolled_key_fingerprint_matches(self, regista):
        _sk, pub = _ed25519_keypair()
        wid = regista.register_witness(
            "https://example.com/witness",
            public_key=pub,
            key_scheme="ed25519",
        )
        entry = regista.enrolled_witness_key(wid)
        expected = f"ed25519:sha256:{hashlib.sha256(pub).hexdigest()}"
        assert entry["fingerprint"] == expected

    def test_hmac_witness_not_enrolled(self, regista):
        wid = regista.register_witness(
            "https://example.com/witness",
            key_scheme="hmac-sha256",
        )
        assert regista.enrolled_witness_key(wid) is None

    def test_enrolled_key_discoverable_via_principals_facade(self, regista):
        _sk, pub = _ed25519_keypair()
        wid = regista.register_witness(
            "https://example.com/witness",
            public_key=pub,
            key_scheme="ed25519",
        )
        active = regista.principals.get_active(witness_principal_id(wid))
        assert active["scheme"] == "ed25519"
        assert bytes.fromhex(active["public_key"]) == pub


class TestRotateWitnessKey:
    def test_rotate_supersedes_old_key(self, regista):
        _sk1, pub1 = _ed25519_keypair()
        wid = regista.register_witness(
            "https://example.com/witness",
            public_key=pub1,
            key_scheme="ed25519",
        )
        old_entry = regista.enrolled_witness_key(wid)
        assert old_entry is not None

        _sk2, pub2 = _ed25519_keypair()
        new_entry = regista.rotate_witness_key(wid, pub2)
        assert new_entry["status"] == "active"
        assert bytes.fromhex(new_entry["public_key"]) == pub2
        assert new_entry["key_id"] != old_entry["key_id"]

        active = regista.enrolled_witness_key(wid)
        assert bytes.fromhex(active["public_key"]) == pub2

        all_keys = regista.principals.list(witness_principal_id(wid))
        statuses = {k["key_id"]: k["status"] for k in all_keys}
        assert statuses[old_entry["key_id"]] == "superseded"
        assert statuses[new_entry["key_id"]] == "active"

    def test_rotate_updates_witness_registration_pubkey(self, regista):
        _sk1, pub1 = _ed25519_keypair()
        wid = regista.register_witness(
            "https://example.com/witness",
            public_key=pub1,
            key_scheme="ed25519",
        )
        _sk2, pub2 = _ed25519_keypair()
        regista.rotate_witness_key(wid, pub2)
        witnesses = regista.list_witnesses()
        assert bytes(witnesses[0]["public_key"]) == pub2

    def test_rotate_hmac_witness_rejected(self, regista):
        wid = regista.register_witness(
            "https://example.com/witness",
            key_scheme="hmac-sha256",
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.rotate_witness_key(wid, b"\x02" * 32)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_rotate_nonexistent_raises(self, regista):
        with pytest.raises(RegistaError) as exc_info:
            regista.rotate_witness_key(uuid.uuid4(), b"\x02" * 32)
        assert exc_info.value.code == ErrorCode.WITNESS_NOT_FOUND

    def test_rotate_wrong_length_rejected(self, regista):
        _sk, pub = _ed25519_keypair()
        wid = regista.register_witness(
            "https://example.com/witness",
            public_key=pub,
            key_scheme="ed25519",
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.rotate_witness_key(wid, b"\x02" * 31)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT


class TestRevokeOnUnregister:
    def test_unregister_revokes_enrolled_key(self, regista):
        _sk, pub = _ed25519_keypair()
        wid = regista.register_witness(
            "https://example.com/witness",
            public_key=pub,
            key_scheme="ed25519",
        )
        old_entry = regista.enrolled_witness_key(wid)
        assert old_entry is not None

        regista.unregister_witness(wid)
        assert regista.enrolled_witness_key(wid) is None

        all_keys = regista.principals.list(witness_principal_id(wid))
        assert len(all_keys) == 1
        assert all_keys[0]["status"] == "revoked"
        assert all_keys[0]["revoked_reason"] == "witness unregistered"

    def test_unregister_hmac_witness_no_principal_change(self, regista):
        wid = regista.register_witness(
            "https://example.com/witness",
            key_scheme="hmac-sha256",
        )
        regista.unregister_witness(wid)
        assert regista.principals.list(witness_principal_id(wid)) == []


class TestEnrolledKeyAbsent:
    def test_enrolled_key_none_for_unknown_witness(self, regista):
        assert regista.enrolled_witness_key(uuid.uuid4()) is None


class TestDoctorCheck:
    def test_check_ok_when_enrolled(self, regista):
        from regista._doctor import _check_witness_key_enrollment

        _sk, pub = _ed25519_keypair()
        regista.register_witness(
            "https://example.com/witness",
            public_key=pub,
            key_scheme="ed25519",
        )
        check = _check_witness_key_enrollment(DSN, regista._project, require_ssl=False)
        assert check.status == "ok"
        assert "enrolled" in check.detail

    def test_check_ok_when_no_ed25519_witnesses(self, regista):
        from regista._doctor import _check_witness_key_enrollment

        regista.register_witness("https://example.com/witness", key_scheme="hmac-sha256")
        check = _check_witness_key_enrollment(DSN, regista._project, require_ssl=False)
        assert check.status == "ok"

    def test_check_warns_on_enrollment_gap(self, regista):
        from regista._doctor import _check_witness_key_enrollment

        _sk, pub = _ed25519_keypair()
        wid = regista.register_witness(
            "https://example.com/witness",
            public_key=pub,
            key_scheme="ed25519",
        )
        with regista._mgr.connect() as conn:
            conn.execute(
                "DELETE FROM principal_keys WHERE principal_id = %s",
                [witness_principal_id(wid)],
            )
            conn.commit()
        check = _check_witness_key_enrollment(DSN, regista._project, require_ssl=False)
        assert check.status == "warn"
        assert str(wid) in check.detail

    def test_check_warns_on_fingerprint_mismatch(self, regista):
        from regista._doctor import _check_witness_key_enrollment

        _sk, pub = _ed25519_keypair()
        wid = regista.register_witness(
            "https://example.com/witness",
            public_key=pub,
            key_scheme="ed25519",
        )
        with regista._mgr.connect() as conn:
            conn.execute(
                "UPDATE principal_keys SET public_key = %s "
                "WHERE principal_id = %s AND status = 'active'",
                [b"\xff" * 32, witness_principal_id(wid)],
            )
            conn.commit()
        check = _check_witness_key_enrollment(DSN, regista._project, require_ssl=False)
        assert check.status == "warn"


class TestDeliveryStillVerifies:
    def test_enrolled_witness_delivery_succeeds(self, regista):
        try:
            import nacl.signing
        except ImportError:
            pytest.skip("PyNaCl not installed")

        from unittest.mock import MagicMock, patch

        sk = nacl.signing.SigningKey.generate()
        pub = bytes(sk.verify_key)

        wid = regista.register_witness(
            "http://localhost:19999/witness",
            public_key=pub,
            key_scheme="ed25519",
        )
        assert regista.enrolled_witness_key(wid) is not None

        wi, _ = regista.create_work_item(
            "test_workflow", "feature", "actor-1",
            custom_fields={"title": "wke-delivery"},
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
        assert len([r for r in receipts if r["status"] == "confirmed"]) == 1
