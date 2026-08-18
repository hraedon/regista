"""Witness key enrolment — **CUT FROM 0.6.0** (TRUST-DOMAIN.md §7 CUT marker, D-7).

Rewritten for P2.2. These tests used to assert that registering an ed25519 witness
enrolled a key into ``principal_keys``, that ``rotate_witness_key`` rotated it, and
that ``unregister_witness`` revoked it. All three did so with **no signed event** —
they were the third of the three §5.1 bypass paths.

Positive witness-independence work does not ship in 0.6.0: the signed witness
lifecycle (``witness_registered``, ``witness_key_rotated``, ...) is struck from the
§5.3 catalogue, and preflight measured zero registrations and zero receipts
estate-wide. So there is no event for those paths to project from, and they now
refuse by name with ``WITNESS_LIFECYCLE_CUT``.

What these tests assert now: the refusal is honest end-to-end, the HMAC transport
path is untouched (webhook delivery is preserved as non-evidentiary transport), and
the doctor check still describes a pre-cut ed25519 registration correctly.
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
from _helpers import seed_precut_ed25519_witness

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


class TestRegisterEd25519WitnessIsRefused:
    """§7 CUT / D-7: enrolling a witness key is refused, not silently skipped."""

    def test_ed25519_registration_is_refused_by_name(self, regista):
        _sk, pub = _ed25519_keypair()
        with pytest.raises(RegistaError) as exc_info:
            regista.register_witness(
                "https://example.com/witness",
                public_key=pub,
                key_scheme="ed25519",
            )
        assert exc_info.value.code is ErrorCode.WITNESS_LIFECYCLE_CUT
        assert exc_info.value.detail["reason"] == "witness_lifecycle_cut_from_0_6_0"

    def test_the_refusal_leaves_no_registration_behind(self, regista):
        """It refuses before the INSERT, so there is no half-registered witness."""
        _sk, pub = _ed25519_keypair()
        with pytest.raises(RegistaError):
            regista.register_witness(
                "https://example.com/witness",
                public_key=pub,
                key_scheme="ed25519",
            )
        assert regista.list_witnesses() == []

    def test_the_refusal_enrols_no_registry_key(self, regista):
        _sk, pub = _ed25519_keypair()
        with pytest.raises(RegistaError):
            regista.register_witness(
                "https://example.com/witness",
                public_key=pub,
                key_scheme="ed25519",
            )
        # The whole point: no unsourced principal_keys row was created (§5.9 rule 2).
        assert regista.principals.list() == []

    def test_ed25519_validation_still_runs_before_the_refusal(self, regista):
        """A wrong-length key is still an argument error, not a capability error.

        Ordering matters for diagnosis: a caller with a malformed key should learn
        that, rather than being told the feature is cut and fixing the wrong thing.
        """
        with pytest.raises(RegistaError) as exc_info:
            regista.register_witness(
                "https://example.com/witness",
                public_key=b"\x01" * 31,
                key_scheme="ed25519",
            )
        assert exc_info.value.code is ErrorCode.INVALID_ARGUMENT

    def test_hmac_witness_registration_still_works(self, regista):
        """Webhook delivery is preserved as non-evidentiary transport (§7)."""
        wid = regista.register_witness(
            "https://example.com/witness",
            key_scheme="hmac-sha256",
        )
        assert regista.enrolled_witness_key(wid) is None
        assert len(regista.list_witnesses()) == 1


class TestRotateWitnessKeyIsRefused:
    def test_rotate_is_refused_by_name(self, regista):
        _sk1, pub1 = _ed25519_keypair()
        wid = seed_precut_ed25519_witness(regista, "https://example.com/witness", pub1)
        _sk2, pub2 = _ed25519_keypair()
        with pytest.raises(RegistaError) as exc_info:
            regista.rotate_witness_key(wid, pub2)
        assert exc_info.value.code is ErrorCode.WITNESS_LIFECYCLE_CUT

    def test_the_refusal_does_not_update_the_registration(self, regista):
        """Refused before the UPDATE: no partial state, no rotated-but-unenrolled key."""
        _sk1, pub1 = _ed25519_keypair()
        wid = seed_precut_ed25519_witness(regista, "https://example.com/witness", pub1)
        _sk2, pub2 = _ed25519_keypair()
        with pytest.raises(RegistaError):
            regista.rotate_witness_key(wid, pub2)
        witnesses = regista.list_witnesses()
        assert bytes(witnesses[0]["public_key"]) == pub1

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
        wid = seed_precut_ed25519_witness(regista, "https://example.com/witness", pub)
        with pytest.raises(RegistaError) as exc_info:
            regista.rotate_witness_key(wid, b"\x02" * 31)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT


class TestUnregisterWithActiveKeyRows:
    def test_unregister_refuses_when_an_active_registry_key_exists(self, regista):
        """A pre-cut ed25519 witness cannot be honestly unregistered.

        Revoking its key requires a signed ``principal_key_revoked`` event, which the
        cut lifecycle cannot produce. Silently deleting the registration and leaving
        the key active would be a quieter version of the same lie, so it refuses.
        (Zero such witnesses exist estate-wide — this is the unreachable-by-design
        branch, tested because "unreachable" claims are how bypasses survive.)
        """
        from regista.testing import seed_legacy_principal_key

        _sk, pub = _ed25519_keypair()
        wid = seed_precut_ed25519_witness(regista, "https://example.com/witness", pub)
        seed_legacy_principal_key(
            regista._mgr, witness_principal_id(wid), pub, "ed25519",
        )
        with pytest.raises(RegistaError) as exc_info:
            regista.unregister_witness(wid)
        assert exc_info.value.code is ErrorCode.WITNESS_LIFECYCLE_CUT

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
        from regista.testing import seed_legacy_principal_key

        _sk, pub = _ed25519_keypair()
        wid = seed_precut_ed25519_witness(
            regista, "https://example.com/witness", pub,
        )
        # A pre-cut witness whose registry key is present reports "ok". The key row
        # is legacy_unsourced — under the cut there is no event that could source it.
        seed_legacy_principal_key(
            regista._mgr, witness_principal_id(wid), pub, "ed25519",
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
        # An ed25519 registration with NO registry key is exactly the state the cut
        # produces, so this check is the one that describes 0.6.0 reality.
        wid = seed_precut_ed25519_witness(
            regista, "https://example.com/witness", pub,
        )
        check = _check_witness_key_enrollment(DSN, regista._project, require_ssl=False)
        assert check.status == "warn"
        assert str(wid) in check.detail

    def test_check_warns_on_fingerprint_mismatch(self, regista):
        from regista._doctor import _check_witness_key_enrollment
        from regista.testing import seed_legacy_principal_key

        _sk, pub = _ed25519_keypair()
        wid = seed_precut_ed25519_witness(
            regista, "https://example.com/witness", pub,
        )
        seed_legacy_principal_key(
            regista._mgr, witness_principal_id(wid), b"\xff" * 32, "ed25519",
        )
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

        # Webhook delivery is preserved as non-evidentiary transport (§7 CUT
        # marker): a pre-cut ed25519 witness still receives and verifies receipts.
        # What it no longer has is an enrolled registry key, and delivery must not
        # depend on one.
        seed_precut_ed25519_witness(regista, "http://localhost:19999/witness", pub)

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
