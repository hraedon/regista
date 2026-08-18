"""Witness receipt verification over a **v6** event (P1.7).

Why this file exists at all. Webhook delivery is preserved as non-evidentiary
transport (``TRUST-DOMAIN.md`` §7 CUT marker, D-7) — a live path, not something that
died with v5 — and ed25519 receipt verification over it was broken for every v6
event. ``_witness`` passed the event row's ``payload_canonical_hash`` column as
``Ed25519Scheme.verify``'s ``envelope_hash`` argument while passing the bare
``canonical_envelope`` as ``envelope``. The scheme's final step is
``compare_digest(H(envelope), envelope_hash)``, so those two arguments have to
describe the *same* byte string. For v1-v5 they do. For v6 they do not:
``V6-ENVELOPE.md`` §5.3 defines the column as
``SHA256(b"regista.event.v6\\x00" || canonical_envelope)`` — the hash of the
domain-tagged **signature input**, not of the envelope.

The failure mode is the reason this needed a dedicated file rather than a line in an
existing one. ``sig_verified`` was unconditionally ``False``, which means the three
*negative* delivery assertions in ``test_witness_integration.py`` passed **vacuously**
— a bad signature was rejected, and so was a good one, and nothing in the suite could
tell those two situations apart. A check that always answers ``False`` satisfies every
negative test ever written against it. So the assertions here come in pairs: each
negative is accompanied by the positive that a check stuck on one answer cannot also
satisfy.
"""

from __future__ import annotations

import hashlib
import uuid
from unittest.mock import MagicMock, patch

import pytest
from _helpers import DSN, WORKFLOW_PATH, seed_precut_ed25519_witness

from regista._signing import (
    classify_envelope_version,
    compute_payload_canonical_hash,
    compute_v6_payload_canonical_hash,
    v6_signature_input,
)
from regista._signing_scheme import Ed25519Scheme
from regista._witness import verify_witness_countersignature
from regista.testing import drop_project_schema

nacl_signing = pytest.importorskip("nacl.signing")


@pytest.fixture(scope="module")
def v6_event(tmp_path_factory):
    """A real v6 ``work_item_created`` row: its envelope bytes and stored hash column.

    Module-scoped because every node here reads the same two immutable byte strings;
    the nodes that need a *writable* store take ``v6_store`` instead.
    """
    from regista import Regista
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project = f"test_p17wv6_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path_factory.mktemp("p17wv6_keys"))
    sub = Regista.create_project(DSN, project, keyset.path)
    try:
        open_v6_epoch(sub, keyset)
        sub.register_workflow_file(WORKFLOW_PATH)
        wi, _ = sub.create_work_item(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "p17-witness-v6"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        created = events[-1]
        yield {
            "canonical_envelope": bytes(created.canonical_envelope),
            "payload_canonical_hash": bytes(created.payload_canonical_hash),
            "hash_alg": created.hash_alg,
        }
    finally:
        sub.close()
        drop_project_schema(DSN, project)


@pytest.fixture
def v6_store(tmp_path):
    from regista import Regista
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project = f"test_p17wv6d_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path)
    sub = Regista.create_project(DSN, project, keyset.path)
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestTheTwoHashesActuallyDiffer:
    """The premise. If these coincided there would be no bug and no fix to prove."""

    def test_the_row_is_v6(self, v6_event):
        assert classify_envelope_version(v6_event["canonical_envelope"]) == 6

    def test_stored_column_is_the_signature_input_hash_not_the_envelope_digest(
        self, v6_event
    ):
        env = v6_event["canonical_envelope"]
        stored = v6_event["payload_canonical_hash"]

        # What the column IS (V6-ENVELOPE.md §5.3).
        assert stored == compute_v6_payload_canonical_hash(env)
        assert stored == hashlib.sha256(v6_signature_input(env)).digest()
        # What the defect assumed it was.
        assert stored != hashlib.sha256(env).digest()

    def test_the_version_aware_helper_agrees_with_the_stored_column(self, v6_event):
        assert compute_payload_canonical_hash(
            v6_event["canonical_envelope"], v6_event["hash_alg"]
        ) == v6_event["payload_canonical_hash"]

    def test_the_helper_is_the_plain_digest_for_a_legacy_envelope(self):
        """v1-v5 have no domain tag, so the helper must not add one.

        A version-aware helper that got this half right would fix v6 and break the
        351k+ legacy events it also has to describe.
        """
        from regista._signing import build_signing_envelope

        legacy = build_signing_envelope(
            event_id=uuid.uuid4(),
            work_item_id=uuid.uuid4(),
            actor_id="agent:worker",
            transition="note",
            payload={"k": "v"},
        )
        assert classify_envelope_version(legacy) == 1
        assert compute_payload_canonical_hash(legacy) == hashlib.sha256(legacy).digest()
        assert compute_payload_canonical_hash(legacy, "sha-512") == hashlib.sha512(
            legacy
        ).digest()


class TestCountersignatureVerification:
    """The positive/negative pair. Neither half is meaningful without the other."""

    def test_a_valid_countersignature_over_a_v6_event_verifies_true(self, v6_event):
        sk = nacl_signing.SigningKey.generate()
        env = v6_event["canonical_envelope"]

        assert verify_witness_countersignature(
            canonical_envelope=env,
            row_payload_canonical_hash=v6_event["payload_canonical_hash"],
            hash_alg=v6_event["hash_alg"],
            witness_signature=sk.sign(env).signature,
            witness_public_key=bytes(sk.verify_key),
        ) is True

    def test_a_tampered_countersignature_over_a_v6_event_verifies_false(self, v6_event):
        sk = nacl_signing.SigningKey.generate()
        env = v6_event["canonical_envelope"]
        good = bytearray(sk.sign(env).signature)
        good[0] ^= 0x01  # one flipped bit, same length, same key

        assert verify_witness_countersignature(
            canonical_envelope=env,
            row_payload_canonical_hash=v6_event["payload_canonical_hash"],
            hash_alg=v6_event["hash_alg"],
            witness_signature=bytes(good),
            witness_public_key=bytes(sk.verify_key),
        ) is False

    def test_another_witnesss_signature_verifies_false(self, v6_event):
        signer = nacl_signing.SigningKey.generate()
        other = nacl_signing.SigningKey.generate()
        env = v6_event["canonical_envelope"]

        assert verify_witness_countersignature(
            canonical_envelope=env,
            row_payload_canonical_hash=v6_event["payload_canonical_hash"],
            hash_alg=v6_event["hash_alg"],
            witness_signature=signer.sign(env).signature,
            witness_public_key=bytes(other.verify_key),
        ) is False

    def test_a_row_whose_hash_column_disagrees_verifies_false(self, v6_event):
        """The row-integrity leg is load-bearing, not decoration.

        A valid witness signature over a canonical_envelope whose sibling
        payload_canonical_hash column does not hash it is a row that disagrees with
        itself. Confirming a receipt over it would attest to bytes the store cannot
        vouch for, so it fails closed — this is the check the defect destroyed rather
        than merely misrouted, and without this node the fix could have been "drop the
        hash comparison" and still shown a green positive/negative pair.
        """
        sk = nacl_signing.SigningKey.generate()
        env = v6_event["canonical_envelope"]
        corrupted = bytearray(v6_event["payload_canonical_hash"])
        corrupted[-1] ^= 0xFF

        assert verify_witness_countersignature(
            canonical_envelope=env,
            row_payload_canonical_hash=bytes(corrupted),
            hash_alg=v6_event["hash_alg"],
            witness_signature=sk.sign(env).signature,
            witness_public_key=bytes(sk.verify_key),
        ) is False

    def test_an_unknown_hash_alg_verifies_false_rather_than_raising(self, v6_event):
        sk = nacl_signing.SigningKey.generate()
        env = v6_event["canonical_envelope"]

        assert verify_witness_countersignature(
            canonical_envelope=env,
            row_payload_canonical_hash=v6_event["payload_canonical_hash"],
            hash_alg="md5",
            witness_signature=sk.sign(env).signature,
            witness_public_key=bytes(sk.verify_key),
        ) is False


class TestTheDefectiveComparisonIsPinned:
    def test_the_old_argument_pairing_rejects_a_signature_the_fix_accepts(
        self, v6_event
    ):
        """The bug, stated as an executable difference on ONE signature.

        Same envelope, same key, same genuinely valid signature. The old call —
        ``verify(envelope=canonical_envelope, envelope_hash=row.payload_canonical_hash)``
        — returns False, because the scheme's ``compare_digest(H(envelope),
        envelope_hash)`` step is comparing the digest of the envelope against the
        digest of the *signature input*. Anyone who reintroduces that pairing turns
        this node red rather than turning three negative delivery tests vacuous.
        """
        sk = nacl_signing.SigningKey.generate()
        env = v6_event["canonical_envelope"]
        signature = sk.sign(env).signature
        pubkey = bytes(sk.verify_key)

        old = Ed25519Scheme().verify(
            env, signature, v6_event["payload_canonical_hash"], pubkey,
        )
        new = verify_witness_countersignature(
            canonical_envelope=env,
            row_payload_canonical_hash=v6_event["payload_canonical_hash"],
            hash_alg=v6_event["hash_alg"],
            witness_signature=signature,
            witness_public_key=pubkey,
        )
        assert old is False
        assert new is True


class TestDeliveryEndToEndOverAV6Event:
    """The same pair through the real ``deliver_pending_witness_receipts`` path.

    ``test_witness_integration.py`` carries these too, but its manifest nodes were
    strict-xfail through the whole period the defect existed. These are unmarked, so
    they are the ones that stay honest if the manifest changes.
    """

    @staticmethod
    def _mock_conn(body: bytes):
        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = body
        conn = MagicMock()
        conn.getresponse.return_value = resp
        return conn

    def test_a_valid_countersignature_confirms_the_receipt(self, v6_store):
        sk = nacl_signing.SigningKey.generate()
        seed_precut_ed25519_witness(
            v6_store, "http://localhost:19999/witness", bytes(sk.verify_key),
        )
        wi, _ = v6_store.create_work_item(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "e2e-good"},
        )
        env = bytes(v6_store.read_events(work_item_id=wi.work_item_id)[-1].canonical_envelope)
        body = ('{"witness_signature": "' + sk.sign(env).signature.hex() + '"}').encode()

        with patch("http.client.HTTPConnection", return_value=self._mock_conn(body)):
            count = v6_store.deliver_pending_witness_receipts()

        assert count == 1
        receipts = v6_store.list_witness_receipts()
        assert [r["status"] for r in receipts] == ["confirmed"]
        assert receipts[0]["witness_scheme"] == "ed25519"

    def test_a_tampered_countersignature_leaves_the_receipt_unconfirmed(self, v6_store):
        sk = nacl_signing.SigningKey.generate()
        seed_precut_ed25519_witness(
            v6_store, "http://localhost:19999/witness", bytes(sk.verify_key),
        )
        wi, _ = v6_store.create_work_item(
            "test_workflow", "feature", "agent:worker",
            custom_fields={"title": "e2e-bad"},
        )
        env = bytes(v6_store.read_events(work_item_id=wi.work_item_id)[-1].canonical_envelope)
        tampered = bytearray(sk.sign(env).signature)
        tampered[0] ^= 0x01
        body = ('{"witness_signature": "' + bytes(tampered).hex() + '"}').encode()

        with patch("http.client.HTTPConnection", return_value=self._mock_conn(body)):
            count = v6_store.deliver_pending_witness_receipts()

        assert count == 0
        receipts = v6_store.list_witness_receipts()
        assert [r["status"] for r in receipts] == ["pending"]
        assert receipts[0]["error_message"] == "witness signature verification failed"
