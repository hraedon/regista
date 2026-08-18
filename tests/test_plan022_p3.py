from __future__ import annotations

import base64
import json
import os
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._testing import KeySet

TESTS_DIR = Path(__file__).parent
# Configurable so a batch can be run against its own database (the same rule
# ``tests/_helpers.py`` already applies); the default is unchanged.
DSN = os.environ.get(
    "REGISTA_TEST_DSN",
    "postgresql://regista_test:regista_test@localhost:5432/regista_test",
)
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")
ED_KEY_PATH = str(TESTS_DIR / "test_keys_ed25519.json")
HMAC_KEY_PATH = str(TESTS_DIR / "test_keys.json")

# The two distinct principals this module is about. ``test_keys_multi_principal.json``
# named them ``alice``/``bob``; ``TRUST-DOMAIN.md`` §2.1 requires
# ``(human|agent|service):<subject>`` and the v6 grammar refuses a bare legacy name at
# ingress, so they map onto two of ``_v6_fixtures.ACTOR_PRINCIPALS``. What the module
# tests — two principals, two keys, per-principal resolution — is unchanged; only the
# spelling of the ids and the fact that the key ids are now derived from the keyset
# rather than hardcoded (``ed-alice-001``) differ.
ALICE = "agent:worker"
BOB = "agent:reviewer"

_HAS_NACL = True
try:
    import nacl.signing  # noqa: F401
except ImportError:
    _HAS_NACL = False

skip_no_nacl = pytest.mark.skipif(not _HAS_NACL, reason="PyNaCl not installed")


def _write_keys(tmp_path, keys_data):
    p = tmp_path / "keys.json"
    p.write_text(json.dumps(keys_data))
    return str(p)


def _gen_ed25519_keypair_b64():
    import nacl.signing

    sk = nacl.signing.SigningKey.generate()
    pk = sk.verify_key
    return base64.b64encode(bytes(sk)).decode("ascii"), base64.b64encode(bytes(pk)).decode("ascii")


def _v6_in_memory(tmp_path, *, strict_asymmetric: bool = False):
    """An ``InMemoryRegista`` on a clean v6 epoch, workflow registered.

    Returns the handle *and* the keyset, because this module asserts on the key id
    an event was signed with and those ids are derived from the keyset
    (``_v6_fixtures._key_id_for``) rather than hardcoded.

    ``open_v6_epoch`` must precede ``register_workflow_file``: the registration
    emits a signed ``workflow_registered`` event and there is no epoch to append it
    to before genesis.
    """

    from regista.testing import InMemoryRegista
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    keyset = make_v6_keyset(tmp_path)
    sub = InMemoryRegista(
        project="test", hmac_key_path=keyset.path, strict_asymmetric=strict_asymmetric,
    )
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    return sub, keyset


@contextmanager
def _v6_postgres(tmp_path, prefix: str, *, strict_asymmetric: bool = False):
    """The Postgres sibling of :func:`_v6_in_memory`, with WI-243's teardown."""

    from regista import Regista
    from regista.testing import drop_project_schema
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project = f"{prefix}_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path)
    sub = Regista.create_project(
        DSN, project, keyset.path, strict_asymmetric=strict_asymmetric,
    )
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    try:
        yield sub, keyset
    finally:
        sub.close()
        drop_project_schema(DSN, project)


def _add_hmac_key(keyset_path: str) -> None:
    """Append an HMAC key to a v6 keyset file, so strict mode has something to refuse.

    The fixture this replaces was HMAC-*only*, which cannot open a v6 epoch (genesis
    is Ed25519). Keeping an HMAC key alongside the actor keys is what keeps
    ``strict_asymmetric`` load-bearing: without one, an unbound actor would be refused
    for want of any key at all and the flag would prove nothing.
    """

    path = Path(keyset_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["keys"].append(
        {
            "key_id": "hmac-001",
            "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
            "status": "active",
            "scheme": "hmac-sha256",
        }
    )
    path.write_text(json.dumps(data), encoding="utf-8")


@skip_no_nacl
class TestPerPrincipalEd25519Signing:
    def test_two_principals_sign_with_different_keys(self, tmp_path):
        sub, keyset = _v6_in_memory(tmp_path)

        wi_alice, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ALICE,
            custom_fields={"title": "alice's work"},
        )
        events_alice = sub.read_events(work_item_id=wi_alice.work_item_id)
        assert events_alice[-1].key_id == keyset.key_for(ALICE).key_id
        assert events_alice[-1].scheme_id == "ed25519"

        wi_bob, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=BOB,
            custom_fields={"title": "bob's work"},
        )
        events_bob = sub.read_events(work_item_id=wi_bob.work_item_id)
        assert events_bob[-1].key_id == keyset.key_for(BOB).key_id
        assert events_bob[-1].scheme_id == "ed25519"

        assert events_alice[-1].key_id != events_bob[-1].key_id

    def test_explicit_key_id_overrides_principal_resolution(self, tmp_path):
        sub, keyset = _v6_in_memory(tmp_path)

        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ALICE,
            custom_fields={"title": "explicit key"},
        )
        evt = sub.append_event(
            wi.work_item_id, BOB, key_id=keyset.key_for(BOB).key_id,
            transition="note", payload={"text": "bob signing as bob"},
        )
        assert evt.key_id == keyset.key_for(BOB).key_id
        assert evt.actor_id == BOB

    def test_postgres_per_principal_signing(self, tmp_path):
        with _v6_postgres(tmp_path, "test_p3") as (sub, keyset):
            wi, _ = sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id=ALICE,
                custom_fields={"title": "pg per-principal"},
            )
            events = sub.read_events(work_item_id=wi.work_item_id)
            assert events[-1].key_id == keyset.key_for(ALICE).key_id
            assert events[-1].scheme_id == "ed25519"

            sub.transition(wi.work_item_id, "start", BOB, actor_metadata={"role": "agent"})
            events = sub.read_events(work_item_id=wi.work_item_id)
            start_evt = next(e for e in events if e.transition == "start")
            assert start_evt.key_id == keyset.key_for(BOB).key_id
            assert start_evt.scheme_id == "ed25519"

    def test_replay_verifies_per_principal_events(self, tmp_path):
        sub, _keyset = _v6_in_memory(tmp_path)

        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ALICE,
            custom_fields={"title": "replay test alice"},
        )
        wi_bob, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=BOB,
            custom_fields={"title": "replay test bob"},
        )
        sub.transition(wi_bob.work_item_id, "start", BOB, actor_metadata={"role": "agent"})

        report = sub.replay()
        assert report.halted == 0, f"Replay halted: {report.entries}"


@skip_no_nacl
class TestIndependentVerification:
    def test_verify_with_exported_public_key_in_memory(self, tmp_path):
        sub, _keyset = _v6_in_memory(tmp_path)

        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ALICE,
            custom_fields={"title": "verify test"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        evt = events[-1]

        assert sub.verify_event_signature(evt) is True

        public_keys = sub.export_public_keys()
        alice_key = next(k for k in public_keys if k["principal_id"] == ALICE)
        pub_bytes = base64.b64decode(alice_key["public_key"])

        assert sub.verify_event_signature(evt, public_key=pub_bytes) is True

        bob_key = next(k for k in public_keys if k["principal_id"] == BOB)
        bob_pub = base64.b64decode(bob_key["public_key"])
        assert sub.verify_event_signature(evt, public_key=bob_pub) is False

    def test_verify_with_exported_public_key_postgres(self, tmp_path):
        with _v6_postgres(tmp_path, "test_p3v") as (sub, _keyset):
            wi, _ = sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id=ALICE,
                custom_fields={"title": "pg verify"},
            )
            events = sub.read_events(work_item_id=wi.work_item_id)
            evt = events[-1]

            assert sub.verify_event_signature(evt) is True

            public_keys = sub.export_public_keys()
            alice_key = next(k for k in public_keys if k["principal_id"] == ALICE)
            pub_bytes = base64.b64decode(alice_key["public_key"])
            assert sub.verify_event_signature(evt, public_key=pub_bytes) is True

    def test_standalone_verify_without_keyset(self, tmp_path):
        from regista._signing import verify_event_result_with_public_key
        from regista._testing import raw_transaction
        from regista._v6_referents import store_referents

        sub, _keyset = _v6_in_memory(tmp_path)

        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ALICE,
            custom_fields={"title": "standalone"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        evt = events[-1]

        public_keys = sub.export_public_keys()
        alice_key = next(k for k in public_keys if k["principal_id"] == ALICE)
        pub_bytes = base64.b64decode(alice_key["public_key"])

        bob_key = next(k for k in public_keys if k["principal_id"] == BOB)
        tampered = base64.b64decode(bob_key["public_key"])

        # No KeySet is consulted — the verifier is handed the raw public bytes and
        # nothing else about the signer, which is what "without keyset" has always
        # meant here. What a v6 verdict additionally needs is the *chain*
        # (``TRUST-DOMAIN.md`` §5.10 steps 1-4 are facts about other events), so the
        # store is presented as material. Key material and trust material are
        # different things: the acceptance chain still decides whether this key was
        # ever bound to this actor, and the supplied key still decides the signature.
        with raw_transaction(sub) as conn:
            referents = store_referents(conn, label="open project")
            assert verify_event_result_with_public_key(
                evt, pub_bytes, referents=referents,
            ).accepted is True
            assert verify_event_result_with_public_key(
                evt, tampered, referents=referents,
            ).accepted is False

    def test_export_public_keys_excludes_hmac(self, tmp_path):
        secret_b64, pub_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "hmac-001",
                    "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
                    "status": "active",
                    "scheme": "hmac-sha256",
                },
                {
                    "key_id": "ed-001",
                    "secret": secret_b64,
                    "public_key": pub_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                },
            ]
        })
        ks = KeySet(kf)
        exported = ks.export_public_keys()
        assert len(exported) == 1
        assert exported[0]["key_id"] == "ed-001"
        assert exported[0]["scheme"] == "ed25519"
        assert exported[0]["principal_id"] == "alice"
        assert "public_key" in exported[0]
        assert "secret" not in exported[0]

    def test_export_public_keys_includes_revoked(self, tmp_path):
        secret_b64, pub_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-revoked",
                    "secret": secret_b64,
                    "public_key": pub_b64,
                    "encoding": "base64",
                    "status": "revoked",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                    "revoked_at": "2026-01-01T00:00:00+00:00",
                },
            ]
        })
        ks = KeySet(kf)
        exported = ks.export_public_keys()
        assert len(exported) == 1
        assert exported[0]["status"] == "revoked"
        assert exported[0]["revoked_at"] == "2026-01-01T00:00:00+00:00"


    def test_verify_without_canonical_envelope_postgres(self, tmp_path):
        from regista._testing import raw_transaction
        from regista._v6_referents import store_referents

        with _v6_postgres(tmp_path, "test_p3ne") as (sub, _keyset):
            wi, _ = sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id=ALICE,
                custom_fields={"title": "no envelope test"},
            )
            sub.transition(
                wi.work_item_id, "start", ALICE,
                actor_metadata={"role": "agent"},
            )

            events = sub.read_events(work_item_id=wi.work_item_id)
            evt = events[-1]

            from regista._types import Event as _Event

            evt_no_env = _Event(
                event_id=evt.event_id,
                work_item_id=evt.work_item_id,
                event_seq=evt.event_seq,
                actor_id=evt.actor_id,
                actor_kind=evt.actor_kind,
                actor_metadata=evt.actor_metadata,
                key_id=evt.key_id,
                workflow_name=evt.workflow_name,
                workflow_version=evt.workflow_version,
                timestamp=evt.timestamp,
                transition=evt.transition,
                payload=evt.payload,
                payload_canonical_hash=evt.payload_canonical_hash,
                signature=evt.signature,
                canonical_envelope=None,
                on_behalf_of=evt.on_behalf_of,
                scheme_id=evt.scheme_id,
                prev_event_hash=evt.prev_event_hash,
                global_seq=evt.global_seq,
                prev_global_event_hash=evt.prev_global_event_hash,
                entity_kind=evt.entity_kind,
                entity_id=evt.entity_id,
                hash_alg=evt.hash_alg,
            )

            public_keys = sub.export_public_keys()
            alice_key = next(k for k in public_keys if k["principal_id"] == ALICE)
            pub_bytes = base64.b64decode(alice_key["public_key"])

            from regista._signing import verify_event_result_with_public_key
            from regista._verification import Applicability, FailureReason

            # WI-267: this used to assert `is True` — the verifier rebuilt a
            # candidate envelope from the row columns when the stored envelope
            # was missing, i.e. it authenticated the row against itself.
            # Reconstruction is an explicit offline operator action, never a
            # verify-path fallback, so there is nothing here to verify.
            #
            # The whole chain is presented to BOTH calls, so the only difference
            # between them is the stored envelope — the point the node makes. And
            # because the chain IS presented, P1.7 phase 4 makes the verdict
            # INVALID rather than the weaker UNVERIFIABLE this asserted before: the
            # row's chain predecessor is presented as a v6 event, so this row is
            # inside the v6 epoch, where the envelope column is written by every
            # append (V6-ENVELOPE.md §9.2). A NULL is destruction, not migration
            # 002's gap. Present nothing instead and it is UNVERIFIABLE again —
            # asserted below, because the conviction must come from the material.
            with raw_transaction(sub) as conn:
                referents = store_referents(conn, label="open project")
                result = verify_event_result_with_public_key(
                    evt_no_env, pub_bytes, referents=referents,
                )
                assert result.applicability is Applicability.INVALID
                assert FailureReason.ENVELOPE_ABSENT in result.reasons
                assert not result.accepted

                unpresented = verify_event_result_with_public_key(
                    evt_no_env, pub_bytes,
                )
                assert unpresented.applicability is Applicability.UNVERIFIABLE
                assert FailureReason.ENVELOPE_ABSENT in unpresented.reasons
                assert not unpresented.accepted

                # The same event WITH its envelope still verifies.
                assert verify_event_result_with_public_key(
                    evt, pub_bytes, scheme_id="ed25519", referents=referents,
                ).ok


@skip_no_nacl
class TestStrictAsymmetric:
    def test_rejects_hmac_fallback(self, tmp_path):
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "hmac-001",
                    "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
                    "status": "active",
                    "scheme": "hmac-sha256",
                },
            ]
        })
        ks = KeySet(kf, strict_asymmetric=True)
        with pytest.raises(RegistaError) as exc_info:
            ks.resolve_signing_key("unknown-actor")
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_rejects_ed25519_without_principal_binding(self, tmp_path):
        secret_b64, pub_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-001",
                    "secret": secret_b64,
                    "public_key": pub_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                },
            ]
        })
        ks = KeySet(kf, strict_asymmetric=True)
        with pytest.raises(RegistaError) as exc_info:
            ks.resolve_signing_key("alice")
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_rejects_ed25519_with_wrong_principal(self, tmp_path):
        secret_b64, pub_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-alice",
                    "secret": secret_b64,
                    "public_key": pub_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                },
            ]
        })
        ks = KeySet(kf, strict_asymmetric=True)
        with pytest.raises(RegistaError) as exc_info:
            ks.resolve_signing_key("bob")
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_accepts_matching_principal_ed25519(self, tmp_path):
        secret_b64, pub_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-alice",
                    "secret": secret_b64,
                    "public_key": pub_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                },
            ]
        })
        ks = KeySet(kf, strict_asymmetric=True)
        entry = ks.resolve_signing_key("alice")
        assert entry.key_id == "ed-alice"
        assert entry.scheme == "ed25519"

    def test_rejects_explicit_hmac_key_in_strict_mode(self, tmp_path):
        secret_b64, pub_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "hmac-001",
                    "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
                    "status": "active",
                    "scheme": "hmac-sha256",
                },
                {
                    "key_id": "ed-alice",
                    "secret": secret_b64,
                    "public_key": pub_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                },
            ]
        })
        ks = KeySet(kf, strict_asymmetric=True)
        with pytest.raises(RegistaError) as exc_info:
            ks.resolve_signing_key("alice", key_id="hmac-001")
        assert exc_info.value.code == ErrorCode.KEY_ROLE_NOT_PERMITTED
        assert "asymmetric" in str(exc_info.value).lower()

    def test_rejects_explicit_ed25519_wrong_principal(self, tmp_path):
        sk1_b64, pk1_b64 = _gen_ed25519_keypair_b64()
        sk2_b64, pk2_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-alice",
                    "secret": sk1_b64,
                    "public_key": pk1_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                },
                {
                    "key_id": "ed-bob",
                    "secret": sk2_b64,
                    "public_key": pk2_b64,
                    "encoding": "base64",
                    "status": "active",
                    "scheme": "ed25519",
                    "principal_id": "bob",
                },
            ]
        })
        ks = KeySet(kf, strict_asymmetric=True)
        with pytest.raises(RegistaError) as exc_info:
            ks.resolve_signing_key("alice", key_id="ed-bob")
        assert exc_info.value.code == ErrorCode.KEY_ROLE_NOT_PERMITTED

    def test_strict_asymmetric_end_to_end_in_memory(self, tmp_path):
        sub, keyset = _v6_in_memory(tmp_path, strict_asymmetric=True)

        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ALICE,
            custom_fields={"title": "strict mode"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        assert events[-1].key_id == keyset.key_for(ALICE).key_id
        assert events[-1].scheme_id == "ed25519"

        sub.transition(wi.work_item_id, "start", BOB, actor_metadata={"role": "agent"})
        events = sub.read_events(work_item_id=wi.work_item_id)
        start_evt = next(e for e in events if e.transition == "start")
        assert start_evt.key_id == keyset.key_for(BOB).key_id

    def test_strict_asymmetric_rejects_unbound_actor_in_memory(self, tmp_path):
        from regista.testing import InMemoryRegista
        from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

        # An HMAC key sits alongside the actor keys precisely so strict mode has
        # something to refuse: `agent:charlie` has no Ed25519 key bound to it, and in
        # permissive mode `resolve_signing_key` would fall back to `hmac-001`.
        keyset = make_v6_keyset(tmp_path)
        _add_hmac_key(keyset.path)
        sub = InMemoryRegista(
            project="test", hmac_key_path=keyset.path,
            strict_asymmetric=True,
        )
        open_v6_epoch(sub, keyset)
        sub.register_workflow_file(WORKFLOW_PATH)
        with pytest.raises(RegistaError) as exc_info:
            sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id="agent:charlie",
                custom_fields={"title": "should fail"},
            )
        assert exc_info.value.code == ErrorCode.UNKNOWN_KEY_ID

    def test_strict_asymmetric_postgres(self, tmp_path):
        with _v6_postgres(tmp_path, "test_p3s", strict_asymmetric=True) as (sub, keyset):
            wi, _ = sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id=ALICE,
                custom_fields={"title": "pg strict"},
            )
            events = sub.read_events(work_item_id=wi.work_item_id)
            assert events[-1].key_id == keyset.key_for(ALICE).key_id
            assert events[-1].scheme_id == "ed25519"

            report = sub.replay()
            assert report.halted == 0

    def test_strict_asymmetric_disabled_by_default(self, tmp_path):
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "hmac-001",
                    "secret": "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0IGtleSBmb3Igc3Vic3RyYXRl",
                    "status": "active",
                    "scheme": "hmac-sha256",
                },
            ]
        })
        ks = KeySet(kf)
        entry = ks.resolve_signing_key("any-actor")
        assert entry.scheme == "hmac-sha256"


@skip_no_nacl
class TestRevocation:
    def test_revoked_key_prevents_new_signing(self, tmp_path):
        sk_b64, pk_b64 = _gen_ed25519_keypair_b64()
        kf = _write_keys(tmp_path, {
            "keys": [
                {
                    "key_id": "ed-alice",
                    "secret": sk_b64,
                    "public_key": pk_b64,
                    "encoding": "base64",
                    "status": "revoked",
                    "scheme": "ed25519",
                    "principal_id": "alice",
                    "revoked_at": "2026-01-01T00:00:00+00:00",
                },
            ]
        })
        ks = KeySet(kf)
        with pytest.raises(RegistaError) as exc_info:
            ks.resolve_signing_key("alice")
        assert exc_info.value.code == ErrorCode.REVOKED_KEY_ID

    def test_revoked_key_still_verifies_in_replay(self, tmp_path):
        sub, keyset = _v6_in_memory(tmp_path)

        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ALICE,
            custom_fields={"title": "before revocation"},
        )

        report = sub.replay()
        assert report.halted == 0

        from regista._keys import KeySet as _KeySet

        key_entry = _KeySet(keyset.path).get_key(keyset.key_for(ALICE).key_id)
        assert key_entry.status == "active"

        assert sub.verify_event_signature(
            sub.read_events(work_item_id=wi.work_item_id)[-1]
        ) is True

    def test_replay_continue_on_revoked(self, tmp_path):
        sub, _keyset = _v6_in_memory(tmp_path)

        sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=ALICE,
            custom_fields={"title": "continue on revoked"},
        )

        report = sub.replay(continue_on_revoked=True)
        assert report.halted == 0


@skip_no_nacl
class TestPostgresFullLifecycle:
    def test_full_lifecycle_strict_asymmetric(self, tmp_path):
        with _v6_postgres(tmp_path, "test_p3l", strict_asymmetric=True) as (sub, keyset):
            wi, _ = sub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id=ALICE,
                custom_fields={"title": "lifecycle"},
            )
            sub.transition(
                wi.work_item_id, "start", ALICE,
                actor_metadata={"role": "agent"},
            )
            sub.transition(
                wi.work_item_id, "submit_review", ALICE,
                actor_metadata={"role": "agent"},
            )

            events = sub.read_events(work_item_id=wi.work_item_id)
            assert all(e.scheme_id == "ed25519" for e in events)

            assert all(e.key_id == keyset.key_for(ALICE).key_id for e in events)

            public_keys = sub.export_public_keys()
            # Every key in the keyset is exported, and nothing else — the same
            # claim the pre-migration `== 2` made against a two-key fixture. The
            # v6 keyset carries one actor key per accepted principal plus the
            # bootstrap key, so the count is read off the keyset rather than
            # hardcoded.
            assert len(public_keys) == len(keyset.keys)
            alice_pub = next(k for k in public_keys if k["principal_id"] == ALICE)
            pub_bytes = base64.b64decode(alice_pub["public_key"])

            for evt in events:
                assert sub.verify_event_signature(evt, public_key=pub_bytes) is True

            report = sub.replay()
            assert report.halted == 0
            assert report.replayed_drift == 0
