from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from regista._signing import (
    build_signing_envelope,
    build_signing_envelope_v2,
    build_signing_envelope_v3,
    build_signing_envelope_v4,
    build_signing_envelope_v5,
    classify_envelope_version,
    verify_event_result,
)
from regista._signing_scheme import HMACSHA256Scheme
from regista._testing import KeySet, sign_event, verify_event
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


#: Canonical per TRUST-DOMAIN.md §2.1 — the v6 ingress refuses a bare legacy name.
#: Only the `regista` fixture below is on the clean epoch; the envelope-version unit
#: tests in this file drive `_signing` directly and keep their legacy actor strings.
WORKER = "agent:worker"


@pytest.fixture
def regista(tmp_path):
    from regista import Regista
    from tests._v6_fixtures import make_v6_keyset, open_v6_epoch

    project = f"test_sign_{uuid.uuid4().hex[:8]}"
    keyset = make_v6_keyset(tmp_path)
    sub = Regista.create_project(DSN, project, keyset.path)
    # The epoch first: `register_workflow_file` emits the signed
    # `workflow_registered` event admission gate 1 requires, and there is no
    # epoch to append it to before `open_v6_epoch` returns.
    open_v6_epoch(sub, keyset)
    sub.register_workflow_file(WORKFLOW_PATH)
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


class TestAC26JsonbDriftSurvival:
    def test_canonical_envelope_stored_on_append(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "AC-26 envelope"},
        )

        events = regista.read_events(work_item_id=wi.work_item_id)
        for evt in events:
            assert evt.canonical_envelope is not None
            assert len(evt.canonical_envelope) > 0

    def test_replay_succeeds_after_events(self, regista):
        wi, _ = regista.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id=WORKER,
            custom_fields={"title": "AC-26 replay"},
        )
        regista.append_event(
            work_item_id=wi.work_item_id,
            actor_id=WORKER,
            transition="custom_event",
            payload={"nested": {"key": "value"}},
        )

        report = regista.replay()
        assert report.replayed_drift == 0
        assert report.halted == 0


class TestDowngradeEnvelopeFiltering:
    def test_verify_rejects_downgrade_when_stored_v4(self):
        key_set = KeySet(KEY_PATH)
        key_entry = key_set.active_key()
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime.now(UTC)
        payload = {"foo": "bar"}

        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            key=key_entry.secret,
        )

        assert classify_envelope_version(envelope) == 4
        assert verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=envelope,
        )

        tampered_envelope = build_signing_envelope_v4(
            event_id=event_id,
            entity_kind="work_item",
            entity_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            hash_alg="sha-256",
            transition="t",
            payload={"foo": "tampered"},
        )
        assert not verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload={"foo": "tampered"},
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=tampered_envelope,
        )

    def test_missing_stored_envelope_is_unverifiable_not_rebuilt(self):
        """WI-267: candidate rebuilding is deleted, not disabled.

        This test used to assert the opposite — that a v1-signed event with NO
        stored envelope verifies because ``verify_event`` rebuilds candidates
        from the row columns. Those candidates are built from the very columns
        an attacker rewrites, so the fallback was the escape hatch S1 removes.
        A row with no envelope is now ``unverifiable``: nothing failed, there is
        nothing to check, and reconstructing the envelope is an explicit offline
        operator action (CUTOVER-POLICY §4), never something the verify path
        does on the fly.
        """
        from regista._verification import Applicability, FailureReason

        key_set = KeySet(KEY_PATH)
        key_entry = key_set.active_key()
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime.now(UTC)
        payload = {"foo": "bar"}
        scheme = HMACSHA256Scheme()

        legacy_envelope = build_signing_envelope(
            event_id, work_item_id, "actor-1", "t", payload, None,
        )
        legacy_signature, legacy_canonical_hash = scheme.sign(
            legacy_envelope, key_entry.secret,
        )

        kwargs = dict(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            signature=legacy_signature,
            canonical_hash=legacy_canonical_hash,
            key=key_entry.secret,
            stored_envelope=None,
        )
        assert not verify_event(**kwargs)

        result = verify_event_result(**kwargs)
        assert result.applicability is Applicability.UNVERIFIABLE
        assert FailureReason.ENVELOPE_ABSENT in result.reasons
        assert result.mismatched_fields == ()

    def test_stored_envelope_corruption_is_not_rescued_by_a_rebuild(self):
        """A corrupted stored envelope must not fall through to a row rebuild."""
        from regista._verification import Applicability

        key_set = KeySet(KEY_PATH)
        key_entry = key_set.active_key()
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime.now(UTC)
        payload = {"foo": "bar"}

        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            key=key_entry.secret,
            actor_kind="agent",
            actor_metadata={"role": "dev"},
        )

        kwargs = dict(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            actor_kind="agent",
            actor_metadata={"role": "dev"},
        )

        # Byte-level corruption of the stored envelope. Every row column still
        # holds exactly the value that was signed, so the OLD code would rebuild
        # a v5 candidate from the row and report success.
        corrupted = bytearray(envelope)
        corrupted[10] ^= 0xFF
        result = verify_event_result(stored_envelope=bytes(corrupted), **kwargs)
        assert result.applicability is Applicability.INVALID
        assert not verify_event(stored_envelope=bytes(corrupted), **kwargs)

        # Truncation: not parseable JSON at all.
        result = verify_event_result(stored_envelope=envelope[:20], **kwargs)
        assert result.applicability is Applicability.INVALID
        assert not verify_event(stored_envelope=envelope[:20], **kwargs)

    def test_verify_v4_event_does_not_match_v3_envelope(self):
        key_set = KeySet(KEY_PATH)
        key_entry = key_set.active_key()
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime.now(UTC)
        payload = {"foo": "bar"}
        prev_event_hash = b"\x00" * 32
        global_seq = 7
        prev_global_event_hash = b"\x11" * 32

        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            key=key_entry.secret,
            prev_event_hash=prev_event_hash,
            global_seq=global_seq,
            prev_global_event_hash=prev_global_event_hash,
        )

        assert classify_envelope_version(envelope) == 4

        v3_envelope = build_signing_envelope_v3(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            prev_event_hash=prev_event_hash,
            global_seq=global_seq,
            prev_global_event_hash=prev_global_event_hash,
        )
        assert classify_envelope_version(v3_envelope) == 3

        assert not verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=v3_envelope,
        )

    def test_classify_envelope_version_correct(self):
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime.now(UTC)
        prev_event_hash = b"\x00" * 32
        global_seq = 7
        prev_global_event_hash = b"\x11" * 32

        v1_envelope = build_signing_envelope(
            event_id, work_item_id, "actor-1", "t", {"x": 1}, None,
        )
        assert classify_envelope_version(v1_envelope) == 1

        v2_envelope = build_signing_envelope_v2(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id="k1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload={"x": 1},
        )
        assert classify_envelope_version(v2_envelope) == 2

        v3_envelope = build_signing_envelope_v3(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id="k1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload={"x": 1},
        )
        assert classify_envelope_version(v3_envelope) == 2

        v3_chain_envelope = build_signing_envelope_v3(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id="k1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload={"x": 1},
            prev_event_hash=prev_event_hash,
            global_seq=global_seq,
            prev_global_event_hash=prev_global_event_hash,
        )
        assert classify_envelope_version(v3_chain_envelope) == 3

        v4_envelope = build_signing_envelope_v4(
            event_id=event_id,
            entity_kind="work_item",
            entity_id=work_item_id,
            actor_id="actor-1",
            key_id="k1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            hash_alg="sha-256",
            transition="t",
            payload={"x": 1},
        )
        assert classify_envelope_version(v4_envelope) == 4

        v4_chain_envelope = build_signing_envelope_v4(
            event_id=event_id,
            entity_kind="work_item",
            entity_id=work_item_id,
            actor_id="actor-1",
            key_id="k1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            hash_alg="sha-256",
            transition="t",
            payload={"x": 1},
            prev_event_hash=prev_event_hash,
            global_seq=global_seq,
            prev_global_event_hash=prev_global_event_hash,
        )
        assert classify_envelope_version(v4_chain_envelope) == 4

        v5_envelope = build_signing_envelope_v5(
            event_id=event_id,
            entity_kind="work_item",
            entity_id=work_item_id,
            actor_id="actor-1",
            actor_kind="agent",
            actor_metadata={"role": "developer"},
            key_id="k1",
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            hash_alg="sha-256",
            transition="t",
            payload={"x": 1},
            prev_event_hash=prev_event_hash,
            global_seq=global_seq,
            prev_global_event_hash=prev_global_event_hash,
        )
        assert classify_envelope_version(v5_envelope) == 5


class TestEnvelopeV5:
    """WI-208: actor_kind/actor_metadata are now signed fields (envelope v5)."""

    @pytest.fixture
    def key_set(self):
        return KeySet(KEY_PATH)

    @pytest.fixture
    def key_entry(self, key_set):
        return key_set.active_key()

    def test_v5_sign_and_verify_roundtrip(self, key_entry):
        """A v5-signed event verifies correctly with actor_kind/actor_metadata."""
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime(2026, 1, 1, tzinfo=UTC)
        payload = {"action": "create"}
        actor_metadata = {"role": "developer", "channel": "cli"}

        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="create",
            payload=payload,
            key=key_entry.secret,
            actor_kind="agent",
            actor_metadata=actor_metadata,
        )

        assert classify_envelope_version(envelope) == 5

        assert verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="create",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=envelope,
            actor_kind="agent",
            actor_metadata=actor_metadata,
        )

    def test_v5_tampered_actor_kind_fails_verification(self, key_entry):
        """Changing actor_kind after signing must invalidate the signature."""
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime(2026, 1, 1, tzinfo=UTC)
        payload = {"action": "approve"}

        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="approve",
            payload=payload,
            key=key_entry.secret,
            actor_kind="agent",
            actor_metadata={"role": "bot"},
        )

        # The stored envelope is v5 — verification with a DIFFERENT actor_kind
        # must fail because the stored envelope is the canonical truth.
        assert not verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="approve",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=envelope,
            actor_kind="human",  # TAMPERED
            actor_metadata={"role": "bot"},
        )

    def test_v5_tampered_actor_metadata_fails_verification(self, key_entry):
        """Changing actor_metadata after signing must invalidate the signature."""
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime(2026, 1, 1, tzinfo=UTC)
        payload = {"action": "merge"}

        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="merge",
            payload=payload,
            key=key_entry.secret,
            actor_kind="human",
            actor_metadata={"role": "reviewer"},
        )

        assert not verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="merge",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=envelope,
            actor_kind="human",
            actor_metadata={"role": "admin"},  # TAMPERED
        )

    def test_v5_backward_compat_v4_events_still_verify(self, key_entry):
        """Events signed with v4 (no actor_kind) must still verify."""
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime(2026, 1, 1, tzinfo=UTC)
        payload = {"action": "create"}

        # Sign without actor_kind → uses v4 envelope
        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="create",
            payload=payload,
            key=key_entry.secret,
        )

        assert classify_envelope_version(envelope) == 4

        # Verify without actor_kind → should try v4 candidate
        assert verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="create",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=envelope,
        )

    def test_v5_downgrade_filtering(self, key_entry):
        """A v5 stored envelope must not verify against a v4 candidate."""
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime(2026, 1, 1, tzinfo=UTC)
        payload = {"x": 1}
        actor_metadata = {"role": "dev"}

        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            key=key_entry.secret,
            prev_event_hash=b"\x00" * 32,
            global_seq=1,
            prev_global_event_hash=b"\x01" * 32,
            actor_kind="agent",
            actor_metadata=actor_metadata,
        )

        assert classify_envelope_version(envelope) == 5

        # Verification with the v5 stored envelope + correct fields → OK
        assert verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=envelope,
            prev_event_hash=b"\x00" * 32,
            global_seq=1,
            prev_global_event_hash=b"\x01" * 32,
            actor_kind="agent",
            actor_metadata=actor_metadata,
        )

        # WI-267: omitting actor_kind no longer skips the check. This test
        # used to assert the opposite and documented the reason as
        # "backward-compatible path for callers that don't pass actor_kind" —
        # i.e. a caller could describe a row without actor_kind and have a v5
        # envelope that signs actor_kind="agent" accepted anyway. The arguments
        # describe the row; a row with no actor_kind disagrees with the signed
        # bytes, and disagreement is INVALID.
        result = verify_event_result(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=envelope,
            prev_event_hash=b"\x00" * 32,
            global_seq=1,
            prev_global_event_hash=b"\x01" * 32,
            # actor_kind deliberately not provided
        )
        assert not result.accepted
        assert "actor_kind" in result.mismatched_field_names

    def test_v5_with_none_actor_metadata(self, key_entry):
        """v5 with actor_metadata=None should sign and verify correctly."""
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime(2026, 1, 1, tzinfo=UTC)
        payload = {"action": "system_op"}

        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="system-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="system_op",
            payload=payload,
            key=key_entry.secret,
            actor_kind="system",
            actor_metadata=None,
        )

        assert classify_envelope_version(envelope) == 5

        assert verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="system-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="system_op",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=envelope,
            actor_kind="system",
            actor_metadata=None,
        )

    def test_v5_none_vs_empty_dict_actor_metadata_differ(self, key_entry):
        """None and {} produce different envelopes (JCS: null vs {})."""
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime(2026, 1, 1, tzinfo=UTC)
        common = dict(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="t",
            payload={"x": 1},
            key=key_entry.secret,
            actor_kind="agent",
        )

        _sig_none, hash_none, env_none = sign_event(actor_metadata=None, **common)
        _sig_empty, hash_empty, env_empty = sign_event(actor_metadata={}, **common)

        assert env_none != env_empty
        assert hash_none != hash_empty

    def test_v4_event_verified_with_actor_kind_provided(self, key_entry):
        """A v4 event should still verify even if actor_kind is provided to verify_event."""
        event_id = uuid.uuid4()
        work_item_id = uuid.uuid4()
        timestamp = datetime(2026, 1, 1, tzinfo=UTC)
        payload = {"action": "create"}

        # Sign without actor_kind → uses v4 envelope
        signature, canonical_hash, envelope = sign_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="create",
            payload=payload,
            key=key_entry.secret,
        )

        assert classify_envelope_version(envelope) == 4

        # Verify WITH actor_kind provided — should still pass via v4 candidate
        # (the v5 candidate won't match, but the v4 candidate will)
        assert verify_event(
            event_id=event_id,
            work_item_id=work_item_id,
            actor_id="actor-1",
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=timestamp,
            transition="create",
            payload=payload,
            signature=signature,
            canonical_hash=canonical_hash,
            key=key_entry.secret,
            stored_envelope=envelope,
            actor_kind="agent",
            actor_metadata={"role": "dev"},
        )
