"""WI-267 — authenticate the row, not just the envelope.

The defect: ``verify_event()`` verified the stored ``canonical_envelope`` bytes
and returned as soon as they verified. Only ``actor_kind``/``actor_metadata``
were reconciled against it, and only on v5 (WI-208). Every consumer then read
the **unsigned row columns**, so a database-write attacker could rewrite
``transition``, ``payload``, ``timestamp``, ``event_seq``, ``prev_event_hash``,
``on_behalf_of``, ``key_id``, ``entity_id`` or ``workflow_name``/``version`` in
the row and everything still verified.

Every test here fails against the unfixed code.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from regista._jcs import canonicalize
from regista._replay import _requires_principal_registration
from regista._signing import (
    _verify_principal_binding_core,
    build_signing_envelope,
    build_signing_envelope_v2,
    build_signing_envelope_v3,
    build_signing_envelope_v4,
    build_signing_envelope_v5,
    classify_envelope_version,
    sign_event,
)
from regista._signing_scheme import HMACSHA256Scheme
from regista._testing import KeySet
from regista._verification import (
    AbsentEnvelopeProbe,
    Applicability,
    Backend,
    EnvelopeVersion,
    EventRow,
    FailureReason,
    FieldMismatch,
    StaticKeyResolver,
    TrustedKeySource,
    VerificationPolicy,
    VerificationResult,
    classify_envelope,
    parse_envelope_strict,
    probe_absent_envelope,
    verify_event_strict,
)
from regista.testing import drop_project_schema

TESTS_DIR = Path(__file__).parent
DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(TESTS_DIR / "test_keys.json")
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")

_LEGACY_ALL = VerificationPolicy(
    accept_legacy_versions=frozenset(
        {
            EnvelopeVersion.V1,
            EnvelopeVersion.V2,
            EnvelopeVersion.V3,
            EnvelopeVersion.V4,
        }
    ),
)


@pytest.fixture
def regista():
    from regista import Regista

    project = f"test_wi267_{uuid.uuid4().hex[:8]}"
    sub = Regista.create_project(DSN, project, KEY_PATH)
    sub.register_workflow_file(WORKFLOW_PATH)
    sub.register_actor_role("agent-1", "agent")
    yield sub
    sub.close()
    drop_project_schema(DSN, project)


@pytest.fixture
def key_entry():
    return KeySet(KEY_PATH).active_key()


def _resolver(key_entry, scheme_id: str = "hmac-sha256"):
    return StaticKeyResolver(
        material=key_entry.secret,
        scheme_id=scheme_id,
        source=TrustedKeySource.KEYSET_FILE,
    )


def _v5_row(key_entry, **overrides):
    """A signed v5 event and the row that honestly projects it."""
    event_id = overrides.pop("event_id", uuid.uuid4())
    entity_id = overrides.pop("entity_id", uuid.uuid4())
    ts = overrides.pop("timestamp", datetime(2026, 3, 1, 12, 0, tzinfo=UTC))
    payload = overrides.pop("payload", {"title": "row auth", "n": 3})
    actor_metadata = overrides.pop("actor_metadata", {"role": "developer"})
    on_behalf_of = overrides.pop("on_behalf_of", {"principal_id": "alice"})
    prev_event_hash = overrides.pop("prev_event_hash", b"\xab" * 32)
    prev_global = overrides.pop("prev_global_event_hash", b"\xcd" * 32)

    signature, canonical_hash, envelope = sign_event(
        event_id=event_id,
        work_item_id=entity_id,
        actor_id="agent-1",
        key_id=key_entry.key_id,
        event_seq=7,
        workflow_name="test_workflow",
        workflow_version=1,
        timestamp=ts,
        transition="start",
        payload=payload,
        key=key_entry.secret,
        on_behalf_of=on_behalf_of,
        prev_event_hash=prev_event_hash,
        prev_global_event_hash=prev_global,
        entity_kind="work_item",
        hash_alg="sha-256",
        actor_kind="agent",
        actor_metadata=actor_metadata,
    )
    assert classify_envelope_version(envelope) == 5

    row = EventRow(
        event_id=event_id,
        work_item_id=entity_id,
        entity_kind="work_item",
        entity_id=entity_id,
        actor_id="agent-1",
        actor_kind="agent",
        actor_metadata=actor_metadata,
        key_id=key_entry.key_id,
        event_seq=7,
        workflow_name="test_workflow",
        workflow_version=1,
        timestamp=ts,
        hash_alg="sha-256",
        on_behalf_of=on_behalf_of,
        transition="start",
        payload=payload,
        prev_event_hash=prev_event_hash,
        prev_global_event_hash=prev_global,
        global_seq=42,
        canonical_envelope=envelope,
        signature=signature,
        payload_canonical_hash=canonical_hash,
        row_scheme_id="hmac-sha256",
    )
    return dataclasses.replace(row, **overrides) if overrides else row


def _v4_row(key_entry):
    event_id = uuid.uuid4()
    entity_id = uuid.uuid4()
    ts = datetime(2026, 2, 1, 9, 30, tzinfo=UTC)
    payload = {"legacy": True}
    signature, canonical_hash, envelope = sign_event(
        event_id=event_id,
        work_item_id=entity_id,
        actor_id="agent-1",
        key_id=key_entry.key_id,
        event_seq=2,
        workflow_name="test_workflow",
        workflow_version=1,
        timestamp=ts,
        transition="start",
        payload=payload,
        key=key_entry.secret,
        on_behalf_of=None,
        entity_kind="work_item",
        hash_alg="sha-256",
        # actor_kind omitted -> v4
    )
    assert classify_envelope_version(envelope) == 4
    return EventRow(
        event_id=event_id,
        work_item_id=entity_id,
        entity_kind="work_item",
        entity_id=entity_id,
        actor_id="agent-1",
        actor_kind="human",  # unsigned in v4 — the row may say anything
        actor_metadata={"anything": "at all"},
        key_id=key_entry.key_id,
        event_seq=2,
        workflow_name="test_workflow",
        workflow_version=1,
        timestamp=ts,
        hash_alg="sha-256",
        on_behalf_of=None,
        transition="start",
        payload=payload,
        prev_event_hash=None,
        prev_global_event_hash=None,
        global_seq=11,
        canonical_envelope=envelope,
        signature=signature,
        payload_canonical_hash=canonical_hash,
        row_scheme_id="hmac-sha256",
    )


# ---------------------------------------------------------------------------
# 1. The mutation matrix
# ---------------------------------------------------------------------------


#: (field name reported in mismatched_fields, row attribute, tampered value).
#: EVERY field a v5 envelope reconciles is here. A field missing from this list
#: is a field an attacker may rewrite unnoticed.
_V5_MUTATIONS: list[tuple[str, str, object]] = [
    ("event_id", "event_id", uuid.UUID("00000000-0000-4000-8000-000000000001")),
    ("entity_kind", "entity_kind", "segment"),
    ("entity_id", "entity_id", uuid.UUID("00000000-0000-4000-8000-000000000002")),
    ("actor_id", "actor_id", "attacker-1"),
    ("actor_kind", "actor_kind", "human"),
    ("actor_metadata", "actor_metadata", {"role": "admin"}),
    ("key_id", "key_id", "some-other-key"),
    ("event_seq", "event_seq", 8),
    ("workflow_name", "workflow_name", "other_workflow"),
    ("workflow_version", "workflow_version", 2),
    ("timestamp", "timestamp", datetime(2026, 3, 1, 13, 0, tzinfo=UTC)),
    ("hash_alg", "hash_alg", "sha-512"),
    ("on_behalf_of", "on_behalf_of", {"principal_id": "bob"}),
    ("transition", "transition", "approve"),
    ("payload", "payload", {"title": "row auth", "n": 4}),
    ("prev_event_hash", "prev_event_hash", b"\x99" * 32),
    ("prev_global_event_hash", "prev_global_event_hash", b"\x88" * 32),
]


class TestMutationMatrix:
    """Every reconciled field, rewritten in the row, named in the failure."""

    @pytest.mark.parametrize(
        ("field", "attr", "value"),
        _V5_MUTATIONS,
        ids=[m[0] for m in _V5_MUTATIONS],
    )
    def test_row_rewrite_is_detected_and_named(self, key_entry, field, attr, value):
        row = _v5_row(key_entry)
        assert getattr(row, attr) != value, "the mutation must actually change something"

        tampered = dataclasses.replace(row, **{attr: value})
        result = verify_event_strict(tampered, keys=_resolver(key_entry))

        assert result.applicability is Applicability.INVALID
        assert not result.ok and not result.accepted
        # The signature over the stored envelope is still perfectly valid —
        # that is precisely why this had to be caught by reconciliation.
        assert result.signature_valid is True
        assert result.row_reconciled is False
        assert FailureReason.ROW_FIELD_MISMATCH in result.reasons
        assert field in result.mismatched_field_names, result.mismatched_field_names

    def test_nulling_a_signed_chain_link_is_a_presence_mismatch(self, key_entry):
        row = _v5_row(key_entry)
        tampered = dataclasses.replace(row, prev_event_hash=None)
        result = verify_event_strict(tampered, keys=_resolver(key_entry))
        assert result.applicability is Applicability.INVALID
        mismatch = next(
            m for m in result.mismatched_fields if m.field == "prev_event_hash"
        )
        assert mismatch.presence_only is True

    def test_adding_an_unsigned_chain_link_is_a_presence_mismatch(self, key_entry):
        """A row that GAINS a link the envelope omitted is tamper, not an upgrade."""
        row = _v5_row(key_entry, prev_event_hash=None)
        assert b"prev_event_hash" not in row.canonical_envelope
        tampered = dataclasses.replace(row, prev_event_hash=b"\x77" * 32)
        result = verify_event_strict(tampered, keys=_resolver(key_entry))
        assert result.applicability is Applicability.INVALID
        mismatch = next(
            m for m in result.mismatched_fields if m.field == "prev_event_hash"
        )
        assert mismatch.presence_only is True

    def test_work_item_id_entity_id_alias_break_is_detected(self, key_entry):
        """``work_item_id`` is unsigned from v4 on; only the alias check binds it.

        Migration 031 made ``entity_id`` the derived column and the signature
        covers it, leaving the ORIGINAL ``work_item_id`` column unauthenticated.
        Without this check the unsigned column steers a consumer to a different
        work item than the one the signature covers.
        """
        row = _v5_row(key_entry)
        tampered = dataclasses.replace(row, work_item_id=uuid.uuid4())
        result = verify_event_strict(tampered, keys=_resolver(key_entry))
        assert result.applicability is Applicability.INVALID
        assert "work_item_id!=entity_id" in result.mismatched_field_names
        assert FailureReason.ENTITY_ALIAS_MISMATCH in result.reasons

    def test_key_id_rewrite_reports_a_mismatch_not_an_unknown_key(self, key_entry):
        """The key is resolved from the ENVELOPE's key_id, not the row's."""
        row = _v5_row(key_entry)
        tampered = dataclasses.replace(row, key_id="not-a-real-key")
        result = verify_event_strict(tampered, keys=_resolver(key_entry))
        assert result.applicability is Applicability.INVALID
        assert "key_id" in result.mismatched_field_names
        assert FailureReason.KEY_ID_MISMATCH in result.reasons
        # Not "I could not find a key" — the signature verified under the key
        # the envelope names, and the ROW is what disagrees.
        assert FailureReason.KEY_UNRESOLVABLE not in result.reasons
        assert result.signature_valid is True

    def test_every_reconciled_field_is_covered_by_this_matrix(self, key_entry):
        """Guard: a new signed field must arrive with a mutation test."""
        row = _v5_row(key_entry)
        result = verify_event_strict(row, keys=_resolver(key_entry))
        covered = {m[0] for m in _V5_MUTATIONS}
        # global_seq is unsigned by design and is asserted separately.
        assert result.authenticated_fields - covered == set(), (
            "authenticated but never mutation-tested: "
            f"{result.authenticated_fields - covered}"
        )


class TestGlobalSeqIsUnsignedByDesign:
    """``global_seq`` is assigned post-signing (spec.md §17.11)."""

    def test_global_seq_rewrite_is_not_a_mismatch(self, key_entry):
        row = _v5_row(key_entry)
        assert b"global_seq" not in row.canonical_envelope
        tampered = dataclasses.replace(row, global_seq=999_999)
        result = verify_event_strict(tampered, keys=_resolver(key_entry))
        assert result.ok
        assert result.mismatched_fields == ()

    def test_global_seq_is_never_authenticated(self, key_entry):
        result = verify_event_strict(_v5_row(key_entry), keys=_resolver(key_entry))
        assert "global_seq" not in result.authenticated_fields
        assert "global_seq" in result.unsigned_fields

    def test_a_signed_global_seq_still_has_to_agree(self, key_entry):
        """No writer emits it, but if a stored envelope carries it, it binds."""
        event_id = uuid.uuid4()
        entity_id = uuid.uuid4()
        ts = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
        envelope = build_signing_envelope_v5(
            event_id=event_id,
            entity_kind="work_item",
            entity_id=entity_id,
            actor_id="agent-1",
            actor_kind="agent",
            actor_metadata=None,
            key_id=key_entry.key_id,
            event_seq=1,
            workflow_name="wf",
            workflow_version=1,
            timestamp=ts,
            hash_alg="sha-256",
            transition="start",
            payload=None,
            global_seq=5,
        )
        sig, chash = HMACSHA256Scheme().sign(envelope, key_entry.secret)
        row = EventRow(
            event_id=event_id, work_item_id=entity_id, entity_kind="work_item",
            entity_id=entity_id, actor_id="agent-1", actor_kind="agent",
            actor_metadata=None, key_id=key_entry.key_id, event_seq=1,
            workflow_name="wf", workflow_version=1, timestamp=ts,
            hash_alg="sha-256", on_behalf_of=None, transition="start",
            payload=None, prev_event_hash=None, prev_global_event_hash=None,
            global_seq=5, canonical_envelope=envelope, signature=sig,
            payload_canonical_hash=chash, row_scheme_id="hmac-sha256",
        )
        assert verify_event_strict(row, keys=_resolver(key_entry)).ok
        tampered = dataclasses.replace(row, global_seq=6)
        bad = verify_event_strict(tampered, keys=_resolver(key_entry))
        assert bad.applicability is Applicability.INVALID
        assert "global_seq" in bad.mismatched_field_names
        # ...and it is STILL not claimed as authenticated.
        assert "global_seq" not in bad.authenticated_fields


class TestNegativeControls:
    def test_honest_v5_event_is_fully_authenticated(self, key_entry):
        result = verify_event_strict(_v5_row(key_entry), keys=_resolver(key_entry))
        assert result.applicability is Applicability.FULLY_AUTHENTICATED
        assert result.ok and result.accepted
        assert result.mismatched_fields == ()
        assert result.row_reconciled is True
        assert result.envelope_version is EnvelopeVersion.V5
        assert result.trusted_key_source is TrustedKeySource.KEYSET_FILE
        for name in (
            "transition", "payload", "actor_id", "actor_kind", "actor_metadata",
            "timestamp", "event_seq", "key_id", "entity_id", "workflow_name",
            "workflow_version", "on_behalf_of", "prev_event_hash",
            "prev_global_event_hash", "hash_alg", "entity_kind", "event_id",
        ):
            assert name in result.authenticated_fields, name

    def test_honest_v4_event_is_legacy_partial_and_names_what_it_did_not_sign(
        self, key_entry,
    ):
        result = verify_event_strict(_v4_row(key_entry), keys=_resolver(key_entry))
        assert result.applicability is Applicability.LEGACY_PARTIAL
        assert result.accepted is True
        assert result.ok is False, "legacy is never `ok`"
        assert result.mismatched_fields == ()
        assert {"actor_kind", "actor_metadata"} <= result.unsigned_fields
        assert {"global_seq", "scheme_id", "work_item_id"} <= result.unsigned_fields
        assert "actor_kind" not in result.authenticated_fields
        assert result.legacy_reason and "actor_kind" in result.legacy_reason

    def test_v4_row_field_the_version_does_sign_still_fails(self, key_entry):
        """Legacy is never reachable from a mismatch."""
        row = _v4_row(key_entry)
        tampered = dataclasses.replace(row, transition="approve")
        result = verify_event_strict(tampered, keys=_resolver(key_entry))
        assert result.applicability is Applicability.INVALID
        assert "transition" in result.mismatched_field_names

    def test_v4_is_invalid_when_policy_does_not_name_it(self, key_entry):
        policy = VerificationPolicy(accept_legacy_versions=frozenset())
        result = verify_event_strict(
            _v4_row(key_entry), keys=_resolver(key_entry), policy=policy,
        )
        assert result.applicability is Applicability.INVALID
        assert FailureReason.LEGACY_ENVELOPE_VERSION in result.reasons

    def test_cutover_watermark_bounds_legacy(self, key_entry):
        row = _v4_row(key_entry)  # global_seq = 11
        below = VerificationPolicy(accept_legacy_before_global_seq=12)
        above = VerificationPolicy(accept_legacy_before_global_seq=11)
        assert (
            verify_event_strict(row, keys=_resolver(key_entry), policy=below).applicability
            is Applicability.LEGACY_PARTIAL
        )
        assert (
            verify_event_strict(row, keys=_resolver(key_entry), policy=above).applicability
            is Applicability.INVALID
        )


class TestNoFallback:
    """Once a stored envelope exists it is the only envelope."""

    def test_corrupted_envelope_is_not_rescued_by_the_row(self, key_entry):
        row = _v5_row(key_entry)
        corrupted = bytearray(row.canonical_envelope)
        corrupted[7] ^= 0xFF
        result = verify_event_strict(
            dataclasses.replace(row, canonical_envelope=bytes(corrupted)),
            keys=_resolver(key_entry),
        )
        assert result.applicability is Applicability.INVALID
        assert result.reasons[0] in (
            FailureReason.CANONICAL_HASH_MISMATCH,
            FailureReason.SIGNATURE_INVALID,
            FailureReason.ENVELOPE_UNPARSEABLE,
            FailureReason.ENVELOPE_UNKNOWN_SCHEMA,
        )

    def test_a_downgraded_stored_envelope_is_not_rescued(self, key_entry):
        """Swapping the stored v5 envelope for a v4 one built from the same row."""
        row = _v5_row(key_entry)
        v4 = build_signing_envelope_v4(
            event_id=row.event_id,
            entity_kind=row.entity_kind,
            entity_id=row.entity_id,
            actor_id=row.actor_id,
            key_id=row.key_id,
            event_seq=row.event_seq,
            workflow_name=row.workflow_name,
            workflow_version=row.workflow_version,
            timestamp=row.timestamp,
            hash_alg=row.hash_alg,
            transition=row.transition,
            payload=row.payload,
            on_behalf_of=row.on_behalf_of,
            prev_event_hash=row.prev_event_hash,
            prev_global_event_hash=row.prev_global_event_hash,
        )
        result = verify_event_strict(
            dataclasses.replace(row, canonical_envelope=v4),
            keys=_resolver(key_entry),
        )
        assert result.applicability is Applicability.INVALID

    def test_missing_envelope_is_unverifiable_not_rebuilt(self, key_entry):
        row = dataclasses.replace(_v5_row(key_entry), canonical_envelope=None)
        result = verify_event_strict(row, keys=_resolver(key_entry))
        assert result.applicability is Applicability.UNVERIFIABLE
        assert FailureReason.ENVELOPE_ABSENT in result.reasons
        assert result.accepted is False

    def test_an_unresolvable_key_never_passes(self, key_entry):
        class _Nothing:
            def resolve(self, key_id):
                return None

        result = verify_event_strict(_v5_row(key_entry), keys=_Nothing())
        assert result.applicability is Applicability.UNVERIFIABLE
        assert result.trusted_key_source is TrustedKeySource.NONE
        assert FailureReason.KEY_UNRESOLVABLE in result.reasons


class TestStrictEnvelopeParsing:
    """Nothing falls through to v1."""

    def test_attacker_authored_object_is_unknown_schema_not_v1(self, key_entry):
        envelope = canonicalize({"event_id": "x", "attacker_field": 1})
        sig, chash = HMACSHA256Scheme().sign(envelope, key_entry.secret)
        row = dataclasses.replace(
            _v5_row(key_entry),
            canonical_envelope=envelope,
            signature=sig,
            payload_canonical_hash=chash,
        )
        result = verify_event_strict(row, keys=_resolver(key_entry), policy=_LEGACY_ALL)
        assert result.envelope_version is EnvelopeVersion.UNKNOWN_SCHEMA
        # INVALID, never UNVERIFIABLE: the envelope exists and its bytes are
        # wrong for every known schema.
        assert result.applicability is Applicability.INVALID
        assert FailureReason.ENVELOPE_UNKNOWN_SCHEMA in result.reasons
        assert classify_envelope_version(envelope) == 0

    @pytest.mark.parametrize(
        "obj",
        [
            {},
            {"x": 1},
            {"event_id": "e", "work_item_id": "w", "actor_id": "a"},  # v1 subset
            {"event_id": "e", "actor_id": "a", "on_behalf_of": None,
             "transition": None, "payload": None},  # v1 minus work_item_id
        ],
        ids=["empty", "junk", "v1_subset", "v1_missing_required"],
    )
    def test_subsets_are_unknown_schema(self, obj):
        assert classify_envelope(obj) is EnvelopeVersion.UNKNOWN_SCHEMA

    def test_a_v5_envelope_missing_actor_metadata_is_not_a_v4_event(self):
        obj = json.loads(
            build_signing_envelope_v5(
                event_id=uuid.uuid4(), entity_kind="work_item",
                entity_id=uuid.uuid4(), actor_id="a", actor_kind="agent",
                actor_metadata=None, key_id="k", event_seq=1, workflow_name="wf",
                workflow_version=1, timestamp=datetime.now(UTC), hash_alg="sha-256",
                transition="t", payload=None,
            )
        )
        del obj["actor_metadata"]
        assert classify_envelope(obj) is EnvelopeVersion.UNKNOWN_SCHEMA

    def test_an_unrecognised_key_halts_rather_than_degrading(self):
        obj = json.loads(
            build_signing_envelope_v4(
                event_id=uuid.uuid4(), entity_kind="work_item",
                entity_id=uuid.uuid4(), actor_id="a", key_id="k", event_seq=1,
                workflow_name="wf", workflow_version=1,
                timestamp=datetime.now(UTC), hash_alg="sha-256", transition="t",
                payload=None,
            )
        )
        obj["project_name"] = "somewhere-else"
        assert classify_envelope(obj) is EnvelopeVersion.UNKNOWN_SCHEMA

    def test_known_versions_still_classify(self):
        now = datetime.now(UTC)
        eid, wid = uuid.uuid4(), uuid.uuid4()
        assert classify_envelope_version(
            build_signing_envelope(eid, wid, "a", "t", {"x": 1}, None)
        ) == 1
        assert classify_envelope_version(
            build_signing_envelope_v2(
                event_id=eid, work_item_id=wid, actor_id="a", key_id="k",
                event_seq=1, workflow_name="wf", workflow_version=1,
                timestamp=now, transition="t", payload=None,
            )
        ) == 2
        assert classify_envelope_version(
            build_signing_envelope_v3(
                event_id=eid, work_item_id=wid, actor_id="a", key_id="k",
                event_seq=1, workflow_name="wf", workflow_version=1,
                timestamp=now, transition="t", payload=None,
                prev_event_hash=b"\x01" * 32,
            )
        ) == 3

    def test_duplicate_keys_are_refused(self):
        with pytest.raises(ValueError, match="duplicate key"):
            parse_envelope_strict(b'{"event_id":"a","event_id":"b"}')

    def test_non_finite_numbers_are_refused(self):
        with pytest.raises(ValueError, match="non-finite"):
            parse_envelope_strict(b'{"event_seq":NaN}')

    def test_non_object_top_level_is_refused(self):
        with pytest.raises(ValueError, match="not a JSON object"):
            parse_envelope_strict(b"[1, 2, 3]")

    def test_unparseable_envelope_is_invalid(self, key_entry):
        row = dataclasses.replace(
            _v5_row(key_entry), canonical_envelope=b"not json at all",
        )
        result = verify_event_strict(row, keys=_resolver(key_entry))
        assert result.envelope_version is EnvelopeVersion.UNPARSEABLE
        assert result.applicability is Applicability.INVALID


class TestSchemeBinding:
    """S2-interim: the scheme comes from trusted key metadata, never the row.

    All three sites the audit named.
    """

    def test_site_1_dispatch_rejects_a_row_claiming_hmac_against_an_ed25519_key(
        self, key_entry,
    ):
        row = _v5_row(key_entry)
        assert row.row_scheme_id == "hmac-sha256"
        result = verify_event_strict(
            row,
            keys=StaticKeyResolver(
                material=key_entry.secret,
                scheme_id="ed25519",  # what the trusted registry says
                source=TrustedKeySource.PRINCIPAL_REGISTRY,
            ),
        )
        assert result.applicability is Applicability.INVALID
        assert FailureReason.SCHEME_MISMATCH in result.reasons
        assert result.scheme_id == "ed25519"
        assert result.row_scheme_id == "hmac-sha256"

    def test_site_2_principal_registration_requirement_uses_the_resolved_key(self):
        asym = frozenset({"ed25519"})
        evt = {"scheme_id": "hmac-sha256"}  # the row's claim

        class _Entry:
            scheme = "ed25519"

        # Without a resolved key the row's claim is the only input (and such an
        # event is not verified either way).
        assert _requires_principal_registration(evt, asym, None) is False
        # With one, the key's scheme decides — the row cannot opt itself out.
        assert _requires_principal_registration(evt, asym, _Entry()) is True

    def test_site_3_binding_does_not_let_a_row_claimed_hmac_skip_the_key_filter(self):
        """``elif scheme_id == "hmac-sha256": pass`` used to skip the filter."""

        @dataclasses.dataclass
        class _Entry:
            key_id: str
            scheme: str
            status: str = "active"
            principal_id: str = "actor-1"
            public_key: bytes = b"\x01" * 32
            valid_from: datetime | None = None
            valid_to: datetime | None = None

        entries = [_Entry(key_id="ed25519-actor-1", scheme="ed25519")]
        calls: list[object] = []

        def _verify(entry):
            calls.append(entry)
            return True

        result = _verify_principal_binding_core(
            entries,
            actor_id="actor-1",
            scheme_id="hmac-sha256",  # the row's claim
            verify_fn=_verify,
            event_key_id="bootstrap-hmac",  # not registered
            event_timestamp=datetime.now(UTC),
        )
        assert result.verified is False
        assert "key-id-mismatch" in (result.error or "")
        assert calls == [], "no key should have been tried"

    def test_site_3_symmetric_only_registries_keep_the_legacy_allowance(self):
        @dataclasses.dataclass
        class _Entry:
            key_id: str
            scheme: str
            status: str = "active"
            principal_id: str = "actor-1"
            public_key: bytes = b"\x01" * 32
            valid_from: datetime | None = None
            valid_to: datetime | None = None

        entries = [_Entry(key_id="hmac-1", scheme="hmac-sha256")]
        result = _verify_principal_binding_core(
            entries,
            actor_id="actor-1",
            scheme_id="hmac-sha256",
            verify_fn=lambda entry: True,
            event_key_id="some-other-hmac-key",
            event_timestamp=datetime.now(UTC),
        )
        assert result.verified is True

    def test_site_3_registry_scheme_disagreement_is_an_error(self):
        @dataclasses.dataclass
        class _Entry:
            key_id: str
            scheme: str
            status: str = "active"
            principal_id: str = "actor-1"
            public_key: bytes = b"\x01" * 32
            valid_from: datetime | None = None
            valid_to: datetime | None = None

        entries = [_Entry(key_id="k1", scheme="ed25519")]
        result = _verify_principal_binding_core(
            entries,
            actor_id="actor-1",
            scheme_id="hmac-sha256",  # the row relabels itself
            verify_fn=lambda entry: True,
            event_key_id="k1",
            event_timestamp=datetime.now(UTC),
        )
        assert result.verified is False
        assert "scheme-mismatch" in (result.error or "")


class TestKeylessInMemory:
    """The keyless exemption is a property of the backend, not of the bytes."""

    def _keyless_row(self, backend):
        return EventRow(
            event_id=uuid.uuid4(), work_item_id=uuid.uuid4(),
            entity_kind="work_item", entity_id=uuid.uuid4(), actor_id="agent-1",
            actor_kind="agent", actor_metadata=None, key_id="in-memory",
            event_seq=1, workflow_name="wf", workflow_version=1,
            timestamp=datetime.now(UTC), hash_alg="sha-256", on_behalf_of=None,
            transition="start", payload=None, prev_event_hash=None,
            prev_global_event_hash=None, global_seq=1,
            canonical_envelope=b"\x00" * 32, signature=b"\x00" * 32,
            payload_canonical_hash=b"\x00" * 32, row_scheme_id="hmac-sha256",
            backend=backend,
        )

    def test_in_memory_keyless_is_unsigned_not_tampered(self):
        result = verify_event_strict(
            self._keyless_row(Backend.IN_MEMORY),
            keys=StaticKeyResolver(material=b""),
            policy=VerificationPolicy(accept_unsigned_keyless=True),
        )
        assert result.envelope_version is EnvelopeVersion.KEYLESS_DUMMY
        assert result.applicability is Applicability.UNVERIFIABLE
        assert FailureReason.UNSIGNED_EVENT in result.reasons
        # The flag permits *processing*; it never manufactures authentication.
        assert result.accepted is True
        assert result.ok is False
        assert result.signature_valid is False
        # The keyless chain is a constant, not a chain.
        assert result.prev_event_hash_ok is None

    def test_keyless_is_not_accepted_by_default(self):
        result = verify_event_strict(
            self._keyless_row(Backend.IN_MEMORY),
            keys=StaticKeyResolver(material=b""),
        )
        assert result.applicability is Applicability.UNVERIFIABLE
        assert result.accepted is False

    def test_the_same_bytes_in_postgres_are_an_attack(self):
        result = verify_event_strict(
            self._keyless_row(Backend.POSTGRES),
            keys=StaticKeyResolver(material=b""),
            policy=VerificationPolicy(accept_unsigned_keyless=True),
        )
        assert result.envelope_version is EnvelopeVersion.UNPARSEABLE
        assert result.applicability is Applicability.INVALID
        assert result.accepted is False


class TestResultModelInvariants:
    def test_a_mismatch_cannot_be_constructed_as_anything_but_invalid(self):
        for applicability in (
            Applicability.FULLY_AUTHENTICATED,
            Applicability.LEGACY_PARTIAL,
            Applicability.UNVERIFIABLE,
        ):
            with pytest.raises(AssertionError, match="mismatched_fields"):
                VerificationResult(
                    event_id=uuid.uuid4(), entity_kind="work_item",
                    entity_id=uuid.uuid4(), global_seq=1,
                    envelope_version=EnvelopeVersion.V5, envelope_present=True,
                    envelope_schema_valid=True, signature_valid=True,
                    scheme_id="hmac-sha256", row_scheme_id="hmac-sha256",
                    hash_alg="sha-256",
                    trusted_key_source=TrustedKeySource.KEYSET_FILE,
                    trusted_key_id="k",
                    mismatched_fields=(FieldMismatch("payload", "a", "b"),),
                    unsigned_fields=frozenset({"global_seq"}),
                    applicability=applicability,
                )

    def test_global_seq_cannot_be_declared_authenticated(self):
        with pytest.raises(AssertionError, match="global_seq"):
            VerificationResult(
                event_id=uuid.uuid4(), entity_kind="work_item",
                entity_id=uuid.uuid4(), global_seq=1,
                envelope_version=EnvelopeVersion.V5, envelope_present=True,
                envelope_schema_valid=True, signature_valid=True,
                scheme_id="hmac-sha256", row_scheme_id="hmac-sha256",
                hash_alg="sha-256",
                trusted_key_source=TrustedKeySource.KEYSET_FILE,
                trusted_key_id="k",
                authenticated_fields=frozenset({"payload", "global_seq"}),
                applicability=Applicability.FULLY_AUTHENTICATED,
            )

    def test_legacy_must_name_its_unsigned_fields(self):
        with pytest.raises(AssertionError, match="LEGACY_PARTIAL"):
            VerificationResult(
                event_id=uuid.uuid4(), entity_kind="work_item",
                entity_id=uuid.uuid4(), global_seq=1,
                envelope_version=EnvelopeVersion.V4, envelope_present=True,
                envelope_schema_valid=True, signature_valid=True,
                scheme_id="hmac-sha256", row_scheme_id="hmac-sha256",
                hash_alg="sha-256",
                trusted_key_source=TrustedKeySource.KEYSET_FILE,
                trusted_key_id="k",
                applicability=Applicability.LEGACY_PARTIAL,
            )

    def test_no_policy_turns_a_mismatch_into_a_pass(self, key_entry):
        """Exhaustive over every policy dimension."""
        row = dataclasses.replace(_v5_row(key_entry), transition="approve")
        for policy in (
            VerificationPolicy(),
            VerificationPolicy(accept_unsigned_keyless=True),
            VerificationPolicy(
                accept_legacy_versions=frozenset(EnvelopeVersion),
                accept_legacy_before_global_seq=10**9,
            ),
            VerificationPolicy(
                full_authentication_versions=frozenset(EnvelopeVersion),
            ),
        ):
            result = verify_event_strict(row, keys=_resolver(key_entry), policy=policy)
            assert result.applicability is Applicability.INVALID
            assert result.accepted is False

    def test_field_mismatch_repr_does_not_leak_payload_content(self, key_entry):
        secret = "SUPER-SECRET-TRANSCRIPT"
        row = _v5_row(key_entry, payload={"content": secret})
        tampered = dataclasses.replace(row, payload={"content": "changed"})
        result = verify_event_strict(tampered, keys=_resolver(key_entry))
        rendered = result.detail or ""
        assert secret not in rendered
        assert "changed" not in rendered
        assert json.dumps(result.to_dict()).count(secret) == 0


class TestNullColumnMasking:
    """Review residual 1 & 2: a NULL column must not read as the signed value.

    ``events_set_entity_id`` (migration 031) is a BEFORE **INSERT** trigger, so
    it does not fire on UPDATE. Nulling a column an envelope signs must be a
    mismatch, not a silent substitution of the default the signer happened to
    use.
    """

    def test_nulled_entity_id_is_a_mismatch_not_authenticated(self, key_entry):
        row = _v5_row(key_entry)
        tampered = dataclasses.replace(row, entity_id=None)
        # The `effective_entity_id` fallback would have masked this: with
        # work_item_id untouched it still equals the signed entity_id.
        assert tampered.effective_entity_id == row.entity_id

        result = verify_event_strict(tampered, keys=_resolver(key_entry))
        assert result.applicability is Applicability.INVALID
        assert "entity_id" in result.mismatched_field_names
        assert "entity_id" not in result.authenticated_fields

    def test_nulled_work_item_id_breaks_the_alias(self, key_entry):
        row = dataclasses.replace(_v5_row(key_entry), work_item_id=None)
        result = verify_event_strict(row, keys=_resolver(key_entry))
        assert result.applicability is Applicability.INVALID
        assert "work_item_id!=entity_id" in result.mismatched_field_names
        assert FailureReason.ENTITY_ALIAS_MISMATCH in result.reasons

    @pytest.mark.parametrize("column", ["hash_alg", "entity_kind"])
    def test_nulled_column_does_not_collapse_to_the_signed_default(
        self, key_entry, column,
    ):
        """`row.get(x) or <default>` used to make a NULL match the signed value."""
        signed_default = {"hash_alg": "sha-256", "entity_kind": "work_item"}[column]
        row = _v5_row(key_entry)
        assert getattr(row, column) == signed_default

        raw = {
            "event_id": row.event_id,
            "work_item_id": row.work_item_id,
            "entity_kind": row.entity_kind,
            "entity_id": row.entity_id,
            "actor_id": row.actor_id,
            "actor_kind": row.actor_kind,
            "actor_metadata": row.actor_metadata,
            "key_id": row.key_id,
            "event_seq": row.event_seq,
            "workflow_name": row.workflow_name,
            "workflow_version": row.workflow_version,
            "timestamp": row.timestamp,
            "hash_alg": row.hash_alg,
            "on_behalf_of": row.on_behalf_of,
            "transition": row.transition,
            "payload": row.payload,
            "prev_event_hash": row.prev_event_hash,
            "prev_global_event_hash": row.prev_global_event_hash,
            "global_seq": row.global_seq,
            "canonical_envelope": row.canonical_envelope,
            "signature": row.signature,
            "payload_canonical_hash": row.payload_canonical_hash,
            "scheme_id": row.row_scheme_id,
        }
        assert verify_event_strict(
            EventRow.from_mapping(raw), keys=_resolver(key_entry),
        ).ok

        raw[column] = None
        result = verify_event_strict(
            EventRow.from_mapping(raw), keys=_resolver(key_entry),
        )
        assert result.applicability is Applicability.INVALID
        assert column in result.mismatched_field_names
        assert column not in result.authenticated_fields


class TestAbsentEnvelopeProbe:
    """Review residual 4: delete-envelope + rewrite-row must not fail OPEN.

    Before WI-267 this attack halted replay, because the rebuild-from-row
    candidate's signature did not match. Classifying it UNVERIFIABLE and
    continuing would have been strictly weaker than the code being replaced.
    """

    def _v1_pre002_row(self, key_entry, *, on_behalf_of=None):
        """A genuinely pre-002 row: v1-shaped signature, no stored envelope."""
        event_id = uuid.uuid4()
        wid = uuid.uuid4()
        payload = {"legacy": "pre-002"}
        envelope = build_signing_envelope(
            event_id, wid, "agent-1", "created", payload, on_behalf_of,
        )
        sig, chash = HMACSHA256Scheme().sign(envelope, key_entry.secret)
        return EventRow(
            event_id=event_id, work_item_id=wid, entity_kind="work_item",
            entity_id=wid, actor_id="agent-1", actor_kind="agent",
            actor_metadata=None, key_id=key_entry.key_id, event_seq=1,
            workflow_name="wf", workflow_version=1,
            timestamp=datetime(2024, 1, 1, tzinfo=UTC), hash_alg="sha-256",
            on_behalf_of=on_behalf_of, transition="created", payload=payload,
            prev_event_hash=None, prev_global_event_hash=None, global_seq=1,
            canonical_envelope=None, signature=sig,
            payload_canonical_hash=chash, row_scheme_id="hmac-sha256",
        )

    def test_a_genuine_pre002_row_probes_consistent(self, key_entry):
        row = self._v1_pre002_row(key_entry)
        assert probe_absent_envelope(row, keys=_resolver(key_entry)) is (
            AbsentEnvelopeProbe.CONSISTENT
        )

    def test_the_on_behalf_of_dropped_v1_variant_probes_consistent(self, key_entry):
        """CUTOVER-POLICY §4.1 names this shape explicitly."""
        event_id = uuid.uuid4()
        wid = uuid.uuid4()
        bare = build_signing_envelope(
            event_id, wid, "agent-1", "created", {"x": 1}, None,
        )
        sig, chash = HMACSHA256Scheme().sign(bare, key_entry.secret)
        row = EventRow(
            event_id=event_id, work_item_id=wid, entity_kind="work_item",
            entity_id=wid, actor_id="agent-1", actor_kind="agent",
            actor_metadata=None, key_id=key_entry.key_id, event_seq=1,
            workflow_name="wf", workflow_version=1,
            timestamp=datetime(2024, 1, 1, tzinfo=UTC), hash_alg="sha-256",
            on_behalf_of={"principal_id": "alice"},  # present on the row only
            transition="created", payload={"x": 1},
            prev_event_hash=None, prev_global_event_hash=None, global_seq=1,
            canonical_envelope=None, signature=sig,
            payload_canonical_hash=chash, row_scheme_id="hmac-sha256",
        )
        assert probe_absent_envelope(row, keys=_resolver(key_entry)) is (
            AbsentEnvelopeProbe.CONSISTENT
        )

    def test_a_v2_pre002_row_probes_consistent(self, key_entry):
        event_id = uuid.uuid4()
        wid = uuid.uuid4()
        ts = datetime(2024, 1, 1, tzinfo=UTC)
        envelope = build_signing_envelope_v2(
            event_id=event_id, work_item_id=wid, actor_id="agent-1",
            key_id=key_entry.key_id, event_seq=3, workflow_name="wf",
            workflow_version=1, timestamp=ts, transition="start", payload=None,
        )
        sig, chash = HMACSHA256Scheme().sign(envelope, key_entry.secret)
        row = EventRow(
            event_id=event_id, work_item_id=wid, entity_kind="work_item",
            entity_id=wid, actor_id="agent-1", actor_kind="agent",
            actor_metadata=None, key_id=key_entry.key_id, event_seq=3,
            workflow_name="wf", workflow_version=1, timestamp=ts,
            hash_alg="sha-256", on_behalf_of=None, transition="start",
            payload=None, prev_event_hash=None, prev_global_event_hash=None,
            global_seq=1, canonical_envelope=None, signature=sig,
            payload_canonical_hash=chash, row_scheme_id="hmac-sha256",
        )
        assert probe_absent_envelope(row, keys=_resolver(key_entry)) is (
            AbsentEnvelopeProbe.CONSISTENT
        )

    def test_deleting_a_v5_envelope_probes_inconsistent(self, key_entry):
        """The attack: NULL the envelope, keep the signature, rewrite at will."""
        row = dataclasses.replace(_v5_row(key_entry), canonical_envelope=None)
        assert probe_absent_envelope(row, keys=_resolver(key_entry)) is (
            AbsentEnvelopeProbe.INCONSISTENT
        )

    def test_rewriting_a_pre002_row_probes_inconsistent(self, key_entry):
        row = self._v1_pre002_row(key_entry)
        tampered = dataclasses.replace(row, payload={"legacy": "rewritten"})
        assert probe_absent_envelope(tampered, keys=_resolver(key_entry)) is (
            AbsentEnvelopeProbe.INCONSISTENT
        )

    def test_the_probe_is_unknown_when_it_cannot_run(self, key_entry):
        class _Nothing:
            def resolve(self, key_id):
                return None

        row = self._v1_pre002_row(key_entry)
        assert probe_absent_envelope(row, keys=_Nothing()) is (
            AbsentEnvelopeProbe.UNKNOWN
        )
        # And it never speaks about a row that HAS an envelope.
        assert probe_absent_envelope(
            _v5_row(key_entry), keys=_resolver(key_entry),
        ) is AbsentEnvelopeProbe.UNKNOWN

    def test_the_probe_can_never_grant_acceptance(self, key_entry):
        """It convicts only. CONSISTENT changes no verdict."""
        row = self._v1_pre002_row(key_entry)
        assert probe_absent_envelope(row, keys=_resolver(key_entry)) is (
            AbsentEnvelopeProbe.CONSISTENT
        )
        result = verify_event_strict(row, keys=_resolver(key_entry))
        assert result.applicability is Applicability.UNVERIFIABLE
        assert result.accepted is False
        assert result.ok is False


# ---------------------------------------------------------------------------
# End-to-end: the same mutations against a live Postgres store
# ---------------------------------------------------------------------------


def _tamper(sub, event_id, column, value):
    from regista._testing import raw_transaction

    with raw_transaction(sub) as conn:
        conn.execute(
            f"UPDATE events SET {column} = %s WHERE event_id = %s",
            [value, event_id],
        )


class TestEndToEndPostgres:
    """A database-write attacker, against the real store and the real consumers."""

    def _one_event(self, sub):
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow",
            work_item_type="feature",
            actor_id="agent-1",
            custom_fields={"title": "wi267"},
        )
        sub.transition(
            wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"},
        )
        events = sub.read_events(work_item_id=wi.work_item_id)
        return wi, events[-1]

    @pytest.mark.parametrize(
        ("column", "value", "field"),
        [
            ("transition", "approve", "transition"),
            ("payload", json.dumps({"rewritten": True}), "payload"),
            ("actor_id", "attacker", "actor_id"),
            ("actor_kind", "human", "actor_kind"),
            ("actor_metadata", json.dumps({"role": "admin"}), "actor_metadata"),
            ("workflow_name", "other_wf", "workflow_name"),
            ("workflow_version", 9, "workflow_version"),
            ("key_id", "other-key", "key_id"),
            ("hash_alg", "sha-512", "hash_alg"),
        ],
    )
    def test_row_column_rewrite_fails_verification(
        self, regista, column, value, field,
    ):
        sub = regista
        _wi, evt = self._one_event(sub)
        assert sub.verify_event_signature(evt) is True

        _tamper(sub, evt.event_id, column, value)
        tampered = sub.read_events(work_item_id=evt.work_item_id)[-1]

        result = sub.verify_event_result(tampered)
        assert result.applicability is Applicability.INVALID, result.summary()
        assert field in result.mismatched_field_names, result.summary()
        assert sub.verify_event_signature(tampered) is False

    def test_timestamp_rewrite_fails_verification(self, regista):
        sub = regista
        _wi, evt = self._one_event(sub)
        _tamper(
            sub, evt.event_id, "timestamp", evt.timestamp + timedelta(seconds=1),
        )
        tampered = sub.read_events(work_item_id=evt.work_item_id)[-1]
        result = sub.verify_event_result(tampered)
        assert result.applicability is Applicability.INVALID
        assert "timestamp" in result.mismatched_field_names

    def test_timestamp_rendering_in_another_timezone_is_not_tamper(self, regista):
        """The envelope holds a fixed ISO string; the row holds an instant."""
        sub = regista
        _wi, evt = self._one_event(sub)
        from zoneinfo import ZoneInfo

        shifted = dataclasses.replace(
            EventRow.from_event(evt),
            timestamp=evt.timestamp.astimezone(ZoneInfo("America/Phoenix")),
        )
        result = verify_event_strict(
            shifted, keys=_resolver(KeySet(KEY_PATH).active_key()),
        )
        assert result.ok, result.summary()

    def test_payload_key_reorder_is_not_tamper(self, regista):
        """jsonb does not preserve key order; JCS re-canonicalises."""
        sub = regista
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow", work_item_type="feature",
            actor_id="agent-1", custom_fields={"title": "reorder"},
        )
        eid = uuid.uuid4()
        sub.append_event(
            work_item_id=wi.work_item_id, actor_id="agent-1",
            transition="custom_event", payload={"z": 1, "a": 2, "m": 3},
            event_id=eid,
        )
        _tamper(sub, eid, "payload", json.dumps({"a": 2, "m": 3, "z": 1}))
        evt = next(
            e for e in sub.read_events(work_item_id=wi.work_item_id)
            if e.event_id == eid
        )
        assert sub.verify_event_result(evt).ok

    def test_global_seq_rewrite_is_not_reported_as_a_mismatch(self, regista):
        sub = regista
        _wi, evt = self._one_event(sub)
        _tamper(sub, evt.event_id, "global_seq", 987654)
        tampered = sub.read_events(work_item_id=evt.work_item_id)[-1]
        result = sub.verify_event_result(tampered)
        assert result.ok, result.summary()
        assert result.mismatched_fields == ()

    def test_replay_halts_on_a_rewritten_transition(self, regista):
        sub = regista
        _wi, evt = self._one_event(sub)
        assert sub.replay().halted == 0

        _tamper(sub, evt.event_id, "transition", "approve")
        report = sub.replay()
        assert report.halted >= 1

    def test_replay_halts_on_a_rewritten_payload(self, regista):
        sub = regista
        _wi, evt = self._one_event(sub)
        _tamper(sub, evt.event_id, "payload", json.dumps({"initial_state": "done"}))
        assert sub.replay().halted >= 1

    def test_a_broken_work_item_entity_alias_fails_verification(self, regista):
        """Repointing the UNSIGNED work_item_id column at another work item.

        The signature covers ``entity_id`` from v4 onward; ``work_item_id`` is
        the original 001 column and carries no signature of its own, so only
        the alias check binds it.
        """
        sub = regista
        _wi, evt = self._one_event(sub)
        _tamper(sub, evt.event_id, "work_item_id", uuid.uuid4())

        from regista._testing import raw_transaction

        with raw_transaction(sub) as conn:
            row = conn.execute(
                "SELECT * FROM events WHERE event_id = %s", [evt.event_id],
            ).fetchone()
        result = verify_event_strict(
            EventRow.from_mapping(row),
            keys=_resolver(KeySet(KEY_PATH).active_key()),
        )
        assert result.applicability is Applicability.INVALID
        assert "work_item_id!=entity_id" in result.mismatched_field_names
        assert FailureReason.ENTITY_ALIAS_MISMATCH in result.reasons

    def test_replay_halts_on_an_unknown_envelope_schema(self, regista):
        sub = regista
        _wi, evt = self._one_event(sub)
        _tamper(
            sub, evt.event_id, "canonical_envelope",
            canonicalize({"event_id": str(evt.event_id), "attacker_field": 1}),
        )
        assert sub.replay().halted >= 1

    def test_deleting_an_envelope_halts_because_the_row_contradicts_itself(
        self, regista,
    ):
        """Review residual 4. This must not be weaker than the old code.

        Nulling `canonical_envelope` on a v5 event leaves the `signature` and
        `payload_canonical_hash` that envelope produced. No shape a genuinely
        pre-002 row could have carried reproduces them, so the row contradicts
        its own cryptographic material and replay halts — as it did before
        WI-267, where the rebuild-from-row candidate failed its signature check.
        """
        sub = regista
        _wi, evt = self._one_event(sub)
        _tamper(sub, evt.event_id, "canonical_envelope", None)
        report = sub.replay()
        assert report.halted >= 1

    def test_a_missing_envelope_on_a_consistent_row_is_counted_not_halted(
        self, regista,
    ):
        """The pre-002 population: an evidentiary gap, reported as one.

        Built by re-signing the row's own values in the v1 shape, i.e. exactly
        what a legitimately envelopeless row looks like.
        """
        sub = regista
        _wi, evt = self._one_event(sub)
        v1 = build_signing_envelope(
            evt.event_id, evt.work_item_id, evt.actor_id,
            evt.transition, evt.payload, evt.on_behalf_of,
        )
        sig, chash = HMACSHA256Scheme().sign(v1, KeySet(KEY_PATH).active_key().secret)
        _tamper(sub, evt.event_id, "canonical_envelope", None)
        _tamper(sub, evt.event_id, "signature", sig)
        _tamper(sub, evt.event_id, "payload_canonical_hash", chash)

        report = sub.replay()
        assert report.halted == 0
        # Counted as unverifiable — NOT folded into the warnings bucket.
        assert report.unverifiable >= 1

    def test_unverifiable_is_zero_on_a_clean_store(self, regista):
        sub = regista
        self._one_event(sub)
        report = sub.replay()
        assert report.unverifiable == 0
        assert report.to_dict().get("unverifiable") is None


class TestInMemoryBackendParity:
    def test_in_memory_row_rewrite_halts_replay(self):
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(project="wi267", hmac_key_path=KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        sub.register_actor_role("agent-1", "agent")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow", work_item_type="feature",
            actor_id="agent-1", custom_fields={"title": "inmem"},
        )
        sub.transition(
            wi.work_item_id, "start", "agent-1", actor_metadata={"role": "agent"},
        )
        assert sub.replay().halted == 0

        evts = sub._store.events[wi.work_item_id]
        evts[-1] = dataclasses.replace(evts[-1], transition="approve")
        sub._store.event_id_index[evts[-1].event_id] = evts[-1]

        from regista._errors import RegistaError

        try:
            report = sub.replay()
        except RegistaError:
            return  # halting via the error path is equally acceptable
        assert report.halted >= 1

    def test_in_memory_envelope_deletion_halts_like_postgres(self):
        """Backend parity for review residual 4."""
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(project="wi267-noenv", hmac_key_path=KEY_PATH)
        sub.register_workflow_file(WORKFLOW_PATH)
        sub.register_actor_role("agent-1", "agent")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow", work_item_type="feature",
            actor_id="agent-1", custom_fields={"title": "noenv"},
        )
        evts = sub._store.events[wi.work_item_id]
        evts[0] = dataclasses.replace(evts[0], canonical_envelope=None)
        sub._store.event_id_index[evts[0].event_id] = evts[0]

        assert sub.replay().halted >= 1

    def test_keyless_in_memory_reports_unverifiable(self):
        from regista.testing import InMemoryRegista

        sub = InMemoryRegista(project="wi267-keyless")
        sub.register_workflow_file(WORKFLOW_PATH)
        sub.register_actor_role("agent-1", "agent")
        wi, _ = sub.create_work_item(
            workflow_name="test_workflow", work_item_type="feature",
            actor_id="agent-1", custom_fields={"title": "keyless"},
        )
        evt = sub.read_events(work_item_id=wi.work_item_id)[0]
        result = sub.verify_event_result(evt)
        assert result.applicability is Applicability.UNVERIFIABLE
        assert FailureReason.UNSIGNED_EVENT in result.reasons
        # Not "signature invalid" — this event was never signed.
        assert result.envelope_version is EnvelopeVersion.KEYLESS_DUMMY
        # ...and the keyless replay REPORTS that nothing was checked. The
        # previous assertion here was `warnings >= 0`, which is vacuous — and
        # the code behind it emitted nothing at all, because a genuine keyless
        # dummy is `accepted` under the keyless policy.
        report = sub.replay()
        assert report.unverifiable >= 1
        assert report.to_dict()["unverifiable"] >= 1
