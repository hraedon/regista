"""P2.3 — §2.6 ``principal_kind_conflict`` must be **computed**, not merely defined.

§2.6, in full, as tests:

* for every event the verifier emits ``actor_id_kind``, ``actor_kind``,
  ``identity_consistency`` and, for pre-v5 envelopes, ``actor_kind_authenticated: false``;
* pre-v5 ``actor_kind`` is unsigned, so ``actor_kind`` must appear in ``unsigned_fields``
  for **every** envelope version below v5, and a consumer reading it for a security
  decision must assert ``"actor_kind" in result.authenticated_fields``.

None of this changes a verdict. Every test here also asserts the applicability it started
with, because §2.7's last row says verification never validates the grammar.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from _helpers import KEY_PATH

from regista._signing import classify_envelope_version, sign_event
from regista._testing import KeySet
from regista._verification import (
    _ALL_ROW_FIELDS,
    _VERSION_UNSIGNED,
    Applicability,
    EnvelopeVersion,
    EventRow,
    StaticKeyResolver,
    TrustedKeySource,
    VerificationPolicy,
    probe_absent_envelope,
    verify_event_strict,
)

TESTS_DIR = Path(__file__).parent

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
def key_entry():
    return KeySet(KEY_PATH).active_key()


def _resolver(key_entry):
    return StaticKeyResolver(
        material=key_entry.secret,
        scheme_id="hmac-sha256",
        source=TrustedKeySource.KEYSET_FILE,
    )


def _signed_row(key_entry, *, actor_id, actor_kind, include_actor_kind=True, **row_overrides):
    """A signed event and the row that honestly projects it.

    ``include_actor_kind=False`` produces a v4 envelope (``actor_kind`` omitted from the
    signature input), which is the pre-v5 case §2.6's hard rule is about.
    """
    event_id = uuid.uuid4()
    entity_id = uuid.uuid4()
    ts = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
    payload = {"n": 1}
    kwargs = dict(
        event_id=event_id,
        work_item_id=entity_id,
        actor_id=actor_id,
        key_id=key_entry.key_id,
        event_seq=1,
        workflow_name="test_workflow",
        workflow_version=1,
        timestamp=ts,
        transition="start",
        payload=payload,
        key=key_entry.secret,
        on_behalf_of=None,
        entity_kind="work_item",
        hash_alg="sha-256",
    )
    if include_actor_kind:
        kwargs["actor_kind"] = actor_kind
        kwargs["actor_metadata"] = {}
    signature, canonical_hash, envelope = sign_event(**kwargs)
    row = EventRow(
        event_id=event_id,
        work_item_id=entity_id,
        entity_kind="work_item",
        entity_id=entity_id,
        actor_id=actor_id,
        actor_kind=actor_kind,
        actor_metadata={} if include_actor_kind else {"whatever": True},
        key_id=key_entry.key_id,
        event_seq=1,
        workflow_name="test_workflow",
        workflow_version=1,
        timestamp=ts,
        hash_alg="sha-256",
        on_behalf_of=None,
        transition="start",
        payload=payload,
        prev_event_hash=None,
        prev_global_event_hash=None,
        global_seq=1,
        canonical_envelope=envelope,
        signature=signature,
        payload_canonical_hash=canonical_hash,
        row_scheme_id="hmac-sha256",
    )
    return row, classify_envelope_version(envelope)


# ---------------------------------------------------------------------------
# §2.6 — the three fields, per event
# ---------------------------------------------------------------------------


def test_every_result_carries_the_identity_trio(key_entry):
    row, version = _signed_row(key_entry, actor_id="agent:mvmcc03", actor_kind="agent")
    assert version == 5
    result = verify_event_strict(row, keys=_resolver(key_entry))
    assert result.actor_id_kind == "agent"
    assert result.actor_kind == "agent"
    assert str(result.identity_consistency) == "consistent"
    assert result.applicability is Applicability.FULLY_AUTHENTICATED


def test_the_231k_corpus_shape_is_surfaced_as_a_conflict_without_changing_the_verdict(
    key_entry,
):
    """§2.6's example: ``human:itadmin`` rows whose ``actor_kind`` says ``agent``.

    §2.6 also records the verified consequence: ``_assurance.py`` computes
    ``human_accepted = (accepter_kind == "human")`` from ``actor_kind``, so these events
    never counted as human judgment, and "no retroactive correction is required" — i.e. the
    verdict must not move.
    """
    row, _ = _signed_row(key_entry, actor_id="human:itadmin", actor_kind="agent")
    result = verify_event_strict(row, keys=_resolver(key_entry))
    assert result.actor_id_kind == "human"
    assert result.actor_kind == "agent"
    assert str(result.identity_consistency) == "principal_kind_conflict"
    # Unchanged verdict.
    assert result.applicability is Applicability.FULLY_AUTHENTICATED
    assert result.accepted is True
    assert result.reasons == ()


def test_a_bare_legacy_actor_id_reports_a_null_kind(key_entry):
    """§2.6: '``actor_id_kind`` — the prefix, or ``null`` for a bare legacy id'."""
    row, _ = _signed_row(key_entry, actor_id="mvmcc03-agent", actor_kind="agent")
    result = verify_event_strict(row, keys=_resolver(key_entry))
    assert result.actor_id_kind is None
    assert str(result.identity_consistency) == "actor_id_ungrammatical"
    assert result.applicability is Applicability.FULLY_AUTHENTICATED


def test_service_principals_reconcile_with_the_row_spelling_system(key_entry):
    row, _ = _signed_row(key_entry, actor_id="service:agent-notes", actor_kind="system")
    result = verify_event_strict(row, keys=_resolver(key_entry))
    assert str(result.identity_consistency) == "consistent"


def test_the_trio_is_present_even_on_outcomes_that_authenticate_nothing(key_entry):
    """The case an operator most needs the label for: a row whose envelope is gone."""
    row, _ = _signed_row(key_entry, actor_id="mvmcc03-agent", actor_kind="agent")
    stripped = __import__("dataclasses").replace(row, canonical_envelope=None)
    result = verify_event_strict(stripped, keys=_resolver(key_entry))
    assert result.applicability is Applicability.UNVERIFIABLE
    assert result.actor_id_kind is None
    assert str(result.identity_consistency) == "actor_id_ungrammatical"
    assert result.actor_kind == "agent"
    # And the probe path still works on the same row.
    assert probe_absent_envelope(stripped, keys=_resolver(key_entry)) is not None


def test_the_trio_appears_in_to_dict(key_entry):
    row, _ = _signed_row(key_entry, actor_id="human:itadmin", actor_kind="agent")
    d = verify_event_strict(row, keys=_resolver(key_entry)).to_dict()
    assert d["actor_id_kind"] == "human"
    assert d["actor_kind"] == "agent"
    assert d["identity_consistency"] == "principal_kind_conflict"
    assert d["actor_kind_authenticated"] is True  # v5 signs actor_kind
    assert d["actor_principal_mapping"] == "self_canonical"


# ---------------------------------------------------------------------------
# §2.6 hard rule — pre-v5 actor_kind is unsigned
# ---------------------------------------------------------------------------


def test_actor_kind_is_unsigned_for_every_envelope_version_below_v5():
    """§2.6: '``actor_kind`` must appear in it for every envelope version below v5'.

    Asserted over the whole table rather than sampled, so adding a version cannot skip it.
    """
    below_v5 = [
        v
        for v in _VERSION_UNSIGNED
        if v in (EnvelopeVersion.V1, EnvelopeVersion.V2, EnvelopeVersion.V3, EnvelopeVersion.V4)
    ]
    assert len(below_v5) == 4
    for version in below_v5:
        assert "actor_kind" in _VERSION_UNSIGNED[version], version


def test_actor_kind_is_signed_from_v5_onward():
    """The other half of the rule: from v5 the field *is* authenticated, so a consumer's
    ``"actor_kind" in authenticated_fields`` assertion actually passes somewhere."""
    assert "actor_kind" not in _VERSION_UNSIGNED[EnvelopeVersion.V5]


def test_actor_kind_is_in_the_all_row_fields_fallback():
    """On outcomes where nothing was authenticated, every readable column is reported
    unsigned — ``actor_kind`` included."""
    assert "actor_kind" in _ALL_ROW_FIELDS


def test_pre_v5_actor_kind_authenticated_is_false(key_entry):
    """§2.6: 'and for pre-v5 envelopes, ``actor_kind_authenticated: false``'."""
    row, version = _signed_row(
        key_entry, actor_id="human:itadmin", actor_kind="agent", include_actor_kind=False
    )
    assert version == 4
    result = verify_event_strict(row, keys=_resolver(key_entry), policy=_LEGACY_ALL)
    assert result.applicability is Applicability.LEGACY_PARTIAL
    assert "actor_kind" in result.unsigned_fields
    assert "actor_kind" not in result.authenticated_fields
    assert result.actor_kind_authenticated is False
    assert result.to_dict()["actor_kind_authenticated"] is False
    # The conflict is still *reported* on a v4 event — as a label, never as evidence.
    assert str(result.identity_consistency) == "principal_kind_conflict"


def test_actor_kind_authenticated_is_derived_from_unsigned_fields_not_stored(key_entry):
    """One source of truth: the flag reads ``authenticated_fields``, so it cannot disagree
    with the field list a consumer is told to check."""
    v5_row, _ = _signed_row(key_entry, actor_id="agent:mvmcc03", actor_kind="agent")
    v5 = verify_event_strict(v5_row, keys=_resolver(key_entry))
    assert v5.actor_kind_authenticated is ("actor_kind" in v5.authenticated_fields) is True

    v4_row, _ = _signed_row(
        key_entry, actor_id="agent:mvmcc03", actor_kind="agent", include_actor_kind=False
    )
    v4 = verify_event_strict(v4_row, keys=_resolver(key_entry), policy=_LEGACY_ALL)
    assert v4.actor_kind_authenticated is ("actor_kind" in v4.authenticated_fields) is False


# ---------------------------------------------------------------------------
# §2 consequence 2 — mapping_absent, only when a population was supplied
# ---------------------------------------------------------------------------


def test_mapping_is_not_evaluated_unless_a_population_is_supplied(key_entry):
    row, _ = _signed_row(key_entry, actor_id="mvmcc03-agent", actor_kind="agent")
    result = verify_event_strict(row, keys=_resolver(key_entry))
    assert str(result.actor_principal_mapping) == "not_evaluated"
    assert str(result.identity_consistency) == "actor_id_ungrammatical"


def test_an_unmapped_writer_is_mapping_absent_not_a_guess(key_entry):
    """§2 consequence 2 verbatim. ``mvmcc03-agent`` looks exactly like ``agent:mvmcc03``;
    supplying that canonical id as the only mapped *principal* must not map the actor."""
    row, _ = _signed_row(key_entry, actor_id="mvmcc03-agent", actor_kind="agent")
    result = verify_event_strict(
        row, keys=_resolver(key_entry), mapped_actor_ids={"agent:mvmcc03"}
    )
    assert str(result.actor_principal_mapping) == "mapping_absent"
    assert str(result.identity_consistency) == "mapping_absent"
    assert result.applicability is Applicability.FULLY_AUTHENTICATED


def test_a_mapped_writer_is_reported_mapped(key_entry):
    row, _ = _signed_row(key_entry, actor_id="mvmcc03-agent", actor_kind="agent")
    result = verify_event_strict(
        row, keys=_resolver(key_entry), mapped_actor_ids={"mvmcc03-agent"}
    )
    assert str(result.actor_principal_mapping) == "mapped"
    assert str(result.identity_consistency) == "actor_id_ungrammatical"


def test_a_kind_conflict_is_never_masked_by_the_mapping_axis(key_entry):
    """The 231k corpus is both facts at once; two fields keep both."""
    row, _ = _signed_row(key_entry, actor_id="human:itadmin", actor_kind="agent")
    result = verify_event_strict(row, keys=_resolver(key_entry), mapped_actor_ids=set())
    assert str(result.identity_consistency) == "principal_kind_conflict"
    assert str(result.actor_principal_mapping) == "self_canonical"


def test_the_mapping_population_can_come_from_a_validated_mapping_document(key_entry):
    """The seam between the payload contract and the verifier's reporting surface."""
    from regista._principal_alias import parse_actor_principal_mapping

    doc = parse_actor_principal_mapping(
        {
            "type": "regista.actor-principal-mapping",
            "version": 1,
            "mapping_id": "3f2c8a10-1111-4222-8333-444455556666",
            "trust_domain_id": "0f6c1b2e-7777-4888-8999-aaaabbbbcccc",
            "scope": {
                "kind": "project",
                "project_instance_id": "11112222-3333-4444-8555-666677778888",
                "event_hash_set_root": None,
                "event_count": None,
                "first_event_hash": None,
                "last_event_hash": None,
            },
            "entries": [
                {
                    "actor_id": "mvmcc03-agent",
                    "principal_id": "agent:mvmcc03",
                    "basis": "operator-inspection",
                    "evidence": "suite.env:38 PRINCIPAL_ID on host mvmcc03",
                }
            ],
            "asserted_by": {
                "principal_id": "human:itadmin",
                "method": "operator-inspection",
                "evidence": "Gate 1",
            },
            "asserted_at": "2026-08-08T00:00:00.000000Z",
            "binding_effect": "reporting_join_only",
        }
    )
    row, _ = _signed_row(key_entry, actor_id="mvmcc03-agent", actor_kind="agent")
    result = verify_event_strict(
        row, keys=_resolver(key_entry), mapped_actor_ids=doc.mapped_actor_ids
    )
    assert str(result.actor_principal_mapping) == "mapped"


def test_mapping_population_never_becomes_a_verdict_input(key_entry):
    """The same event, verified with and without a mapping population, must produce the
    same applicability, acceptance and reasons."""
    row, _ = _signed_row(key_entry, actor_id="mvmcc03-agent", actor_kind="agent")
    without = verify_event_strict(row, keys=_resolver(key_entry))
    with_empty = verify_event_strict(row, keys=_resolver(key_entry), mapped_actor_ids=set())
    for field in ("applicability", "accepted", "reasons", "signature_valid", "row_reconciled"):
        assert getattr(without, field) == getattr(with_empty, field), field
