"""P2.3 — the ``regista.principal-alias/v1`` payload contract and the deliberate
``actor_id → principal_id`` mapping document.

Normative sources: ``docs/0.6.0/TRUST-DOMAIN.md`` §2.5 (with §10 D-4 folding the
separately-proposed ``identity_cutover_attested`` record into one event kind with a
**mandatory** ``scope``) and §2 CONFIRMED consequence 2.

This is the payload CONTRACT only. Writing a validated payload into the trust log is
P2.2/P1.7 machinery; see the module docstring of ``regista._principal_alias`` for the seam.
"""

from __future__ import annotations

import copy

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._principal_alias import (
    ACTOR_PRINCIPAL_MAPPING_TYPE,
    ACTOR_PRINCIPAL_MAPPING_VERSION,
    BINDING_EFFECT_REPORTING_JOIN_ONLY,
    PRINCIPAL_ALIAS_TYPE,
    PRINCIPAL_ALIAS_VERSION,
    AliasRelation,
    AliasScopeKind,
    MappingBasis,
    alias_covers_actor_id,
    parse_actor_principal_mapping,
    parse_principal_alias,
)

_ALIAS_ID = "3f2c8a10-1111-4222-8333-444455556666"
_DOMAIN_ID = "0f6c1b2e-7777-4888-8999-aaaabbbbcccc"
_PROJECT_ID = "11112222-3333-4444-8555-666677778888"
_ROOT = "sha256:" + "ab" * 32
_FIRST = "sha256:" + "cd" * 32
_LAST = "sha256:" + "ef" * 32


def _event_set_scope(**overrides):
    scope = {
        "kind": "event-set",
        "project_instance_id": None,
        "event_hash_set_root": _ROOT,
        "event_count": 230976,
        "first_event_hash": _FIRST,
        "last_event_hash": _LAST,
    }
    scope.update(overrides)
    return scope


def _unscoped_scope(**overrides):
    scope = {
        "kind": "unscoped",
        "project_instance_id": None,
        "event_hash_set_root": None,
        "event_count": None,
        "first_event_hash": None,
        "last_event_hash": None,
    }
    scope.update(overrides)
    return scope


def _project_scope(**overrides):
    scope = {
        "kind": "project",
        "project_instance_id": _PROJECT_ID,
        "event_hash_set_root": None,
        "event_count": None,
        "first_event_hash": None,
        "last_event_hash": None,
    }
    scope.update(overrides)
    return scope


def _alias(**overrides):
    """§2.5's own worked example: the ~231k conflated-execution corpus."""
    payload = {
        "type": "regista.principal-alias",
        "version": 1,
        "alias_id": _ALIAS_ID,
        "trust_domain_id": _DOMAIN_ID,
        "from_principal_id": "human:itadmin",
        "to_principal_id": "agent:mvmcc03",
        "relation": "legacy_conflated_execution",
        "scope": _event_set_scope(),
        "asserted_by": {
            "principal_id": "human:itadmin",
            "method": "operator-inspection",
            "evidence": "preflight-live.json estate.principal_kind_conflicts",
        },
        "asserted_at": "2026-08-08T00:00:00.000000Z",
        "binding_effect": "reporting_join_only",
    }
    payload.update(overrides)
    return payload


def _mapping(**overrides):
    payload = {
        "type": "regista.actor-principal-mapping",
        "version": 1,
        "mapping_id": _ALIAS_ID,
        "trust_domain_id": _DOMAIN_ID,
        "scope": _project_scope(),
        "entries": [
            {
                "actor_id": "mvmcc03-agent",
                "principal_id": "agent:mvmcc03",
                "basis": "operator-inspection",
                "evidence": "suite.env:38 PRINCIPAL_ID on host mvmcc03",
            },
            {
                "actor_id": "agent-notes",
                "principal_id": "service:agent-notes",
                "basis": "configuration-record",
                "evidence": "agent-notes CLI writes under its own service identity",
            },
        ],
        "asserted_by": {
            "principal_id": "human:itadmin",
            "method": "operator-inspection",
            "evidence": "Gate 1 identity assignment",
        },
        "asserted_at": "2026-08-08T00:00:00.000000Z",
        "binding_effect": "reporting_join_only",
    }
    payload.update(overrides)
    return payload


def _reason(exc: RegistaError) -> str:
    return exc.value.detail["reason"] if hasattr(exc, "value") else exc.detail["reason"]


# ---------------------------------------------------------------------------
# The happy path and the wire constants
# ---------------------------------------------------------------------------


def test_the_doc_worked_example_validates():
    alias = parse_principal_alias(_alias())
    assert alias.relation is AliasRelation.LEGACY_CONFLATED_EXECUTION
    assert alias.scope.kind is AliasScopeKind.EVENT_SET
    assert alias.scope.event_count == 230976
    assert alias.binding_effect == "reporting_join_only"


def test_round_trip_is_stable():
    payload = _alias()
    assert parse_principal_alias(payload).to_dict() == payload


def test_wire_constants():
    assert PRINCIPAL_ALIAS_TYPE == "regista.principal-alias"
    assert PRINCIPAL_ALIAS_VERSION == 1
    assert BINDING_EFFECT_REPORTING_JOIN_ONLY == "reporting_join_only"
    assert ACTOR_PRINCIPAL_MAPPING_TYPE == "regista.actor-principal-mapping"
    assert ACTOR_PRINCIPAL_MAPPING_VERSION == 1


def test_relation_and_scope_kind_enums_are_exactly_the_ratified_sets():
    assert {str(r) for r in AliasRelation} == {
        "same_subject",
        "legacy_conflated_execution",
        "renamed",
    }
    assert {str(k) for k in AliasScopeKind} == {"unscoped", "project", "event-set"}


# ---------------------------------------------------------------------------
# §2.5 — binding_effect is a literal, and an alias never binds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    ["signature_binding", "reporting_join", "", None, "REPORTING_JOIN_ONLY", "full"],
)
def test_binding_effect_admits_no_other_value(value):
    """§2.5: 'there is no other permitted value in v1'."""
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(_alias(binding_effect=value))
    assert exc.value.code == ErrorCode.PRINCIPAL_ALIAS_INVALID
    assert exc.value.detail["reason"] == "binding_effect_not_reporting_join_only"


def test_a_validated_alias_says_plainly_that_it_does_not_satisfy_binding():
    assert parse_principal_alias(_alias()).satisfies_signature_binding is False


# ---------------------------------------------------------------------------
# §2.5 — the from/to grammar asymmetry
# ---------------------------------------------------------------------------


def test_from_may_be_a_legacy_bare_name():
    """The whole point: today's bare names are the ``from`` side."""
    alias = parse_principal_alias(
        _alias(
            from_principal_id="mvmcc03-agent",
            relation="renamed",
            scope=_project_scope(),
        )
    )
    assert alias.from_principal_id == "mvmcc03-agent"


def test_from_may_not_be_junk():
    """Aliasing an unparseable string would let any string be joined into a canonical
    principal's reporting identity — the one thing the mandatory scope bounds."""
    for bad in ("key:pk_1", "human:", "a b", "Human:x", "witness:abc"):
        with pytest.raises(RegistaError) as exc:
            parse_principal_alias(
                _alias(from_principal_id=bad, relation="renamed", scope=_project_scope())
            )
        assert exc.value.detail["reason"] == "from_principal_not_aliasable", bad


def test_to_must_be_canonical():
    for bad in ("mvmcc03-agent", "witness:abc", "key:pk_1", "human:"):
        with pytest.raises(RegistaError) as exc:
            parse_principal_alias(_alias(to_principal_id=bad))
        assert exc.value.detail["reason"] == "not_canonical", bad
        assert exc.value.detail["path"] == "alias.to_principal_id"


def test_a_self_alias_is_refused():
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(
            _alias(from_principal_id="agent:mvmcc03", to_principal_id="agent:mvmcc03")
        )
    assert exc.value.detail["reason"] == "self_alias"


def test_the_asserter_must_itself_be_canonical():
    """A legacy bare name cannot be the authority that retires legacy names."""
    payload = _alias()
    payload["asserted_by"] = dict(payload["asserted_by"], principal_id="itadmin")
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(payload)
    assert exc.value.detail["path"] == "alias.asserted_by.principal_id"


# ---------------------------------------------------------------------------
# §2.5 / WI-055 — the prohibition on a global alias, enforced structurally
# ---------------------------------------------------------------------------


def test_a_global_alias_from_human_itadmin_for_conflated_execution_is_refused():
    """§2.5: 'WI-055 explicitly forbids a *global* alias from ``human:itadmin`` to a new
    agent id, because that id also names genuine human activity elsewhere; the mandatory
    ``scope`` object is how that prohibition is enforced rather than merely stated.'"""
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(_alias(scope=_unscoped_scope()))
    assert exc.value.code == ErrorCode.PRINCIPAL_ALIAS_INVALID
    assert exc.value.detail["reason"] == "conflated_execution_requires_event_set_scope"
    assert exc.value.detail["scope_kind"] == "unscoped"


def test_a_project_wide_conflated_execution_alias_is_also_refused():
    """**Judgment call, stated loudly.** §2.5 pairs ``legacy_conflated_execution`` with
    ``scope.kind="event-set"`` and gives the reason: the ``from`` id "also names genuine
    human activity elsewhere". A project-scoped conflation alias has the same defect at
    project granularity — it re-attributes every human write in that project — so this
    validator requires the enumerable, hash-bounded event set, which is **stricter** than
    merely banning ``unscoped``.

    If Gate 1 turns out to need a project-scoped conflation alias, loosening this is a
    one-line change to ``parse_principal_alias``; tightening it after aliases are signed is
    not. That asymmetry is why it starts strict.
    """
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(_alias(scope=_project_scope()))
    assert exc.value.detail["reason"] == "conflated_execution_requires_event_set_scope"
    assert exc.value.detail["scope_kind"] == "project"


def test_unscoped_is_still_available_for_the_other_two_relations():
    """The prohibition is about conflated execution, not about scoping in general: a
    genuine rename or same-subject join can be domain-wide."""
    for relation in ("same_subject", "renamed"):
        alias = parse_principal_alias(
            _alias(relation=relation, scope=_unscoped_scope())
        )
        assert alias.scope.kind is AliasScopeKind.UNSCOPED


# ---------------------------------------------------------------------------
# §2.5 — the mandatory scope object, field by field
# ---------------------------------------------------------------------------


def test_scope_is_mandatory_and_its_keys_are_exact():
    payload = _alias()
    del payload["scope"]
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(payload)
    assert exc.value.detail["reason"] == "unknown_or_missing_field"

    partial = _event_set_scope()
    del partial["event_count"]
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(_alias(scope=partial))
    assert exc.value.detail["missing"] == ["event_count"]

    extra = _event_set_scope()
    extra["surprise"] = 1
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(_alias(scope=extra))
    assert exc.value.detail["unknown"] == ["surprise"]


def test_unscoped_may_not_carry_inert_event_fields():
    """A scope that can carry ignored fields is a scope a reader cannot trust."""
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(
            _alias(relation="renamed", scope=_unscoped_scope(event_count=230976))
        )
    assert exc.value.detail["reason"] == "unscoped_field_must_be_null"


def test_project_scope_requires_a_project_instance_id_and_no_event_fields():
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(
            _alias(relation="renamed", scope=_project_scope(project_instance_id=None))
        )
    assert exc.value.detail["reason"] == "not_a_string"

    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(
            _alias(relation="renamed", scope=_project_scope(event_hash_set_root=_ROOT))
        )
    assert exc.value.detail["reason"] == "project_scope_event_field_must_be_null"


def test_event_set_scope_requires_the_full_hash_bound():
    for field in ("event_hash_set_root", "first_event_hash", "last_event_hash"):
        with pytest.raises(RegistaError) as exc:
            parse_principal_alias(_alias(scope=_event_set_scope(**{field: None})))
        assert exc.value.detail["path"] == f"alias.scope.{field}"

    for bad_count in (0, -1, None, "230976", True):
        with pytest.raises(RegistaError) as exc:
            parse_principal_alias(_alias(scope=_event_set_scope(event_count=bad_count)))
        assert exc.value.detail["reason"] == "event_count_not_positive", bad_count


def test_event_set_scope_may_not_also_name_a_project():
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(_alias(scope=_event_set_scope(project_instance_id=_PROJECT_ID)))
    assert exc.value.detail["reason"] == "event_set_project_instance_id_must_be_null"


def test_digests_must_be_lowercase_sha256():
    for bad in ("sha256:" + "AB" * 32, "sha512:" + "ab" * 32, "ab" * 32, "sha256:abc"):
        with pytest.raises(RegistaError) as exc:
            parse_principal_alias(_alias(scope=_event_set_scope(event_hash_set_root=bad)))
        assert exc.value.detail["reason"] == "malformed_digest", bad


# ---------------------------------------------------------------------------
# Type / version / id discipline
# ---------------------------------------------------------------------------


def test_type_and_version_are_pinned():
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(_alias(type="regista.identity-cutover-attested"))
    assert exc.value.detail["reason"] == "wrong_type"
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(_alias(version=2))
    assert exc.value.detail["reason"] == "wrong_version"


def test_uuids_must_be_lowercase_canonical():
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(_alias(alias_id=_ALIAS_ID.upper()))
    assert exc.value.detail["reason"] == "non_canonical_uuid"
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(_alias(trust_domain_id="not-a-uuid"))
    assert exc.value.detail["reason"] == "malformed_uuid"


def test_asserted_at_must_be_microsecond_utc():
    for bad in ("2026-08-08T00:00:00Z", "2026-08-08T00:00:00.000Z", "2026-08-08"):
        with pytest.raises(RegistaError) as exc:
            parse_principal_alias(_alias(asserted_at=bad))
        assert exc.value.detail["reason"] == "malformed_timestamp", bad


def test_unknown_relation_is_refused():
    with pytest.raises(RegistaError) as exc:
        parse_principal_alias(_alias(relation="same_person"))
    assert exc.value.detail["reason"] == "unknown_relation"


def test_alias_covers_actor_id_compares_exact_strings():
    alias = parse_principal_alias(_alias())
    assert alias_covers_actor_id(alias, "human:itadmin") is True
    assert alias_covers_actor_id(alias, "agent:mvmcc03") is False
    assert alias_covers_actor_id(alias, "itadmin") is False


# ---------------------------------------------------------------------------
# §2 consequence 2 — the deliberate actor_id → principal_id mapping document
# ---------------------------------------------------------------------------


def test_the_mapping_document_validates_and_round_trips():
    payload = _mapping()
    doc = parse_actor_principal_mapping(payload)
    assert doc.to_dict() == payload
    assert doc.mapped_actor_ids == frozenset({"mvmcc03-agent", "agent-notes"})
    assert doc.principal_for("mvmcc03-agent") == "agent:mvmcc03"
    assert doc.principal_for("never-seen") is None


def test_every_writing_actor_resolves_to_exactly_one_canonical_principal():
    """P2.3's acceptance criterion. A duplicate is refused even when both entries agree —
    a reader who has to reconcile duplicates will eventually pick the wrong one."""
    payload = _mapping()
    payload["entries"] = payload["entries"] + [
        {
            "actor_id": "mvmcc03-agent",
            "principal_id": "agent:mvmcc03",
            "basis": "operator-inspection",
            "evidence": "same assignment, stated twice",
        }
    ]
    with pytest.raises(RegistaError) as exc:
        parse_actor_principal_mapping(payload)
    assert exc.value.code == ErrorCode.PRINCIPAL_MAPPING_INVALID
    assert exc.value.detail["reason"] == "duplicate_actor_id"
    assert exc.value.detail["actor_id"] == "mvmcc03-agent"


def test_a_mapping_target_must_be_canonical():
    payload = _mapping()
    payload["entries"][0]["principal_id"] = "mvmcc03-agent"
    with pytest.raises(RegistaError) as exc:
        parse_actor_principal_mapping(payload)
    assert exc.value.detail["reason"] == "not_canonical"


@pytest.mark.parametrize(
    "basis",
    [
        # the spellings an enumerated denylist would have covered
        "string-similarity",
        "string_similarity",
        "name-similarity",
        # ...and the ones it would not: the refusal is on the *shape* of the claim, so it
        # cannot be spelled around
        "fuzzy-match",
        "fuzzy_matching",
        "nameSimilarityScore",
        "looks-like-the-host",
        "levenshtein match",
        "STRING-SIMILARITY",
        "  string-similarity  ",
        "best-match-heuristic",
    ],
)
def test_similarity_is_a_named_refusal_however_it_is_spelled(basis):
    """§2 consequence 2: the mapping 'is **never** inferred from string similarity'.

    An enumerated denylist can always be spelled around, and a generic "not in enum" would
    not tell an operator *why*. Matching the shape of the claim — case-insensitively, on
    substrings — means a new spelling lands on the same named refusal rather than on a
    weaker one.
    """
    payload = _mapping()
    payload["entries"][0]["basis"] = basis
    with pytest.raises(RegistaError) as exc:
        parse_actor_principal_mapping(payload)
    assert exc.value.code == ErrorCode.PRINCIPAL_MAPPING_INVALID
    assert exc.value.detail["reason"] == "string_similarity_is_never_a_basis", basis
    assert "never inferred from string similarity" in exc.value.message


@pytest.mark.parametrize("basis", ["inferred", "inference", "guess", "guessed", "GUESS"])
def test_inference_bases_get_their_own_named_refusal(basis):
    """Not similarity claims, but still inference rather than deliberate assignment — a
    distinct reason so an operator is told which rule they hit."""
    payload = _mapping()
    payload["entries"][0]["basis"] = basis
    with pytest.raises(RegistaError) as exc:
        parse_actor_principal_mapping(payload)
    assert exc.value.detail["reason"] == "inference_is_never_a_basis", basis


def test_an_unrecognised_basis_still_falls_through_to_unknown_basis():
    """Closing the similarity enumeration must not swallow the ordinary enum check —
    otherwise every typo would be reported as a similarity claim, which is a lie."""
    payload = _mapping()
    payload["entries"][0]["basis"] = "operator-inspecton"  # typo, not a similarity claim
    with pytest.raises(RegistaError) as exc:
        parse_actor_principal_mapping(payload)
    assert exc.value.detail["reason"] == "unknown_basis"


def test_the_similarity_denylist_never_catches_a_legal_basis():
    """Substring matching is only safe while no legal basis contains a marker. Asserted
    over the whole enum, so growing :class:`MappingBasis` cannot silently make a legal
    value unusable."""
    from regista._principal_alias import _SIMILARITY_MARKERS, _forbidden_basis_reason

    for member in MappingBasis:
        assert _forbidden_basis_reason(str(member)) is None, member
        lowered = str(member).lower()
        for marker in _SIMILARITY_MARKERS:
            assert marker not in lowered, (member, marker)

    # And every legal basis really does parse.
    for member in MappingBasis:
        payload = _mapping()
        payload["entries"][0]["basis"] = str(member)
        assert parse_actor_principal_mapping(payload).entries[0].basis is member


def test_the_basis_enum_contains_no_inference_member():
    assert {str(b) for b in MappingBasis} == {
        "operator-inspection",
        "configuration-record",
        "idp-record",
    }


def test_mapping_entries_must_be_non_empty():
    with pytest.raises(RegistaError) as exc:
        parse_actor_principal_mapping(_mapping(entries=[]))
    assert exc.value.detail["reason"] == "entries_empty"


def test_mapping_is_scoped_like_an_alias():
    """'recorded as signed scoped mappings (Gate 1)' — the same mandatory scope object."""
    doc = parse_actor_principal_mapping(_mapping(scope=_event_set_scope()))
    assert doc.scope.kind is AliasScopeKind.EVENT_SET
    with pytest.raises(RegistaError) as exc:
        parse_actor_principal_mapping(_mapping(scope={"kind": "project"}))
    assert exc.value.detail["reason"] == "unknown_or_missing_field"


def test_mapping_binding_effect_is_also_reporting_join_only():
    """A mapping tells a reporter which principal a legacy writer's records belong to. It
    authorises nothing."""
    with pytest.raises(RegistaError) as exc:
        parse_actor_principal_mapping(_mapping(binding_effect="signature_binding"))
    assert exc.value.detail["reason"] == "binding_effect_not_reporting_join_only"


def test_mapping_document_is_not_mutated_by_parsing():
    payload = _mapping()
    before = copy.deepcopy(payload)
    parse_actor_principal_mapping(payload)
    assert payload == before
