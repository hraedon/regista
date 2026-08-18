"""P2.3 — the canonical principal grammar and backend-safe naming.

Normative source: ``docs/0.6.0/TRUST-DOMAIN.md`` §2.1 (ABNF + "additional rules, all
enforced") and §2.2 (the derived backend name).

These tests pin the *grammar*, which is a wire contract: a principal id that validates
today is a principal id whose signed events must keep verifying, and a spelling that is
refused today must stay refused or previously-refused identities silently become legal.
Every closed set is asserted as a set, not sampled.
"""

from __future__ import annotations

import hashlib

import pytest

from regista._errors import ErrorCode, RegistaError
from regista._principals import (
    ACTOR_KIND_BY_PRINCIPAL_KIND,
    BACKEND_NAME_DOMAIN,
    BACKEND_NAME_PREFIX,
    FORBIDDEN_KINDS,
    MAX_PRINCIPAL_ID_BYTES,
    MAX_SUBJECT_LENGTH,
    PRINCIPAL_KINDS,
    SUBJECT_EDGE_FORBIDDEN,
    IdentityConsistency,
    MappingStatus,
    PrincipalForm,
    backend_name,
    classify_principal_id,
    identity_consistency,
    is_backend_name,
    is_canonical_principal_id,
    mapping_status,
    parse_principal_id,
    principal_id_kind,
    resolve_backend_name,
    validate_principal_id,
)

# ---------------------------------------------------------------------------
# §2.1 — the closed sets, asserted exactly
# ---------------------------------------------------------------------------


def test_kind_set_is_exactly_the_three_ratified_kinds():
    """§2.1: 'There is no ``unknown`` kind and no extension mechanism in 0.6.0.'"""
    assert PRINCIPAL_KINDS == frozenset({"human", "agent", "service"})


def test_witness_is_not_a_kind():
    """§2.3 cut the fourth convention. ``witness:<uuid>`` must not validate."""
    assert "witness" not in PRINCIPAL_KINDS
    c = classify_principal_id("witness:0f6c1b2e-1111-4222-8333-444455556666")
    assert c.form is PrincipalForm.UNGRAMMATICAL
    assert c.reason == "kind_not_canonical"
    # ...but the canonical service form §2.3 names for a future release does validate.
    assert is_canonical_principal_id("service:witness.0f6c1b2e-1111-4222-8333-444455556666")


def test_key_is_never_a_principal_at_every_creation_path():
    """§2.1: '``key:*`` is never a principal … rejected as a kind at every creation path'."""
    assert FORBIDDEN_KINDS == frozenset({"key"})
    c = classify_principal_id("key:pk_4f70570b481745a8")
    assert c.form is PrincipalForm.UNGRAMMATICAL
    # A *named* reason, not a generic "unknown kind" — this is the rule WI-055 called out.
    assert c.reason == "key_is_never_a_principal"
    with pytest.raises(RegistaError) as exc:
        validate_principal_id("key:pk_4f70570b481745a8")
    assert exc.value.code == ErrorCode.PRINCIPAL_ID_UNGRAMMATICAL
    assert exc.value.detail["reason"] == "key_is_never_a_principal"


@pytest.mark.parametrize(
    "value",
    [
        "human:itadmin",
        "agent:mvmcc03",
        "agent:mvmcc02",
        "agent:mvmhermes01",
        "agent:mvmcc03-claude-code",
        "service:witness.0f6c1b2e-1111-4222-8333-444455556666",
        # §2.1: 'an IdP subject containing colons … is legal and unambiguous'
        "service:idp:tenant-a/svc-7",
        # every subject-char class in one subject
        "agent:a.b_c-d~e:f/g9",
        "human:0f6c1b2e-1111-4222-8333-444455556666",
    ],
)
def test_canonical_examples_validate(value):
    assert is_canonical_principal_id(value)
    assert validate_principal_id(value) == value


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("", "empty"),
        ("Human:itadmin", "kind_not_canonical"),  # §2.1: case-sensitive, lowercase
        ("HUMAN:itadmin", "kind_not_canonical"),
        ("robot:x", "kind_not_canonical"),
        ("unknown:x", "kind_not_canonical"),  # §2.1: 'There is no `unknown` kind'
        ("human:", "subject_empty"),
        ("human::x", "subject_edge_char"),
        ("human:.x", "subject_edge_char"),
        ("human:-x", "subject_edge_char"),
        ("human:_x", "subject_edge_char"),
        ("human:/x", "subject_edge_char"),
        ("human:x:", "subject_edge_char"),
        ("human:x.", "subject_edge_char"),
        ("human:x-", "subject_edge_char"),
        ("human:x_", "subject_edge_char"),
        ("human:x/", "subject_edge_char"),
        ("human:a b", "subject_char_not_allowed"),
        ("human:a+b", "subject_char_not_allowed"),
        ("human:a@b", "subject_char_not_allowed"),
        ("human:a%b", "subject_char_not_allowed"),
        ("human:ítadmin", "non_ascii"),  # §2.1: ASCII only
        ("plm@hraedon.com", "not_kind_colon_subject"),  # the estate's email convention
        ("a b", "not_kind_colon_subject"),
    ],
)
def test_ungrammatical_examples_are_refused_with_a_named_reason(value, reason):
    c = classify_principal_id(value)
    assert c.form is PrincipalForm.UNGRAMMATICAL, value
    assert c.reason == reason, value
    assert c.kind is None
    with pytest.raises(RegistaError) as exc:
        validate_principal_id(value)
    assert exc.value.code == ErrorCode.PRINCIPAL_ID_UNGRAMMATICAL
    assert exc.value.detail["reason"] == reason


def test_subject_is_everything_after_the_first_colon():
    parsed = parse_principal_id("service:idp:tenant-a/svc-7")
    assert parsed.kind == "service"
    assert parsed.subject == "idp:tenant-a/svc-7"
    assert parsed.text == "service:idp:tenant-a/svc-7"


def test_subject_edge_forbidden_set_is_exactly_the_five_characters_named():
    assert set(SUBJECT_EDGE_FORBIDDEN) == {":", ".", "-", "_", "/"}


def test_subject_length_bounds_are_1_to_247():
    assert MAX_SUBJECT_LENGTH == 247
    ok = "agent:" + "a" * 247
    assert is_canonical_principal_id(ok)
    too_long = "agent:" + "a" * 248
    assert classify_principal_id(too_long).reason == "subject_too_long"


def test_total_length_ceiling_is_256_utf8_bytes():
    """§2.1: 'Total length ≤ 256 bytes UTF-8.'

    The ABNF's own bound is tighter: the longest kind is ``service`` (7) plus ``:`` plus a
    247-char subject = 255 characters, which is also what
    ``V6-ENVELOPE.md`` §1 records (``≤ 255``). The 256-byte rule is therefore a ceiling the
    subject bound already keeps us under, and the two never disagree. Asserted here so a
    future kind-set widening cannot cross 256 unnoticed.
    """
    assert MAX_PRINCIPAL_ID_BYTES == 256
    longest = "service:" + "a" * MAX_SUBJECT_LENGTH
    assert len(longest) == 255
    assert is_canonical_principal_id(longest)
    assert max(len(k) for k in PRINCIPAL_KINDS) + 1 + MAX_SUBJECT_LENGTH <= (
        MAX_PRINCIPAL_ID_BYTES
    )
    # Over the byte ceiling is refused before any subject reasoning.
    assert classify_principal_id("agent:" + "a" * 300).reason == "too_long"


def test_nfc_is_asserted_even_though_ascii_makes_it_a_no_op():
    """§2.1 asserts NFC 'so a future relaxation cannot silently change bytes that were
    already signed'. Under ASCII-only the assertion is unreachable via a non-NFC ASCII
    string, so the property is proven the only way it can be: normalisation is a no-op on
    every value the grammar accepts."""
    import unicodedata

    for value in ("human:itadmin", "service:idp:tenant-a/svc-7", "agent:a~b_c-d.e"):
        assert unicodedata.normalize("NFC", value) == value
    # A decomposed non-ASCII value is refused, and refused as non-ASCII (which is checked
    # first) rather than slipping through as "already normalised".
    assert classify_principal_id("human:éx").reason == "non_ascii"


def test_non_string_input_is_classified_not_crashed():
    for value in (None, 42, b"human:itadmin", ["human:itadmin"]):
        c = classify_principal_id(value)
        assert c.form is PrincipalForm.UNGRAMMATICAL
        assert c.reason == "not_a_string"


# ---------------------------------------------------------------------------
# §2.4 convention 2 — the legacy bare name is a distinct, aliasable failure mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        # §2.4's own live examples
        "human-1",
        "suite-service",
        "mvmcc03-agent",
        # and the ones the preflight actually found
        "agent-notes",
        "claude-fable-5",
        "adversarial-reviewer-nemotron-3-ultra",
        "plm",
    ],
)
def test_legacy_bare_names_classify_as_bare_name_not_junk(value):
    c = classify_principal_id(value)
    assert c.form is PrincipalForm.BARE_NAME
    assert c.kind is None
    assert c.reason == "bare_name_not_canonical"


def test_bare_name_refusal_carries_a_pointer_to_the_alias_path():
    """Criterion 19's operator affordance: the refusal must say what to do instead."""
    with pytest.raises(RegistaError) as exc:
        validate_principal_id("mvmcc03-agent")
    assert exc.value.code == ErrorCode.PRINCIPAL_ID_NOT_CANONICAL
    assert exc.value.detail["remedy"] == "principal_alias_bound"
    assert exc.value.detail["alias_payload_type"] == "regista.principal-alias"
    assert "§2.5" in exc.value.message
    # And it never claims the alias will make the old name work for signing.
    assert "never satisfies signature binding" in exc.value.message


def test_bare_name_and_ungrammatical_use_distinct_error_codes():
    """A distinct code is what lets an operator tell 'old convention' from 'not an id'."""
    assert ErrorCode.PRINCIPAL_ID_NOT_CANONICAL != ErrorCode.PRINCIPAL_ID_UNGRAMMATICAL


# ---------------------------------------------------------------------------
# §2.6 — actor_id_kind and the computed conflict state
# ---------------------------------------------------------------------------


def test_actor_id_kind_is_null_for_a_bare_legacy_id():
    """§2.6: '``actor_id_kind`` — the prefix, or ``null`` for a bare legacy id'."""
    assert principal_id_kind("human:itadmin") == "human"
    assert principal_id_kind("agent:mvmcc03") == "agent"
    assert principal_id_kind("service:witness.abc") == "service"
    assert principal_id_kind("mvmcc03-agent") is None
    assert principal_id_kind("witness:abc") is None  # a non-canonical prefix is not a kind


def test_actor_kind_vocabulary_maps_service_to_the_row_spelling_system():
    """regista's ``actor_kind`` set is {agent, human, system} (`_contract.py:19`); the
    principal kind set is {human, agent, service}. The mapping must be total over the
    principal kinds or a canonical id could never be reported consistent."""
    from regista._contract import _VALID_ACTOR_KINDS

    assert set(ACTOR_KIND_BY_PRINCIPAL_KIND) == set(PRINCIPAL_KINDS)
    assert _VALID_ACTOR_KINDS == frozenset({"agent", "human", "system"})
    for kind, accepted in ACTOR_KIND_BY_PRINCIPAL_KIND.items():
        assert accepted & _VALID_ACTOR_KINDS, kind


def test_the_231k_corpus_shape_is_a_principal_kind_conflict():
    """§2.6's worked example: ``human:itadmin`` rows carrying ``actor_kind=agent``."""
    assert (
        identity_consistency("human:itadmin", "agent")
        is IdentityConsistency.PRINCIPAL_KIND_CONFLICT
    )
    assert identity_consistency("human:itadmin", "human") is IdentityConsistency.CONSISTENT
    assert identity_consistency("agent:mvmcc03", "agent") is IdentityConsistency.CONSISTENT
    assert identity_consistency("service:witness.a", "system") is IdentityConsistency.CONSISTENT


def test_bare_actor_id_is_ungrammatical_not_a_kind_conflict():
    assert (
        identity_consistency("mvmcc03-agent", "agent")
        is IdentityConsistency.ACTOR_ID_UNGRAMMATICAL
    )


def test_null_actor_kind_is_named_not_silently_consistent():
    """``EventRow.actor_kind`` is ``str | None``; claiming ``consistent`` for a comparison
    that was never made would be a false claim."""
    assert (
        identity_consistency("human:itadmin", None) is IdentityConsistency.ACTOR_KIND_ABSENT
    )


def test_mapping_absent_only_when_a_population_was_supplied():
    """§2 consequence 2: 'An unmapped writer is ``identity_consistency: mapping_absent``,
    not a guess.' Silence when no population was given is the honest default."""
    assert (
        identity_consistency("mvmcc03-agent", "agent")
        is IdentityConsistency.ACTOR_ID_UNGRAMMATICAL
    )
    assert (
        identity_consistency("mvmcc03-agent", "agent", mapped_actor_ids=[])
        is IdentityConsistency.MAPPING_ABSENT
    )
    assert (
        identity_consistency("mvmcc03-agent", "agent", mapped_actor_ids=["mvmcc03-agent"])
        is IdentityConsistency.ACTOR_ID_UNGRAMMATICAL
    )


def test_a_kind_conflict_is_never_masked_by_the_mapping_axis():
    """The 231k corpus is *both* facts. Collapsing them into one field loses one."""
    assert (
        identity_consistency("human:itadmin", "agent", mapped_actor_ids=[])
        is IdentityConsistency.PRINCIPAL_KIND_CONFLICT
    )
    assert (
        mapping_status("human:itadmin", mapped_actor_ids=[]) is MappingStatus.SELF_CANONICAL
    )


def test_mapping_status_tristate():
    assert mapping_status("mvmcc03-agent") is MappingStatus.NOT_EVALUATED
    assert mapping_status("mvmcc03-agent", mapped_actor_ids=[]) is MappingStatus.MAPPING_ABSENT
    assert (
        mapping_status("mvmcc03-agent", mapped_actor_ids={"mvmcc03-agent"})
        is MappingStatus.MAPPED
    )
    assert mapping_status("agent:mvmcc03") is MappingStatus.SELF_CANONICAL


def test_identity_consistency_never_infers_a_principal_from_string_similarity():
    """§2 consequence 2. ``mvmcc03-agent`` looks exactly like ``agent:mvmcc03``; the
    grammar layer must still refuse to connect them."""
    assert principal_id_kind("mvmcc03-agent") is None
    assert (
        mapping_status("mvmcc03-agent", mapped_actor_ids={"agent:mvmcc03"})
        is MappingStatus.MAPPING_ABSENT
    )


# ---------------------------------------------------------------------------
# §2.2 — backend-safe naming
# ---------------------------------------------------------------------------


def test_backend_name_matches_the_frozen_formula_byte_for_byte():
    """§2.2: ``"rp-" || lowercase_hex(SHA256(domain || utf8(principal_id))[0:16])``.

    Recomputed here from the spec text rather than from the module's constants, so a typo
    in either the domain separator or the truncation length is caught.
    """
    for principal_id in (
        "human:itadmin",
        "agent:mvmcc03",
        "service:idp:tenant-a/svc-7",
        "mvmcc03-agent",
    ):
        expected = "rp-" + hashlib.sha256(
            b"regista.principal-name.v1\x00" + principal_id.encode("utf-8")
        ).hexdigest()[:32]
        assert backend_name(principal_id) == expected
    assert BACKEND_NAME_DOMAIN == b"regista.principal-name.v1\x00"
    assert BACKEND_NAME_PREFIX == "rp-"


def test_backend_name_pins_a_known_vector():
    """A literal so a refactor of the derivation cannot silently rename every secret."""
    assert backend_name("human:itadmin") == "rp-ef29a69834a92009bb7faf4661dc703b"


def test_backend_name_is_16_bytes_of_hex_and_contains_no_colon():
    name = backend_name("service:idp:tenant-a/svc-7")
    assert is_backend_name(name)
    assert len(name) == len("rp-") + 32
    assert ":" not in name  # the whole point: KV and the Windows store forbid it
    assert name == name.lower()


def test_backend_name_is_not_a_colon_to_hyphen_substitution():
    """§2.2: 'The ratified decision is a collision-resistant derived name, **not**
    ``:``→``-`` substitution.' The substitution collides; the derivation does not."""
    assert backend_name("human:it-admin") != backend_name("human-it:admin")
    assert "human-it-admin" not in (
        backend_name("human:it-admin"),
        backend_name("human-it:admin"),
    )
    # And the two colliding-under-substitution ids get distinct derived names.
    assert len({backend_name("human:it-admin"), backend_name("human-it:admin")}) == 2


def test_backend_name_accepts_legacy_ids_because_they_already_hold_secrets():
    """Grammar enforcement belongs at the §2.7 creation paths, not at name derivation: a
    legacy principal whose secret cannot be addressed is a principal that cannot be
    revoked."""
    assert is_backend_name(backend_name("mvmcc03-agent"))


def test_backend_name_refuses_an_empty_principal_id():
    with pytest.raises(RegistaError) as exc:
        backend_name("")
    assert exc.value.code == ErrorCode.INVALID_ARGUMENT
    assert exc.value.detail["reason"] == "empty_principal_id"


def test_resolve_backend_name_derives_and_compares():
    candidates = ["human:itadmin", "agent:mvmcc03", "mvmcc03-agent"]
    for candidate in candidates:
        assert resolve_backend_name(backend_name(candidate), candidates) == candidate


def test_resolve_backend_name_returns_none_rather_than_guessing():
    """§2.2's lookup is only as complete as the candidate set. ``None`` means 'not among
    the principals I was given', never 'not a principal' — and never a near-match."""
    assert resolve_backend_name(backend_name("agent:mvmcc03"), ["mvmcc03-agent"]) is None
    assert resolve_backend_name(backend_name("agent:mvmcc03"), []) is None


def test_resolve_backend_name_refuses_a_malformed_name():
    for bad in ("mvmcc03-agent", "rp-", "rp-XYZ", "rp-" + "a" * 31, "RP-" + "a" * 32):
        with pytest.raises(RegistaError) as exc:
            resolve_backend_name(bad, ["human:itadmin"])
        assert exc.value.code == ErrorCode.INVALID_ARGUMENT
        assert exc.value.detail["reason"] == "malformed_backend_name"


def test_parsed_principal_id_exposes_its_backend_name():
    parsed = parse_principal_id("human:itadmin")
    assert parsed.backend_name == backend_name("human:itadmin")


# ---------------------------------------------------------------------------
# §2.2 — the mandated CLI lookup verb
# ---------------------------------------------------------------------------
#
# "a lookup verb (`regista principal resolve-backend-name <backend_name>`) must exist, or
# the KV tree becomes unauditable by hand — which the migration posture depends on."


def _run_cli(*args):
    import subprocess
    import sys

    return subprocess.run(
        [sys.executable, "-m", "regista._cli", *args],
        capture_output=True,
        text=True,
    )


def test_the_resolve_backend_name_verb_exists():
    out = _run_cli("principal", "resolve-backend-name", "--help")
    assert out.returncode == 0
    assert "BACKEND_NAME" in out.stdout
    assert "--principal-id" in out.stdout


def test_the_verb_confirms_a_candidate_without_a_database():
    """The ``--principal-id`` mode is pure derivation: no DSN, no registry, no secret read.
    That is what makes the KV tree auditable by hand from any machine."""
    name = backend_name("human:itadmin")
    out = _run_cli(
        "principal", "resolve-backend-name", name, "--principal-id", "human:itadmin", "--json"
    )
    assert out.returncode == 0, out.stderr
    import json

    payload = json.loads(out.stdout)
    assert payload["principal_id"] == "human:itadmin"
    assert payload["confirmed"] is True
    assert payload["derived_backend_name"] == name
    assert payload["source"] == "candidate"


def test_the_verb_exits_non_zero_on_a_non_match_and_names_what_it_derived():
    name = backend_name("human:itadmin")
    out = _run_cli(
        "principal", "resolve-backend-name", name, "--principal-id", "agent:mvmcc03", "--json"
    )
    assert out.returncode == 1
    import json

    payload = json.loads(out.stdout)
    assert payload["confirmed"] is False
    assert payload["principal_id"] is None
    assert payload["derived_backend_name"] == backend_name("agent:mvmcc03")


def test_the_verb_refuses_a_malformed_backend_name():
    out = _run_cli("principal", "resolve-backend-name", "human:itadmin", "--json")
    assert out.returncode == 1
    import json

    payload = json.loads(out.stdout)
    assert payload["ok"] is False
    assert payload["error"]["code"] == "INVALID_ARGUMENT"
    assert "malformed_backend_name" in payload["error"]["detail"]


def test_the_verb_never_prints_secret_material():
    """§2.2 stores the canonical id *inside* the secret, but the resolver reads the
    non-secret ``principal_keys`` registry instead, so nothing it prints can be key
    material. Asserted on the shape of what it emits."""
    name = backend_name("human:itadmin")
    out = _run_cli(
        "principal", "resolve-backend-name", name, "--principal-id", "human:itadmin", "--json"
    )
    import json

    payload = json.loads(out.stdout)
    assert set(payload) == {
        "backend_name",
        "principal_id",
        "confirmed",
        "derived_backend_name",
        "source",
        "candidates_considered",
    }
    for forbidden in ("secret", "private", "public_key", "material", "fingerprint"):
        assert forbidden not in out.stdout.lower()
