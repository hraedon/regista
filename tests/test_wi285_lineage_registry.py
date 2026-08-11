from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from regista import LineageRelation, lineage_relation
from regista._contract import validate_actor_metadata, validate_delegation_chain
from regista._errors import ErrorCode, RegistaError
from regista._lineage import MODEL_LINEAGE_FAMILIES, declared_model_lineage
from regista._signing import canonicalize_v6_envelope
from regista._verification import V6EnvelopeError
from regista.testing import InMemoryRegista

TESTS_DIR = Path(__file__).parent
KEY_PATH = str(TESTS_DIR / "test_keys.json")
V6_VECTOR = TESTS_DIR / "vectors" / "v6" / "v6-envelope-basic.json"

EXPECTED_FAMILIES = {
    "claude-haiku",
    "claude-opus",
    "claude-sonnet",
    "deepseek",
    "fable",
    "glm",
    "gpt-codex",
    "gpt-luna",
    "gpt-sol",
    "kimi",
    "longcat",
    "nemotron",
    "qwen",
}


def test_registry_is_the_release_controlled_family_vocabulary() -> None:
    assert MODEL_LINEAGE_FAMILIES == EXPECTED_FAMILIES


@pytest.mark.parametrize("lineage", sorted(EXPECTED_FAMILIES))
def test_every_registered_family_is_accepted(lineage: str) -> None:
    validate_actor_metadata({"model_lineage": lineage})
    validate_delegation_chain(
        {
            "principal_id": "agent:delegated",
            "principal_kind": "agent",
            "principal_lineage": lineage,
        }
    )


def test_explicit_null_lineage_remains_undeclared() -> None:
    validate_actor_metadata({"model_lineage": None})
    validate_delegation_chain(
        {"principal_id": "agent:test", "principal_lineage": None}
    )


@pytest.mark.parametrize(
    "lineage",
    [
        "claude",
        "opus",
        "opus-5",
        "claude-opus-5",
        "claude-opus-4-8",
        "glm-5.2",
        "nemotron-3-ultra",
        "openai/gpt-5.6-sol",
        "umans-glm-5.2",
        "opencode",
        " CLAUDE-OPUS ",
        "",
        42,
    ],
)
def test_unknown_ambiguous_and_versioned_tokens_are_rejected(lineage: object) -> None:
    with pytest.raises(RegistaError) as exc_info:
        validate_actor_metadata({"model_lineage": lineage})
    assert exc_info.value.code is ErrorCode.INVALID_MODEL_LINEAGE


def test_delegated_lineage_uses_the_same_registry() -> None:
    with pytest.raises(RegistaError) as exc_info:
        validate_delegation_chain(
            {
                "principal_id": "agent:delegated",
                "principal_kind": "agent",
                "principal_lineage": "claude-opus-5",
            }
        )
    assert exc_info.value.code is ErrorCode.INVALID_MODEL_LINEAGE


def test_delegated_lineage_is_validated_without_principal_kind() -> None:
    with pytest.raises(RegistaError) as exc_info:
        validate_delegation_chain(
            {
                "principal_id": "agent:delegated",
                "principal_lineage": "claude-opus-5",
            }
        )
    assert exc_info.value.code is ErrorCode.INVALID_MODEL_LINEAGE
    assert exc_info.value.detail["field"] == "on_behalf_of.principal_lineage"


def test_unresolvable_values_never_compare_distinct() -> None:
    assert lineage_relation({"claude-opus"}, "claude") is LineageRelation.UNKNOWN
    assert lineage_relation({"claude-opus-5"}, "glm") is LineageRelation.UNKNOWN
    assert lineage_relation({"claude-opus", "typo"}, "glm") is LineageRelation.UNKNOWN
    assert declared_model_lineage("claude") is None


def test_same_family_builds_compare_same_after_canonical_mapping() -> None:
    author_model = "claude-opus-5"
    reviewer_model = "claude-opus-4-8"
    model_to_family = {
        author_model: "claude-opus",
        reviewer_model: "claude-opus",
    }
    assert (
        lineage_relation(
            {model_to_family[author_model]}, model_to_family[reviewer_model]
        )
        is LineageRelation.SAME
    )


def test_v6_producer_rejects_an_unknown_family() -> None:
    case = json.loads(V6_VECTOR.read_text(encoding="utf-8"))
    envelope = copy.deepcopy(case["input"]["envelope_declaration_order"])
    envelope["producer"]["model_lineage"] = "claude-opus-5"
    with pytest.raises(V6EnvelopeError, match="registered model family"):
        canonicalize_v6_envelope(envelope)


def test_in_memory_write_refuses_unknown_lineage_before_emitting_event() -> None:
    sub = InMemoryRegista(project="wi285-ingress", hmac_key_path=KEY_PATH)
    sub.register_workflow((TESTS_DIR / "test_workflow.yaml").read_text(encoding="utf-8"))
    try:
        with pytest.raises(RegistaError) as exc_info:
            sub.create_work_item(
                "test_workflow",
                "feature",
                "agent:author",
                actor_metadata={"model_lineage": "claude-opus-5"},
                custom_fields={"title": "refused before append"},
            )
        assert exc_info.value.code is ErrorCode.INVALID_MODEL_LINEAGE
        assert sub.read_events(limit=100) == []
    finally:
        sub.close()
