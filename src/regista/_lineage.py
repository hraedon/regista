from __future__ import annotations

import json
from typing import Any, TypeGuard

from ._errors import ErrorCode, RegistaError

MODEL_LINEAGE_FAMILIES: frozenset[str] = frozenset(
    {
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
)


def is_model_lineage(value: object) -> TypeGuard[str]:
    return isinstance(value, str) and value in MODEL_LINEAGE_FAMILIES


def declared_model_lineage(value: object) -> str | None:
    return value if is_model_lineage(value) else None


def validate_model_lineage(value: object, *, field: str) -> str:
    if not is_model_lineage(value):
        raise RegistaError(
            ErrorCode.INVALID_MODEL_LINEAGE,
            f"Invalid {field} {value!r}. Must be one of {sorted(MODEL_LINEAGE_FAMILIES)}",
            detail={
                "field": field,
                "model_lineage": value,
                "allowed": sorted(MODEL_LINEAGE_FAMILIES),
            },
        )
    return value


def raw_event_model_lineage(event: Any) -> object:
    canonical_envelope = getattr(event, "canonical_envelope", None)
    if canonical_envelope is not None:
        try:
            parsed = json.loads(canonical_envelope)
        except (TypeError, ValueError, UnicodeDecodeError):
            return None
        if isinstance(parsed, dict) and parsed.get("version") == 6:
            try:
                from ._verification import parse_v6_envelope_strict

                parsed = parse_v6_envelope_strict(canonical_envelope)
            except (TypeError, ValueError):
                return None
            producer = parsed.get("producer")
            return producer.get("model_lineage") if isinstance(producer, dict) else None

    metadata = getattr(event, "actor_metadata", None)
    return metadata.get("model_lineage") if isinstance(metadata, dict) else None


def event_model_lineage(event: Any) -> str | None:
    return declared_model_lineage(raw_event_model_lineage(event))
