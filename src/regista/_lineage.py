from __future__ import annotations

import json
from typing import Any, TypeGuard

from ._errors import ErrorCode, RegistaError

#: The canonical lineage vocabulary. A *family* is the unit of review
#: independence: two events with different families were produced by minds
#: independent enough for one to adversarially review the other.
#:
#: Families are unversioned (``V6-ENVELOPE.md`` §1.8) — ``claude-opus-5`` and
#: ``claude-opus-4-8`` are both ``claude-opus``. Whether that rule holds for
#: every line is an open question the owner has flagged: ``kimi-k3`` is a 2.8T
#: model where ``kimi-k2.7`` is 1T, which is a larger gap than some *different*
#: families. See regista WI-286 — the fix is not to smuggle a version into this
#: token but to carry the observed version alongside it, so the independence
#: policy stays changeable at read time.
#:
#: Sibling models of one release are separate families, not one: ``gpt-luna``,
#: ``gpt-terra`` and ``gpt-sol`` are the three gpt-5.6 models and are treated
#: exactly as ``claude-opus``/``claude-sonnet``/``fable`` are — distinct, even
#: though they share a vendor and a release. (Owner decision, 2026-08-10: if
#: Sonnet/Opus/Fable are different lineages then Luna/Terra/Sol are too.)
#:
#: ``codex`` is deliberately absent: it is a *harness*, not a model. A model id
#: that says only ``codex`` does not identify which model ran, and the honest
#: answer is an unresolvable lineage the probe will surface — not a family
#: invented to make the field non-empty.
MODEL_LINEAGE_FAMILIES: frozenset[str] = frozenset(
    {
        "claude-haiku",
        "claude-opus",
        "claude-sonnet",
        "deepseek",
        "fable",
        "glm",
        "gpt-luna",
        "gpt-sol",
        "gpt-terra",
        "kimi",
        "longcat",
        "minimax",
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
