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


#: The review-verdict payload member carrying the reviewer's role-specific model
#: lineage (``REVIEW-VERDICTS.md`` §2.2, ``reviewer_claims.model_lineage``).
_REVIEWER_CLAIMS_KEY = "reviewer_claims"
_REVIEWER_LINEAGE_KEY = "model_lineage"


def verdict_reviewer_lineage(payload: Any) -> str | None:
    """The reviewer's claimed lineage in a review-verdict ``payload``, or None.

    Reads ``payload.reviewer_claims.model_lineage`` (``REVIEW-VERDICTS.md``
    §2.2) and validates it against the closed lineage registry in the same
    ``declared_model_lineage`` sense as ``actor_metadata``: an unvalidated or
    absent value declares nothing and reads as absent yet again, never as an
    invented distinct lineage. A payload that is not a review-verdict (no
    ``reviewer_claims`` object) contributes nothing.
    """
    if not isinstance(payload, dict):
        return None
    claims = payload.get(_REVIEWER_CLAIMS_KEY)
    if not isinstance(claims, dict):
        return None
    return declared_model_lineage(claims.get(_REVIEWER_LINEAGE_KEY))


def reviewer_model_lineage(event: Any) -> str | None:
    """The reviewer's *effective* claimed lineage for ``event`` (WI-305 A).

    Prefers the signed review-verdict payload's ``reviewer_claims.model_lineage``
    — the v6 vehicle, where the role-specific assertion lives and where
    ``actor.metadata`` may not carry ``model_lineage`` at all — and falls back
    to the legacy per-event lineage (``actor_metadata``/``producer``) for events
    written before the verdict carried the claim. ``event`` is anything
    event-shaped: a stored event or a validator ``ctx`` (both expose a
    ``payload``).
    """
    claimed = verdict_reviewer_lineage(getattr(event, "payload", None))
    if claimed is not None:
        return claimed
    return event_model_lineage(event)


def require_canonical_reviewer_lineage(payload: Any) -> None:
    """Reject at ingress a review-verdict whose reviewer lineage claim is not canonical.

    A review-verdict payload that declares a ``reviewer_claims`` object MUST carry
    a canonical ``model_lineage`` (one of ``MODEL_LINEAGE_FAMILIES``). An absent,
    malformed, or unknown value raises ``INVALID_MODEL_LINEAGE`` rather than being
    silently read as undeclared: a signed verdict may not carry a lineage the
    cross-lineage gate would fail closed on at read time. A payload with no
    ``reviewer_claims`` block declares nothing and passes.
    """
    if not isinstance(payload, dict):
        return
    claims = payload.get(_REVIEWER_CLAIMS_KEY)
    if claims is None:
        return
    value = claims.get(_REVIEWER_LINEAGE_KEY) if isinstance(claims, dict) else claims
    if not is_model_lineage(value):
        raise RegistaError(
            ErrorCode.INVALID_MODEL_LINEAGE,
            "reviewer_claims.model_lineage must be a canonical model lineage",
            detail={
                "field": "reviewer_claims.model_lineage",
                "model_lineage": value,
                "allowed": sorted(MODEL_LINEAGE_FAMILIES),
            },
        )


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
