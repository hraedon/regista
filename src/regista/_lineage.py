from __future__ import annotations

import json
from collections.abc import Mapping
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


#: The retired v4 review-verdict payload member. It remains readable only when
#: replaying concrete legacy envelopes; v6 takes lineage from ``producer``.
_REVIEWER_CLAIMS_KEY = "reviewer_claims"
_REVIEWER_LINEAGE_KEY = "model_lineage"


def verdict_reviewer_lineage(payload: Any) -> str | None:
    """Read the legacy v4 reviewer's claimed lineage, or return ``None``.

    This reader exists only for concrete persisted v4 replay. A v6 event must
    never use this vehicle: its signed envelope producer is authoritative.
    """
    if not isinstance(payload, dict):
        return None
    claims = payload.get(_REVIEWER_CLAIMS_KEY)
    if not isinstance(claims, dict):
        return None
    return declared_model_lineage(claims.get(_REVIEWER_LINEAGE_KEY))


def reject_obsolete_reviewer_claims(payload: Any) -> None:
    """Reject the retired reviewer-lineage payload vehicle in v6.

    The signed envelope already carries the reviewer's producer. Keeping a
    second lineage field creates two competing authorities, so even an empty
    ``reviewer_claims`` object has no supported v6 meaning.
    """
    if not isinstance(payload, Mapping) or _REVIEWER_CLAIMS_KEY not in payload:
        return
    raise RegistaError(
        ErrorCode.INVALID_ARGUMENT,
        "reviewer_claims is obsolete in v6 review verdicts; reviewer lineage "
        "must come from the signed producer block",
        detail={
            "reason": "obsolete_reviewer_claims",
            "field": _REVIEWER_CLAIMS_KEY,
        },
    )


def _producer_fields(producer: Any) -> tuple[object, object]:
    if isinstance(producer, Mapping):
        return producer.get("model"), producer.get("model_lineage")
    return getattr(producer, "model", None), getattr(producer, "model_lineage", None)


def _canonical_producer_lineage(producer: Any) -> str | None:
    model, lineage = _producer_fields(producer)
    if not isinstance(model, str) or not model.strip():
        return None
    return declared_model_lineage(lineage)


def event_has_v6_envelope(event: Any) -> bool:
    """True if ``event`` carries a v6 canonical envelope (``version == 6``)."""
    canonical_envelope = getattr(event, "canonical_envelope", None)
    if canonical_envelope is None:
        return False
    try:
        parsed = json.loads(canonical_envelope)
    except (TypeError, ValueError, UnicodeDecodeError):
        return False
    return isinstance(parsed, dict) and parsed.get("version") == 6


def _is_v6_event_or_context(event: Any) -> bool:
    if event_has_v6_envelope(event) or getattr(event, "producer", None) is not None:
        return True
    return any(
        event_has_v6_envelope(prior)
        for prior in getattr(event, "prior_events", ())
    )


def _signed_or_candidate_producer(event: Any) -> Any | None:
    candidate = getattr(event, "producer", None)
    if candidate is not None:
        return candidate
    canonical_envelope = getattr(event, "canonical_envelope", None)
    if canonical_envelope is None:
        return None
    try:
        from ._verification import parse_v6_envelope_strict

        parsed = parse_v6_envelope_strict(canonical_envelope)
    except (TypeError, ValueError):
        return None
    producer = parsed.get("producer")
    return producer if isinstance(producer, Mapping) else None


def require_v6_reviewer_model_lineage(event: Any) -> str:
    """Return the reviewer's canonical lineage from the v6 producer only.

    Persisted events supply the signed envelope producer. A validator context
    supplies the exact producer object that the v6 writer will sign after the
    validator returns. Missing model material, a null model, and an unknown
    lineage all fail closed before distinctness is evaluated.
    """
    producer = _signed_or_candidate_producer(event)
    lineage = _canonical_producer_lineage(producer)
    if lineage is None:
        raise RegistaError(
            ErrorCode.INVALID_MODEL_LINEAGE,
            "a v6 review verdict requires a non-null producer.model and a "
            "canonical producer.model_lineage",
            detail={
                "reason": "reviewer_producer_lineage_missing_or_noncanonical",
                "field": "producer.model_lineage",
                "model": _producer_fields(producer)[0] if producer is not None else None,
                "model_lineage": (
                    _producer_fields(producer)[1] if producer is not None else None
                ),
                "allowed": sorted(MODEL_LINEAGE_FAMILIES),
            },
        )
    return lineage


def reviewer_model_lineage(event: Any) -> str | None:
    """The reviewer's effective lineage for ``event``.

    v6 uses only the signed envelope producer (or the candidate producer in a
    pre-append validator context). Legacy v4 replay retains the old payload
    claim and actor-metadata fallback because those are the vehicles present in
    persisted legacy envelopes.
    """
    if _is_v6_event_or_context(event):
        return _canonical_producer_lineage(_signed_or_candidate_producer(event))
    claimed = verdict_reviewer_lineage(getattr(event, "payload", None))
    if claimed is not None:
        return claimed
    return event_model_lineage(event)


def require_canonical_reviewer_lineage(payload: Any) -> None:
    """Validate the legacy v4 review-verdict lineage claim when it is present.

    v6 rejects the entire vehicle through
    :func:`reject_obsolete_reviewer_claims`; this helper is retained only for
    compatibility with persisted v4 replay.
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
