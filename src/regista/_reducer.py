"""Reducer v1 — the deterministic reduction of a signed event prefix.

This is the function `content_state_digest` is computed over
(`REVIEW-VERDICTS.md` §2.3, as simplified by `RECONCILIATION.md` Resolution 4):

    content_state_digest = SHA256(
        b"regista.review-subject.state.v1\\x00" || JCS(reduce_v1(E[0..k]))
    )

A signed review verdict binds itself to the content it reviewed by naming this digest. So the
reduction has to satisfy a property ordinary replay does not: **byte-identical output for the
same signed prefix, on any machine, on any interpreter, at any version.** If it drifts, verdicts
signed before the drift cannot be verified after it, and the binding that makes a verdict mean
anything silently stops holding.

Three rules follow from that, and they are the whole difference between this module and
``_replay._replay_work_item``:

1. **Pure function of signed material.** Input is canonical envelope bytes plus the workflow
   definitions carried by signed ``workflow_registered`` events. No database, no
   ``workflow_registry`` row, no projection table. An offline auditor holding only a bundle must
   reach the same answer — a subject binding a bundle verifier cannot check is not a binding.

2. **Fail closed, never fail soft.** ``_replay`` logs a warning and substitutes ``None`` for a
   malformed timestamp (``_replay._parse_not_before``). That is right for replay, whose job is to
   rebuild a projection from a messy history, and wrong here: it converts a *parsing*
   disagreement into a *digest* disagreement, silently. Anything this reducer cannot parse raises
   :class:`ReducerError`.

3. **No delegation to version-dependent parsers.** ``datetime.fromisoformat`` accepts a
   different language on different interpreters — measured, not assumed: CPython 3.14 parses
   ``"2026-08-09T24:00:00Z"`` as the following midnight, while CPython 3.12, CPython 3.13 and
   PyPy 3.11 raise ``ValueError``. Combined with rule 2's fail-soft opposite, that single string
   produces two different reduced states, two different digests, and a verdict that verifies on
   one host and reads as stale on another. This module parses RFC 3339 itself, with an explicit
   grammar, so acceptance is a property of the specification rather than of the runtime.

See ``tests/test_reducer_v1_determinism.py`` for the conformance vectors, and
``tools/reducer_v1_sweep.py`` for the cross-interpreter sweep.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from hashlib import sha256
from typing import Any

from ._jcs import canonicalize

REDUCER_VERSION = 1

STATE_DOMAIN = b"regista.review-subject.state.v1\x00"

#: Transitions that mutate claim/lease state rather than item content.
_CLAIM_TRANSITIONS = frozenset(
    {
        "claim_acquired",
        "claim_stolen",
        "claim_released",
        "claim_expired",
        "claim_heartbeat",
    }
)

#: Transitions handled without consulting a workflow definition. Mirrors
#: ``_replay._replay_work_item``; kept as an explicit set so a new transition
#: cannot be added to replay and silently change every historical digest.
_INTRINSIC_TRANSITIONS = frozenset(
    {"created", "escalated", "not_before_set", "link_created", "link_removed", "hook_dead_lettered"}
) | _CLAIM_TRANSITIONS

#: Fields that describe who holds the work rather than what the work says.
_CLAIM_FIELDS = ("claimed_by", "claim_expires_at", "claim_coalesce_threshold", "attempt_number")

# RFC 3339 with a mandatory offset. Deliberately narrower than ISO 8601: no week
# dates, no ordinal dates, no basic format, no 24:00, no bare date, no naive
# timestamp. Every one of those is a place two implementations can disagree.
_RFC3339 = re.compile(
    r"^(?P<y>\d{4})-(?P<mo>\d{2})-(?P<d>\d{2})"
    r"[Tt]"
    r"(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})"
    r"(?:\.(?P<frac>\d{1,9}))?"
    r"(?:[Zz]|(?P<sign>[+-])(?P<oh>\d{2}):(?P<om>\d{2}))$"
)


class ReducerError(ValueError):
    """The prefix cannot be reduced. Never recovered from, never defaulted."""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise ReducerError(f"duplicate object key in signed bytes: {key!r}")
        seen.add(key)
    return dict(pairs)


def _reject_constant(name: str) -> Any:
    raise ReducerError(f"non-JSON constant in signed bytes: {name}")


#: JCS's safe integer domain (`_vendor/rfc8785.py`). Values outside it have no canonical form.
_SAFE_INT_MAX = 2**53 - 1


def _check_number_domain(value: int | float, *, where: str) -> None:
    """Reject numbers whose canonical form cannot be re-canonicalised.

    JCS serialises numbers in ES6 form, which prints any float below 1e21 without an exponent.
    So the float ``1e16`` canonicalises to the *integer literal* ``10000000000000000`` — and
    when a verifier parses those canonical bytes back, it gets a Python ``int`` of 10^16, which
    is outside JCS's safe integer domain and **cannot be canonicalised again**.

    The band is exact and measured: floats with ``2**53 <= |v| < 1e21`` round-trip into
    uncanonicalisable integers. At or above 1e21 ES6 switches to exponential form and the value
    round-trips as a float; below 2**53 the integer is inside the safe domain.

    That is a hole in the envelope contract, not just in this reducer: an event carrying such a
    number is signable, is canonical, and yet has no computable subject digest.

    This reducer takes the **stricter** line and rejects every number with ``|v| >= 2**53``,
    integer or float, rather than carving out the exact non-round-tripping band. Two reasons.
    The precise rule needs a case analysis over ES6's exponential-form threshold, and a rule two
    implementations must reproduce identically should be one comparison. And the region above
    2**53 is where number handling differs most between implementations anyway — it is the
    region where a JSON number stops being exactly representable as a double. Values that large
    are identifiers; identifiers belong in strings.

    This is stricter than JCS and stricter than `V6-ENVELOPE.md` §2.5 as frozen. §2.5 needs the
    matching amendment — otherwise ingress accepts events whose digest cannot be computed.
    """
    if isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > _SAFE_INT_MAX:
            raise ReducerError(
                f"{where}: integer {value} is outside JCS's safe domain (|v| <= 2**53-1)"
            )
        return
    if value != value or value in (float("inf"), float("-inf")):  # NaN / +-Inf
        raise ReducerError(f"{where}: {value} has no canonical form")
    if abs(value) >= 2**53:
        raise ReducerError(
            f"{where}: float {value!r} has magnitude >= 2**53. Inside "
            "[2**53, 1e21) its canonical form re-parses as an uncanonicalisable "
            "integer; above that it round-trips but is rejected by the same rule"
        )


def _walk_numbers(value: Any, *, where: str) -> None:
    if isinstance(value, Mapping):
        for key, sub in value.items():
            _walk_numbers(sub, where=f"{where}.{key}")
    elif isinstance(value, (list, tuple)):
        for i, sub in enumerate(value):
            _walk_numbers(sub, where=f"{where}[{i}]")
    elif isinstance(value, (int, float)):
        _check_number_domain(value, where=where)


def parse_signed_json(raw: bytes) -> Any:
    """Parse canonical bytes strictly.

    Duplicate keys are a rejection rather than a last-one-wins merge: which one wins is a
    property of the parser, so accepting them makes the digest depend on the parser.
    ``NaN`` / ``Infinity`` are rejected for the same reason JCS rejects them — they have no
    canonical form.
    """
    try:
        parsed = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except UnicodeDecodeError as exc:
        raise ReducerError("signed bytes are not valid UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ReducerError(f"signed bytes are not valid JSON: {exc}") from exc
    _walk_numbers(parsed, where="envelope")
    return parsed


def normalize_timestamp(value: object, *, field: str) -> str:
    """Normalise an RFC 3339 timestamp to the single lexical form v6 signs.

    Returns ``YYYY-MM-DDThh:mm:ss.ffffffZ`` — UTC, literal ``Z``, exactly six fractional
    digits (``V6-ENVELOPE.md`` §2.3).

    Sub-microsecond digits are **truncated, not rounded**. Rounding would make
    ``…:59.9999999Z`` carry into the next second, so the reduced state would depend on a
    decision every implementation has to make identically and none of them documents.
    Truncation has one obvious answer.
    """
    if not isinstance(value, str):
        raise ReducerError(f"{field}: expected an RFC 3339 string, got {type(value).__name__}")
    m = _RFC3339.match(value)
    if m is None:
        raise ReducerError(f"{field}: not RFC 3339 with an offset: {value!r}")

    year, month, day = int(m["y"]), int(m["mo"]), int(m["d"])
    hour, minute, second = int(m["h"]), int(m["mi"]), int(m["s"])
    if not (1 <= month <= 12 and 1 <= day <= 31):
        raise ReducerError(f"{field}: date out of range: {value!r}")
    if hour > 23 or minute > 59 or second > 59:
        # 24:00 and leap seconds are both legal ISO 8601 and both parse differently
        # across interpreters. Neither is representable in the normal form, so both
        # are rejected here rather than normalised into a guess.
        raise ReducerError(f"{field}: hour/minute/second out of range: {value!r}")

    micros = int((m["frac"] or "").ljust(6, "0")[:6] or 0)

    # Offsets are applied arithmetically rather than through the calendar so that the
    # result never depends on a tz database.
    total_minutes = hour * 60 + minute
    if m["sign"]:
        offset_hours, offset_minutes = int(m["oh"]), int(m["om"])
        if offset_hours > 23 or offset_minutes > 59:
            raise ReducerError(f"{field}: offset out of range: {value!r}")
        offset = offset_hours * 60 + offset_minutes
        total_minutes -= offset if m["sign"] == "+" else -offset

    day_shift, total_minutes = divmod(total_minutes, 1440)
    ordinal = _to_ordinal(year, month, day) + day_shift
    year, month, day = _from_ordinal(ordinal)
    hour, minute = divmod(total_minutes, 60)
    return (
        f"{year:04d}-{month:02d}-{day:02d}"
        f"T{hour:02d}:{minute:02d}:{second:02d}.{micros:06d}Z"
    )


def _is_leap(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


_DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _to_ordinal(year: int, month: int, day: int) -> int:
    days = _DAYS_IN_MONTH[month - 1] + (1 if month == 2 and _is_leap(year) else 0)
    if day > days:
        raise ReducerError(f"day {day} out of range for {year:04d}-{month:02d}")
    total = 365 * (year - 1) + (year - 1) // 4 - (year - 1) // 100 + (year - 1) // 400
    for m in range(1, month):
        total += _DAYS_IN_MONTH[m - 1] + (1 if m == 2 and _is_leap(year) else 0)
    return total + day


def _from_ordinal(ordinal: int) -> tuple[int, int, int]:
    year = max(1, (ordinal - 1) // 366 + 1)
    while _to_ordinal(year + 1, 1, 1) <= ordinal:
        year += 1
    remaining = ordinal - _to_ordinal(year, 1, 1) + 1
    month = 1
    while True:
        days = _DAYS_IN_MONTH[month - 1] + (1 if month == 2 and _is_leap(year) else 0)
        if remaining <= days:
            return year, month, remaining
        remaining -= days
        month += 1


def _require_object(value: object, *, field: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ReducerError(f"{field}: expected an object or null")
    return value


def reduce_v1(
    envelopes: Sequence[bytes],
    *,
    workflow_definitions: Mapping[tuple[str, int], Mapping[str, Any]],
    include_claim_state: bool = False,
) -> dict[str, Any]:
    """Reduce a signed event prefix to the state a review verdict binds to.

    ``envelopes`` are the canonical signed bytes of one entity's chain, in chain order, up to
    and including the event named by ``reviewed_through_event_hash``. Chain order is
    predecessor-link traversal; it is **never** ``global_seq`` order, which is unsigned.

    ``workflow_definitions`` maps ``(name, version)`` to the ``definition`` object carried by
    the signed ``workflow_registered`` event (``V6-ENVELOPE.md`` §1.9). A referenced definition
    that is absent is an error, not an unknown-transition warning: without it the reduction is
    not determined by the material presented.

    ``include_claim_state`` selects the field set; it defaults to **False** (content only) by
    the 2026-08-09 decision recorded in :func:`reduced_field_names`.
    """
    state: str | None = None
    custom_fields: dict[str, Any] = {}
    needs_review = False
    not_before: str | None = None
    last_entity_seq = 0
    attempt_number = 0
    claimed_by: str | None = None
    claim_expires_at: str | None = None
    claim_coalesce_threshold: float | int = 0.0

    for position, raw in enumerate(envelopes):
        env = parse_signed_json(raw)
        if not isinstance(env, Mapping):
            raise ReducerError(f"event {position}: envelope is not an object")

        transition = env.get("transition")
        if not isinstance(transition, str) or not transition:
            # Resolution 3: every v6 event carries a non-empty transition.
            raise ReducerError(f"event {position}: transition must be a non-empty string")

        entity_seq = env.get("entity_seq")
        if not isinstance(entity_seq, int) or isinstance(entity_seq, bool) or entity_seq < 1:
            raise ReducerError(f"event {position}: entity_seq must be an integer >= 1")
        last_entity_seq = entity_seq

        payload = _require_object(env.get("payload"), field=f"event {position} payload")

        if transition == "created":
            state = payload.get("initial_state")
            if state is not None and not isinstance(state, str):
                raise ReducerError(f"event {position}: initial_state must be a string or null")
            custom_fields = dict(
                _require_object(payload.get("custom_fields"), field="custom_fields")
            )
            nb = payload.get("not_before")
            not_before = None if nb is None else normalize_timestamp(nb, field="not_before")

        elif transition == "not_before_set":
            nb = payload.get("not_before")
            not_before = None if nb is None else normalize_timestamp(nb, field="not_before")

        elif transition == "escalated":
            needs_review = True

        elif transition in _CLAIM_TRANSITIONS:
            if transition in ("claim_acquired", "claim_stolen"):
                attempt_number += 1
                holder_field = "actor_id" if transition == "claim_acquired" else "new_actor_id"
                holder = payload.get(holder_field)
                if holder is not None and not isinstance(holder, str):
                    raise ReducerError(
                        f"event {position}: {holder_field} must be a string or null"
                    )
                claimed_by = holder
                expires = payload.get("expires_at")
                if expires is not None:
                    claim_expires_at = normalize_timestamp(expires, field="expires_at")
            elif transition == "claim_heartbeat":
                expires = payload.get("expires_at")
                if expires is not None:
                    claim_expires_at = normalize_timestamp(expires, field="expires_at")
                threshold = payload.get("coalesce_threshold") or 0.0
                if not isinstance(threshold, (int, float)) or isinstance(threshold, bool):
                    raise ReducerError(f"event {position}: coalesce_threshold must be numeric")
                claim_coalesce_threshold = threshold
            else:  # claim_released, claim_expired
                claimed_by = None
                claim_expires_at = None
                claim_coalesce_threshold = 0.0

        elif transition in _INTRINSIC_TRANSITIONS:
            pass  # link_created / link_removed / hook_dead_lettered touch no reduced field

        else:
            workflow = env.get("workflow")
            if not isinstance(workflow, Mapping):
                raise ReducerError(
                    f"event {position}: transition {transition!r} needs a workflow, "
                    "but the envelope carries none"
                )
            wf_name = workflow.get("name")
            wf_version = workflow.get("version")
            if not isinstance(wf_name, str) or not isinstance(wf_version, int):
                raise ReducerError(
                    f"event {position}: workflow reference must carry a string name "
                    "and an integer version"
                )
            wf_key = (wf_name, wf_version)
            definition = workflow_definitions.get(wf_key)
            if definition is None:
                raise ReducerError(
                    f"event {position}: no signed registration supplied for workflow {wf_key!r}"
                )
            transitions = definition.get("transitions")
            if not isinstance(transitions, Sequence) or isinstance(transitions, (str, bytes)):
                raise ReducerError(f"event {position}: workflow definition has no transitions list")

            for candidate in transitions:
                if not isinstance(candidate, Mapping):
                    raise ReducerError(f"event {position}: malformed transition entry")
                if candidate.get("name") == transition and candidate.get("from_state") == state:
                    to_state = candidate.get("to_state")
                    if not isinstance(to_state, str):
                        raise ReducerError(f"event {position}: to_state must be a string")
                    state = to_state
                    break
            else:
                # Replay warns and continues here. The reducer cannot: "the transition did
                # not apply" and "the definition supplied was the wrong one" are the same
                # observation, and guessing which produces a digest nobody can reproduce.
                raise ReducerError(
                    f"event {position}: transition {transition!r} is not valid "
                    f"from state {state!r} in workflow {wf_key!r}"
                )

            update = payload.get("custom_fields_update")
            if update:
                custom_fields = {
                    **custom_fields,
                    **_require_object(update, field="custom_fields_update"),
                }
            claimed_by = None
            claim_expires_at = None

    reduced: dict[str, Any] = {
        "reducer_version": REDUCER_VERSION,
        "current_state": state,
        "custom_fields": custom_fields,
        "needs_review": needs_review,
        "not_before": not_before,
        "last_entity_seq": last_entity_seq,
    }
    if include_claim_state:
        reduced.update(
            {
                "attempt_number": attempt_number,
                "claimed_by": claimed_by,
                "claim_expires_at": claim_expires_at,
                "claim_coalesce_threshold": claim_coalesce_threshold,
            }
        )
    return reduced


def reduced_field_names(*, include_claim_state: bool = False) -> tuple[str, ...]:
    """The reduced field set, in declaration order (JCS sorts them anyway).

    **Decided 2026-08-09: claim state is excluded, and that is the default.** Both field sets are
    proved byte-stable by the conformance vectors, so this was an operational call rather than a
    determinism one — but it is not a close call, for two reasons that are about correctness
    rather than taste:

    1. **Including claim state breaks the pass → accept flow in the ordinary case.**
       `REVIEW-VERDICTS.md` §2.5 requires an ``accept`` to carry the same ``subject_digest`` as
       the pass it supersedes, or a later ``reviewed_through_event_hash`` whose
       ``content_state_digest`` is unchanged. An accepter routinely *claims* the item in order to
       act on it. With claim state inside the digest, that claim changes the digest, and the
       accept can never match the pass it is accepting. The gate would fail closed on its own
       happy path.
    2. **It hands out a denial tool.** ``claim_expired`` is emitted by the maintenance thread
       with no human involved. If a lease expiry stales every verdict on an item, anything that
       can cause churn — including ordinary timeouts — can invalidate a completed review. §4.4's
       monotonicity invariant is about stopping appended work from *inflating* a claim; a
       mechanism that lets background timers *destroy* one is the same defect pointing the other
       way, and D11 already names "hand an attacker a denial tool" as the reason an unverdicted
       event must not downgrade.

    So "stale a verdict after any state-changing event" is read as **any event that changes what
    the item says** — which is what a *content* state digest was named for. ``claimed_by``,
    ``claim_expires_at``, ``claim_coalesce_threshold`` and ``attempt_number`` describe who is
    holding the work, not what the work is. ``attempt_number`` is the closest call of the four,
    since a retry count is arguably history rather than lease state; it goes with the others
    because it is derived entirely from claim transitions.

    ``include_claim_state=True`` is retained, tested and frozen so the decision is reversible
    without reopening Gate 0 — and so that anyone who thinks it should be reversed argues with
    the two points above rather than with an absent option.
    """
    base = (
        "reducer_version",
        "current_state",
        "custom_fields",
        "needs_review",
        "not_before",
        "last_entity_seq",
    )
    return base + _CLAIM_FIELDS if include_claim_state else base


def content_state_digest(
    envelopes: Sequence[bytes],
    *,
    workflow_definitions: Mapping[tuple[str, int], Mapping[str, Any]],
    include_claim_state: bool = False,
) -> str:
    """``sha256:<hex>`` over the domain-separated JCS of :func:`reduce_v1`."""
    reduced = reduce_v1(
        envelopes,
        workflow_definitions=workflow_definitions,
        include_claim_state=include_claim_state,
    )
    return "sha256:" + sha256(STATE_DOMAIN + canonicalize(reduced)).hexdigest()


def reduce_and_canonicalize(
    envelopes: Iterable[bytes],
    *,
    workflow_definitions: Mapping[tuple[str, int], Mapping[str, Any]],
    include_claim_state: bool = False,
) -> bytes:
    """The exact JCS bytes the digest is taken over. Exposed for conformance vectors."""
    return canonicalize(
        reduce_v1(
            list(envelopes),
            workflow_definitions=workflow_definitions,
            include_claim_state=include_claim_state,
        )
    )
