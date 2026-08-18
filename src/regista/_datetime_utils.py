from __future__ import annotations

from datetime import UTC, datetime


def ts_equal(a: datetime | None, b: datetime | None) -> bool:
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    a_aware = a.tzinfo is not None
    b_aware = b.tzinfo is not None
    if a_aware and b_aware:
        return a.astimezone(UTC) == b.astimezone(UTC)
    if not a_aware and not b_aware:
        return a == b
    if a_aware:
        a = a.astimezone(UTC).replace(tzinfo=None)
    else:
        b = b.astimezone(UTC).replace(tzinfo=None)
    return a == b


def to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


#: ``V6-ENVELOPE.md`` §2.3 is a **single** lexical form for ``occurred_at``: exactly
#: six fractional digits and a literal ``Z``. There is no alternate spelling and no
#: tolerance, because two renderings of one instant are two different signed byte
#: strings.
V6_OCCURRED_AT_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def v6_occurred_at(value: datetime) -> str:
    """Render ``occurred_at`` in the one lexical form §2.3 admits.

    Use this instead of ``datetime.isoformat()`` anywhere a v6 envelope timestamp is
    emitted. ``isoformat()`` drops to **three** fractional digits whenever the
    microseconds happen to land on a whole millisecond, and the strict parser rejects
    that — so the bug appears only for roughly one instant in a thousand, which is
    exactly the kind of defect that reaches production. ``%f`` always renders six.

    The inverse is :func:`parse_v6_occurred_at`, kept beside it so the round trip is
    obviously exact.
    """

    return to_utc(value).strftime(V6_OCCURRED_AT_FORMAT)


def parse_v6_occurred_at(value: str) -> datetime:
    """Parse the §2.3 lexical form back to an aware UTC datetime."""

    return datetime.strptime(value, V6_OCCURRED_AT_FORMAT).replace(tzinfo=UTC)


def ts_equal_within(
    a: datetime | None, b: datetime | None, threshold_seconds: float,
) -> bool:
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    diff = abs((to_utc(a) - to_utc(b)).total_seconds())
    return diff <= threshold_seconds
