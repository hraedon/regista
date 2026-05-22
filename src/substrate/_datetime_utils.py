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


def ts_equal_within(
    a: datetime | None, b: datetime | None, threshold_seconds: float,
) -> bool:
    if a is None and b is None:
        return True
    if a is None or b is None:
        return False
    diff = abs((to_utc(a) - to_utc(b)).total_seconds())
    return diff <= threshold_seconds
