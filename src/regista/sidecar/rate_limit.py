from __future__ import annotations

import os
import time
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


@dataclass
class RateLimiter:
    requests_per_second: float = 10.0
    burst: int = 20
    enabled: bool = True
    _buckets: dict[str, _Bucket] = field(default_factory=lambda: defaultdict(lambda: _Bucket(0, 0)))

    def allow(self, key: str) -> bool:
        if not self.enabled:
            return True
        now = time.monotonic()
        bucket = self._buckets[key]
        elapsed = now - bucket.last_refill
        bucket.tokens = min(self.burst, bucket.tokens + elapsed * self.requests_per_second)
        bucket.last_refill = now
        if bucket.tokens >= 1:
            bucket.tokens -= 1
            return True
        return False


def make_limiter() -> RateLimiter:
    disabled = os.environ.get("REGISTA_DISABLE_RATE_LIMIT", "").lower() in ("1", "true", "yes")
    return RateLimiter(enabled=not disabled)
