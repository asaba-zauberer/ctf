"""Simple in-memory rate limiting utilities."""
from __future__ import annotations

import time
from collections import deque
from typing import Deque, Dict


class RateLimitExceeded(Exception):
    """Raised when a caller exceeds the allowed rate."""


class RateLimiter:
    def __init__(self, limit: int, interval_seconds: float) -> None:
        self.limit = limit
        self.interval = interval_seconds
        self._buckets: Dict[str, Deque[float]] = {}

    def hit(self, key: str) -> None:
        """Register a hit for the given key or raise RateLimitExceeded."""
        now = time.monotonic()
        bucket = self._buckets.setdefault(key, deque())
        while bucket and now - bucket[0] > self.interval:
            bucket.popleft()
        if len(bucket) >= self.limit:
            raise RateLimitExceeded(f"Rate limit exceeded for key={key}")
        bucket.append(now)
