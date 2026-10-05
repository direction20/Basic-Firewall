"""
Sliding-window rate limiter.

Shared by the network firewall (SYN-flood / connection-flood
detection) and the WAF (per-IP HTTP request rate limiting) -- the
underlying problem ("has this key done too much in the last N
seconds?") is identical in both cases.
"""

import time
from collections import deque, defaultdict


class RateLimiter:
    def __init__(self, max_events: int, window_seconds: float):
        self.max_events = max_events
        self.window = window_seconds
        self.events: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        """Record an event for `key`. Returns False if this pushes it over the limit."""
        now = time.time()
        q = self.events[key]
        q.append(now)
        self._trim(q, now)
        return len(q) <= self.max_events

    def is_blocked(self, key: str) -> bool:
        """Check current status for `key` WITHOUT recording a new event."""
        now = time.time()
        q = self.events.get(key)
        if not q:
            return False
        self._trim(q, now)
        return len(q) > self.max_events

    def _trim(self, q: deque, now: float):
        while q and now - q[0] > self.window:
            q.popleft()
