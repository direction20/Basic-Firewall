"""Sliding-window rate limiter -- same approach as the network firewall's, kept WAF-standalone."""

import time
from collections import deque, defaultdict


class RateLimiter:
    def __init__(self, max_events: int, window_seconds: float):
        self.max_events = max_events
        self.window = window_seconds
        self.events: dict[str, deque] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = time.time()
        q = self.events[key]
        q.append(now)
        self._trim(q, now)
        return len(q) <= self.max_events

    def is_blocked(self, key: str) -> bool:
        now = time.time()
        q = self.events.get(key)
        if not q:
            return False
        self._trim(q, now)
        return len(q) > self.max_events

    def _trim(self, q: deque, now: float):
        while q and now - q[0] > self.window:
            q.popleft()
