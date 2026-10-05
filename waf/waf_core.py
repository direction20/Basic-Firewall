"""
Core WAF inspection logic: given the parts of an incoming HTTP
request, decide whether to allow or block it, and why.
"""

from dataclasses import dataclass
from typing import Optional

from signatures import scan
from ratelimit import RateLimiter
from iplist import IPList
from logger import get_logger

logger = get_logger("waf", "waf.log")


@dataclass
class Decision:
    allowed: bool
    reason: str


class WAF:
    def __init__(self, requests_per_window: int = 30, window_seconds: float = 10.0):
        self.limiter = RateLimiter(max_events=requests_per_window, window_seconds=window_seconds)
        self.ip_list = IPList()

    def inspect(self, client_ip: str, method: str, path: str,
                query_string: str = "", body: str = "", headers: Optional[dict] = None) -> Decision:
        headers = headers or {}

        if self.ip_list.is_blocked(client_ip):
            return self._deny(client_ip, method, path, "IP on block list")

        if not self.ip_list.is_allowed_override(client_ip) and self.limiter.is_blocked(client_ip):
            return self._deny(client_ip, method, path, "rate limit exceeded")
        self.limiter.allow(client_ip)

        combined = " ".join([path, query_string, body, " ".join(str(v) for v in headers.values())])
        hits = scan(combined)
        if hits:
            categories = ", ".join(sorted({h.category for h in hits}))
            return self._deny(client_ip, method, path, f"signature match: {categories}")

        logger.info(f"ALLOW {method} {path} from {client_ip}")
        return Decision(allowed=True, reason="ok")

    def _deny(self, client_ip, method, path, reason) -> Decision:
        logger.warning(f"BLOCK {method} {path} from {client_ip} ({reason})")
        return Decision(allowed=False, reason=reason)
