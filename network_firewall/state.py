"""
Stateful connection tracking.

Once a connection has been allowed, return traffic for that same
connection should flow without re-checking the full rule list every
time -- that's the difference between a stateful firewall and a naive
packet-by-packet filter. This module implements a simplified version
of the conntrack table real firewalls (iptables/netfilter, pf, etc.)
maintain.
"""

import time
from dataclasses import dataclass


@dataclass
class ConnectionState:
    last_seen: float
    state: str  # "NEW", "ESTABLISHED"


class ConnectionTracker:
    def __init__(self, timeout_seconds: int = 120):
        self.timeout = timeout_seconds
        self.table: dict[tuple, ConnectionState] = {}

    @staticmethod
    def _key(pkt_info: dict) -> tuple:
        # Normalize direction so both sides of a connection map to the
        # same table entry (a reply packet looks like the reverse of
        # the original request).
        a = (pkt_info.get("src_ip"), pkt_info.get("src_port"))
        b = (pkt_info.get("dst_ip"), pkt_info.get("dst_port"))
        pair = tuple(sorted([a, b]))
        return (pkt_info.get("protocol"), pair)

    def is_established(self, pkt_info: dict) -> bool:
        """
        True if this connection has already been allowed once before.
        Mirrors real conntrack: the first packet is NEW (still has to
        pass the rule engine); any packet after that -- including the
        reply that flips it to ESTABLISHED -- is fast-pathed.
        """
        self._expire_old()
        key = self._key(pkt_info)
        return key in self.table

    def track(self, pkt_info: dict, allowed: bool):
        if not allowed:
            return
        key = self._key(pkt_info)
        now = time.time()
        if key in self.table:
            self.table[key].last_seen = now
            self.table[key].state = "ESTABLISHED"
        else:
            self.table[key] = ConnectionState(last_seen=now, state="NEW")

    def _expire_old(self):
        now = time.time()
        expired = [k for k, v in self.table.items() if now - v.last_seen > self.timeout]
        for k in expired:
            del self.table[k]
