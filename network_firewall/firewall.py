"""
Main firewall engine: combines the rule engine, connection tracker,
and rate limiter to decide ACCEPT/DROP for each packet.

Two ways to feed it packets:

  - process_packet(pkt): takes a Scapy packet object. Works equally
    well with live-captured packets and synthetically crafted ones --
    the test suite uses crafted packets, since this sandbox has no
    live network interface with real traffic to sniff.

  - sniff_live(interface): wraps scapy.sniff() for use on your own
    machine against real traffic. Requires root/admin privileges and
    Npcap (Windows) or libpcap (Linux/Mac) installed. Run this
    locally on your own machine, not inside this sandbox.
"""

from scapy.all import IP, TCP, UDP, ICMP, sniff

from .rules import RuleEngine, Action
from .state import ConnectionTracker
from .ratelimit import RateLimiter
from .logger import get_logger

logger = get_logger("network_firewall", "network_firewall.log")


def extract_packet_info(pkt) -> dict:
    info = {"src_ip": None, "dst_ip": None, "protocol": "ANY",
            "src_port": None, "dst_port": None, "flags": None}
    if IP in pkt:
        info["src_ip"] = pkt[IP].src
        info["dst_ip"] = pkt[IP].dst
    if TCP in pkt:
        info["protocol"] = "TCP"
        info["src_port"] = pkt[TCP].sport
        info["dst_port"] = pkt[TCP].dport
        info["flags"] = str(pkt[TCP].flags)
    elif UDP in pkt:
        info["protocol"] = "UDP"
        info["src_port"] = pkt[UDP].sport
        info["dst_port"] = pkt[UDP].dport
    elif ICMP in pkt:
        info["protocol"] = "ICMP"
    return info


class Firewall:
    def __init__(self, rule_engine: RuleEngine = None,
                 syn_flood_threshold: int = 20, syn_flood_window: float = 5.0):
        self.rule_engine = rule_engine or RuleEngine(default_action=Action.DROP)
        self.tracker = ConnectionTracker()
        self.syn_limiter = RateLimiter(max_events=syn_flood_threshold, window_seconds=syn_flood_window)

    def process_packet(self, pkt) -> str:
        info = extract_packet_info(pkt)

        # 1. Flood / DoS protection -- checked first, before any rule lookup.
        is_syn = info["protocol"] == "TCP" and info["flags"] and "S" in info["flags"] and "A" not in info["flags"]
        if is_syn:
            if self.syn_limiter.is_blocked(info["src_ip"]):
                logger.warning(f"DROP (SYN flood protection) src={info['src_ip']}")
                return Action.DROP.value
            self.syn_limiter.allow(info["src_ip"])

        # 2. Stateful fast path -- already-established connections skip rule evaluation.
        if self.tracker.is_established(info):
            self.tracker.track(info, allowed=True)
            return Action.ACCEPT.value

        # 3. Rule engine evaluation.
        action, rule = self.rule_engine.evaluate(info)
        self.tracker.track(info, allowed=(action == Action.ACCEPT))

        reason = rule.description if rule else "default policy"
        logger.info(f"{action.value} {info['protocol']} {info['src_ip']}:{info['src_port']} -> "
                    f"{info['dst_ip']}:{info['dst_port']} ({reason})")
        return action.value

    def sniff_live(self, interface: str = None, count: int = 0):
        """Run locally on your own machine -- needs root/admin and a real interface."""
        sniff(iface=interface, count=count, prn=lambda p: self.process_packet(p), store=False)
