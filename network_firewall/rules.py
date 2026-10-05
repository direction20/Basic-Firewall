"""
Rule engine for the network-layer firewall.

Rules are evaluated in order; the first matching rule decides the action.
If no rule matches, the engine falls back to a configurable default policy
(default-deny, the standard secure baseline).
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class Action(str, Enum):
    ACCEPT = "ACCEPT"
    DROP = "DROP"


class Protocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    ANY = "ANY"


@dataclass
class Rule:
    action: Action
    protocol: Protocol = Protocol.ANY
    src_ip: Optional[str] = None       # None = matches any source
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    description: str = ""

    def matches(self, pkt_info: dict) -> bool:
        if self.protocol != Protocol.ANY and pkt_info.get("protocol") != self.protocol.value:
            return False
        if self.src_ip and pkt_info.get("src_ip") != self.src_ip:
            return False
        if self.dst_ip and pkt_info.get("dst_ip") != self.dst_ip:
            return False
        if self.src_port and pkt_info.get("src_port") != self.src_port:
            return False
        if self.dst_port and pkt_info.get("dst_port") != self.dst_port:
            return False
        return True


class RuleEngine:
    def __init__(self, default_action: Action = Action.DROP):
        self.rules: list[Rule] = []
        self.default_action = default_action

    def add_rule(self, rule: Rule, position: Optional[int] = None):
        if position is None:
            self.rules.append(rule)
        else:
            self.rules.insert(position, rule)

    def remove_rule(self, index: int):
        del self.rules[index]

    def evaluate(self, pkt_info: dict) -> tuple[Action, Optional[Rule]]:
        for rule in self.rules:
            if rule.matches(pkt_info):
                return rule.action, rule
        return self.default_action, None
