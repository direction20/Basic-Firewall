from .rules import Rule, RuleEngine, Action, Protocol


def default_ruleset() -> RuleEngine:
    """A small, realistic example ruleset. Edit/extend this for your own setup."""
    engine = RuleEngine(default_action=Action.DROP)

    # Blocklist rules go FIRST. Order matters: if a generic "allow port 443"
    # rule were checked before this, a blocked IP's HTTPS traffic would slip
    # through, since that rule never looks at src_ip at all.
    engine.add_rule(Rule(Action.DROP, src_ip="203.0.113.66", description="known malicious IP"))

    engine.add_rule(Rule(Action.ACCEPT, Protocol.UDP, dst_port=53, description="allow DNS"))
    engine.add_rule(Rule(Action.ACCEPT, Protocol.TCP, dst_port=80, description="allow HTTP"))
    engine.add_rule(Rule(Action.ACCEPT, Protocol.TCP, dst_port=443, description="allow HTTPS"))

    # SSH locked down to one trusted admin IP -- replace with your own
    engine.add_rule(Rule(Action.ACCEPT, Protocol.TCP, dst_port=22, src_ip="10.0.0.5",
                          description="allow SSH from admin"))
    engine.add_rule(Rule(Action.DROP, Protocol.TCP, dst_port=22,
                          description="block SSH from anywhere else"))

    return engine
