from scapy.all import IP, TCP, UDP

from network_firewall.firewall import Firewall
from network_firewall.default_rules import default_ruleset
from network_firewall.rules import Action


def make_pkt(src, dst, sport, dport, proto="TCP", flags="S"):
    if proto == "TCP":
        return IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport)


def test_allow_http():
    fw = Firewall(default_ruleset())
    pkt = make_pkt("198.51.100.10", "192.0.2.1", 51000, 80)
    assert fw.process_packet(pkt) == Action.ACCEPT.value


def test_block_ssh_from_untrusted():
    fw = Firewall(default_ruleset())
    pkt = make_pkt("198.51.100.10", "192.0.2.1", 51000, 22)
    assert fw.process_packet(pkt) == Action.DROP.value


def test_allow_ssh_from_admin():
    fw = Firewall(default_ruleset())
    pkt = make_pkt("10.0.0.5", "192.0.2.1", 51000, 22)
    assert fw.process_packet(pkt) == Action.ACCEPT.value


def test_block_known_bad_ip():
    fw = Firewall(default_ruleset())
    pkt = make_pkt("203.0.113.66", "192.0.2.1", 51000, 443)
    assert fw.process_packet(pkt) == Action.DROP.value


def test_default_drop_for_unlisted_port():
    fw = Firewall(default_ruleset())
    pkt = make_pkt("198.51.100.10", "192.0.2.1", 51000, 9999)
    assert fw.process_packet(pkt) == Action.DROP.value


def test_stateful_established_connection():
    fw = Firewall(default_ruleset())
    pkt = make_pkt("198.51.100.10", "192.0.2.1", 51000, 80)
    fw.process_packet(pkt)  # first packet -- matched + tracked by the HTTP rule
    reply = make_pkt("192.0.2.1", "198.51.100.10", 80, 51000, flags="SA")
    assert fw.process_packet(reply) == Action.ACCEPT.value


def test_syn_flood_protection():
    fw = Firewall(default_ruleset(), syn_flood_threshold=5, syn_flood_window=5.0)
    attacker = "198.51.100.99"
    results = [fw.process_packet(make_pkt(attacker, "192.0.2.1", 51000 + i, 80)) for i in range(10)]
    assert Action.DROP.value in results
