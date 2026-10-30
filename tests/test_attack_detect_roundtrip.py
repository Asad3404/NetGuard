"""Round-trip: each attack's built packets are caught by its detector.

This is the tightest possible coupling check — the exact packets an attack
constructs (in dry-run, nothing transmitted) are fed straight into the matching
detector, which must alert. If an attack's wire format and its detector ever
drift apart, this fails.
"""

from netguard.attacks import (
    ArpSpoofAttack,
    DhcpStarvationAttack,
    DnsSpoofAttack,
    RogueDhcpOffer,
    SynScanAttack,
)
from netguard.detectors import (
    ArpSpoofDetector,
    DhcpAttackDetector,
    DnsSpoofDetector,
    SynScanDetector,
)

from .conftest import stamp


def _feed(det, packets):
    alerts = []
    for pkt in stamp(packets, step=0.001):
        alerts.extend(det.feed(pkt))
    alerts.extend(det.finalize())
    return alerts


def test_arp_attack_caught():
    atk = ArpSpoofAttack(
        victim_ip="192.168.1.10", victim_mac="02:00:00:00:00:0a",
        gateway_ip="192.168.1.1", gateway_mac="02:00:00:00:00:01",
        attacker_mac="02:00:00:00:00:66", lab_ack=True, dry_run=True, rounds=1,
    )
    # Prime the detector with the true bindings first so the flip is visible.
    det = ArpSpoofDetector()
    from scapy.all import ARP, Ether
    prime = [
        Ether(src="02:00:00:00:00:01") / ARP(op=2, psrc="192.168.1.1",
            hwsrc="02:00:00:00:00:01", pdst="192.168.1.10", hwdst="02:00:00:00:00:0a"),
        Ether(src="02:00:00:00:00:0a") / ARP(op=2, psrc="192.168.1.10",
            hwsrc="02:00:00:00:00:0a", pdst="192.168.1.1", hwdst="02:00:00:00:00:01"),
    ]
    alerts = _feed(det, prime + atk.run().packets)
    assert any(a.category == "arp-spoof" for a in alerts)


def test_dhcp_starvation_caught():
    atk = DhcpStarvationAttack(count=15, seed=1, lab_ack=True, dry_run=True, max_packets=50)
    det = DhcpAttackDetector(starvation_threshold=10, starvation_window_s=60.0)
    alerts = _feed(det, atk.run().packets)
    assert any(a.category == "dhcp-starvation" for a in alerts)


def test_dhcp_rogue_offer_caught():
    atk = RogueDhcpOffer(
        client_mac="02:00:00:00:00:0a", offered_ip="192.168.1.111",
        server_ip="192.168.1.66", rogue_gateway="192.168.1.66",
        rogue_dns="192.168.1.66", lab_ack=True, dry_run=True,
    )
    det = DhcpAttackDetector(expected_servers={"192.168.1.1"})
    alerts = _feed(det, atk.run().packets)
    assert any(a.category == "dhcp-rogue-server" for a in alerts)


def test_dns_attack_caught():
    atk = DnsSpoofAttack(
        victim_ip="192.168.1.10", resolver_ip="192.168.1.53",
        qname="bank.example.com", spoof_ip="192.168.1.66", lab_ack=True, dry_run=True,
    )
    # The forged answer alone is caught by the "unexpected resolver" rule only
    # if the resolver is known; here the forged src IS the resolver IP, so we
    # test the race by also feeding a real answer with different rdata.
    det = DnsSpoofDetector()
    from tests.test_dns_detector import response
    real = response("192.168.1.53", 0x1337, "bank.example.com", "203.0.113.5")
    alerts = _feed(det, [real] + atk.run().packets)
    assert any(a.category == "dns-poison-race" for a in alerts)


def test_synscan_attack_caught():
    atk = SynScanAttack(
        target_ip="192.168.1.10", start_port=1, end_port=150,
        lab_ack=True, dry_run=True, max_packets=200,
    )
    det = SynScanDetector(port_threshold=100, window_s=60.0)
    alerts = _feed(det, atk.run().packets)
    assert any(a.category == "tcp-syn-scan" for a in alerts)
