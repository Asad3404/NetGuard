"""DNS spoof detector: unexpected-resolver and poisoning-race signals."""

from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether

from netguard.detectors import DnsSpoofDetector

from .conftest import stamp


def response(src_ip, txid, qname, answer, dst_ip="192.168.1.10", dport=50000):
    q = qname if qname.endswith(".") else qname + "."
    return (
        Ether(src="02:00:00:00:00:53", dst="02:00:00:00:00:0a")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=53, dport=dport)
        / DNS(id=txid, qr=1, aa=1, qd=DNSQR(qname=q, qtype="A"),
              an=DNSRR(rrname=q, type="A", ttl=300, rdata=answer))
    )


def query(src_ip, txid, qname, dst_ip="192.168.1.53"):
    q = qname if qname.endswith(".") else qname + "."
    return (
        Ether(src="02:00:00:00:00:0a", dst="02:00:00:00:00:53")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=50000, dport=53)
        / DNS(id=txid, qr=0, qd=DNSQR(qname=q, qtype="A"))
    )


def _collect(det, pkts):
    alerts = []
    for pkt in stamp(pkts):
        alerts.extend(det.feed(pkt))
    return alerts


def test_poison_race_conflicting_answers():
    det = DnsSpoofDetector()
    pkts = [
        response("192.168.1.53", 0x4242, "bank.example.com", "203.0.113.5"),
        response("192.168.1.66", 0x4242, "bank.example.com", "192.168.1.66"),
    ]
    alerts = _collect(det, pkts)
    race = [a for a in alerts if a.category == "dns-poison-race"]
    assert len(race) == 1
    assert "203.0.113.5" in race[0].fields["answer_a"]
    assert "192.168.1.66" in race[0].fields["answer_b"]
    assert len(race[0].evidence) == 2  # both packets kept as evidence


def test_unexpected_resolver():
    det = DnsSpoofDetector(expected_resolvers={"192.168.1.53"})
    alerts = _collect(det, [response("192.168.1.66", 0x1, "evil.example.com", "192.168.1.66")])
    bad = [a for a in alerts if a.category == "dns-unexpected-resolver"]
    assert len(bad) == 1
    assert bad[0].fields["src"] == "192.168.1.66"


def test_expected_resolver_single_answer_is_silent():
    det = DnsSpoofDetector(expected_resolvers={"192.168.1.53"})
    alerts = _collect(det, [response("192.168.1.53", 0x1, "example.com", "203.0.113.5")])
    assert alerts == []


def test_identical_answer_is_not_a_race():
    """A retransmitted identical answer (same rdata) should not be flagged."""
    det = DnsSpoofDetector()
    pkts = [
        response("192.168.1.53", 0x9, "example.com", "203.0.113.5"),
        response("192.168.1.53", 0x9, "example.com", "203.0.113.5"),
    ]
    assert [a for a in _collect(det, pkts) if a.category == "dns-poison-race"] == []


def test_queries_are_ignored():
    det = DnsSpoofDetector(expected_resolvers={"192.168.1.53"})
    assert _collect(det, [query("192.168.1.10", 0x1, "example.com")]) == []


def test_different_txid_same_name_not_a_race():
    """Two legitimate lookups of one name (different txids) are not a race."""
    det = DnsSpoofDetector()
    pkts = [
        response("192.168.1.53", 0x1, "example.com", "203.0.113.5"),
        response("192.168.1.53", 0x2, "example.com", "203.0.113.6"),
    ]
    assert [a for a in _collect(det, pkts) if a.category == "dns-poison-race"] == []
