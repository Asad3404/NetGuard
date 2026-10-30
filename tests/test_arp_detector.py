"""ARP spoof detector: binding-change and one-MAC-many-IPs signals."""

from scapy.all import ARP, Ether

from netguard.detectors import ArpSpoofDetector

from .conftest import stamp


def _reply(psrc, hwsrc, pdst="192.168.1.10", hwdst="02:00:00:00:00:0a"):
    return Ether(src=hwsrc) / ARP(op=2, psrc=psrc, hwsrc=hwsrc, pdst=pdst, hwdst=hwdst)


def _collect(detector, packets):
    alerts = []
    for pkt in stamp(packets):
        alerts.extend(detector.feed(pkt))
    return alerts


def test_binding_change_alerts():
    det = ArpSpoofDetector()
    pkts = [
        _reply("192.168.1.1", "02:00:00:00:00:01"),  # learn
        _reply("192.168.1.1", "02:00:00:00:00:66"),  # flip -> alert
    ]
    alerts = _collect(det, pkts)
    cats = [a.category for a in alerts]
    assert "arp-spoof" in cats
    spoof = next(a for a in alerts if a.category == "arp-spoof")
    assert spoof.fields["ip"] == "192.168.1.1"
    assert spoof.fields["old_mac"] == "02:00:00:00:00:01"
    assert spoof.fields["new_mac"] == "02:00:00:00:00:66"
    assert spoof.evidence  # evidence captured


def test_one_mac_many_ips_alerts():
    det = ArpSpoofDetector()
    attacker = "02:00:00:00:00:66"
    pkts = [
        _reply("192.168.1.1", attacker),
        _reply("192.168.1.10", attacker),
    ]
    alerts = _collect(det, pkts)
    assert any(a.category == "arp-mac-many-ips" for a in alerts)
    many = next(a for a in alerts if a.category == "arp-mac-many-ips")
    assert many.fields["mac"] == attacker
    assert set(many.fields["ips"]) == {"192.168.1.1", "192.168.1.10"}


def test_first_seen_binding_is_silent():
    """Learning a brand-new IP->MAC must not alert."""
    det = ArpSpoofDetector()
    alerts = _collect(det, [_reply("192.168.1.1", "02:00:00:00:00:01")])
    assert alerts == []


def test_stable_bindings_do_not_alert():
    """Repeating the same (consistent) bindings is benign."""
    det = ArpSpoofDetector()
    pkts = [
        _reply("192.168.1.1", "02:00:00:00:00:01"),
        _reply("192.168.1.10", "02:00:00:00:00:0a", pdst="192.168.1.1", hwdst="02:00:00:00:00:01"),
        _reply("192.168.1.1", "02:00:00:00:00:01"),  # same again
    ]
    alerts = _collect(det, pkts)
    assert alerts == []


def test_requests_are_ignored():
    """ARP who-has (op=1) does not assert a binding and must not alert."""
    det = ArpSpoofDetector()
    req = Ether(src="02:00:00:00:00:66") / ARP(
        op=1, psrc="192.168.1.1", hwsrc="02:00:00:00:00:66", pdst="192.168.1.10"
    )
    req2 = Ether(src="02:00:00:00:00:66") / ARP(
        op=1, psrc="192.168.1.10", hwsrc="02:00:00:00:00:66", pdst="192.168.1.1"
    )
    assert _collect(det, [req, req2]) == []
