"""TCP SYN port-scan detector: many ports from one source in a window."""

from scapy.all import IP, TCP, Ether

from netguard.detectors import SynScanDetector

from .conftest import stamp


def syn(src, dport, sport=40000, dst="192.168.1.10"):
    return Ether(src="02:00:00:00:00:66") / IP(src=src, dst=dst) / TCP(
        sport=sport, dport=dport, flags="S"
    )


def synack(src, sport, dport, dst="192.168.1.10"):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="SA")


def ack(src, dport, sport=40000, dst="192.168.1.10"):
    return Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="A")


def _collect(det, pkts):
    alerts = []
    for pkt in stamp(pkts, step=0.001):
        alerts.extend(det.feed(pkt))
    alerts.extend(det.finalize())
    return alerts


def test_scan_over_threshold_fires():
    det = SynScanDetector(port_threshold=100, window_s=5.0)
    pkts = [syn("192.168.1.66", p, sport=40000 + i) for i, p in enumerate(range(1, 151))]
    alerts = _collect(det, pkts)
    scan = [a for a in alerts if a.category == "tcp-syn-scan"]
    assert len(scan) == 1
    assert scan[0].fields["src"] == "192.168.1.66"
    assert scan[0].fields["distinct_ports"] >= 100


def test_scan_fires_once_per_source():
    det = SynScanDetector(port_threshold=10, window_s=5.0)
    pkts = [syn("192.168.1.66", p, sport=40000 + i) for i, p in enumerate(range(1, 51))]
    alerts = _collect(det, pkts)
    assert len([a for a in alerts if a.category == "tcp-syn-scan"]) == 1


def test_few_ports_do_not_alert():
    det = SynScanDetector(port_threshold=100, window_s=5.0)
    pkts = [syn("192.168.1.66", p, sport=40000 + i) for i, p in enumerate((80, 443, 22))]
    assert _collect(det, pkts) == []


def test_handshake_traffic_not_a_scan():
    """Complete handshakes (SYN/ACK and ACK) must not inflate the port count."""
    pkts = []
    for i, port in enumerate((80, 443)):
        sp = 51000 + i
        pkts.append(syn("192.168.1.10", port, sport=sp, dst="192.168.1.20"))
        pkts.append(synack("192.168.1.20", sport=port, dport=sp, dst="192.168.1.10"))
        pkts.append(ack("192.168.1.10", port, sport=sp, dst="192.168.1.20"))
    # Only 2 distinct bare-SYN ports here. Set the threshold to 3 (one above the
    # real SYN count): if SYN/ACK or ACK packets were wrongly counted the port
    # total would reach 3 and fire. It must stay silent, proving they're ignored.
    det = SynScanDetector(port_threshold=3, window_s=5.0)
    assert [a for a in _collect(det, pkts) if a.category == "tcp-syn-scan"] == []


def test_distinct_sources_counted_separately():
    """Two sources each scanning a few ports should not combine into one alert."""
    det = SynScanDetector(port_threshold=10, window_s=5.0)
    pkts = []
    for i in range(5):
        pkts.append(syn("192.168.1.66", i + 1, sport=40000 + i))
        pkts.append(syn("192.168.1.77", i + 1, sport=41000 + i))
    assert [a for a in _collect(det, pkts) if a.category == "tcp-syn-scan"] == []
