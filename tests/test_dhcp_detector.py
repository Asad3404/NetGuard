"""DHCP detector: rogue-server and starvation signals."""

from scapy.all import IP, UDP, Ether
from scapy.layers.dhcp import BOOTP, DHCP

from netguard.detectors import DhcpAttackDetector

from .conftest import stamp


def _chaddr(mac):
    return bytes(int(x, 16) for x in mac.split(":"))


def discover(mac, xid=1):
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=_chaddr(mac), xid=xid)
        / DHCP(options=[("message-type", "discover"), "end"])
    )


def offer(server_ip, client_mac="02:00:00:00:00:0a"):
    return (
        Ether(src="02:aa:aa:aa:aa:aa", dst=client_mac)
        / IP(src=server_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr="192.168.1.10", siaddr=server_ip, chaddr=_chaddr(client_mac))
        / DHCP(options=[("message-type", "offer"), ("server_id", server_ip), "end"])
    )


def _collect(det, pkts):
    alerts = []
    for pkt in stamp(pkts):
        alerts.extend(det.feed(pkt))
    return alerts


def test_rogue_server_with_expected_set():
    det = DhcpAttackDetector(expected_servers={"192.168.1.1"})
    alerts = _collect(det, [offer("192.168.1.1"), offer("192.168.1.66")])
    rogue = [a for a in alerts if a.category == "dhcp-rogue-server"]
    assert len(rogue) == 1
    assert rogue[0].fields["server_ip"] == "192.168.1.66"


def test_rogue_server_learned_first():
    """With no expected set, the first server is learned and a second flagged."""
    det = DhcpAttackDetector()
    alerts = _collect(det, [offer("192.168.1.1"), offer("192.168.1.1"), offer("192.168.1.66")])
    rogue = [a for a in alerts if a.category == "dhcp-rogue-server"]
    assert len(rogue) == 1
    assert rogue[0].fields["server_ip"] == "192.168.1.66"


def test_expected_server_is_silent():
    det = DhcpAttackDetector(expected_servers={"192.168.1.1"})
    alerts = _collect(det, [offer("192.168.1.1"), offer("192.168.1.1")])
    assert alerts == []


def test_starvation_fires_over_threshold():
    det = DhcpAttackDetector(starvation_threshold=10, starvation_window_s=10.0)
    pkts = [discover(f"02:00:00:00:01:{i:02x}", xid=i) for i in range(12)]
    alerts = _collect(det, pkts)
    starv = [a for a in alerts if a.category == "dhcp-starvation"]
    assert len(starv) == 1
    assert starv[0].fields["distinct_macs"] >= 10


def test_starvation_fires_once_not_per_packet():
    det = DhcpAttackDetector(starvation_threshold=5, starvation_window_s=10.0)
    pkts = [discover(f"02:00:00:00:02:{i:02x}", xid=i) for i in range(20)]
    alerts = _collect(det, pkts)
    assert len([a for a in alerts if a.category == "dhcp-starvation"]) == 1


def test_few_clients_do_not_starve():
    """A normal trickle of DISCOVERs from a couple of MACs is benign."""
    det = DhcpAttackDetector(starvation_threshold=10, starvation_window_s=10.0)
    pkts = [discover("02:00:00:00:00:0a", xid=1), discover("02:00:00:00:00:0b", xid=2)]
    assert _collect(det, pkts) == []


def test_starvation_respects_window():
    """Distinct MACs spread outside the window must not accumulate to a false alert."""
    det = DhcpAttackDetector(starvation_threshold=5, starvation_window_s=1.0)
    # 10 discovers, each 0.5s apart => at most ~3 within any 1s window.
    pkts = []
    base = 1000.0
    for i in range(10):
        d = discover(f"02:00:00:00:03:{i:02x}", xid=i)
        d.time = base + i * 0.5
        pkts.append(d)
    alerts = []
    for pkt in pkts:
        alerts.extend(det.feed(pkt))
    assert [a for a in alerts if a.category == "dhcp-starvation"] == []
