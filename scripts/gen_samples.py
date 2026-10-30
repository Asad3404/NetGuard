#!/usr/bin/env python3
"""Generate the bundled SYNTHETIC sample PCAPs.

Every packet here is fabricated in memory with Scapy and written to a .pcap —
nothing is captured from a real network. The captures are deliberately small
and labelled synthetic so a reviewer can run the detectors offline, with no
Docker and no root, and see each alert fire (and see the benign baseline stay
silent).

Run:  python scripts/gen_samples.py --out samples
"""

from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether
from scapy.layers.dhcp import BOOTP, DHCP

from netguard.core.pcap import write_pcap

# A fixed base timestamp (2026-01-01T00:00:00Z) so captures are reproducible.
BASE_T = 1767225600.0


def _stamp(packets: list, base: float = BASE_T, step: float = 0.01) -> list:
    """Assign increasing capture timestamps so windowed detectors behave."""
    for i, pkt in enumerate(packets):
        pkt.time = base + i * step
    return packets


def _mac(b: int) -> str:
    return f"02:00:00:00:00:{b:02x}"


def _discover(mac: str, xid: int) -> Ether:
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=bytes(int(x, 16) for x in mac.split(":")), xid=xid)
        / DHCP(options=[("message-type", "discover"), "end"])
    )


def _offer(server_ip: str, client_mac: str, yiaddr: str) -> Ether:
    return (
        Ether(src="02:aa:aa:aa:aa:aa", dst=client_mac)
        / IP(src=server_ip, dst="255.255.255.255")
        / UDP(sport=67, dport=68)
        / BOOTP(op=2, yiaddr=yiaddr, siaddr=server_ip,
                chaddr=bytes(int(x, 16) for x in client_mac.split(":")))
        / DHCP(options=[("message-type", "offer"), ("server_id", server_ip),
                        ("router", server_ip), ("lease_time", 3600), "end"])
    )


def _dns_response(src_ip: str, dst_ip: str, txid: int, qname: str, answer: str, dport: int = 50000):
    q = qname if qname.endswith(".") else qname + "."
    # Wrap in Ethernet so every sample shares one link-layer type (avoids
    # Scapy's "inconsistent linktypes" warning when written to one pcap).
    return (
        Ether(src="02:00:00:00:00:53", dst="02:00:00:00:00:0a")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=53, dport=dport)
        / DNS(id=txid, qr=1, aa=1, qd=DNSQR(qname=q, qtype="A"),
              an=DNSRR(rrname=q, type="A", ttl=300, rdata=answer))
    )


# --------------------------------------------------------------------------- #
# samples
# --------------------------------------------------------------------------- #
def build_benign() -> list:
    """Normal ARP, DHCP, DNS and TCP. Must NOT trigger any detector."""
    pkts: list = []
    # Stable ARP: each IP at exactly one MAC, each MAC owns one IP.
    pkts.append(Ether(src="02:00:00:00:00:01") / ARP(op=2, psrc="192.168.1.1",
                hwsrc="02:00:00:00:00:01", pdst="192.168.1.10", hwdst="02:00:00:00:00:0a"))
    pkts.append(Ether(src="02:00:00:00:00:0a") / ARP(op=2, psrc="192.168.1.10",
                hwsrc="02:00:00:00:00:0a", pdst="192.168.1.1", hwdst="02:00:00:00:00:01"))
    # One clean DHCP handshake from one client, one server.
    client = "02:00:00:00:00:0a"
    pkts.append(_discover(client, xid=0x1111))
    pkts.append(_offer("192.168.1.1", client, "192.168.1.10"))
    # A few DNS lookups, each unique txid, answered only by the real resolver.
    for i, name in enumerate(["example.com", "kth.se", "github.com"]):
        pkts.append(_dns_response("192.168.1.53", "192.168.1.10", 0x2000 + i, name, "203.0.113.%d" % (10 + i)))
    # A couple of complete TCP handshakes to two ports (not a scan).
    e1 = Ether(src="02:00:00:00:00:0a", dst="02:00:00:00:00:14")
    e2 = Ether(src="02:00:00:00:00:14", dst="02:00:00:00:00:0a")
    for i, port in enumerate((80, 443)):
        sp = 51000 + i
        pkts.append(e1 / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=sp, dport=port, flags="S", seq=100))
        pkts.append(e2 / IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=port, dport=sp, flags="SA", seq=500, ack=101))
        pkts.append(e1 / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=sp, dport=port, flags="A", seq=101, ack=501))
    return _stamp(pkts)


def build_arp_spoof() -> list:
    """Learn benign bindings, then poison them (binding flip + one MAC many IPs)."""
    pkts: list = []
    # Benign learning phase.
    pkts.append(Ether(src="02:00:00:00:00:01") / ARP(op=2, psrc="192.168.1.1",
                hwsrc="02:00:00:00:00:01", pdst="192.168.1.10", hwdst="02:00:00:00:00:0a"))
    pkts.append(Ether(src="02:00:00:00:00:0a") / ARP(op=2, psrc="192.168.1.10",
                hwsrc="02:00:00:00:00:0a", pdst="192.168.1.1", hwdst="02:00:00:00:00:01"))
    # Attacker (02:...:66) now claims BOTH the gateway and the victim IP.
    attacker = "02:00:00:00:00:66"
    pkts.append(Ether(src=attacker) / ARP(op=2, psrc="192.168.1.1",
                hwsrc=attacker, pdst="192.168.1.10", hwdst="02:00:00:00:00:0a"))
    pkts.append(Ether(src=attacker) / ARP(op=2, psrc="192.168.1.10",
                hwsrc=attacker, pdst="192.168.1.1", hwdst="02:00:00:00:00:01"))
    return _stamp(pkts)


def build_dhcp_starvation() -> list:
    """One benign handshake, then a flood of DISCOVERs with distinct MACs."""
    pkts: list = []
    pkts.append(_discover("02:00:00:00:00:0a", xid=0x1111))
    pkts.append(_offer("192.168.1.1", "02:00:00:00:00:0a", "192.168.1.10"))
    for i in range(20):  # 20 distinct MACs >> default threshold of 10
        pkts.append(_discover(_mac(0x80 + i), xid=0x3000 + i))
    return _stamp(pkts, step=0.05)  # all well within the 10s window


def build_dhcp_rogue() -> list:
    """Real server offers, then a rogue server offers from a different IP."""
    pkts: list = []
    client = "02:00:00:00:00:0a"
    pkts.append(_discover(client, xid=0x1111))
    pkts.append(_offer("192.168.1.1", client, "192.168.1.10"))  # real
    pkts.append(_offer("192.168.1.66", client, "192.168.1.111"))  # rogue
    return _stamp(pkts)


def build_dns_spoof() -> list:
    """A query answered by the real resolver AND a forged, conflicting answer."""
    pkts: list = []
    txid = 0x4242
    qname = "bank.example.com"
    # Real resolver answer.
    pkts.append(_dns_response("192.168.1.53", "192.168.1.10", txid, qname, "203.0.113.5"))
    # Forged answer: same txid+qname, different rdata, different source.
    pkts.append(_dns_response("192.168.1.66", "192.168.1.10", txid, qname, "192.168.1.66"))
    return _stamp(pkts)


def build_synscan() -> list:
    """One source SYNs to 150 distinct ports in a short window."""
    pkts: list = []
    eth = Ether(src="02:00:00:00:00:66", dst="02:00:00:00:00:0a")
    for i, port in enumerate(range(1, 151)):
        pkts.append(eth / IP(src="192.168.1.66", dst="192.168.1.10")
                    / TCP(sport=40000 + i, dport=port, flags="S", seq=1000 + i))
    return _stamp(pkts, step=0.001)


SAMPLES = {
    "benign": build_benign,
    "arp_spoof": build_arp_spoof,
    "dhcp_starvation": build_dhcp_starvation,
    "dhcp_rogue": build_dhcp_rogue,
    "dns_spoof": build_dns_spoof,
    "synscan": build_synscan,
}


def generate(out_dir: str | Path) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, builder in SAMPLES.items():
        path = out / f"{name}.pcap"
        write_pcap(path, builder())
        written.append(path)
        print(f"wrote {path} ({len(builder())} packets)")
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description="Generate synthetic sample PCAPs.")
    ap.add_argument("--out", default="samples", help="output directory (default: samples)")
    args = ap.parse_args()
    generate(args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
