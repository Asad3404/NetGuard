"""Small helpers for building and inspecting packets.

Scapy is powerful but verbose. These helpers keep the attack and detector
modules readable by centralising the few constructions and field lookups that
are used over and over. Nothing here sends anything; it only builds packets and
reads fields.
"""

from __future__ import annotations

from scapy.all import ARP, DNS, DNSQR, DNSRR, IP, UDP, Ether
from scapy.layers.dhcp import BOOTP, DHCP

# A broadcast MAC, used by ARP/DHCP helpers.
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
# ARP opcodes, named for readability.
ARP_WHO_HAS = 1
ARP_IS_AT = 2


def arp_reply(*, psrc: str, hwsrc: str, pdst: str, hwdst: str) -> Ether:
    """Build an unsolicited ARP reply ("is-at") Ethernet frame.

    This is the primitive behind ARP spoofing: tell *pdst* that *psrc* lives at
    *hwsrc*. The caller is responsible for the safety checks in
    :mod:`netguard.core.safety`.
    """
    return Ether(src=hwsrc, dst=hwdst) / ARP(
        op=ARP_IS_AT, psrc=psrc, hwsrc=hwsrc, pdst=pdst, hwdst=hwdst
    )


def arp_request(*, psrc: str, hwsrc: str, pdst: str) -> Ether:
    """Build an ARP request ("who-has") broadcast frame."""
    return Ether(src=hwsrc, dst=BROADCAST_MAC) / ARP(
        op=ARP_WHO_HAS, psrc=psrc, hwsrc=hwsrc, pdst=pdst, hwdst="00:00:00:00:00:00"
    )


def dns_response(
    *,
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    txid: int,
    qname: str,
    answer_ip: str,
    ttl: int = 300,
) -> IP:
    """Build a forged DNS answer mapping *qname* to *answer_ip*.

    This is the primitive behind DNS spoofing: a UDP/53 response carrying an
    A record the client did not get from its real resolver.
    """
    qname_b = qname if qname.endswith(".") else qname + "."
    return (
        IP(src=src_ip, dst=dst_ip)
        / UDP(sport=sport, dport=dport)
        / DNS(
            id=txid,
            qr=1,
            aa=1,
            qd=DNSQR(qname=qname_b, qtype="A"),
            an=DNSRR(rrname=qname_b, type="A", ttl=ttl, rdata=answer_ip),
        )
    )


def is_arp(pkt) -> bool:
    return pkt.haslayer(ARP)


def is_dns(pkt) -> bool:
    return pkt.haslayer(DNS)


def is_dhcp(pkt) -> bool:
    return pkt.haslayer(DHCP)


# DHCP message-type names <-> codes. Scapy stores the value as an int when a
# packet is parsed from the wire/PCAP, but as the string name when a packet is
# constructed in memory (e.g. DHCP(options=[("message-type", "discover")])).
# We must accept both forms.
_DHCP_MSG_NAMES = {
    "discover": 1,
    "offer": 2,
    "request": 3,
    "decline": 4,
    "ack": 5,
    "nak": 6,
    "release": 7,
    "inform": 8,
}


def dhcp_message_type(pkt) -> int | None:
    """Return the DHCP message-type code (1=DISCOVER .. 8=INFORM), or None.

    DHCP stores its real intent in a tagged option list; the ``message-type``
    option is the one that says whether a packet is a DISCOVER, OFFER, etc.
    """
    if not pkt.haslayer(DHCP):
        return None
    for opt in pkt[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "message-type":
            val = opt[1]
            if isinstance(val, str):
                return _DHCP_MSG_NAMES.get(val.lower())
            try:
                return int(val)
            except (TypeError, ValueError):
                return None
    return None


# DHCP message-type codes, named.
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5

__all__ = [
    "ARP",
    "BOOTP",
    "DHCP",
    "DNS",
    "DNSQR",
    "DNSRR",
    "Ether",
    "IP",
    "UDP",
    "BROADCAST_MAC",
    "ARP_WHO_HAS",
    "ARP_IS_AT",
    "DHCP_DISCOVER",
    "DHCP_OFFER",
    "DHCP_REQUEST",
    "DHCP_ACK",
    "arp_reply",
    "arp_request",
    "dns_response",
    "is_arp",
    "is_dns",
    "is_dhcp",
    "dhcp_message_type",
]
