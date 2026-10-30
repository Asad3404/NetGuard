"""TCP SYN port scan (lab-only).

Protocol weakness
-----------------
This is less a protocol *flaw* than an unavoidable property of TCP's handshake:
to learn whether a port is open, you send a SYN and see whether you get a
SYN/ACK (open), a RST (closed), or nothing (filtered). A "half-open" SYN scan
never completes the handshake, which historically kept it out of application
logs. There is no way for a host to refuse to reveal this without also refusing
legitimate connections; the signal a defender keys on is instead the *pattern* —
one source firing SYNs at many ports in a short window.

What this module does
---------------------
Builds a bounded series of SYN packets to a list (or range) of ports on a
single private target. It is rate-limited, defaults to dry-run, and requires
the lab flag. It only sends the SYNs; it does not process responses, so it is a
traffic generator for the detector, not a full scanner.
"""

from __future__ import annotations

from ..core.packets import IP
from .base import Attack

try:
    from scapy.all import TCP
except Exception:  # pragma: no cover - scapy always provides TCP
    TCP = None


class SynScanAttack(Attack):
    name = "syn-scan"

    def __init__(
        self,
        *,
        target_ip: str,
        ports: list[int] | None = None,
        start_port: int = 1,
        end_port: int = 1024,
        src_ip: str = "10.0.0.66",
        **kwargs,
    ) -> None:
        self.target_ip = target_ip
        super().__init__(**kwargs)
        if ports is not None:
            self.ports = [int(p) for p in ports]
        else:
            self.ports = list(range(int(start_port), int(end_port) + 1))
        self.src_ip = src_ip

    def build_packets(self) -> list:
        packets = []
        for i, port in enumerate(self.ports):
            # Vary the source port the way a real scanner does.
            sport = 40000 + (i % 20000)
            packets.append(
                IP(src=self.src_ip, dst=self.target_ip)
                / TCP(sport=sport, dport=port, flags="S", seq=1000 + i)
            )
        return packets
