"""DHCP attack detector (starvation + rogue server).

Detection logic
---------------
Two independent signals, matching the two attacks:

1. **Rogue server.** DHCP OFFER/ACK packets should only ever come from the
   network's known DHCP server(s). The detector is given the expected server
   IP(s); an OFFER/ACK from any other source IP is a rogue server. If no
   expected set is configured, it learns the first server it sees and flags any
   later, different server.
2. **Starvation.** DHCP starvation floods DISCOVERs, each with a *different*
   client MAC. The detector counts distinct client MACs seen in DISCOVER
   packets within a sliding time window; crossing a threshold fires an alert.
   Normal networks see a trickle of DISCOVERs from a small, stable set of MACs.

Both signals read the DHCP message-type option rather than guessing from ports,
so they are robust to relayed/odd ports.
"""

from __future__ import annotations

from collections import deque

from ..core.alerts import Alert, Evidence
from ..core.packets import (
    DHCP_ACK,
    DHCP_DISCOVER,
    DHCP_OFFER,
    IP,
    dhcp_message_type,
    is_dhcp,
)
from .base import Detector


class DhcpAttackDetector(Detector):
    name = "dhcp"

    def __init__(
        self,
        *,
        expected_servers: set[str] | None = None,
        starvation_window_s: float = 10.0,
        starvation_threshold: int = 10,
    ) -> None:
        self.expected_servers = set(expected_servers) if expected_servers else None
        self._learned_server: str | None = None
        self._flagged_servers: set[str] = set()
        self.window = float(starvation_window_s)
        self.threshold = int(starvation_threshold)
        # deque of (ts, client_mac) for DISCOVERs within the window.
        self._discovers: deque[tuple[float, str]] = deque()
        self._starvation_fired = False

    def feed(self, pkt) -> list[Alert]:
        if not is_dhcp(pkt):
            return []
        mtype = dhcp_message_type(pkt)
        if mtype is None:
            return []
        ts = float(getattr(pkt, "time", 0.0))
        alerts: list[Alert] = []

        if mtype in (DHCP_OFFER, DHCP_ACK):
            alerts.extend(self._check_server(pkt, ts, mtype))
        elif mtype == DHCP_DISCOVER:
            alerts.extend(self._check_starvation(pkt, ts))
        return alerts

    def _check_server(self, pkt, ts: float, mtype: int) -> list[Alert]:
        src = pkt[IP].src if pkt.haslayer(IP) else None
        if not src:
            return []
        if self.expected_servers is not None:
            ok = src in self.expected_servers
        else:
            if self._learned_server is None:
                self._learned_server = src
            ok = src == self._learned_server
        if ok or src in self._flagged_servers:
            return []
        self._flagged_servers.add(src)
        kind = "OFFER" if mtype == DHCP_OFFER else "ACK"
        return [
            Alert(
                detector=self.name,
                category="dhcp-rogue-server",
                severity="high",
                message=f"DHCP {kind} from an unexpected server (possible rogue DHCP)",
                fields={
                    "server_ip": src,
                    "expected": sorted(self.expected_servers)
                    if self.expected_servers is not None
                    else [self._learned_server],
                },
                evidence=[Evidence(ts, pkt.summary(), {"msg_type": kind})],
            )
        ]

    def _check_starvation(self, pkt, ts: float) -> list[Alert]:
        mac = (pkt.src or "").lower()
        self._discovers.append((ts, mac))
        # Drop entries older than the window.
        while self._discovers and ts - self._discovers[0][0] > self.window:
            self._discovers.popleft()
        distinct = {m for _, m in self._discovers}
        if len(distinct) >= self.threshold and not self._starvation_fired:
            self._starvation_fired = True
            return [
                Alert(
                    detector=self.name,
                    category="dhcp-starvation",
                    severity="high",
                    message="many distinct client MACs sent DHCP DISCOVER in a short window",
                    fields={
                        "distinct_macs": len(distinct),
                        "window_s": self.window,
                        "threshold": self.threshold,
                    },
                    evidence=[Evidence(ts, pkt.summary(), {"msg_type": "DISCOVER"})],
                )
            ]
        return []
