"""TCP SYN port-scan detector.

Detection logic
---------------
A SYN scan is one source probing many destination ports in a short time. The
individual packets are perfectly ordinary TCP SYNs; the *pattern* is the tell.
The detector keeps, per source IP, a sliding time window of the distinct
destination ports that received a bare SYN (SYN set, ACK clear — i.e. a
connection *attempt*, not part of an established flow). When one source touches
more than ``port_threshold`` distinct ports within ``window_s``, it alerts.

Tuning notes
------------
* Only ``flags == S`` (SYN without ACK) counts, so normal three-way handshakes
  (SYN, then SYN/ACK, then ACK) and established traffic do not inflate the
  count.
* The threshold and window are the two knobs a defender tunes against their
  baseline; the defaults (100 ports / 5 s) catch an aggressive scan while
  ignoring a handful of parallel connections a browser might open.
"""

from __future__ import annotations

from collections import defaultdict, deque

from ..core.alerts import Alert, Evidence
from ..core.packets import IP
from .base import Detector

try:
    from scapy.all import TCP
except Exception:  # pragma: no cover
    TCP = None


class SynScanDetector(Detector):
    name = "synscan"

    def __init__(self, *, window_s: float = 5.0, port_threshold: int = 100) -> None:
        self.window = float(window_s)
        self.threshold = int(port_threshold)
        # src_ip -> deque of (ts, dport)
        self._hits: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        self._fired: set[str] = set()
        # Remember the last packet summary per source for evidence.
        self._last_summary: dict[str, tuple[float, str]] = {}

    def feed(self, pkt) -> list[Alert]:
        if TCP is None or not pkt.haslayer(TCP) or not pkt.haslayer(IP):
            return []
        tcp = pkt[TCP]
        # A bare SYN is a connection attempt. 0x02 = SYN, 0x12 = SYN/ACK.
        flags = int(tcp.flags)
        if not (flags & 0x02) or (flags & 0x10):  # SYN set, ACK clear
            return []
        src = pkt[IP].src
        dport = int(tcp.dport)
        ts = float(getattr(pkt, "time", 0.0))

        dq = self._hits[src]
        dq.append((ts, dport))
        while dq and ts - dq[0][0] > self.window:
            dq.popleft()
        self._last_summary[src] = (ts, pkt.summary())

        distinct_ports = {p for _, p in dq}
        if len(distinct_ports) >= self.threshold and src not in self._fired:
            self._fired.add(src)
            return [
                Alert(
                    detector=self.name,
                    category="tcp-syn-scan",
                    severity="medium",
                    message="one source sent SYNs to many ports in a short window (port scan)",
                    fields={
                        "src": src,
                        "distinct_ports": len(distinct_ports),
                        "window_s": self.window,
                        "threshold": self.threshold,
                    },
                    evidence=[Evidence(ts, pkt.summary(), {"flags": "S"})],
                )
            ]
        return []
