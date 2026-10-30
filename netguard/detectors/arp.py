"""ARP spoofing detector.

Detection logic
---------------
Normal ARP has a stable, one-to-one-ish mapping: an IP lives at one MAC, and
that binding changes only rarely (a host reboots, a NIC is swapped, a failover
occurs). ARP spoofing breaks this in two observable ways:

1. **Binding change / conflict.** An IP that was seen at MAC *A* suddenly starts
   claiming MAC *B*. The attacker is overwriting the victim's/gateway's known
   mapping. This is the strongest single-packet signal.
2. **One MAC, many IPs.** The attacker's MAC answers for several IPs at once
   (it is impersonating both the gateway and the victim). A host legitimately
   owning many IPs on one NIC is possible, so this is a weaker, corroborating
   signal and is rated lower.

To keep false positives down we learn bindings from ARP replies and only alert
when an *established* binding changes. The first time we see an IP we just learn
it; we do not alert on first contact.
"""

from __future__ import annotations

from ..core.alerts import Alert, Evidence
from ..core.packets import ARP, ARP_IS_AT
from .base import Detector


class ArpSpoofDetector(Detector):
    name = "arp"

    def __init__(self, *, alert_on_many_ips: int = 2) -> None:
        # ip -> mac we currently believe is authoritative.
        self._ip_to_mac: dict[str, str] = {}
        # mac -> set of IPs it has claimed.
        self._mac_to_ips: dict[str, set[str]] = {}
        # Only flag "one MAC, many IPs" once it claims at least this many.
        self._many_ips = max(2, int(alert_on_many_ips))
        self._flagged_macs: set[str] = set()

    def feed(self, pkt) -> list[Alert]:
        if not pkt.haslayer(ARP):
            return []
        arp = pkt[ARP]
        # Only replies (is-at) assert a binding. Requests (who-has) carry the
        # sender's own binding too, but replies are where spoofing lives.
        if int(arp.op) != ARP_IS_AT:
            return []

        ip = arp.psrc
        mac = (arp.hwsrc or "").lower()
        if not ip or not mac or ip == "0.0.0.0":
            return []

        ts = float(getattr(pkt, "time", 0.0))
        alerts: list[Alert] = []

        prev = self._ip_to_mac.get(ip)
        if prev is None:
            # First time we see this IP: learn it, don't alert.
            self._ip_to_mac[ip] = mac
        elif prev != mac:
            # Established binding changed — the core ARP-spoof signal.
            alerts.append(
                Alert(
                    detector=self.name,
                    category="arp-spoof",
                    severity="high",
                    message="ARP binding changed for an IP (possible cache poisoning)",
                    fields={"ip": ip, "old_mac": prev, "new_mac": mac},
                    evidence=[Evidence(ts, pkt.summary(), {"op": "is-at"})],
                )
            )
            # Adopt the new mapping so we flag the *next* flip too, not every
            # packet of an ongoing flood.
            self._ip_to_mac[ip] = mac

        ips_for_mac = self._mac_to_ips.setdefault(mac, set())
        ips_for_mac.add(ip)
        if len(ips_for_mac) >= self._many_ips and mac not in self._flagged_macs:
            self._flagged_macs.add(mac)
            alerts.append(
                Alert(
                    detector=self.name,
                    category="arp-mac-many-ips",
                    severity="medium",
                    message="one MAC is claiming multiple IPs (possible MITM)",
                    fields={"mac": mac, "ips": sorted(ips_for_mac)},
                    evidence=[Evidence(ts, pkt.summary(), {"op": "is-at"})],
                )
            )
        return alerts
