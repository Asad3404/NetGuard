"""DNS spoofing detector.

Detection logic
---------------
A spoofed DNS answer is, by construction, a *second* answer racing the real
resolver, or an answer from somewhere other than the configured resolver. Two
signals:

1. **Unexpected responder.** If the detector is told which resolver IP(s) are
   legitimate, any DNS response sourced from a different IP is suspicious.
2. **Duplicate / conflicting answers.** Even without knowing the resolver, a
   single query (identified by transaction ID + question name) should get one
   answer. Two answers for the same (txid, qname) — especially with *different*
   rdata — is the signature of a poisoning race: the forged packet and the real
   one both arrive.

The detector keys on (txid, qname) within a short window so that an ordinary
later lookup of the same name (new txid) is not mistaken for a duplicate.
"""

from __future__ import annotations

from ..core.alerts import Alert, Evidence
from ..core.packets import DNS, DNSRR, IP, is_dns
from .base import Detector


class DnsSpoofDetector(Detector):
    name = "dns"

    def __init__(
        self,
        *,
        expected_resolvers: set[str] | None = None,
        window_s: float = 5.0,
    ) -> None:
        self.expected_resolvers = (
            set(expected_resolvers) if expected_resolvers else None
        )
        self.window = float(window_s)
        # (txid, qname) -> list of (ts, src_ip, answer_ips, summary)
        self._seen: dict[tuple[int, str], list[tuple]] = {}
        self._flagged: set[tuple[int, str]] = set()

    @staticmethod
    def _answers(dns) -> list[str]:
        out: list[str] = []
        count = int(getattr(dns, "ancount", 0) or 0)
        an = dns.an
        for _ in range(count):
            if an is None:
                break
            if isinstance(an, DNSRR) and getattr(an, "type", None) == 1:  # A record
                rd = an.rdata
                out.append(rd.decode() if isinstance(rd, bytes) else str(rd))
            an = an.payload if hasattr(an, "payload") else None
            if an is None or not isinstance(an, DNSRR):
                break
        return out

    def feed(self, pkt) -> list[Alert]:
        if not is_dns(pkt):
            return []
        dns = pkt[DNS]
        # Responses only (qr == 1) with at least one answer.
        if int(getattr(dns, "qr", 0)) != 1:
            return []
        qname = ""
        if dns.qd is not None:
            qn = dns.qd.qname
            qname = qn.decode() if isinstance(qn, bytes) else str(qn)
        txid = int(getattr(dns, "id", 0))
        src = pkt[IP].src if pkt.haslayer(IP) else None
        ts = float(getattr(pkt, "time", 0.0))
        answers = self._answers(dns)
        alerts: list[Alert] = []
        key = (txid, qname)

        # Signal 1: unexpected responder.
        if (
            self.expected_resolvers is not None
            and src is not None
            and src not in self.expected_resolvers
            and key not in self._flagged
        ):
            self._flagged.add(key)
            alerts.append(
                Alert(
                    detector=self.name,
                    category="dns-unexpected-resolver",
                    severity="high",
                    message="DNS response from an IP that is not the expected resolver",
                    fields={
                        "src": src,
                        "qname": qname,
                        "answers": answers,
                        "expected": sorted(self.expected_resolvers),
                    },
                    evidence=[Evidence(ts, pkt.summary(), {"txid": txid})],
                )
            )

        # Signal 2: duplicate/conflicting answer for the same (txid, qname).
        prior = self._seen.get(key, [])
        # Keep only prior answers within the window.
        prior = [row for row in prior if ts - row[0] <= self.window]
        for p_ts, p_src, p_ans, p_sum in prior:
            if set(p_ans) != set(answers) and key not in self._flagged:
                self._flagged.add(key)
                alerts.append(
                    Alert(
                        detector=self.name,
                        category="dns-poison-race",
                        severity="high",
                        message="two conflicting DNS answers for one query (poisoning race)",
                        fields={
                            "qname": qname,
                            "txid": txid,
                            "answer_a": p_ans,
                            "answer_b": answers,
                            "src_a": p_src,
                            "src_b": src,
                        },
                        evidence=[
                            Evidence(p_ts, p_sum, {"which": "first"}),
                            Evidence(ts, pkt.summary(), {"which": "second"}),
                        ],
                    )
                )
                break
        prior.append((ts, src, answers, pkt.summary()))
        self._seen[key] = prior
        return alerts
