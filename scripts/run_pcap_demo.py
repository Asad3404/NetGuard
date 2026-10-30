#!/usr/bin/env python3
"""Offline end-to-end demo: no Docker, no root.

Runs every detector over each bundled sample PCAP and prints the alerts, so a
reviewer can watch the attack captures light up and the benign baseline stay
quiet. Regenerate the samples first with ``python scripts/gen_samples.py`` (or
``make samples``); ``make demo`` does both.
"""

from __future__ import annotations

import sys
from pathlib import Path

from netguard.core.sniffer import PacketSource, run_detector
from netguard.detectors import DETECTORS, CompositeDetector

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"

# Which sample should produce alerts, and roughly what we expect to see.
EXPECTED = {
    "benign.pcap": "no alerts (clean baseline)",
    "arp_spoof.pcap": "ARP binding change + one MAC claiming many IPs",
    "dhcp_starvation.pcap": "many distinct client MACs (starvation)",
    "dhcp_rogue.pcap": "DHCP OFFER from an unexpected server",
    "dns_spoof.pcap": "conflicting DNS answers for one query",
    "synscan.pcap": "one source SYNing many ports",
}


def run_one(pcap: Path) -> int:
    detector = CompositeDetector([cls() for cls in DETECTORS.values()])
    source = PacketSource.from_pcap(pcap)
    print(f"\n=== {pcap.name} — expect: {EXPECTED.get(pcap.name, '?')} ===")
    alerts = run_detector(source, detector, on_alert=lambda a: print("  " + a.human()))
    if not alerts:
        print("  (no alerts)")
    return len(alerts)


def main() -> int:
    if not SAMPLES_DIR.exists() or not any(SAMPLES_DIR.glob("*.pcap")):
        print(
            "No sample PCAPs found. Generate them first:\n"
            "  python scripts/gen_samples.py --out samples\n"
            "  (or: make samples)",
            file=sys.stderr,
        )
        return 1
    total = 0
    for name in EXPECTED:
        pcap = SAMPLES_DIR / name
        if pcap.exists():
            total += run_one(pcap)
    print(f"\n# demo complete — {total} alert(s) across the attack captures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
