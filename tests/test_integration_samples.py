"""End-to-end: run every detector over the bundled synthetic captures.

Proves the attack captures light up with the expected category and that the
benign baseline stays completely silent — the central claim of the project.
"""

import pytest

from netguard.core.sniffer import PacketSource, run_detector
from netguard.detectors import DETECTORS, CompositeDetector


def _run(pcap):
    det = CompositeDetector([cls() for cls in DETECTORS.values()])
    return run_detector(PacketSource.from_pcap(pcap), det)


def test_benign_sample_is_silent(samples_dir):
    alerts = _run(samples_dir / "benign.pcap")
    assert alerts == [], [a.human() for a in alerts]


@pytest.mark.parametrize(
    "sample,expected_category",
    [
        ("arp_spoof.pcap", "arp-spoof"),
        ("dhcp_starvation.pcap", "dhcp-starvation"),
        ("dhcp_rogue.pcap", "dhcp-rogue-server"),
        ("dns_spoof.pcap", "dns-poison-race"),
        ("synscan.pcap", "tcp-syn-scan"),
    ],
)
def test_attack_sample_fires(samples_dir, sample, expected_category):
    alerts = _run(samples_dir / sample)
    cats = [a.category for a in alerts]
    assert expected_category in cats, cats


def test_arp_sample_also_flags_many_ips(samples_dir):
    cats = [a.category for a in _run(samples_dir / "arp_spoof.pcap")]
    assert "arp-mac-many-ips" in cats
