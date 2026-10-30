"""Passive detectors: one per attack class.

Each detector reads packets (from a PCAP file or a live interface, via
:class:`netguard.core.sniffer.PacketSource`) and emits structured
:class:`~netguard.core.alerts.Alert` objects based on protocol semantics.
"""

from .arp import ArpSpoofDetector
from .base import Detector
from .composite import CompositeDetector
from .dhcp import DhcpAttackDetector
from .dns import DnsSpoofDetector
from .synscan import SynScanDetector

# Map CLI name -> detector class. The CLI builds one of each for "detect all".
DETECTORS = {
    "arp": ArpSpoofDetector,
    "dhcp": DhcpAttackDetector,
    "dns": DnsSpoofDetector,
    "synscan": SynScanDetector,
}

__all__ = [
    "Detector",
    "CompositeDetector",
    "ArpSpoofDetector",
    "DhcpAttackDetector",
    "DnsSpoofDetector",
    "SynScanDetector",
    "DETECTORS",
]
