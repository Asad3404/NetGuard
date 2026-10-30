"""Core building blocks: alerts, safety rails, packet helpers, I/O, sniffer."""

from .alerts import SEVERITIES, Alert, Evidence
from .pcap import iter_pcap, read_pcap, write_pcap
from .safety import SafetyError, guard_attack, is_private_target
from .sniffer import PacketSource, run_detector

__all__ = [
    "Alert",
    "Evidence",
    "SEVERITIES",
    "PacketSource",
    "run_detector",
    "SafetyError",
    "guard_attack",
    "is_private_target",
    "read_pcap",
    "iter_pcap",
    "write_pcap",
]
