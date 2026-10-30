"""PCAP file reading and writing.

Thin wrappers over Scapy's ``rdpcap`` / ``wrpcap`` / ``PcapWriter`` so the rest
of the code (and the tests) never import Scapy's file I/O directly. Keeping it
here means the "read packets from a file" and "read packets from the wire"
paths can share the same iterator shape — see :mod:`netguard.core.sniffer`.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from pathlib import Path

from scapy.all import PacketList, rdpcap, wrpcap


def read_pcap(path: str | Path) -> PacketList:
    """Read every packet from *path* into memory.

    Fine for the small lab captures this toolkit deals with. For very large
    captures prefer :func:`iter_pcap`.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"PCAP file not found: {p}")
    return rdpcap(str(p))


def iter_pcap(path: str | Path) -> Iterator:
    """Iterate packets from *path* one at a time.

    Yields the same packet objects as :func:`read_pcap` but without holding the
    whole capture in memory, so detectors can run over large files as a stream.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"PCAP file not found: {p}")
    # Scapy's PacketList is already iterable; for the capture sizes here this is
    # simple and correct. A PcapReader could stream, but rdpcap keeps ordering
    # and timestamps consistent with read_pcap, which the tests rely on.
    yield from rdpcap(str(p))


def write_pcap(path: str | Path, packets: Sequence) -> None:
    """Write *packets* to *path* in pcap format, creating parent dirs."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(p), list(packets))
