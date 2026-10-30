"""A single packet-source abstraction for live interfaces and PCAP files.

Detectors should not care whether packets come from a live NIC or a saved
capture. :class:`PacketSource` gives them one interface — iterate packets — for
both. This is what lets the exact same detection code be unit-tested against a
crafted PCAP and then run live in the lab without changes.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from pathlib import Path

from .pcap import iter_pcap


class PacketSource:
    """A source of packets, backed by either a PCAP file or a live interface.

    Construct with exactly one of :meth:`from_pcap` or :meth:`from_iface`.
    Iterating the source yields Scapy packets. For a live source iteration
    blocks until ``count`` packets have been seen or ``timeout`` elapses; for a
    PCAP source it simply walks the file.
    """

    def __init__(
        self,
        *,
        pcap_path: str | Path | None = None,
        iface: str | None = None,
        bpf_filter: str | None = None,
        count: int = 0,
        timeout: float | None = None,
    ) -> None:
        if (pcap_path is None) == (iface is None):
            raise ValueError("provide exactly one of pcap_path or iface")
        self.pcap_path = pcap_path
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.count = count
        self.timeout = timeout

    @classmethod
    def from_pcap(cls, path: str | Path, *, bpf_filter: str | None = None) -> PacketSource:
        return cls(pcap_path=path, bpf_filter=bpf_filter)

    @classmethod
    def from_iface(
        cls,
        iface: str,
        *,
        bpf_filter: str | None = None,
        count: int = 0,
        timeout: float | None = None,
    ) -> PacketSource:
        return cls(iface=iface, bpf_filter=bpf_filter, count=count, timeout=timeout)

    def __iter__(self) -> Iterator:
        if self.pcap_path is not None:
            yield from iter_pcap(self.pcap_path)
        else:
            yield from self._iter_live()

    def _iter_live(self) -> Iterator:
        # Imported lazily so that reading PCAPs (the default, root-free path)
        # never needs live-capture privileges or a working L2 socket.
        from scapy.all import sniff

        collected: list = []

        def _collect(pkt) -> None:
            collected.append(pkt)

        sniff(
            iface=self.iface,
            filter=self.bpf_filter,
            prn=_collect,
            count=self.count,
            timeout=self.timeout,
            store=False,
        )
        yield from collected


def run_detector(source: PacketSource, detector, on_alert: Callable | None = None) -> list:
    """Feed every packet from *source* into *detector*, collecting alerts.

    ``detector`` is any object with a ``feed(packet) -> list[Alert]`` method
    (see :class:`netguard.detectors.base.Detector`). ``on_alert`` is an optional
    callback invoked for each alert as it is produced, so a CLI can stream
    alerts live instead of waiting for the capture to finish.
    """
    alerts: list = []
    for pkt in source:
        for alert in detector.feed(pkt):
            alerts.append(alert)
            if on_alert is not None:
                on_alert(alert)
    # Some detectors hold windowed state that only resolves at end-of-stream.
    for alert in detector.finalize():
        alerts.append(alert)
        if on_alert is not None:
            on_alert(alert)
    return alerts
