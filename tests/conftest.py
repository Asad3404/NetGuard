"""Shared test fixtures.

Most unit tests craft packets directly in memory (fast, no file I/O). A few
integration tests want the real bundled captures, so the ``samples_dir``
fixture (re)generates them into a temp dir using the same script the repo ships.
"""

from __future__ import annotations

import time

import pytest

# Scapy imports are collected here so individual tests stay terse.
from scapy.all import ARP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether  # noqa: F401
from scapy.layers.dhcp import BOOTP, DHCP  # noqa: F401


def stamp(packets, base=1767225600.0, step=0.01):
    """Assign increasing timestamps to a list of packets (for window logic)."""
    for i, pkt in enumerate(packets):
        pkt.time = base + i * step
    return packets


@pytest.fixture
def now():
    return time.time()


@pytest.fixture(scope="session")
def samples_dir(tmp_path_factory):
    """Generate the synthetic sample PCAPs into a temp dir, once per session."""
    from scripts.gen_samples import generate

    out = tmp_path_factory.mktemp("samples")
    generate(out)
    return out
