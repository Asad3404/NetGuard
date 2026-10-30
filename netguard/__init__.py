"""NetGuard — a Scapy-based network attack & detection toolkit.

NetGuard is an educational project. It contains two halves that mirror each
other:

* ``netguard.attacks`` — implementations of classic L2/L3/DNS attacks, written
  so that they are *bounded, rate-limited, and refuse to run against anything
  that is not a private/lab target*. They exist to generate the exact traffic
  the detectors are built to catch.
* ``netguard.detectors`` — passive detectors that read either a live interface
  or a PCAP file and emit structured alerts based on protocol semantics.

See the README and ``docs/`` for the protocol-level explanation of every
attack and the reasoning behind each detector. The attack side is for isolated
labs, loopback, and the bundled synthetic PCAPs only.
"""

__version__ = "0.1.0"
__author__ = "asad3404"

__all__ = ["__version__", "__author__"]
