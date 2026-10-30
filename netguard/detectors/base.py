"""Common interface for detectors.

A detector is a small state machine. It is fed packets one at a time via
:meth:`Detector.feed`, updates its internal state, and returns a (possibly
empty) list of :class:`~netguard.core.alerts.Alert` for *that* packet. Some
detectors also hold windowed state that only resolves at the end of a capture;
those emit remaining alerts from :meth:`Detector.finalize`.

This streaming shape is what lets one detector run identically over a PCAP file
and a live interface (see :func:`netguard.core.sniffer.run_detector`).
"""

from __future__ import annotations

from ..core.alerts import Alert


class Detector:
    """Base class for all detectors."""

    #: Short name, also used as the ``detector`` field on alerts.
    name: str = "detector"

    def feed(self, pkt) -> list[Alert]:
        """Process one packet, returning any alerts it triggers."""
        raise NotImplementedError

    def finalize(self) -> list[Alert]:
        """Return alerts that can only be decided at end-of-stream.

        Default: nothing. Windowed detectors (e.g. SYN scan) override this.
        """
        return []
