"""Run several detectors over a single packet stream.

The CLI's ``detect`` with no specific detector selected wants to catch anything
in a capture. :class:`CompositeDetector` fans each packet out to every wrapped
detector and concatenates their alerts, so it plugs into
:func:`netguard.core.sniffer.run_detector` just like a single detector.
"""

from __future__ import annotations

from ..core.alerts import Alert
from .base import Detector


class CompositeDetector(Detector):
    name = "composite"

    def __init__(self, detectors: list[Detector]) -> None:
        self.detectors = list(detectors)

    def feed(self, pkt) -> list[Alert]:
        alerts: list[Alert] = []
        for det in self.detectors:
            alerts.extend(det.feed(pkt))
        return alerts

    def finalize(self) -> list[Alert]:
        alerts: list[Alert] = []
        for det in self.detectors:
            alerts.extend(det.finalize())
        return alerts
