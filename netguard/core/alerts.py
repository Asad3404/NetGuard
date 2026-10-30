"""Structured alerts shared by every detector.

A detector's job is to turn "a sequence of packets" into "a human- and
machine-readable statement that something suspicious happened, and here is the
evidence". The :class:`Alert` dataclass is that statement. It is deliberately
small and boring: a severity, a short message, a bag of structured fields, and
a list of evidence rows (packet summaries + timestamps) so a reviewer can trace
*why* the alert fired.

Alerts render two ways:

* ``str(alert)`` / :meth:`Alert.human` — a single human-readable line.
* :meth:`Alert.to_json` — one JSON object, suitable for writing as a JSON Lines
  stream (one alert per line) that another tool (SIEM, jq, a notebook) can read.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field


@dataclass
class Evidence:
    """One piece of supporting evidence for an alert.

    ``ts`` is a UNIX timestamp (seconds); ``summary`` is a short human string
    (typically ``packet.summary()`` from Scapy); ``detail`` holds any extra
    structured fields worth keeping.
    """

    ts: float
    summary: str
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"ts": self.ts, "summary": self.summary, "detail": self.detail}


# Severity ordering, lowest to highest. Detectors pick one of these strings.
SEVERITIES = ("info", "low", "medium", "high", "critical")


@dataclass
class Alert:
    """A single detection result.

    Attributes
    ----------
    detector:
        Name of the detector that produced the alert (e.g. ``"arp"``).
    category:
        A short machine slug for the attack class (e.g. ``"arp-spoof"``).
    severity:
        One of :data:`SEVERITIES`.
    message:
        Human-readable one-line description.
    fields:
        Structured key/value pairs (the IPs/MACs/ports involved).
    evidence:
        Supporting packets/timestamps that triggered the alert.
    ts:
        When the alert was raised (UNIX seconds). Defaults to "now".
    """

    detector: str
    category: str
    severity: str
    message: str
    fields: dict = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    ts: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"severity must be one of {SEVERITIES}, got {self.severity!r}"
            )

    def human(self) -> str:
        """Render a single human-readable line."""
        parts = " ".join(f"{k}={v}" for k, v in self.fields.items())
        head = f"[{self.severity.upper():8}] {self.detector}/{self.category}: {self.message}"
        return f"{head}  {parts}".rstrip()

    def __str__(self) -> str:  # pragma: no cover - thin wrapper
        return self.human()

    def to_dict(self) -> dict:
        return {
            "ts": self.ts,
            "detector": self.detector,
            "category": self.category,
            "severity": self.severity,
            "message": self.message,
            "fields": self.fields,
            "evidence": [e.to_dict() for e in self.evidence],
        }

    def to_json(self) -> str:
        """Render the alert as a single-line JSON object (JSON Lines)."""
        return json.dumps(self.to_dict(), sort_keys=True, default=str)
