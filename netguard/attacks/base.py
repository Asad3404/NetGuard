"""Common interface and shared plumbing for every attack module.

All attacks subclass :class:`Attack`. The base class gives them:

* a uniform ``run()`` entry point that *always* runs the safety guard first,
* a ``--dry-run`` mode that builds and prints the packets it *would* send
  without putting a single frame on the wire (this is what the tests and the
  offline demo use), and
* a small, bounded sender with per-attack rate limiting.

The design goal is that an attack is a transparent, readable object: it prints
what it is doing, it is bounded by construction, and it cannot send anything
until the lab checks pass.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..core.safety import guard_attack


@dataclass
class AttackResult:
    """What an attack did, returned for logging/tests."""

    name: str
    sent: int
    dry_run: bool
    packets: list = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class Attack:
    """Base class for lab-only attacks.

    Subclasses implement :meth:`build_packets` (pure: return the list of packets
    this attack would send) and set :attr:`name`. They usually do not need to
    override :meth:`run`.
    """

    name: str = "attack"
    # The single target IP this attack points at, or None for broadcast-domain
    # attacks (DHCP starvation). Used by the safety guard.
    target_ip: str | None = None

    def __init__(
        self,
        *,
        lab_ack: bool = False,
        dry_run: bool = True,
        rate_pps: float = 5.0,
        max_packets: int = 50,
        verbose: bool = True,
    ) -> None:
        # dry_run defaults to True on purpose: the safe thing happens unless the
        # operator explicitly asks to transmit.
        self.lab_ack = lab_ack
        self.dry_run = dry_run
        self.rate_pps = max(0.1, float(rate_pps))
        self.max_packets = max(1, int(max_packets))
        self.verbose = verbose

    # --- to be implemented by subclasses -------------------------------------

    def build_packets(self) -> list:
        """Return the list of packets this attack would send. Pure, no I/O."""
        raise NotImplementedError

    # --- shared behaviour -----------------------------------------------------

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(f"[{self.name}] {msg}")

    def run(self) -> AttackResult:
        """Run the attack: guard, build, then send (unless dry-run)."""
        # Hard safety gate. Raises SafetyError on any violation; nothing below
        # this line executes until the gate passes.
        guard_attack(self.target_ip, self.lab_ack)

        packets = self.build_packets()[: self.max_packets]
        self._log(
            f"prepared {len(packets)} packet(s); "
            f"mode={'DRY-RUN (nothing sent)' if self.dry_run else 'LIVE'} "
            f"rate={self.rate_pps}pps cap={self.max_packets}"
        )

        if self.dry_run:
            for i, pkt in enumerate(packets, 1):
                self._log(f"  would send #{i}: {pkt.summary()}")
            return AttackResult(self.name, sent=0, dry_run=True, packets=packets,
                                notes=["dry-run: no packets transmitted"])

        return self._send(packets)

    def _send(self, packets: list) -> AttackResult:
        """Transmit *packets* at the configured rate. Live mode only."""
        # Imported lazily so dry-run / PCAP paths never need L2 send privileges.
        from scapy.all import sendp

        interval = 1.0 / self.rate_pps
        sent = 0
        for i, pkt in enumerate(packets, 1):
            self._log(f"  sending #{i}: {pkt.summary()}")
            sendp(pkt, verbose=False)
            sent += 1
            if i < len(packets):
                time.sleep(interval)
        return AttackResult(self.name, sent=sent, dry_run=False, packets=packets)
