"""Lab-only attack modules.

Every attack here is bounded, rate-limited, defaults to dry-run, and refuses to
run unless it is given a private target and an explicit lab acknowledgement.
They exist to produce the traffic that :mod:`netguard.detectors` is built to
catch. Do not run them against any network you do not own or are not explicitly
authorised to test.
"""

from .arp import ArpSpoofAttack
from .base import Attack, AttackResult
from .dhcp import DhcpStarvationAttack, RogueDhcpOffer
from .dns import DnsSpoofAttack
from .synscan import SynScanAttack

# Map CLI subcommand name -> a small factory description used by cli.py.
ATTACKS = {
    "arp": ArpSpoofAttack,
    "dhcp": DhcpStarvationAttack,
    "dns": DnsSpoofAttack,
    "synscan": SynScanAttack,
}

__all__ = [
    "Attack",
    "AttackResult",
    "ArpSpoofAttack",
    "DhcpStarvationAttack",
    "RogueDhcpOffer",
    "DnsSpoofAttack",
    "SynScanAttack",
    "ATTACKS",
]
