"""Safety rails for the attack side of NetGuard.

Every attack module routes through this module before it is allowed to send a
single packet. The rules are intentionally strict and fail-closed:

1. **Private targets only.** A target IP must be in RFC 1918 / RFC 4193 private
   space, loopback, or link-local. Any public/global address is refused.
2. **Explicit lab acknowledgement.** The operator must pass the
   ``--i-understand-this-is-a-lab`` flag (surfaced as ``lab_ack=True`` here).
   Without it the attack refuses to run.

These checks exist so the toolkit cannot be pointed at the open internet by
accident. They are a guard rail, not a sandbox: anyone editing the source can
remove them, which is exactly why the ethics/scope section of the README states
the legal and ethical boundary in plain language. The code enforces the common
case; the human is responsible for the rest.
"""

from __future__ import annotations

import ipaddress


class SafetyError(RuntimeError):
    """Raised when an attack is asked to do something outside the lab scope."""


# Flag text the CLI requires. Kept here so the message and the flag can't drift.
LAB_ACK_FLAG = "--i-understand-this-is-a-lab"


def is_private_target(ip: str) -> bool:
    """Return True if *ip* is a safe lab target.

    "Safe" means private (RFC 1918 / RFC 4193), loopback, or link-local. These
    are the only ranges that can exist inside an isolated lab without also being
    routable on the public internet. Anything else — including a bare hostname
    that does not parse as an IP — is treated as unsafe.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def require_private_target(ip: str) -> None:
    """Raise :class:`SafetyError` unless *ip* is a private/lab target."""
    if not is_private_target(ip):
        raise SafetyError(
            f"refusing to target {ip!r}: NetGuard attacks may only target private/"
            f"lab addresses (RFC 1918, loopback, or link-local). This is a hard "
            f"guard rail — see the ethics section of the README."
        )


def require_lab_ack(lab_ack: bool) -> None:
    """Raise :class:`SafetyError` unless the lab acknowledgement was given."""
    if not lab_ack:
        raise SafetyError(
            f"refusing to run an attack without explicit lab acknowledgement. "
            f"Pass {LAB_ACK_FLAG} to confirm you are on an isolated lab network "
            f"that you own or are authorised to test."
        )


def guard_attack(target_ip: str | None, lab_ack: bool) -> None:
    """Run every pre-flight safety check for an attack.

    Call this once at the top of every attack's ``run()``. ``target_ip`` may be
    ``None`` for attacks that are inherently broadcast/local (e.g. DHCP
    starvation targets the broadcast domain, not a single host); the lab
    acknowledgement is still required in that case.
    """
    require_lab_ack(lab_ack)
    if target_ip is not None:
        require_private_target(target_ip)
