"""NetGuard command-line interface.

Three subcommands:

* ``netguard detect``  — run detectors over a PCAP (``--pcap``) or a live
  interface (``--iface``). By default every detector runs; ``--only`` narrows
  it. Alerts print human-readable, or as JSON Lines with ``--json``.
* ``netguard replay``  — convenience alias that feeds a sample PCAP through all
  detectors (same as ``detect --pcap`` but phrased as "replay this sample").
* ``netguard attack``  — run a lab-only attack. Refuses to do anything unless
  the operator passes ``--i-understand-this-is-a-lab`` and the target is a
  private address, and defaults to ``--dry-run`` so nothing is transmitted
  unless ``--live`` is given.

The attack side is for isolated labs / loopback / the bundled synthetic PCAPs
only. See the ethics section of the README.
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .core.safety import LAB_ACK_FLAG, SafetyError
from .core.sniffer import PacketSource, run_detector
from .detectors import DETECTORS, CompositeDetector


# --------------------------------------------------------------------------- #
# detect / replay
# --------------------------------------------------------------------------- #
def _build_detectors(names: list[str]) -> CompositeDetector:
    chosen = []
    for n in names:
        cls = DETECTORS[n]
        chosen.append(cls())
    return CompositeDetector(chosen)


def _emit(alert, as_json: bool) -> None:
    print(alert.to_json() if as_json else alert.human())


def cmd_detect(args: argparse.Namespace) -> int:
    names = args.only.split(",") if args.only else list(DETECTORS)
    names = [n.strip() for n in names if n.strip()]
    unknown = [n for n in names if n not in DETECTORS]
    if unknown:
        print(f"error: unknown detector(s): {', '.join(unknown)}", file=sys.stderr)
        print(f"       choose from: {', '.join(DETECTORS)}", file=sys.stderr)
        return 2

    detector = _build_detectors(names)

    if args.pcap:
        source = PacketSource.from_pcap(args.pcap, bpf_filter=args.bpf)
        where = f"pcap {args.pcap}"
    else:
        source = PacketSource.from_iface(
            args.iface, bpf_filter=args.bpf, count=args.count, timeout=args.timeout
        )
        where = f"iface {args.iface}"

    if not args.json:
        print(f"# netguard detect — reading {where}; detectors: {', '.join(names)}")

    alerts = run_detector(source, detector, on_alert=lambda a: _emit(a, args.json))

    if not args.json:
        print(f"# done: {len(alerts)} alert(s)")
    return 1 if alerts else 0


def cmd_replay(args: argparse.Namespace) -> int:
    # replay is just detect over a pcap with every detector.
    ns = argparse.Namespace(
        pcap=args.pcap, iface=None, only=args.only, json=args.json,
        bpf=None, count=0, timeout=None,
    )
    return cmd_detect(ns)


# --------------------------------------------------------------------------- #
# attack
# --------------------------------------------------------------------------- #
def _common_attack_kwargs(args: argparse.Namespace) -> dict:
    return {
        "lab_ack": args.lab_ack,
        "dry_run": not args.live,
        "rate_pps": args.rate,
        "max_packets": args.max_packets,
    }


def cmd_attack(args: argparse.Namespace) -> int:
    try:
        if args.kind == "arp":
            from .attacks import ArpSpoofAttack

            atk = ArpSpoofAttack(
                victim_ip=args.victim_ip,
                victim_mac=args.victim_mac,
                gateway_ip=args.gateway_ip,
                gateway_mac=args.gateway_mac,
                attacker_mac=args.attacker_mac,
                rounds=args.rounds,
                **_common_attack_kwargs(args),
            )
        elif args.kind == "dhcp":
            from .attacks import DhcpStarvationAttack

            atk = DhcpStarvationAttack(
                count=args.count, seed=args.seed, **_common_attack_kwargs(args)
            )
        elif args.kind == "dns":
            from .attacks import DnsSpoofAttack

            atk = DnsSpoofAttack(
                victim_ip=args.victim_ip,
                resolver_ip=args.resolver_ip,
                qname=args.qname,
                spoof_ip=args.spoof_ip,
                txid=args.txid,
                **_common_attack_kwargs(args),
            )
        elif args.kind == "synscan":
            from .attacks import SynScanAttack

            atk = SynScanAttack(
                target_ip=args.target_ip,
                start_port=args.start_port,
                end_port=args.end_port,
                src_ip=args.src_ip,
                **_common_attack_kwargs(args),
            )
        else:  # pragma: no cover - argparse prevents this
            print(f"error: unknown attack {args.kind!r}", file=sys.stderr)
            return 2

        result = atk.run()
    except SafetyError as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 3

    print(
        f"# {result.name}: built {len(result.packets)} packet(s), "
        f"sent {result.sent} ({'dry-run' if result.dry_run else 'LIVE'})"
    )
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netguard",
        description="Scapy-based network attack (lab-only) & detection toolkit.",
    )
    p.add_argument("--version", action="version", version=f"netguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # detect ----------------------------------------------------------------
    d = sub.add_parser("detect", help="run detectors over a PCAP or live interface")
    src = d.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap", help="path to a PCAP file to analyse")
    src.add_argument("--iface", help="live interface to sniff (needs privileges)")
    d.add_argument(
        "--only",
        help=f"comma-separated subset of detectors ({', '.join(DETECTORS)})",
    )
    d.add_argument("--json", action="store_true", help="emit alerts as JSON Lines")
    d.add_argument("--bpf", help="optional BPF capture filter")
    d.add_argument("--count", type=int, default=0, help="live: stop after N packets")
    d.add_argument("--timeout", type=float, default=None, help="live: stop after N seconds")
    d.set_defaults(func=cmd_detect)

    # replay ----------------------------------------------------------------
    r = sub.add_parser("replay", help="feed a sample PCAP through all detectors")
    r.add_argument("pcap", help="path to a PCAP file")
    r.add_argument("--only", help="comma-separated subset of detectors")
    r.add_argument("--json", action="store_true", help="emit alerts as JSON Lines")
    r.set_defaults(func=cmd_replay)

    # attack ----------------------------------------------------------------
    a = sub.add_parser(
        "attack",
        help="run a lab-only attack (refuses without lab ack + private target)",
    )
    a.add_argument(
        LAB_ACK_FLAG,
        dest="lab_ack",
        action="store_true",
        help="confirm this is an isolated lab you own/are authorised to test",
    )
    a.add_argument("--live", action="store_true", help="actually transmit (default: dry-run)")
    a.add_argument("--rate", type=float, default=5.0, help="packets per second (default 5)")
    a.add_argument("--max-packets", type=int, default=50, help="hard cap on packets (default 50)")
    atk_sub = a.add_subparsers(dest="kind", required=True)

    a_arp = atk_sub.add_parser("arp", help="ARP cache poisoning (victim<->gateway)")
    a_arp.add_argument("--victim-ip", required=True)
    a_arp.add_argument("--victim-mac", required=True)
    a_arp.add_argument("--gateway-ip", required=True)
    a_arp.add_argument("--gateway-mac", required=True)
    a_arp.add_argument("--attacker-mac", required=True)
    a_arp.add_argument("--rounds", type=int, default=3)

    a_dhcp = atk_sub.add_parser("dhcp", help="DHCP starvation (DISCOVER flood)")
    a_dhcp.add_argument("--count", type=int, default=20)
    a_dhcp.add_argument("--seed", type=int, default=None)

    a_dns = atk_sub.add_parser("dns", help="DNS spoofed answer")
    a_dns.add_argument("--victim-ip", required=True)
    a_dns.add_argument("--resolver-ip", required=True)
    a_dns.add_argument("--qname", required=True)
    a_dns.add_argument("--spoof-ip", required=True)
    a_dns.add_argument("--txid", type=lambda s: int(s, 0), default=0x1337)

    a_syn = atk_sub.add_parser("synscan", help="TCP SYN port scan")
    a_syn.add_argument("--target-ip", required=True)
    a_syn.add_argument("--start-port", type=int, default=1)
    a_syn.add_argument("--end-port", type=int, default=1024)
    a_syn.add_argument("--src-ip", default="10.0.0.66")

    a.set_defaults(func=cmd_attack)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
