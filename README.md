# NetGuard

**A Scapy-based toolkit that both *performs* (in an isolated lab) and *detects*
classic L2/L3/DNS network attacks — written to show I understand these
protocols well enough to break and defend them in code.**

NetGuard is the third project in a portfolio built toward the KTH *Networks and
Systems Security* track, alongside [SecureNet Lab](#) (a segmented containerlab
network) and [Detection-as-Code](#) (Sigma rules + CI). Where those cover
network design and detection content, this one is about the protocols
themselves: for each attack there is an implementation *and* a matching detector
that reads live traffic or a PCAP and explains, with evidence, why it fired.

> **Scope, up front:** the attack half is for isolated labs, loopback, and the
> bundled synthetic PCAPs **only**. Every attack refuses to run unless it is
> given a private (RFC 1918 / loopback / link-local) target *and* an explicit
> `--i-understand-this-is-a-lab` acknowledgement, and defaults to dry-run.
> See [Ethics & scope](#ethics--scope).

---

## At a glance

| Attack | Module | Detector | Core detection logic | Tests |
|---|---|---|---|---|
| **ARP cache poisoning** | `netguard/attacks/arp.py` | `netguard/detectors/arp.py` | An *established* IP→MAC binding changes, or one MAC claims many IPs. | `tests/test_arp_detector.py` |
| **DHCP starvation** | `netguard/attacks/dhcp.py` (`DhcpStarvationAttack`) | `netguard/detectors/dhcp.py` | Many *distinct client MACs* send DISCOVER within a sliding window. | `tests/test_dhcp_detector.py` |
| **Rogue DHCP** | `netguard/attacks/dhcp.py` (`RogueDhcpOffer`) | `netguard/detectors/dhcp.py` | OFFER/ACK from an IP that is not the expected/learned server. | `tests/test_dhcp_detector.py` |
| **DNS spoofing / cache poisoning** | `netguard/attacks/dns.py` | `netguard/detectors/dns.py` | Two conflicting answers for one `(txid, qname)`, or a response from a non-resolver IP. | `tests/test_dns_detector.py` |
| **TCP SYN port scan** | `netguard/attacks/synscan.py` | `netguard/detectors/synscan.py` | One source sends bare SYNs to many distinct ports within a window. | `tests/test_synscan_detector.py` |

Every attack's self-built packets are also fed straight back into its detector
in `tests/test_attack_detect_roundtrip.py`, and all detectors run over the
bundled captures (including a **benign baseline that must stay silent**) in
`tests/test_integration_samples.py`.

Full protocol write-ups — the weakness each attack abuses and how the detector
tells it apart from normal traffic — are in [`docs/`](docs/):
[ARP](docs/arp.md) · [DHCP](docs/dhcp.md) · [DNS](docs/dns.md) ·
[SYN scan](docs/synscan.md).

---

## Architecture

```
netguard/
├── core/            # shared plumbing
│   ├── alerts.py    #   structured Alert (human line + JSON Lines) with evidence
│   ├── safety.py    #   private-target + lab-ack guard rails (fail-closed)
│   ├── packets.py   #   Scapy construction/inspection helpers
│   ├── pcap.py      #   read/write/iterate PCAP files
│   └── sniffer.py   #   PacketSource: one interface for live NIC *and* PCAP
├── attacks/         # lab-only; each bounded, rate-limited, dry-run by default
│   ├── base.py      #   Attack base class (guard → build → send)
│   ├── arp.py  dhcp.py  dns.py  synscan.py
├── detectors/       # passive; each a small feed(pkt)->alerts state machine
│   ├── base.py  composite.py
│   ├── arp.py  dhcp.py  dns.py  synscan.py
└── cli.py           # `netguard detect | replay | attack`
```

The key design idea is the **mirror**: attack and detector come in pairs, and a
detector consumes packets through one `PacketSource` abstraction so the *same*
detection code runs against a crafted PCAP in a unit test and against a live
interface in the lab, unchanged.

---

## Install & run

Requires Python ≥ 3.10. Developed on Windows 11 + WSL2 (Ubuntu 22.04); nothing
is OS-specific for the default (PCAP) path.

```bash
# 1. clone, then create and activate a virtualenv
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

# 2. install the package (editable) with dev tools
pip install -e ".[dev]"            # or: make setup
```

### Run the tests (no root, no Docker)

```bash
pytest                             # or: make test
```

### Run the offline demo (no root, no Docker)

Generates the synthetic PCAPs and replays each through all detectors:

```bash
make demo
# equivalently:
python scripts/gen_samples.py --out samples
python scripts/run_pcap_demo.py
```

### Use the CLI

```bash
# Detect over a sample capture (human-readable)
netguard detect --pcap samples/arp_spoof.pcap

# Detect over a capture, emitting JSON Lines (one alert per line)
netguard detect --pcap samples/dns_spoof.pcap --json

# Replay a sample through every detector (alias for detect --pcap)
netguard replay samples/synscan.pcap

# Detect live on an interface (needs capture privileges)
sudo netguard detect --iface eth0 --only arp,dns

# Run an attack — LAB ONLY. Defaults to dry-run; refuses public targets.
netguard attack --i-understand-this-is-a-lab synscan --target-ip 192.168.1.10
# add --live to actually transmit (only do this on an isolated lab you own)
```

`netguard detect` exits `1` when any alert fired and `0` when the capture was
clean, so it slots into scripts and CI.

### Optional: the live lab topology

A four-node docker-compose / containerlab topology (attacker, victim, host,
resolver) on an **internal** bridge is in [`demo/`](demo/). It is optional and
for on-the-wire screenshots; the PCAP demo above is the default. See
[`demo/README.md`](demo/README.md).

---

## Results

> **[FILL FROM YOUR RUN]** — the numbers and screenshots below are placeholders.
> Run the commands and paste real output; do not ship invented results.

### Offline PCAP demo (`make demo`)

| Capture | Expected | Alerts fired | Notes |
|---|---|---|---|
| `benign.pcap` | none (clean baseline) | `[FILL FROM YOUR RUN]` | |
| `arp_spoof.pcap` | `arp-spoof` + `arp-mac-many-ips` | `[FILL FROM YOUR RUN]` | |
| `dhcp_starvation.pcap` | `dhcp-starvation` | `[FILL FROM YOUR RUN]` | |
| `dhcp_rogue.pcap` | `dhcp-rogue-server` | `[FILL FROM YOUR RUN]` | |
| `dns_spoof.pcap` | `dns-poison-race` | `[FILL FROM YOUR RUN]` | |
| `synscan.pcap` | `tcp-syn-scan` | `[FILL FROM YOUR RUN]` | |

### Test suite

```
[FILL FROM YOUR RUN]  e.g. "62 passed in 0.80s"
```

### Live lab run (optional)

`[FILL FROM YOUR RUN]` — screenshots / alert excerpts from `demo/run_demo.sh`.

---

## Lessons learned (from building this)

- **Attack and detector are two views of one invariant.** Writing them as pairs
  forced each detector to key on the *protocol property the attack violates*
  (an ARP binding is stable; one DNS query has one answer; a DHCP server is
  singular) rather than on incidental packet features. The round-trip test
  exists precisely so the two halves cannot drift apart.
- **Specificity beats volume.** My first instinct for DHCP starvation was "alert
  on a high DISCOVER rate", which false-positives on any busy network. Counting
  *distinct client MACs in a window* is the signature that is actually unique to
  the attack. The same lesson shows up in SYN-scan (count distinct *ports per
  source*, and only bare SYNs) and DNS (compare *rdata*, keyed on `txid+qname`,
  so retransmits and later lookups don't fire).
- **Scapy stores constructed vs. parsed packets differently.** A DHCP
  `message-type` is the string `"discover"` on an in-memory packet but an int
  once written to and re-read from a PCAP. The detector has to accept both — a
  bug the integration tests caught immediately.
- **Modern `ipaddress` counts the TEST-NET/doc ranges as private.** My safety
  check leans on `is_private`/`is_loopback`/`is_link_local`; verifying its exact
  behaviour (rather than assuming) is what a guard rail deserves.
- **Fail-closed safety belongs in one place.** Routing every attack through a
  single `guard_attack()` means the "private target + lab ack" rule can't be
  forgotten in a new attack module.

---

## Future work

- **IPv6:** NDP spoofing (the ARP analogue) and its detector; DHCPv6.
- **More detectors:** gratuitous-ARP storms, DNS NXDOMAIN flooding, TCP
  connect/FIN/XMAS scan variants, and a slow-scan ("low-and-slow") heuristic to
  cover the known SYN-scan blind spot.
- **Baseline learning:** a short passive learning phase to auto-populate the
  expected resolver(s) and DHCP server(s) instead of configuring them by hand.
- **Alert sinks:** emit the JSON Lines straight to a SIEM, and ship Sigma rules
  matching this tool's alert schema (ties into the Detection-as-Code repo).
- **Performance:** switch the PCAP path to a streaming `PcapReader` for very
  large captures.

---

## Ethics & scope

NetGuard's attack modules exist to generate the traffic its detectors are built
to catch, in a controlled setting, as a learning exercise. They are **not** a
pentest toolkit for arbitrary networks.

- **Lab only.** Use the attack side exclusively on an isolated lab, loopback, or
  the bundled synthetic PCAPs — a network you own or are explicitly authorised
  to test.
- **Enforced in code.** Every attack refuses to run unless the target is a
  private address (RFC 1918 / loopback / link-local) **and** the operator passes
  `--i-understand-this-is-a-lab`. Attacks default to **dry-run** (they build and
  print packets but transmit nothing) and are bounded and rate-limited. These
  checks live in `netguard/core/safety.py` and are covered by
  `tests/test_safety.py`.
- **A guard rail, not a sandbox.** Anyone can edit the source to remove the
  checks. The responsibility for lawful, authorised use is the operator's.
  Unauthorised interception or disruption of networks is illegal in most
  jurisdictions.

If you only want to see the detectors work, you never need the attack side at
all: `make demo` runs entirely on the bundled captures.

---

## How this was built

Designed and directed by **asad3404**, with AI assistance used as a pair-
programmer for boilerplate and review. I chose the scope, the attack/detector
pairing, the detection heuristics, and the safety model, and I understand and
can defend each module and the protocol weakness it targets — the `docs/` notes
are written from that understanding. Synthetic sample traffic is generated by
`scripts/gen_samples.py` and clearly labelled as synthetic; no real capture or
third-party data is bundled, and there are no secrets in the repo.

## License

MIT — see [LICENSE](LICENSE).
