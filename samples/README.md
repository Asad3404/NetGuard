# Sample captures (synthetic — generated, not committed)

The `.pcap` files in this directory are **synthetic**: every packet is
fabricated in memory by `scripts/gen_samples.py`, nothing is captured from a
real network. They are intentionally **not** checked into git (see
`.gitignore`) so the repo stays text-only and the captures are always
reproducible from source.

Generate them with either:

```bash
python scripts/gen_samples.py --out samples
# or
make samples
```

This produces:

| File | Contents | Expected detector result |
|---|---|---|
| `benign.pcap` | normal ARP, DHCP, DNS, TCP handshakes | **no alerts** (baseline) |
| `arp_spoof.pcap` | learned bindings, then a poisoning flip | `arp-spoof`, `arp-mac-many-ips` |
| `dhcp_starvation.pcap` | DISCOVER flood with many distinct MACs | `dhcp-starvation` |
| `dhcp_rogue.pcap` | real OFFER, then a rogue server's OFFER | `dhcp-rogue-server` |
| `dns_spoof.pcap` | real answer + conflicting forged answer | `dns-poison-race` |
| `synscan.pcap` | one source SYNing 150 ports | `tcp-syn-scan` |

The test suite regenerates them into a temp directory automatically (see
`tests/conftest.py`), so `pytest` works on a fresh clone with no extra steps.
