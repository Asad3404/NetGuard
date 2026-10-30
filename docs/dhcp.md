# DHCP starvation & rogue DHCP

## The protocol, briefly

DHCP (RFC 2131) assigns IP configuration automatically. The handshake is
**DORA**:

1. **D**ISCOVER — client broadcasts "is there a DHCP server?"
2. **O**FFER — server(s) broadcast/unicast an offered address.
3. **R**EQUEST — client broadcasts "I'll take that one (from server X)".
4. **A**CK — the chosen server confirms the lease.

The server identifies a client only by the hardware address it puts in the
`chaddr` field / client-id option. The client identifies the server only by
whichever OFFER it likes (usually the first).

## The weakness

There is **no authentication in either direction**.

- **The server trusts the client's identity.** Each DISCOVER with a new MAC
  looks like a new host, so the server reserves a lease for it. An attacker who
  floods DISCOVERs with thousands of **fabricated MACs** drains the address
  pool — legitimate clients can no longer get an address. This is **DHCP
  starvation**, a denial of service.
- **The client trusts the server's identity.** Nothing stops an attacker from
  answering DISCOVERs with their own OFFER. If the rogue OFFER wins the race (or
  the real server is starved first), the client accepts an attacker-controlled
  default gateway and DNS server — a **rogue DHCP** man-in-the-middle. The two
  attacks combine naturally: starve the real server, then be the only one left
  to answer.

## What NetGuard's attack module does

`netguard/attacks/dhcp.py` has two classes:

- `DhcpStarvationAttack` builds a bounded burst of DISCOVERs, each with a random
  locally-administered MAC (seedable for reproducible samples).
- `RogueDhcpOffer` builds a single forged OFFER advertising an attacker gateway
  and DNS.

Both are rate-limited, default to dry-run, and require the lab acknowledgement.
Starvation targets the broadcast domain, not one host, so it is gated by the lab
flag alone.

## How the detector distinguishes it from normal traffic

`netguard/detectors/dhcp.py` reads the **DHCP message-type option** (so it is
not fooled by relayed or unusual ports) and keys on two signals:

| Normal traffic | Attack traffic | Detector signal |
|---|---|---|
| OFFER/ACK come only from the network's known server(s). | A rogue server sends OFFER/ACK from a different source IP. | **Rogue server**: configure `expected_servers`, or let the detector learn the first server and flag any other → `dhcp-rogue-server` (high). |
| A handful of DISCOVERs from a small, stable set of client MACs. | Dozens of DISCOVERs with all-different MACs in seconds. | **Starvation**: count *distinct client MACs* in a sliding `starvation_window_s`; crossing `starvation_threshold` → `dhcp-starvation` (high). |

### Why "distinct MACs in a window", not "DISCOVER rate"?

A busy network (a lab coming online, a conference Wi-Fi) can have a high
DISCOVER *rate* legitimately — but from a bounded set of real MACs that keep
reappearing (retransmits, renewals). Starvation's signature is specifically the
**diversity** of client identities, so counting distinct MACs is far more
specific than counting packets. The sliding window means a slow trickle of new
devices over hours never accumulates into a false alert; the test
`test_starvation_respects_window` pins exactly that behaviour.

### Tuning

`expected_servers` is the single most valuable input: in any real network you
know your DHCP server, so set it and the rogue-server signal becomes
near-zero-false-positive. The starvation threshold/window are tuned against your
baseline rate of genuinely new devices.
