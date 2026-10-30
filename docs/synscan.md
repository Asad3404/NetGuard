# TCP SYN port scan

## The protocol, briefly

TCP opens a connection with a three-way handshake:

1. Client → server: **SYN** (I'd like to talk, here's my initial sequence
   number).
2. Server → client: **SYN/ACK** if the port is open, or **RST** if it is
   closed.
3. Client → server: **ACK**, and the connection is established.

## The "weakness"

This one is less a protocol *flaw* than an unavoidable property of how TCP
advertises service availability. To discover whether a port is open you only
need step 2: send a SYN and observe the reply.

- **SYN/ACK** → the port is **open**.
- **RST** → the port is **closed**.
- **nothing** → **filtered** (a firewall dropped it).

A **SYN scan** ("half-open" scan) sends the SYN, reads the reply, and then
*never sends the final ACK* — it tears the half-open connection down with a RST
instead. Historically this meant the connection was never fully established, so
it never reached the application and never appeared in application logs, which
is why the technique was called "stealth". A host cannot refuse to reveal open
vs. closed without also refusing legitimate clients, so there is no clean fix at
the protocol level; detection happens at the **pattern** level instead.

## What NetGuard's attack module does

`netguard/attacks/synscan.py` builds a bounded series of bare SYN packets to a
range (or list) of ports on a single private target, varying the source port
the way a real scanner does. It is rate-limited, defaults to dry-run, requires
the lab flag, and only sends SYNs (it does not process the replies), so it is a
pattern generator for the detector rather than a usable scanner.

## How the detector distinguishes it from normal traffic

`netguard/detectors/synscan.py` keeps, per source IP, a sliding time window of
the **distinct destination ports** that received a *bare* SYN, and alerts when
one source exceeds `port_threshold` distinct ports within `window_s`.

| Normal traffic | Attack traffic | Detector signal |
|---|---|---|
| A host opens a handful of connections, completing the handshake (SYN, SYN/ACK, ACK) on each. | One source fires SYNs at many ports in seconds, never completing handshakes. | **Fan-out of bare SYNs**: distinct SYN-only destination ports per source over a window → `tcp-syn-scan` (medium). |

### Two choices that keep it specific

- **Only `flags == S` counts** (SYN set, ACK clear). A SYN/ACK (`0x12`) is a
  *server* answering, and the final ACK is part of a normal handshake; counting
  either would let ordinary traffic inflate the port total. The test
  `test_handshake_traffic_not_a_scan` proves SYN/ACK and ACK are ignored.
- **Per-source counting.** Two different hosts each opening a few connections
  must not combine into one "scan" — see
  `test_distinct_sources_counted_separately`.

### Tuning

`port_threshold` and `window_s` are the two knobs a defender sets against their
baseline. The defaults (100 distinct ports in 5 s) catch an aggressive scan
while ignoring the handful of parallel connections a browser or a sync client
opens. A slow "low-and-slow" scan that stays under the threshold per window is
the known blind spot — the trade-off is accepting some evasion in exchange for a
low false-positive rate, which is the right default for a noisy LAN. Severity is
**medium** rather than high because a scan is reconnaissance, not yet
compromise.
