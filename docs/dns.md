# DNS spoofing / cache poisoning

## The protocol, briefly

Classic DNS (RFC 1035) over UDP/53 is a single-shot request/response. A client
(or a recursive resolver acting on its behalf) sends a query — "what is the A
record for `bank.example.com`?" — and accepts the first response that **matches
the outstanding query**. The match is only four things:

1. source IP = the resolver it asked,
2. destination port = the ephemeral port it sent from,
3. the question section (name + type), and
4. the 16-bit **transaction ID** it chose.

If a response matches all four, it is accepted — and if the client is a caching
resolver, cached for the record's TTL.

## The weakness

Those four fields are **weak authentication**:

- An **on-path** attacker (same LAN, or after an ARP MITM) can simply read all
  four and craft a perfect, faster response. They always win the race.
- An **off-path** attacker must guess. The transaction ID is only 16 bits, and
  historically the source port was predictable too, so the combined entropy was
  low enough to brute-force (this is the essence of the 2008 Kaminsky attack).
  Source-port randomisation (RFC 5452) raised the bar, and DNSSEC /
  DNS-over-TLS/HTTPS fix it properly by authenticating or encrypting the
  exchange — but plain UDP DNS on a LAN is still trivially spoofable by anyone
  on-path.

The payoff is large: one accepted forged answer poisons the cache, so **every**
later lookup of that name is redirected until the TTL expires.

## What NetGuard's attack module does

`netguard/attacks/dns.py` builds a single forged A-record response that claims
to come from the real resolver and maps a chosen name to an attacker IP. It
requires the forged answer IP to be private, requires the lab flag, and defaults
to dry-run. Delivering it for real means winning the race against the resolver —
which is exactly the timing artefact the detector keys on.

## How the detector distinguishes it from normal traffic

`netguard/detectors/dns.py` uses two signals:

| Normal traffic | Attack traffic | Detector signal |
|---|---|---|
| Responses come from the configured resolver(s). | The forged answer is sourced from some other IP. | **Unexpected resolver**: with `expected_resolvers` set, any response from another IP → `dns-unexpected-resolver` (high). |
| One query gets one answer. | The real answer and the forged answer both arrive for the same query. | **Poisoning race**: two responses with the same `(transaction-id, qname)` but **different** rdata, within a short window → `dns-poison-race` (high). |

### Why key on `(txid, qname)` and compare rdata?

- Keying on the **transaction ID + question** means an ordinary *later* lookup
  of the same name (which uses a fresh txid) is not mistaken for a duplicate —
  see `test_different_txid_same_name_not_a_race`.
- Comparing **rdata** means a benign retransmission of the identical answer
  (same addresses) is ignored; only *conflicting* answers fire — see
  `test_identical_answer_is_not_a_race`.

The poison-race signal is powerful because it needs no prior knowledge of the
resolver at all: the mere existence of two contradictory answers to one question
is intrinsically wrong. The unexpected-resolver signal is the cheaper check when
you *do* know your resolver. Together they cover both the on-path case (you see
both answers) and the misconfiguration/rogue case (answer from the wrong box).
