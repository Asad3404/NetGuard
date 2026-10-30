# ARP cache poisoning / spoofing

## The protocol, briefly

ARP (Address Resolution Protocol, RFC 826) is the glue between L3 and L2 on an
Ethernet/IPv4 segment. When a host has an IP to talk to on its local subnet but
does not know the corresponding MAC, it broadcasts an **ARP request**
("who-has 192.168.1.1? tell 192.168.1.10") and waits for an **ARP reply**
("192.168.1.1 is-at `aa:bb:cc:...`"). It caches that answer and uses it until
the entry ages out.

## The weakness

ARP has **no authentication and no state**:

1. A reply is believed on its face — there is nothing in the protocol tying the
   claimed IP↔MAC binding to any credential or prior exchange.
2. Most stacks accept **gratuitous / unsolicited** replies and will happily
   overwrite an existing cache entry from one. A host does not have to have
   asked.

So any machine on the same broadcast domain can forge replies. The classic
man-in-the-middle is a pair of lies:

- Tell the **victim**: "the gateway (192.168.1.1) is at *my* MAC."
- Tell the **gateway**: "the victim (192.168.1.10) is at *my* MAC."

Now both send their traffic to the attacker, who forwards it on (to stay
invisible) while reading or modifying it. Because entries age out, a real
attacker re-sends the forged replies periodically to keep the caches poisoned.

## What NetGuard's attack module does

`netguard/attacks/arp.py` builds exactly that pair of gratuitous replies, for a
small fixed number of `rounds`. It is bounded (`max_packets`), rate-limited,
defaults to dry-run, and refuses to run unless the victim IP is private and the
lab flag is set. It is a traffic generator for the detector, not a full MITM
(it never enables forwarding).

## How the detector distinguishes it from normal traffic

`netguard/detectors/arp.py` learns IP→MAC bindings from the ARP replies it sees
and leans on two facts about *normal* ARP:

| Normal traffic | Attack traffic | Detector signal |
|---|---|---|
| An IP's MAC is stable; it changes only on reboot/NIC-swap/failover (rare). | The victim's and gateway's bindings suddenly point at the attacker's MAC. | **Binding change**: an *already-learned* IP starts claiming a different MAC → `arp-spoof` (high). |
| A MAC owns the one IP (or few) assigned to its interface. | One MAC (the attacker's) answers for several IPs it is impersonating. | **One MAC, many IPs** → `arp-mac-many-ips` (medium). |

Two deliberate choices keep false positives down:

- **First-seen bindings are silent.** The detector only alerts when an
  *established* binding flips, not when it learns an IP for the first time.
- **Only replies (op=2) assert a binding.** Requests are ignored for the
  binding-change logic.

### Where it can be fooled / tuned

A host that legitimately moves (DHCP lease handed to a new NIC, a VRRP/HSRP
virtual IP failing over between routers) produces a genuine binding change and
would alert. In a real deployment you would allow-list known virtual IPs or
correlate with the DHCP log. That trade-off — sensitivity vs. the rare
legitimate rebinding — is the core tuning decision for any ARP watcher, and it
is why the binding-change signal is rated **high** but still just a signal, not
proof.
