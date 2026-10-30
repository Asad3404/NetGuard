# Demo topology (optional lab mode)

This directory is **optional**. The default, authoritative demo needs no Docker
and no root:

```bash
make demo          # regenerate the sample PCAPs and replay them through the detectors
```

Everything here is for showing the attacks and detectors on a *real wire*,
end-to-end, for screenshots in the writeup.

## What's here

| File | Purpose |
|---|---|
| `Dockerfile` | Slim Python image with NetGuard installed, used by every node. |
| `docker-compose.yml` | Four nodes (attacker, victim, host1, resolver) on one **internal** bridge (`172.28.0.0/24`) with no route to the internet. |
| `run_demo.sh` | Starts the topology, runs each attack LIVE from the attacker, and shows the victim's detector catching it. |
| `topology.clab.yml` | The same topology expressed for [containerlab](https://containerlab.dev/), to drop into SecureNet Lab. |

## Run it (docker-compose)

Requires Docker (WSL2 backend is fine). Raw-socket send/sniff needs the
`NET_ADMIN`/`NET_RAW` capabilities, which the compose file grants per service.

```bash
cd demo
./run_demo.sh
```

## Run it (containerlab)

```bash
docker build -t netguard:demo -f demo/Dockerfile .
sudo ip link add br-lab type bridge && sudo ip link set br-lab up
sudo containerlab deploy -t demo/topology.clab.yml
```

## Scope reminder

The bridge is `internal: true` — it has no gateway off the host, so the attacks
physically cannot leave the lab. Even so, every attack still requires the
explicit `--i-understand-this-is-a-lab` flag and refuses any non-private target.
Do not point these tools at a network you do not own or are not authorised to
test. See the ethics section of the top-level README.

> Live L2 capture across a Docker bridge can be finicky depending on your
> WSL2/Docker configuration. If a live alert doesn't appear, the PCAP demo
> (`make demo`) exercises the identical detector code deterministically.
