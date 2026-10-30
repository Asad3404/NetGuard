#!/usr/bin/env bash
# Optional end-to-end lab demo on the docker-compose topology.
#
# For each attack: start the detector on the victim, fire the attack LIVE from
# the attacker against private lab addresses, then show the alert the detector
# produced. Requires Docker (WSL2 backend is fine) and the capabilities granted
# in docker-compose.yml.
#
# The privilege-free, deterministic demo is `make demo` (bundled PCAPs); this
# script is the "see it on a real wire" version for the writeup/screenshots.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

COMPOSE="docker compose"
VICTIM_IP=172.28.0.10
ATTACKER=ng-attacker
VICTIM=ng-victim

ack=--i-understand-this-is-a-lab

echo "== building & starting topology =="
$COMPOSE up -d --build

run_case () {
  local title="$1"; shift
  local filter="$1"; shift
  echo
  echo "===================================================================="
  echo "== $title"
  echo "===================================================================="
  # Start the detector on the victim, capped so it returns on its own.
  docker exec "$VICTIM" sh -c \
    "timeout 15 netguard detect --iface eth0 --bpf '$filter' --json" \
    > "/tmp/ng_$RANDOM.jsonl" 2>/dev/null &
  local detpid=$!
  sleep 2
  # Fire the attack LIVE from the attacker.
  docker exec "$ATTACKER" "$@" || true
  wait "$detpid" || true
}

# ARP poisoning against the victim<->resolver pair.
run_case "ARP cache poisoning" "arp" \
  netguard attack $ack --live --rate 5 arp \
    --victim-ip "$VICTIM_IP" --victim-mac "$(docker exec $VICTIM cat /sys/class/net/eth0/address)" \
    --gateway-ip 172.28.0.53 --gateway-mac "$(docker exec ng-resolver cat /sys/class/net/eth0/address)" \
    --attacker-mac "$(docker exec $ATTACKER cat /sys/class/net/eth0/address)"

# DHCP starvation (broadcast domain).
run_case "DHCP starvation" "udp port 67 or udp port 68" \
  netguard attack $ack --live --rate 10 dhcp --count 20

# DNS spoof aimed at the victim.
run_case "DNS spoofing" "udp port 53" \
  netguard attack $ack --live dns \
    --victim-ip "$VICTIM_IP" --resolver-ip 172.28.0.53 \
    --qname bank.example.com --spoof-ip 172.28.0.66

# SYN scan of the victim.
run_case "TCP SYN scan" "tcp" \
  netguard attack $ack --live --rate 200 synscan \
    --target-ip "$VICTIM_IP" --start-port 1 --end-port 200

echo
echo "== tearing down =="
$COMPOSE down

cat <<'EOF'

NOTE: live L2 capture across a docker bridge can be finicky depending on your
WSL2/Docker setup. If an alert did not appear above, fall back to the
deterministic PCAP demo, which exercises the exact same detector code:

    make demo
EOF
