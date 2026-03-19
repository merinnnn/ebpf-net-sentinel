#!/usr/bin/env bash
# Creates:
#   - Network namespace "ns-research"
#   - veth pair: ns0 (host side, capture here) <-> ns1 (inside ns-research)
#   - IP addresses: host=10.99.0.1/24, namespace=10.99.0.2/24
#   - lo up inside the namespace
#
# Usage:
#   sudo bash ubuntu/setup/setup_research_net.sh [up|down|status]
#
# After running 'up':
#   - Start the daemon:  sudo bash ubuntu/live/run_live.sh ns0
#   - Generate traffic:  sudo ip netns exec ns-research <command>
#       ping 10.99.0.1
#       iperf3 -c 10.99.0.1
#       nmap -sS 10.99.0.1
#       hping3 --flood -S 10.99.0.1
#       tcpreplay -i ns1 your.pcap   (from host, no netns needed for tcpreplay)

set -euo pipefail

NS="ns-research"
VETH_HOST="ns0"
VETH_NS="ns1"
HOST_IP="10.99.0.1"
NS_IP="10.99.0.2"
PREFIX="24"

cmd="${1:-up}"

case "$cmd" in

  up)
    if ip netns list | grep -q "^${NS}"; then
      echo "[!] Namespace '${NS}' already exists. Run 'down' first to recreate."
      exit 1
    fi

    echo "[*] Creating namespace: ${NS}"
    ip netns add "$NS"

    echo "[*] Creating veth pair: ${VETH_HOST} <-> ${VETH_NS}"
    ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
    ip link set "$VETH_NS" netns "$NS"

    echo "[*] Configuring host side: ${VETH_HOST} = ${HOST_IP}/${PREFIX}"
    ip addr add "${HOST_IP}/${PREFIX}" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up

    echo "[*] Configuring namespace side: ${VETH_NS} = ${NS_IP}/${PREFIX}"
    ip netns exec "$NS" ip addr add "${NS_IP}/${PREFIX}" dev "$VETH_NS"
    ip netns exec "$NS" ip link set "$VETH_NS" up
    ip netns exec "$NS" ip link set lo up

    echo "[*] Disabling checksum offloading (required for Zeek to see valid packets)"
    ethtool -K "$VETH_HOST" tx off rx off gso off gro off lro off tso off 2>/dev/null || true
    ip netns exec "$NS" ethtool -K "$VETH_NS" tx off rx off gso off gro off lro off tso off 2>/dev/null || true

    echo ""
    echo "  Research network is up."
    echo "  Capture interface : ${VETH_HOST}  (${HOST_IP})"
    echo "  Traffic source    : ${VETH_NS} inside namespace '${NS}'  (${NS_IP})"
    echo ""
    echo "  Start daemon  : sudo bash ubuntu/live/run_live.sh ${VETH_HOST}"
    echo "  Open a shell  : sudo ip netns exec ${NS} bash"
    echo "  Quick test    : sudo ip netns exec ${NS} ping -c3 ${HOST_IP}"
    ;;

  down)
    echo "[*] Tearing down research network..."
    if ip link show "$VETH_HOST" >/dev/null 2>&1; then
      ip link del "$VETH_HOST"
      echo "    Deleted veth pair ${VETH_HOST} - ${VETH_NS}"
    fi
    if ip netns list | grep -q "^${NS}"; then
      ip netns del "$NS"
      echo "    Deleted namespace ${NS}"
    fi
    echo "[*] Done."
    ;;

  status)
    echo "Namespace"
    ip netns list | grep "$NS" || echo "  (not found)"
    echo ""
    echo "Host side: ${VETH_HOST}"
    ip addr show "$VETH_HOST" 2>/dev/null || echo "  (not found)"
    echo ""
    echo "Namespace side: ${VETH_NS}"
    ip netns exec "$NS" ip addr show "$VETH_NS" 2>/dev/null || echo "  (not found)"
    ;;

  *)
    echo "Usage: sudo bash ubuntu/setup/setup_research_net.sh [up|down|status]"
    exit 2
    ;;

esac
