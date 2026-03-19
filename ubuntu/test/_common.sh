#!/usr/bin/env bash

NS="ns-research"
HOST_IP="10.99.0.1"
NS_IP="10.99.0.2"

ns_exec() { ip netns exec "$NS" "$@"; }

check_ns() {
  if ! ip netns list | grep -q "^${NS}"; then
    echo "[!] Namespace '${NS}' not found. Run first:"
    echo "    sudo bash ubuntu/setup/setup_research_net.sh up"
    exit 1
  fi
  if ! ip link show ns0 &>/dev/null; then
    echo "[!] ns0 interface not found."
    exit 1
  fi
}

require_tool() {
  if ! command -v "$1" &>/dev/null; then
    echo "[!] '$1' not installed. Run: sudo bash ubuntu/test/install_tools.sh"
    exit 1
  fi
}
