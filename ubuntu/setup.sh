#!/usr/bin/env bash
set -euo pipefail

# RUN ONCE: Setup Ubuntu for eBPF development
sudo apt-get update
sudo apt-get install -y software-properties-common ca-certificates curl gnupg
sudo add-apt-repository -y universe
sudo apt-get update

sudo apt-get install -y \
  git build-essential clang llvm make pkg-config \
  linux-headers-$(uname -r) \
  bpftool libbpf-dev libelf-dev zlib1g-dev \
  golang \
  zeek \
  tcpreplay tcpdump \
  python3 python3-pip python3-venv

echo "[*] Ubuntu setup complete."
