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
  linux-tools-common linux-tools-generic linux-tools-$(uname -r) \
  libbpf-dev libelf-dev zlib1g-dev \
  golang \
  tcpreplay tcpdump \
  python3 python3-pip python3-venv

sudo apt-get install -y bpfcc-tools || true

echo "[*] Base Ubuntu eBPF tooling setup complete."
