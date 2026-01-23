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

# Sanity check installations
echo "[*] Verifying installations..."
gcc --version
bpftool version
clang --version
tcpdump --version
tcpreplay --version

echo "[*] Base Ubuntu eBPF tooling setup complete."

# Add Zeek repo for xUbuntu 20.04
echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /" \
  | sudo tee /etc/apt/sources.list.d/zeek.list > /dev/null

# Add the signing key
curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/Release.key" \
  | gpg --dearmor \
  | sudo tee /etc/apt/trusted.gpg.d/zeek.gpg > /dev/null

sudo apt-get update
sudo apt-get install -y zeek

# Verify Zeek installation
zeek --version

echo "[*] Zeek installation complete."