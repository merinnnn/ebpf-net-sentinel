#!/usr/bin/env bash
set -euo pipefail

# Update and install base packages
sudo apt-get update
sudo apt-get install -y software-properties-common ca-certificates curl gnupg
sudo add-apt-repository -y universe
sudo apt-get update

# Install eBPF tooling and dependencies
echo "[*] Installing eBPF tooling and dependencies..."
sudo apt-get install -y \
  git build-essential clang llvm make pkg-config \
  linux-headers-$(uname -r) \
  linux-tools-common linux-tools-generic linux-tools-$(uname -r) \
  libbpf-dev libelf-dev zlib1g-dev \
  golang \
  tcpreplay tcpdump \
  python3 python3-pip python3-venv

# Install bpftool from source (latest stable)
echo "[*] Installing bpftool from source..."
sudo apt-get install -y bpfcc-tools || true

# Sanity check installations
echo "[*] Verifying installations..."
gcc --version
bpftool version
clang --version
tcpdump --version
tcpreplay --version

echo "[*] Base Ubuntu eBPF tooling setup complete."

# Hostname sanity (Postfix can break if hostname contains dot + numeric label like *.04)
HN="$(hostname)"
if [[ "$HN" == *.* ]]; then
  echo "[!] Hostname contains a dot ($HN). This can break Postfix/Zeek installs."
  echo "    Fix: sudo hostnamectl set-hostname ebpf-ubuntu-20"
  exit 1
fi

# Add Zeek repo for xUbuntu 20.04
echo "deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /" \
  | sudo tee /etc/apt/sources.list.d/zeek.list > /dev/null

curl -fsSL "https://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/Release.key" \
  | gpg --dearmor \
  | sudo tee /etc/apt/trusted.gpg.d/zeek.gpg > /dev/null

sudo apt-get update

# Lighter install with just core + client
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y zeek-core zeek-client

# Verify Zeek installation
zeek --version || /opt/zeek/bin/zeek --version
echo "[*] Zeek installation complete."

# Usage
# bash setup.sh
# or
# chmod +x setup.sh && ./setup.sh