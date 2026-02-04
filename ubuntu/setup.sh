#!/usr/bin/env bash
set -euo pipefail

# Update and install base packages
sudo apt-get update
sudo apt-get install -y software-properties-common ca-certificates curl gnupg wget
sudo add-apt-repository -y universe
sudo apt-get update

# Install eBPF tooling and dependencies
echo "[*] Installing eBPF tooling and dependencies..."
sudo apt-get install -y \
  git build-essential clang llvm make pkg-config \
  linux-headers-$(uname -r) \
  linux-tools-common linux-tools-generic linux-tools-$(uname -r) \
  libbpf-dev libelf-dev zlib1g-dev \
  tcpreplay tcpdump \
  tshark \
  python3 python3-pip python3-venv

# Install Go 1.21+ (1.13.8 on ubuntu 20.04)
GO_VER="1.21.13"
echo "[*] Installing Go ${GO_VER}..."
sudo apt-get remove -y golang-go golang || true

cd /tmp
curl -L --fail --retry 5 --retry-delay 2 --connect-timeout 15 \
  -o "go${GO_VER}.linux-amd64.tar.gz" \
  "https://dl.google.com/go/go${GO_VER}.linux-amd64.tar.gz"
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf "go${GO_VER}.linux-amd64.tar.gz"
rm -f "go${GO_VER}.linux-amd64.tar.gz"

# Make Go available for:
# - current shell
# - future shells
# - non-interactive shells (make, sudo envs, scripts)
export PATH=/usr/local/go/bin:$PATH

if ! grep -q "/usr/local/go/bin" ~/.bashrc 2>/dev/null; then
  echo 'export PATH=/usr/local/go/bin:$PATH' >> ~/.bashrc
fi

echo 'export PATH=/usr/local/go/bin:$PATH' | sudo tee /etc/profile.d/go-path.sh > /dev/null
sudo chmod 644 /etc/profile.d/go-path.sh

# Symlink go into /usr/local/bin (already in PATH)
sudo ln -sf /usr/local/go/bin/go /usr/local/bin/go
sudo ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt

echo "[*] Go installed:"
go version || /usr/local/go/bin/go version

# bpftool provided by linux-tools-$(uname -r)
echo "[*] Installing bpftool (linux-tools-$(uname -r))..."
sudo apt-get install -y bpfcc-tools || true

# Sanity check installations
echo "[*] Verifying installations..."
gcc --version
bpftool version
clang --version
tcpdump --version
tcpreplay --version
editcap -h 2>&1 | head -1 || echo "[!] editcap not found"
go version

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
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y zeek-core zeek-client

# Ensure zeek + zeek-cut are on PATH
if [[ -x /opt/zeek/bin/zeek ]] && ! command -v zeek >/dev/null 2>&1; then
  sudo ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
fi
if [[ -x /opt/zeek/bin/zeek-cut ]] && ! command -v zeek-cut >/dev/null 2>&1; then
  sudo ln -sf /opt/zeek/bin/zeek-cut /usr/local/bin/zeek-cut
fi

zeek --version
if command -v zeek-cut >/dev/null 2>&1; then
  echo "[*] zeek-cut available."
else
  echo "[!] zeek-cut not found (OK if you convert JSON logs via python)."
fi

echo "[*] Zeek installation complete."

# Usage
# bash setup.sh
# or
# chmod +x setup.sh && ./setup.sh
