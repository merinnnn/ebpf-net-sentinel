#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends software-properties-common ca-certificates curl gnupg wget
add-apt-repository -y universe
apt-get update

apt-get install -y --no-install-recommends \
  bpfcc-tools \
  build-essential \
  clang \
  gpg \
  libbpf-dev \
  libelf-dev \
  llvm \
  make \
  pkg-config \
  python3 \
  python3-pip \
  python3-venv \
  tcpdump \
  tcpreplay \
  tshark \
  zlib1g-dev

GO_VER="1.21.13"
apt-get remove -y golang-go golang || true
cd /tmp
curl -L --fail --retry 5 --retry-delay 2 --connect-timeout 15 \
  -o "go${GO_VER}.linux-amd64.tar.gz" \
  "https://dl.google.com/go/go${GO_VER}.linux-amd64.tar.gz"
rm -rf /usr/local/go
tar -C /usr/local -xzf "go${GO_VER}.linux-amd64.tar.gz"
rm -f "go${GO_VER}.linux-amd64.tar.gz"
ln -sf /usr/local/go/bin/go /usr/local/bin/go
ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
cd /

curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_20.04/Release.key \
  | gpg --dearmor \
  > /usr/share/keyrings/security_zeek.gpg

echo "deb [signed-by=/usr/share/keyrings/security_zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/xUbuntu_20.04/ /" \
  > /etc/apt/sources.list.d/security_zeek.list

apt-get update
apt-get install -y --no-install-recommends zeek-core zeek-client

ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
if [[ -x /opt/zeek/bin/zeek-cut ]]; then
  ln -sf /opt/zeek/bin/zeek-cut /usr/local/bin/zeek-cut
fi

rm -rf /var/lib/apt/lists/*
