#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  bpfcc-tools \
  bpftool \
  build-essential \
  clang \
  gpg \
  golang-go \
  libbpf-dev \
  libelf-dev \
  llvm \
  make \
  pkg-config \
  tcpdump \
  tcpreplay \
  tshark \
  wget \
  zlib1g-dev

curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
  | gpg --dearmor \
  > /usr/share/keyrings/security_zeek.gpg

echo "deb [signed-by=/usr/share/keyrings/security_zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /" \
  > /etc/apt/sources.list.d/security_zeek.list

apt-get update
apt-get install -y --no-install-recommends zeek

ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
if [[ -x /opt/zeek/bin/zeek-cut ]]; then
  ln -sf /opt/zeek/bin/zeek-cut /usr/local/bin/zeek-cut
fi

rm -rf /var/lib/apt/lists/*
