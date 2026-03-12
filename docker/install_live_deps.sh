#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
  bpftool \
  ca-certificates \
  clang \
  curl \
  gnupg \
  iproute2 \
  jq \
  libbpf-dev \
  libelf-dev \
  make \
  procps \
  python3 \
  python3-pip \
  sudo \
  wget

UBUNTU_VERSION="$(. /etc/os-release && printf '%s' "${VERSION_ID}")"

curl -fsSL "https://download.opensuse.org/repositories/security:zeek/xUbuntu_${UBUNTU_VERSION}/Release.key" \
  | gpg --dearmor \
  > /usr/share/keyrings/security_zeek.gpg

echo "deb [signed-by=/usr/share/keyrings/security_zeek.gpg] https://download.opensuse.org/repositories/security:/zeek/xUbuntu_${UBUNTU_VERSION}/ /" \
  > /etc/apt/sources.list.d/security_zeek.list

apt-get update
apt-get install -y --no-install-recommends zeek-core zeek-client

ln -sf /opt/zeek/bin/zeek /usr/local/bin/zeek
if [[ -x /opt/zeek/bin/zeek-cut ]]; then
  ln -sf /opt/zeek/bin/zeek-cut /usr/local/bin/zeek-cut
fi

rm -rf /var/lib/apt/lists/*
