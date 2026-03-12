#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y --no-install-recommends \
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

if ! apt-get install -y --no-install-recommends bpftool; then
  BPFT_PROVIDER="$(
    apt-cache search '^linux-.*tools-common$' \
      | awk '{print $1}' \
      | grep -E '^linux-(hwe|lowlatency-hwe|nvidia)-' \
      | sort -Vr \
      | head -n 1
  )"
  if [[ -z "${BPFT_PROVIDER}" ]]; then
    BPFT_PROVIDER="$(apt-cache search '^linux-.*tools-common$' | awk '/tools-common/ {print $1; exit}')"
  fi
  if [[ -z "${BPFT_PROVIDER}" ]]; then
    echo "could not find a bpftool provider package" >&2
    exit 1
  fi
  apt-get install -y --no-install-recommends "${BPFT_PROVIDER}"
  BPFT_BIN="$(find /usr/lib -type f -name bpftool | head -n 1)"
  if [[ -z "${BPFT_BIN}" ]]; then
    echo "bpftool binary not found after installing ${BPFT_PROVIDER}" >&2
    exit 1
  fi
  ln -sf "${BPFT_BIN}" /usr/local/bin/bpftool
fi

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
