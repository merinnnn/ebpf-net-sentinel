#!/usr/bin/env bash
set -euo pipefail

IFACE="${1:-}"
if [[ -z "$IFACE" ]]; then
  echo "Usage: sudo bash ubuntu/run_live.sh <iface>"
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARGS=(
  "$IFACE"
  --flush-secs "${FLUSH_SECS:-5}"
  --poll-secs "${POLL_SECS:-3}"
  --mode "${MODE:-both}"
)
if [[ "${DISABLE_KPROBES:-1}" == "1" ]]; then
  ARGS+=(--disable-kprobes)
fi

exec python3 "$ROOT_DIR/ubuntu/live_capture_daemon.py" "${ARGS[@]}"
