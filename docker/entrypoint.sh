#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${NETSENTINEL_REPO_ROOT:-/opt/netsentinel}"
DATA_DIR="${NETSENTINEL_DATA_DIR:-${ROOT_DIR}/data}"
APP_CACHE_DIR="${NETSENTINEL_APP_CACHE_DIR:-${DATA_DIR}/app}"
PORT="${PORT:-8501}"
HOST="${STREAMLIT_SERVER_ADDRESS:-0.0.0.0}"

export NETSENTINEL_REPO_ROOT="${ROOT_DIR}"
export NETSENTINEL_DATA_DIR="${DATA_DIR}"
export NETSENTINEL_APP_CACHE_DIR="${APP_CACHE_DIR}"
export PYTHONUNBUFFERED=1
export PYTHONDONTWRITEBYTECODE=1

mkdir -p "${DATA_DIR}" "${APP_CACHE_DIR}"

run_live_monitor() {
  exec streamlit run live/live_monitor.py --server.address="${HOST}" --server.port="${PORT}"
}

case "${1:-live-monitor}" in
  live-monitor)
    shift || true
    run_live_monitor "$@"
    ;;
  shell)
    exec bash
    ;;
  *)
    exec "$@"
    ;;
esac
