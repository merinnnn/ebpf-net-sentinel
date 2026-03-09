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

bootstrap_runtime() {
  if [[ "${NETSENTINEL_SKIP_BOOTSTRAP:-0}" != "1" ]]; then
    python3 app/backend/jobs/bootstrap_runtime.py
  fi
}

maybe_build_netmon() {
  if [[ "${NETSENTINEL_PREBUILD_NETMON:-0}" != "1" ]]; then
    return
  fi

  if command -v make >/dev/null 2>&1 && command -v clang >/dev/null 2>&1 && command -v bpftool >/dev/null 2>&1 && command -v go >/dev/null 2>&1; then
    echo "[netsentinel] Prebuilding netmon artifacts..."
    make -C ebpf_core
  else
    echo "[netsentinel] Skipping netmon prebuild because one or more toolchain commands are missing."
  fi
}

run_streamlit() {
  bootstrap_runtime
  maybe_build_netmon
  exec streamlit run app/app.py --server.address="${HOST}" --server.port="${PORT}"
}

case "${1:-streamlit}" in
  streamlit)
    shift || true
    run_streamlit "$@"
    ;;
  bootstrap)
    shift || true
    bootstrap_runtime
    if [[ "$#" -eq 0 ]]; then
      exit 0
    fi
    exec "$@"
    ;;
  shell)
    exec bash
    ;;
  *)
    exec "$@"
    ;;
esac
