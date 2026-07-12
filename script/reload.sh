#!/usr/bin/env bash
# Hot-reload FastAPI config without restarting workers.
#
# 1. Copies source config.yaml into cmake-build-release/ (FastAPI's
#    compile-time CONFIG_PATH points there).
# 2. Sends SIGUSR1 to the FastAPI process. The signal handler in
#    app_signal.cpp sets reload_requested; the main lcore's MaybeReload
#    loop re-reads and atomically swaps the rule tables.
#
# Usage: ./script/reload.sh
#        pixi run reload

set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src_config="$project_root/config.yaml"
build_config_dir="$project_root/cmake-build-release"
build_config="$build_config_dir/config.yaml"

mkdir -p "$build_config_dir"
cp "$src_config" "$build_config"

pid=$(pidof FastAPI || true)
if [ -z "$pid" ]; then
  echo "FastAPI not running (config copied to $build_config)" >&2
  exit 1
fi

echo "Reloading FastAPI (pid $pid)..."
# FastAPI runs under sudo (it needs hugepage memlock); a plain `kill`
# as the invoking user gets EPERM. Use sudo unconditionally for the
# signal; will fail with a clear message if no passwordless sudo.
if kill -USR1 "$pid" 2>/dev/null; then
  exit 0
fi
if command -v sudo >/dev/null 2>&1; then
  sudo kill -USR1 "$pid"
else
  echo "kill failed (sudo not available)" >&2
  exit 1
fi
