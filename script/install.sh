#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

BUILD_DIR="cmake-build-debug"
TARGET="FastAPI"

echo "==> Configuring CMake via pixi..."
pixi run --manifest-path "$PROJECT_ROOT/pixi.toml" cmake

echo "==> Building via pixi..."
pixi run --manifest-path "$PROJECT_ROOT/pixi.toml" build

BINARY="$PROJECT_ROOT/$BUILD_DIR/$TARGET"

echo "==> Setting capabilities for AFPACKET + --no-huge..."
sudo setcap cap_net_raw,cap_ipc_lock,cap_net_admin+ep "$BINARY"

echo "==> Done. Run with: $BINARY"
