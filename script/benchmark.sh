#!/usr/bin/env bash
# Benchmark script for FastAPI DPDK SPI packet processor.
#
# Usage:
#   ./script/benchmark.sh [count] [workers] [match_percent]
#
# Defaults: count=1000000 (1M packets), workers=15 (lcore 0 is main, lcores
# 1-15 are workers on a 16-core host), match_percent=100
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${BUILD_DIR:-$PROJECT_DIR/cmake-build-release}"
BINARY="${BUILD_DIR}/FastAPI"

COUNT="${1:-1000000}"
WORKERS="${2:-15}"
MATCH_PERCENT="${3:-100}"

echo "============================================="
echo "  FastAPI DPDK Benchmark"
echo "============================================="
echo "  Packets:    ${COUNT}"
echo "  Workers:    ${WORKERS}"
echo "  Match%:     ${MATCH_PERCENT}%"
echo "  Build dir:  ${BUILD_DIR}"
echo "============================================="

# Step 1: Run SPI correctness test
echo ""
echo "[1/3] Running SPI rule correctness tests..."
echo "---------------------------------------------"
if python3 "${PROJECT_DIR}/test/test_spi_rules.py"; then
  echo "[OK] SPI tests passed"
else
  echo "[FAIL] SPI tests failed — aborting benchmark"
  exit 1
fi

# Step 2: Generate PCAP benchmark shards
echo ""
echo "[2/3] Generating benchmark PCAP shards..."
echo "---------------------------------------------"
SHARD_DIR="${PROJECT_DIR}/test/bench_pcap_shards"
rm -rf "$SHARD_DIR"
python3 "${PROJECT_DIR}/test/gen_test_pcap.py" "$SHARD_DIR" \
  --count "$COUNT" --shards "$WORKERS" --match-percent "$MATCH_PERCENT"
echo "[OK] Generated $(ls "$SHARD_DIR"/*.pcap 2>/dev/null | wc -l) shard files"

# Step 3: Run benchmark with PCAP replay
echo ""
echo "[3/3] Running PCAP benchmark..."
echo "---------------------------------------------"
"${PROJECT_DIR}/test/test_env.sh" bench-pcap "$COUNT" "$WORKERS" "$MATCH_PERCENT"

echo ""
echo "============================================="
echo "  Benchmark complete"
echo "============================================="
