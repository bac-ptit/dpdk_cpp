#!/usr/bin/env bash
# test_env.sh — FastAPI bench driver.
#
# Responsibilities (and ONLY these responsibilities):
#   1. Generate pcap shards for the requested packet count.
#   2. Copy $PROJECT_DIR/config.yaml to the binary directory ($BUILD_DIR).
#   3. Run the FastSPI binary with a bench timeout (default $BENCH_TIMEOUT or 15s).
#
# Everything else — hugepage tuning, mempool sizing, CPU/queue pinning,
# rule overrides, l3_forward toggles, dispatch_queue_size, flow_ttl_sec —
# must live in $PROJECT_DIR/config.yaml. The bench script never mutates
# the user's config; it only stages it next to the binary so the binary's
# runtime CONFIG_PATH resolves to a fresh, unmodified copy.
#
# Configuration is read FROM config.yaml, not written to it:
#   - spi.worker_count  → number of pcap shards to generate
#   - eal.virtual_devices[0] rx_pcap=... → pcap output directory
#
# Subcommands (only two, by design):
#   bench       — gen_dpi_bench_pcap.py (packets WITH L7 payloads — TLS
#                 ClientHello SNIs so the DPI path can extract hostnames
#                 and match DPI rules). End-to-end benchmark using whatever
#                 rules config.yaml declares (SPI + DPI when DPI is enabled).
#   bench-spi   — gen_test_pcap.py (packets WITHOUT payload — 5-tuple
#                 only, no L7). Used to measure pure SPI throughput:
#                 without L7 bytes there's nothing for ExtractHostname /
#                 MatchDpi to chew on, so the DPI path is bypassed
#                 regardless of DPI rules. Compare against `bench` to
#                 isolate DPI overhead.
#
# All settings — burst_size, queues, packet_distribution, memory_size,
# cpu_core_list, l3_forward, SPI rules, DPI rules — are honored as-is
# from config.yaml. To switch SPI-only vs SPI+DPI behaviour, edit
# config.yaml directly (set `dpi.enabled: false` to disable DPI).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Build directory + binary path.
BUILD_DIR="${BUILD_DIR:-$PROJECT_DIR/cmake-build-release}"
if [ ! -d "$BUILD_DIR" ] && [ -d "$PROJECT_DIR/build_release" ]; then
  BUILD_DIR="$PROJECT_DIR/build_release"
fi
BUILD_DIR="$(cd "$BUILD_DIR" && pwd)"
APP_BINARY="${APP_BINARY:-$BUILD_DIR/FastAPI}"

# Defaults — overridable via env.
DEFAULT_COUNT="${DEFAULT_COUNT:-1000000}"
# Default short timeout for the FastSPI binary. The binary doesn't exit on
# its own when fed an infinite_rx pcap — `timeout` is the only thing that
# stops it after BENCH_TIMEOUT seconds and lets the bench driver print
# stats and exit cleanly. 15s is enough to see steady-state Mpps on any
# modern machine.
DEFAULT_BENCH_TIMEOUT_SEC="${DEFAULT_BENCH_TIMEOUT_SEC:-15}"
# Default GENEROUS timeout for pcap generation. Pcap gen is a separate
# phase with no IPC and no real-time constraint; on a slow box with
# --count 1000000 it can run for minutes. Bind it independently of the
# bench timeout so a 10-minute pcap gen doesn't crash the whole script.
DEFAULT_GEN_TIMEOUT_SEC="${DEFAULT_GEN_TIMEOUT_SEC:-600}"
DEFAULT_WORKERS="${DEFAULT_WORKERS:-7}"
DEFAULT_PCAP_DIR="${DEFAULT_PCAP_DIR:-$SCRIPT_DIR/bench_pcap_shards}"

usage() {
  cat <<EOF
Usage: $0 {bench|bench-spi} [count]

Tasks (the ONLY ones the script does):
  1. Generate pcap shards for [count] packets (timeout: \$GEN_TIMEOUT or ${DEFAULT_GEN_TIMEOUT_SEC}s default)
  2. Copy \$PROJECT_DIR/config.yaml to the binary directory (\$BUILD_DIR)
  3. Run the FastSPI binary with a bench timeout (\$BENCH_TIMEOUT or ${DEFAULT_BENCH_TIMEOUT_SEC}s default)

All runtime configuration is read from \$PROJECT_DIR/config.yaml:
  spi.worker_count          -> shard count for pcap generation
  eal.virtual_devices[0]    -> pcap output directory
  everything else            -> honored as-is (memory_size, cpu_core_list,
                               queues, SPI rules, DPI rules, l3_forward, ...)

Environment variables:
  BENCH_TIMEOUT=N    Override FastSPI binary timeout in seconds (default $DEFAULT_BENCH_TIMEOUT_SEC)
  GEN_TIMEOUT=N      Override pcap-generator timeout in seconds (default $DEFAULT_GEN_TIMEOUT_SEC)
  BUILD_DIR=path     Override build directory (default cmake-build-release)
  DEFAULT_COUNT=N    Default packet count when no argument given (default $DEFAULT_COUNT)

Examples:
  pixi run bench                        # 1M packets, full SPI+DPI path
  pixi run bench-spi                     # 1M packets, SPI-only (5-tuple, no L7)
  BENCH_TIMEOUT=60 pixi run bench-spi   # 1M packets, 60s run, SPI-only
  $0 bench-spi 500000                   # 500K packets, SPI-only path
EOF
  exit 1
}

# Read worker_count from config.yaml (used as shard count for pcap generator).
# Falls back to DEFAULT_WORKERS if the file is missing or unparseable.
get_workers() {
  python3 - "$PROJECT_DIR/config.yaml" "$DEFAULT_WORKERS" <<'PY' 2>/dev/null || echo "$DEFAULT_WORKERS"
import sys, yaml
try:
    cfg = yaml.safe_load(open(sys.argv[1]))
    print(cfg['spi']['worker_count'])
except Exception:
    print(sys.argv[2])
PY
}

# Read pcap output directory from config.yaml's first virtual_device.
# Falls back to DEFAULT_PCAP_DIR if no virtual_device is configured
# (e.g. for live NIC testing — the script still won't be useful there).
get_pcap_dir() {
  python3 - "$PROJECT_DIR/config.yaml" "$DEFAULT_PCAP_DIR" <<'PY' 2>/dev/null || echo "$DEFAULT_PCAP_DIR"
import sys, re, yaml, os
try:
    cfg = yaml.safe_load(open(sys.argv[1]))
    vdevs = cfg.get('eal', {}).get('virtual_devices', [])
    if vdevs:
        m = re.search(r'rx_pcap=([^,]+)', vdevs[0])
        if m:
            print(os.path.dirname(m.group(1)))
            sys.exit(0)
except Exception:
    pass
print(sys.argv[2])
PY
}

require_app_binary() {
  if [ ! -f "$APP_BINARY" ]; then
    echo "[!] Binary not found at $APP_BINARY."
    echo "    Build first (e.g. 'pixi run build' or 'pixi run build-release')."
    exit 1
  fi
}

# Run the FastSPI binary under sudo with a hard timeout. setcap grants the
# CAP_NET_RAW/CAP_IPC_LOCK/CAP_NET_ADMIN capabilities the binary needs
# for hugepage-backed mbufs and raw-queue setup; without setcap, sudo
# would have to be the only way to grant them and the operator would
# type their password on every bench.
#
# Scope: the `timeout` here ONLY wraps the FastSPI binary invocation.
# Pcap generation and config staging run separately with their own
# timeout (see do_bench), so a slow `--count` generation never eats
# into the BENCH_TIMEOUT budget for the actual run.
run_app() {
  local timeout="${BENCH_TIMEOUT:-$DEFAULT_BENCH_TIMEOUT_SEC}"
  require_app_binary
  sudo setcap cap_net_raw,cap_ipc_lock,cap_net_admin+ep "$APP_BINARY"
  (cd "$BUILD_DIR" && sudo timeout "${timeout}s" "$APP_BINARY") || true
}

# The single task. Args:
#   $1 = packet count (default: DEFAULT_COUNT)
#   $2 = absolute path to the pcap generator script
do_bench() {
  local count="${1:-$DEFAULT_COUNT}"
  local generator="$2"
  local workers pcap_dir
  local gen_timeout="${GEN_TIMEOUT:-$DEFAULT_GEN_TIMEOUT_SEC}"
  workers="$(get_workers)"
  pcap_dir="$(get_pcap_dir)"

  echo "[*] Generating pcap shards:"
  echo "    count=$count  workers=$workers  dir=$pcap_dir"
  echo "    generator=$generator  (timeout: ${gen_timeout}s)"
  rm -rf "$pcap_dir"
  mkdir -p "$pcap_dir"
  # Pcap generation has its own (long) timeout — separate from the bench
  # timeout used for the FastSPI binary. Wrapping the gen here means a
  # stuck gen doesn't hang the whole script indefinitely.
  timeout "${gen_timeout}s" python3 "$generator" "$pcap_dir" --count "$count" --shards "$workers" --match-percent 100 --prefix bench_q

  echo "[*] Copying config.yaml to $BUILD_DIR/ (binary reads ./config.yaml at runtime)..."
  cp "$PROJECT_DIR/config.yaml" "$BUILD_DIR/config.yaml"

  echo "[*] Running $APP_BINARY (timeout: ${BENCH_TIMEOUT:-$DEFAULT_BENCH_TIMEOUT_SEC}s)..."
  run_app
}

cmd_bench()     { do_bench "${1:-$DEFAULT_COUNT}" "$SCRIPT_DIR/gen_dpi_bench_pcap.py"; }
cmd_bench_spi() { do_bench "${1:-$DEFAULT_COUNT}" "$SCRIPT_DIR/gen_test_pcap.py"; }

case "${1:-}" in
  bench|bench-spi)
    subcmd="${1}"
    shift
    cmd_"${subcmd//-/_}" "$@"
    ;;
  *)
    usage
    ;;
esac
