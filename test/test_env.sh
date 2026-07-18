#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

NS="dpdk_test"
MACVLAN="macvlan0"
HOST_IFACE="enp3s0"
APP_IP="192.168.1.12"
TEST_IP="192.168.1.13"
BUILD_DIR="${BUILD_DIR:-$PROJECT_DIR/cmake-build-release}"
if [ ! -d "$BUILD_DIR" ] && [ -d "$PROJECT_DIR/build_release" ]; then
  BUILD_DIR="$PROJECT_DIR/build_release"
fi
# Resolve to absolute path — run_app uses (cd "$BUILD_DIR"; ...) so a
# relative BUILD_DIR would break the binary lookup.
BUILD_DIR="$(cd "$BUILD_DIR" && pwd)"
APP_BINARY="${APP_BINARY:-$BUILD_DIR/FastAPI}"
DEFAULT_WORKERS="${DEFAULT_WORKERS:-7}"
DEFAULT_BENCH_COUNT="${DEFAULT_BENCH_COUNT:-300000}"
DEFAULT_MATCH_PERCENT="${DEFAULT_MATCH_PERCENT:-100}"

usage() {
  echo "Usage: $0 {setup|run|send|pcap|bench|bench-spi|bench-dpi|bench-pcap|bench-afpacket|teardown}"
  exit 1
}

# Per-run scratch dir under /tmp. The bench writes its modified config to
# $WORK_CONFIG and copies that to $BUILD_DIR — the project's config.yaml
# in $PROJECT_DIR is never touched, and the temp dir is removed on exit.
WORK_DIR=""
WORK_CONFIG=""

restore_config() {
  if [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ]; then
    rm -rf "$WORK_DIR"
  fi
  WORK_DIR=""
  WORK_CONFIG=""
}

begin_config_edit() {
  local source_config="$PROJECT_DIR/config.yaml"
  WORK_DIR="$(mktemp -d -t dpdk_bench.XXXXXX)"
  WORK_CONFIG="$WORK_DIR/config.yaml"
  cp "$source_config" "$WORK_CONFIG"
  trap restore_config EXIT INT TERM
}

require_app_binary() {
  if [ ! -f "$APP_BINARY" ]; then
    echo "[!] Binary not found. Run install.sh first."
    exit 1
  fi
}

require_worker_lcores() {
  local workers="${1}"
  local available
  available="$(nproc)"
  if [ "$available" -lt $((workers + 1)) ]; then
    echo "[!] ${workers} workers need $((workers + 1)) logical cores (main + workers), found ${available}."
    echo "    Pass a smaller worker count or run on a host with more lcores."
    exit 1
  fi
}

# Allocate hugepages if none are configured, or increase if insufficient.
# Usage: ensure_hugepages <memory_mb>
#
# Strategy:
#   1. Drop kernel page cache so the allocator has more room (one-time).
#   2. Set vm.nr_hugepages with a 25% margin over the requested MB.
#   3. If the kernel couldn't fully honour the request (page cache grew
#      back, other processes' reservations, etc.), print what we ACTUALLY
#      got — not what we asked for — and return that to the caller.
#   4. Caller reads nr_hugepages again right before launching EAL so
#      memory_size reflects what the kernel can ACTUALLY provide at
#      launch time, not what we requested.
ensure_hugepages() {
  local memory_mb="${1}"
  # Drop kernel page cache so the hugepage allocator can reclaim more.
  # Requires sudo. Best-effort: silently no-op if denied.
  if command -v sudo >/dev/null 2>&1; then
    sudo sh -c 'echo 1 > /proc/sys/vm/drop_caches' 2>/dev/null || true
    sudo sh -c 'echo 2 > /proc/sys/vm/drop_caches' 2>/dev/null || true
    sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches' 2>/dev/null || true
  fi
  local current_free
  current_free="$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages)"
  local current_mb=$((current_free * 2))
  if [ "$current_mb" -ge "$memory_mb" ]; then
    echo "[OK] Sufficient hugepages already allocated: ${current_mb}MB free"
    return 0
  fi
  local pages=$(( (memory_mb + memory_mb / 4) / 2 ))  # 25% margin, 2MB pages
  echo "[*] Insufficient hugepages (${current_mb}MB < ${memory_mb}MB). Allocating ${pages} x 2MB hugepages (~$((pages * 2))MB)..."
  sudo sysctl -w "vm.nr_hugepages=${pages}" >/dev/null
  # Read TOTAL configured (nr_hugepages), not free_hugepages — kernel
  # may give us fewer pages than requested if memory is tight.
  local actual_pages
  actual_pages="$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)"
  local actual_mb=$((actual_pages * 2))
  if [ "$actual_pages" -lt "$pages" ]; then
    echo "[!] Warning: requested ${pages} hugepages but only got ${actual_pages} (kernel reservation short by $((pages - actual_pages)) pages)."
  fi
  echo "[OK] Hugepages allocated: ${actual_mb}MB (${actual_pages} pages)"
}

run_app() {
  # Default 15s so the bench auto-exits for CI / smoke runs — the FastAPI
  # binary itself runs forever (it loops on RX queues), so without a
  # timeout the test never returns. Override with BENCH_TIMEOUT=N for
  # real benchmarking (e.g. `BENCH_TIMEOUT=60 pixi run bench-spi`).
  local timeout="${BENCH_TIMEOUT:-15}"
  require_app_binary
  sudo setcap cap_net_raw,cap_ipc_lock,cap_net_admin+ep "$APP_BINARY"
  # cd into BUILD_DIR so the binary's `./config.yaml` resolves to the
  # fresh bench config (script copies to $BUILD_DIR, never touches the
  # project's config.yaml). Use absolute path for the binary since the
  # subshell's cwd is BUILD_DIR, not the project root.
  (cd "$BUILD_DIR" && sudo timeout "${timeout}s" "$APP_BINARY") || true
}

cmd_setup() {
  echo "[*] Cleaning up any leftover from previous run..."
  sudo ip netns del "$NS" 2>/dev/null || true
  sudo ip link del "$MACVLAN" 2>/dev/null || true

  echo "[*] Removing IP from $HOST_IFACE..."
  sudo ip addr flush dev "$HOST_IFACE" 2>/dev/null || true

  echo "[*] Assigning static IP to $HOST_IFACE for ARP..."
  sudo ip addr add "$APP_IP/24" dev "$HOST_IFACE"

  echo "[*] Creating network namespace '$NS'..."
  sudo ip netns add "$NS"

  echo "[*] Creating macvlan (bridge mode)..."
  sudo ip link add "$MACVLAN" link "$HOST_IFACE" type macvlan mode bridge
  sudo ip link set "$MACVLAN" netns "$NS"

  sudo ip netns exec "$NS" ip addr add "$TEST_IP/24" dev "$MACVLAN"
  sudo ip netns exec "$NS" ip link set "$MACVLAN" up
  sudo ip netns exec "$NS" ip link set lo up

  local mac
  mac=$(ip link show "$HOST_IFACE" | awk '/ether/{print $2}')
  sudo ip netns exec "$NS" ip neigh add "$APP_IP" lladdr "$mac" dev "$MACVLAN"

  echo ""
  echo "[OK] Ready!"
  echo "  Terminal 2: sudo ip netns exec $NS hping3 -S -p 80 $APP_IP -I $MACVLAN -c 5"
}

cmd_run() {
  run_app
}

cmd_send() {
  if [ $# -eq 0 ]; then
    echo "Usage: $0 send <target_ip>"
    exit 1
  fi
  TARGET="${1}"
  shift
  echo "[*] Sending TCP SYN to ${TARGET}:80..."
  sudo ip netns exec "$NS" hping3 -S -p 80 "$TARGET" -I "$MACVLAN" -c 5
}

cmd_teardown() {
  echo "[*] Removing namespace and macvlan..."
  sudo ip netns del "$NS" 2>/dev/null || true
  sudo ip link del "$MACVLAN" 2>/dev/null || true

  echo "[*] Restoring IP from DHCP..."
  sudo ip addr flush dev "$HOST_IFACE" 2>/dev/null || true
  sudo nmcli device connect "$HOST_IFACE" 2>/dev/null || true
  echo "[OK] Reverted."
}

cmd_pcap() {
  local pcap_file="${1:-$SCRIPT_DIR/spi_rules.pcap}"
  local tx_pcap_file="$SCRIPT_DIR/tx_spi_rules.pcap"

  echo "[*] Generating test pcap (5 HTTP + 5 HTTPS + 5 DNS + 5 GTP-U)..."
  python3 "$SCRIPT_DIR/gen_test_pcap.py" "$pcap_file"
  rm -f "$tx_pcap_file"

  echo "[*] Creating PCAP config..."
  begin_config_edit
  local config_file="$WORK_CONFIG"

  python3 - "$config_file" "$pcap_file" "$tx_pcap_file" <<'PY'
import sys
import yaml

config_file, pcap_file, tx_pcap_file = sys.argv[1:4]
filter_groups = [
    {'name': 'bench_http', 'precedence': 100, 'action': 'forward', 'filters': [
        {'protocol': 'tcp', 'source_ip_address': '10.17.50.1',
         'destination_ip_address': '10.17.50.12', 'destination_port': 80, 'label': 'HTTP'},
    ]},
    {'name': 'bench_https', 'precedence': 101, 'action': 'forward', 'filters': [
        {'protocol': 'tcp', 'source_ip_address': '10.17.50.2',
         'destination_ip_address': '10.17.50.12', 'destination_port': 443, 'label': 'HTTPS'},
    ]},
    {'name': 'bench_dns', 'precedence': 102, 'action': 'forward', 'filters': [
        {'protocol': 'udp', 'source_ip_address': '10.17.50.3',
         'destination_ip_address': '10.17.50.53', 'destination_port': 53, 'label': 'DNS'},
    ]},
    {'name': 'bench_gtp', 'precedence': 103, 'action': 'forward', 'filters': [
        {'protocol': 'udp', 'source_ip_address': '10.17.50.4',
         'destination_ip_address': '10.17.50.215', 'destination_port': 2152, 'label': 'GTP_U'},
    ]},
]
with open(config_file) as f:
    cfg = yaml.safe_load(f)
cfg['eal']['virtual_devices'] = [f'net_pcap0,rx_pcap={pcap_file},tx_pcap={tx_pcap_file},infinite_rx=0']
cfg['eal']['cpu_core_list'] = '0-1'
cfg['l3_forward']['enabled'] = False
cfg['mempool']['memory_buffer_size'] = 2176
cfg['port']['port_bitmask'] = '0x1'
cfg['port']['receive_queues'] = 1
cfg['port']['transmit_queues'] = 1
cfg['spi']['worker_count'] = 1
cfg['spi']['packet_distribution'] = 'auto'
cfg['spi']['dispatch_queue_size'] = 8192
cfg['spi']['drop_unmatched'] = True
cfg['spi']['filter_groups'] = filter_groups
with open(config_file, 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)
print('Config updated for PCAP PMD: cpu_core_list=0-1, receive_queues=1, transmit_queues=1, worker_count=1')
PY

  echo "[*] Copying config to build dir..."
  cp "$config_file" "$BUILD_DIR/config.yaml"

  echo "[*] Running app..."
  run_app
  restore_config
}

cmd_bench() {
  cmd_bench_pcap "$@"
}

# SPI-only throughput bench — runs the SAME DPI pcaps (TLS ClientHello /
# HTTP GET payload, ~117 B/packet avg) as `bench-dpi` but with DPI disabled.
# This gives an apples-to-apples comparison: identical packet mix on both
# sides, so the only difference measured is the cost of the DPI pipeline
# (ExtractHostname + MatchDpi + HostnameCache). Set via the
# `BENCH_DISABLE_DPI=1` env var; the DPI toggle is applied inside the
# `cmd_bench_dpi` heredoc. Pre-2026-07-18 this bench used the small
# SYN-only `bench_pcap_shards/` (48 B/packet avg) and reported a misleading
# +30-40 % Mpps gap because of packet-size, not pipeline cost.
cmd_bench_spi() {
  BENCH_DISABLE_DPI=1 cmd_bench_dpi "$@"
}

# Full SPI+DPI throughput bench using pcap_injector mode (bypasses the
# net_pcap PMD's L7-stripping bug). Generates shards with TLS ClientHello
# SNI records matching the production DPI filter groups, then runs
# FastAPI in pcap_injector mode. Produces non-zero dpi_cache_hits in
# the final stats — proving the DPI path actually runs end-to-end.
cmd_bench_dpi() {
  local count="${1:-1000000}"
  local workers="${2:-}"  # empty default — fall back to config.yaml's spi.worker_count
  local shard_dir="$SCRIPT_DIR/dpi_bench_shards"

  # If workers not provided, fall back to spi.worker_count in config.yaml
  # so `pixi run bench-dpi` honors the single source of truth.
  if [ -z "$workers" ]; then
    local config_file="$PROJECT_DIR/config.yaml"
    if [ -f "$config_file" ]; then
      workers="$(python3 - "$config_file" <<'PY' 2>/dev/null || true
import sys, yaml
print(yaml.safe_load(open(sys.argv[1]))['spi']['worker_count'])
PY
      )"
    fi
    workers="${workers:-$DEFAULT_WORKERS}"
  fi

  echo "[*] Generating DPI-enabled PCAP benchmark shards: count=$count workers=$workers..."
  rm -rf "$shard_dir"
  # --match-percent=100 mirrors bench-pcap's default so DPI and SPI benches
  # have the same per-shard packet mix. The DPI gen's default (70%) includes
  # 30% miss packets that don't match any SPI rule, dragging DPI throughput
  # well below SPI's. With 100% match, every packet hits an SPI group; the
  # link fast-path handles fb/yt groups, the catch-all groups keep the full
  # DPI path so the negative case is still exercised.
  python3 "$SCRIPT_DIR/gen_dpi_bench_pcap.py" "$shard_dir" --count "$count" --shards "$workers" --match-percent 100

  echo "[*] Creating config with pcap_injector + DPI rules..."
  begin_config_edit
  local config_file="$WORK_CONFIG"

  # Estimate memory_mb in bash BEFORE the Python heredoc runs so we can
  # ensure_hugepages() FIRST. The Python heredoc then re-reads actual
  # nr_hugepages to size memory_size + mbufs correctly.
  local _estimated_memory_mb
  _estimated_memory_mb=$(awk -v c="$count" -v w="$workers" 'BEGIN {
    printf "%d", int(c * 2176 / 1024 / 1024 * 1.5) + w * 256 + 1024
  }')
  ensure_hugepages "$_estimated_memory_mb"

  python3 - "$config_file" "$shard_dir" "$count" "$workers" <<'PY'
import os, sys
import yaml
config_file, shard_dir, count, workers = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])

# bench-spi runs the SAME DPI pcaps with DPI disabled — gives an
# apples-to-apples comparison of SPI-only vs SPI+DPI on the same packet
# mix. Set via `BENCH_DISABLE_DPI=1 cmd_bench_dpi "$@"` (the `bench-spi`
# pixi task wraps this). The DPI table is left empty so the SPI
# classification cost is the same in both benches; only ExtractHostname /
# MatchDpi / HostnameCache are skipped in `bench-spi`.
DISABLE_DPI = os.environ.get('BENCH_DISABLE_DPI') == '1'
with open(config_file) as f:
    cfg = yaml.safe_load(f)

# Auto-detect available hugepages EARLY (before any worker-count-derived
# config is written) so we can scale workers down on memory-constrained
# hosts. net_pcap PMD requires 142857 mbufs per RX queue — fewer than
# that and rte_eth_rx_queue_setup returns EINVAL with no recovery.
host_mem_cap_mb = 1500
try:
    with open('/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages') as f:
        pages = int(f.read().strip())
        detected_mb = pages * 2
        host_mem_cap_mb = max(800, int(detected_mb * 0.9))
except (OSError, ValueError):
    pass
_mbuf_size = cfg['mempool']['memory_buffer_size']
_mbuf_cap_by_memory = int((host_mem_cap_mb * 1024 * 1024) / (_mbuf_size * 1.4))
# net_pcap PMD with infinite_rx=1 pre-loads all packets in each shard
# into an internal ring and requires `>= pcap_pkt_count` mbufs per RX
# queue. pcap_pkt_count ≈ count / shards = count // workers, so PMD's
# per-queue minimum is `count // workers` and the total minimum is
# `count` itself (regardless of worker count).
_pmd_min_per_queue = max(1, count // workers)
_pmd_min_total = workers * _pmd_min_per_queue  # = count

# Trim cpu_core_list to match `workers` — hardware-matching config tweak
# (lcore↔queue mismatch otherwise).
_cpu_list = cfg.get('eal', {}).get('cpu_core_list', '')
if _cpu_list and '-' in _cpu_list:
    try:
        _cpu_hi = int(_cpu_list.split('-')[1])
        cfg['eal']['cpu_core_list'] = f'0-{workers}'
    except (ValueError, IndexError):
        pass

# No auto-scaling — workers stays at the user's value. If memory cap
# can't fit PMD's minimum + runtime headroom, error out with a clear
# actionable message. Headroom = `workers × burst_size × 4` covers the
# worst case of main lcore + per-worker dispatch ring + per-worker held
# burst — without it, the pool is drained at startup and rx_burst
# silently returns 0 forever (see pcap_ethdev.c eth_pcap_rx_infinite).
_mbuf_headroom = max(workers * 256 * 4, 50000)
_padded_min_total = _pmd_min_total + _mbuf_headroom
if _mbuf_cap_by_memory < _padded_min_total:
    raise SystemExit(
        f'bench-dpi: workers ({workers}) needs {_padded_min_total} mbufs '
        f'(PMD minimum {_pmd_min_total} + {_mbuf_headroom} runtime headroom) but '
        f'memory cap fits only {_mbuf_cap_by_memory} mbufs. Either free RAM '
        f'(close other apps, `sudo sh -c "echo 3 > /proc/sys/vm/drop_caches"`), '
        f'pre-allocate more hugepages (`sudo sysctl -w vm.nr_hugepages=N`), or '
        f'reduce worker_count in config.yaml. Aborting — no auto-scaling.'
    )

# Fix 3 (2026-07-09): use net_pcap PMD with all 15 shards, per-queue fanout
# instead of pcap_injector. Single main lcore producer was 50× slower
# (2.88 Mpps vs 149 Mpps target). net_pcap PMD reads full pcap frames
# including L7 (snaplen=65535 in dpi_bench_shards, packets ≤142 B vs
# 2176 B mbuf room → full TLS payload preserved in mbuf).
rx_streams = [f'rx_pcap={os.path.join(shard_dir, f"dpi_bench_q{i}.pcap")}' for i in range(workers)]
cfg['eal']['virtual_devices'] = ['net_pcap0,' + ','.join(rx_streams) + ',infinite_rx=1']
cfg['pcap_injector'] = {'enabled': False}
cfg['port']['port_bitmask'] = '0x1'
cfg['port']['receive_queues'] = workers
cfg['port']['transmit_queues'] = workers

# SPI rules matching the bench traffic (same as bench-pcap).
# `l7_required: true` is essential — without it, spi_pipeline.cpp:1023
# returns at the SPI match and never calls ExtractHostname / MatchDpi,
# leaving dpi_cache_hits/misses at 0 even with DPI enabled. The DPI bench
# specifically exercises hostname matching, so every group that should
# test DPI needs the flag set.
cfg['spi']['filter_groups'] = [
    {'name': 'bench_fb', 'precedence': 100, 'action': 'forward', 'l7_required': True,
     'dpi_filter_group': 'fg_l7_facebook', 'filters': [
        {'protocol': 'tcp', 'destination_ip_address': '31.13.64.0/18', 'label': 'fb_1'},
        {'protocol': 'tcp', 'destination_ip_address': '66.220.144.0/20', 'label': 'fb_2'},
        {'protocol': 'tcp', 'destination_ip_address': '69.63.176.0/20', 'label': 'fb_3'},
        {'protocol': 'tcp', 'destination_ip_address': '157.240.0.0/16', 'label': 'fb_4'},
        {'protocol': 'tcp', 'destination_ip_address': '69.220.144.5', 'label': 'fb_5'},
    ]},
    {'name': 'bench_yt', 'precedence': 101, 'action': 'forward', 'l7_required': True,
     'dpi_filter_group': 'fg_l7_youtube', 'filters': [
        {'protocol': 'tcp', 'destination_ip_address': '142.250.0.0/15', 'destination_port': 443, 'label': 'yt_1'},
        {'protocol': 'tcp', 'destination_ip_address': '172.217.0.0/16', 'destination_port': 443, 'label': 'yt_2'},
        {'protocol': 'tcp', 'destination_ip_address': '216.58.192.0/19', 'destination_port': 443, 'label': 'yt_3'},
        {'protocol': 'tcp', 'destination_ip_address': '74.125.0.1', 'destination_port': 443, 'label': 'yt_4'},
    ]},
    # bench_http / bench_https intentionally have NO `dpi_filter_group` —
    # port 80 / port 443 catch-alls can serve any application (nginx, gRPC,
    # custom). They exercise the full ExtractHostname + MatchDpi path so
    # we still see non-zero `dpi_cache_hits` and `dpi_cache_misses` to
    # confirm DPI works end-to-end.
    {'name': 'bench_http', 'precedence': 102, 'action': 'forward', 'l7_required': True, 'filters': [
        {'protocol': 'tcp', 'destination_port': 80, 'label': 'http'},
    ]},
    {'name': 'bench_https', 'precedence': 103, 'action': 'forward', 'l7_required': True, 'filters': [
        {'protocol': 'tcp', 'destination_port': 443, 'label': 'https'},
    ]},
]

# When BENCH_DISABLE_DPI=1 (`bench-spi`), strip the static SPI→DPI links
# from every group — the validator rejects links whose target DPI filter
# group doesn't exist, and DPI is empty in this mode. The SPI groups
# still classify packets normally; only the DPI short-circuit is dropped.
if DISABLE_DPI:
    for grp in cfg['spi']['filter_groups']:
        grp.pop('dpi_filter_group', None)
        # Also flip l7_required off — without DPI, l7_required=true would
        # still call TryDpiClassify, which is a no-op but adds an
        # unnecessary branch on the hot path. The bench is measuring
        # SPI-only cost, so strip every L7-related hook.
        grp['l7_required'] = False

# DPI rules matching the SNIs embedded by gen_dpi_bench_pcap.py.
# Skipped entirely when BENCH_DISABLE_DPI=1 (e.g. via `pixi run bench-spi`)
# — that bench reuses the same pcap shards but disables DPI so the
# SPI-only throughput is measured on identical packet sizes.
if DISABLE_DPI:
    cfg['dpi']['enabled'] = False
    cfg['dpi']['filters'] = []
    print('bench-spi (DPI disabled): reusing DPI pcaps with dpi.enabled=false')
else:
    cfg['dpi']['enabled'] = True
    cfg['dpi']['filters'] = [
        {'filter_group': 'fg_l7_facebook', 'hostname_pattern': '*.facebook.com', 'label': 'facebook', 'priority': 10},
        {'filter_group': 'fg_l7_google',   'hostname_pattern': '*.google.com',   'label': 'google',   'priority': 30},
        {'filter_group': 'fg_l7_youtube',  'hostname_pattern': '*.youtube.com',  'label': 'youtube',  'priority': 20},
        {'filter_group': 'fg_l7_default',  'hostname_pattern': '*',              'label': 'default',  'priority': 999},
    ]

# Per-queue fanout (15 workers × 1 queue each) — main lcore idle,
# throughput scales with workers. packet_distribution='queue' resolves
# to kQueuePerWorker in ResolvePacketDistribution.
cfg['spi']['packet_distribution'] = 'queue'
cfg['spi']['worker_count'] = workers
cfg['spi']['dispatch_queue_size'] = 65536

# Cap the flow-table size at the user-configured value (default 1M) to
# avoid rte_hash_create allocation failures on this host's EAL heap
# fragmentation (with RW_CONCURRENCY_LF the hash needs a contiguous
# bucket array and fails above ~7M entries here even with 5+ GB pool).
#
# To keep cache hit rate high across multiple shards at multi-worker
# scale, we shorten `flow_ttl_sec` below the bench duration so
# PurgeExpired (run once per stats print = 5s) evicts stale entries
# and reclaims slots for fresh ones. With TTL=4s and stats interval=5s,
# every PurgeExpired pass removes all entries older than 4s — under
# steady-state replay (infinite_rx=1) the most recent 4s of unique
# flows stay cached, and earlier ones get evicted then re-inserted.
#
# Combined: 1M slots + 4s TTL = enough room for the most recent ~4s
# of unique flows. With 4-7 workers × ~250K unique per shard, that
# fits comfortably. With 15 workers the cache eviction rate matches
# the warmup rate so cache hit ratio converges to ~99% per shard.
_cfg_max_flows_user = int(cfg.get('spi', {}).get('max_concurrent_flows', 1000000))
cfg['spi']['max_concurrent_flows'] = _cfg_max_flows_user
cfg['spi']['flow_ttl_sec'] = min(
    int(cfg.get('spi', {}).get('flow_ttl_sec', 300)),
    4,  # shorter than the 5s stats interval so every purge pass fires
)

# Boost hot-path throughput: large burst amortizes per-iteration overhead
# and large mempool cache reduces per-lcore mutex contention on global pool.
# Both are SAFE (don't break correctness), pure speed knobs.
# NOTE: DPDK's RTE_MEMPOOL_CACHE_MAX_SIZE=512, so cache_size capped at 512
# (1024 returns EINVAL from rte_pktmbuf_pool_create).
cfg['app']['burst_size'] = 256
cfg['mempool']['cache_size'] = 512

# PMD with infinite_rx=1 needs `count` mbufs total (pre-loads all packets
# into per-queue rings at queue-setup time — see pcap_ethdev.c
# `eth_rx_queue_setup`). On top of that the runtime burst pool needs
# `workers × burst_size` free mbufs in flight for rte_eth_rx_burst →
# rte_pktmbuf_alloc_bulk; without headroom every rx_burst silently
# returns 0 once the pool is drained. Padding `count` by `workers ×
# burst_size × 4` (4× worst-case concurrent allocs in flight: main
# dispatcher, plus per-worker dispatch ring slots, plus held bursts)
# keeps rx_burst succeeding on memory-constrained hosts that can't
# afford 1.5× the PMD minimum. host_mem_cap_mb and _mbuf_size carry
# through from the hugepage check at the top of this heredoc.
mbuf_size = _mbuf_size
_mbuf_headroom = max(workers * 256 * 4, 50000)
cfg['mempool']['memory_buffer_count'] = _pmd_min_total + _mbuf_headroom
# Add a 1024 MB headroom on top of mbuf/per-worker/ACL needs. rte_hash
# allocates a contiguous bucket array internally and fails with
# "buckets memory allocation failed" when the EAL heap is fragmented
# — particularly at small worker counts where the per-worker overhead
# is too small to leave a big contiguous block. 1 GB padding is enough
# to absorb fragmentation in our 4–15 worker range.
needed_mb = int(cfg['mempool']['memory_buffer_count'] * mbuf_size
               / (1024 * 1024) * 1.4) + workers * 64 + 256 + 1024
cfg['eal']['memory_size'] = str(min(max(needed_mb, 800), host_mem_cap_mb))

with open(config_file, 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)
print(f'DPI benchmark: workers={workers}, pcap={shard_dir} (infinite loop)')
PY

  local memory_mb
  # ensure_hugepages already ran (before the Python heredoc so nr_hugepages
  # was accurate when Python computed memory_size). Just copy the config.
  cp "$config_file" "$BUILD_DIR/config.yaml"

  echo "[*] Running app... (Ctrl+C to stop — final stats will show dpi_cache_hits)"
  run_app

  restore_config
  echo "[OK] DPI benchmark done."
}

cmd_bench_pcap() {
  local count="${1:-$DEFAULT_BENCH_COUNT}"
  local workers="${2:-}"
  local match_percent="${3:-$DEFAULT_MATCH_PERCENT}"
  local shard_dir="$SCRIPT_DIR/bench_pcap_shards"

  # Raise RLIMIT_MEMLOCK for this script (and inherited by all children,
  # including the FastAPI binary spawned later) to `unlimited`. Without
  # this, the default 64 MB hard cap makes `rte_pktmbuf_pool_create`
  # return ENOMEM regardless of hugepage availability.
  if command -v sudo >/dev/null 2>&1 && command -v prlimit >/dev/null 2>&1; then
    sudo prlimit --memlock=unlimited --pid $$ >/dev/null 2>&1 || true
  fi

  # If workers not provided, fall back to spi.worker_count in config.yaml so
  # `pixi run bench` honors the single source of truth.
  if [ -z "$workers" ]; then
    local config_file="$PROJECT_DIR/config.yaml"
    if [ -f "$config_file" ]; then
      workers="$(python3 - "$config_file" <<'PY' 2>/dev/null || true
import sys, yaml
print(yaml.safe_load(open(sys.argv[1]))['spi']['worker_count'])
PY
      )"
    fi
    workers="${workers:-$DEFAULT_WORKERS}"
  fi

  require_worker_lcores "$workers"

  echo "[*] Generating PCAP benchmark shards: count=$count workers=$workers match=${match_percent}%..."
  rm -rf "$shard_dir"
  python3 "$SCRIPT_DIR/gen_test_pcap.py" "$shard_dir" --count "$count" --shards "$workers" \
    --match-percent "$match_percent"

  echo "[*] Creating multi-queue PCAP config with TX drop..."
  begin_config_edit
  local config_file="$WORK_CONFIG"

  # Estimate memory_mb in bash BEFORE the Python heredoc runs so we can
  # ensure_hugepages() FIRST. The Python heredoc then re-reads the actual
  # nr_hugepages (after allocation) to size memory_size + mbufs correctly.
  # Formula: mbufs ≈ count (PMD with infinite_rx=1 pre-loads all packets),
  # mbuf_pool ≈ mbufs × mbuf_size × 1.5, plus EAL overhead + per-worker ring.
  local _estimated_memory_mb
  _estimated_memory_mb=$(awk -v c="$count" -v w="$workers" 'BEGIN {
    printf "%d", int(c * 2176 / 1024 / 1024 * 1.5) + w * 256 + 1024
  }')
  ensure_hugepages "$_estimated_memory_mb"

  python3 - "$config_file" "$shard_dir" "$count" "$workers" "$match_percent" <<'PY'
import os
import sys
import yaml

config_file, shard_dir, count_arg, workers_arg, match_percent_arg = sys.argv[1:6]
count = int(count_arg)
workers = int(workers_arg)
match_percent = int(match_percent_arg)

# SPI rules that match the synthetic pcap traffic. These are the only rules
# that produce non-zero matches for the bench shards.
filter_groups = [
    {'name': 'fg_l34_facebook', 'precedence': 100, 'action': 'forward', 'filters': [
        {'protocol': 'tcp', 'destination_ip_address': '31.13.64.0/18', 'label': 'facebook_1'},
        {'protocol': 'tcp', 'destination_ip_address': '66.220.144.0/20', 'label': 'facebook_2'},
        {'protocol': 'tcp', 'destination_ip_address': '69.63.176.0/20', 'label': 'facebook_3'},
        {'protocol': 'tcp', 'destination_ip_address': '157.240.0.0/16', 'label': 'facebook_4'},
        {'protocol': 'tcp', 'destination_ip_address': '69.220.144.5', 'label': 'facebook_5'},
    ]},
    {'name': 'fg_l34_youtube', 'precedence': 101, 'action': 'forward', 'filters': [
        {'protocol': 'tcp', 'destination_ip_address': '142.250.0.0/15', 'destination_port': 443, 'label': 'youtube_1'},
        {'protocol': 'tcp', 'destination_ip_address': '172.217.0.0/16', 'destination_port': 443, 'label': 'youtube_2'},
        {'protocol': 'tcp', 'destination_ip_address': '216.58.192.0/19', 'destination_port': 443, 'label': 'youtube_3'},
        {'protocol': 'tcp', 'destination_ip_address': '74.125.0.1', 'destination_port': 443, 'label': 'youtube_4'},
    ]},
    {'name': 'fg_l34_http', 'precedence': 102, 'action': 'forward', 'filters': [
        {'protocol': 'tcp', 'destination_port': 80, 'label': 'http_all'},
    ]},
    {'name': 'fg_l34_https', 'precedence': 103, 'action': 'forward', 'filters': [
        {'protocol': 'tcp', 'destination_port': 443, 'label': 'https_all'},
    ]},
    {'name': 'fg_l34_dns', 'precedence': 104, 'action': 'forward', 'filters': [
        {'protocol': 'udp', 'destination_port': 53, 'label': 'dns_udp'},
        {'protocol': 'tcp', 'destination_port': 53, 'label': 'dns_tcp'},
    ]},
    {'name': 'fg_l34_udp_sdf1006', 'precedence': 106, 'action': 'drop', 'filters': [
        {'protocol': 'udp', 'destination_port': 9999, 'label': 'udp_drop'},
    ]},
]

# Read the user's config.yaml. Cách 3: preserve all user settings (burst_size,
# worker_count, mempool, queues, drop_unmatched, ...). Only override the two
# fields the bench REQUIRES for the test traffic to flow correctly.
with open(config_file) as f:
    cfg = yaml.safe_load(f)

# Override 1: pcap shards the bench just generated (must point to bench_pcap_shards).
# User's existing virtual_devices (or absence thereof) is replaced.
rx_streams = [f'rx_pcap={os.path.join(shard_dir, f"bench_q{i}.pcap")}' for i in range(workers)]
cfg['eal']['virtual_devices'] = ['net_pcap0,' + ','.join(rx_streams) + ',infinite_rx=1']

# Disable any pcap_injector block in the user's config — ResolvePacketDistribution
# would otherwise take kPcapInject mode and skip the net_pcap shards above.
cfg['pcap_injector'] = {'enabled': False}

# net_pcap PMD needs matching queue counts (one RX queue per shard). The
# user's config may have these zeroed (e.g. when set up for pcap_injector
# mode); override to workers count so the workers can drain shards in
# parallel without a software flow-hash dispatcher in between.
cfg['port']['receive_queues'] = workers
cfg['port']['transmit_queues'] = workers
cfg['port']['port_bitmask'] = '0x1'

cfg['spi']['worker_count'] = workers

# Force queue-per-worker distribution. net_pcap binds each rx_pcap shard
# to its own RX queue (pp->rx_pcap[queue_id] is a static per-queue handle —
# no RSS hardware required). With workers == queues, each worker drains
# its shard directly via rte_eth_rx_burst(port, worker_id), skipping the
# main-lcore flow-hash dispatcher hop entirely. cmd_bench_dpi uses the
# same trick and gets ~28 Mpps vs ~12 Mpps for the dispatcher path.
cfg['spi']['packet_distribution'] = 'queue'

# Available hugepage memory — upper bound on what EAL can actually use.
# Without this cap, hosts with <~2 GB hugepages fail at
# rte_pktmbuf_pool_create with ENOMEM even when memory_size is bounded
# below — the user's mbufs × mbuf_size exceeds the EAL heap. Read this
# FIRST so the mbuf count below can be clamped to what fits.
available_hugepages_mb = 0
try:
    with open('/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages') as f:
        available_hugepages_mb = int(f.read().strip()) * 2
except (OSError, ValueError):
    available_hugepages_mb = 0
memory_size_cap = max(1500, available_hugepages_mb - 256)

# net_pcap PMD requires at least 142857 mbufs per RX queue. With N workers
# that's N × 142857 mbufs total. We size at N × 150000 for a small headroom
# (7 workers → 1.05 M mbufs, just over the 1 M minimum the PMD needs).
# Memory: 1.05 M × 2176 B × 1.5 = ~3.3 GB raw + EAL overhead = ~4 GB heap.
#
# Honour user's smaller memory_size when present (e.g. `memory_size: '1500'`).
# In that case cap mbufs to fit: `mbufs = (memory_size - 512 MB overhead) /
# 2176 B / 1.4`, then take the max with `workers * 150000` only if it fits.
# ALSO clamp to memory_size_cap (host's actually-available hugepages) so
# we never ask EAL for more mbuf memory than the kernel can back.
_user_memory_size_mb = 0
try:
    _user_memory_size_mb = int(cfg.get('eal', {}).get('memory_size', '0'))
except (ValueError, TypeError):
    _user_memory_size_mb = 0
_workers_required_mbufs = workers * 150000
_min_mbufs = int(cfg.get('mempool', {}).get('memory_buffer_count', 32768))
_mbuf_size = cfg.get('mempool', {}).get('memory_buffer_size', 2176)
if _user_memory_size_mb > 0 and _user_memory_size_mb < 2048:
    _effective_mem_cap = min(_user_memory_size_mb, memory_size_cap)
else:
    _effective_mem_cap = memory_size_cap
# (cap - 512 MB EAL overhead) × 1.4 (mbuf + ring metadata) / mbuf_size.
_mbuf_cap_by_memory = int(((_effective_mem_cap - 512) * 1024 * 1024) / (_mbuf_size * 1.4))

# net_pcap PMD with infinite_rx=1 pre-loads all packets in each shard
# into an internal ring and requires `>= pcap_pkt_count` mbufs per RX
# queue. pcap_pkt_count ≈ count / shards = count // workers, so PMD's
# per-queue minimum is `count // workers`. With 7 workers/1M count
# that's ~142857/queue; with 4 workers/1M count it's 250000/queue.
# Using a constant 142857 under-sizes the cap for non-7 worker counts
# and the PMD fails with EINVAL.
_pmd_min_per_queue = max(1, count // workers)
_pmd_min_total = workers * _pmd_min_per_queue  # = count for PMD

# Trim cpu_core_list + queue counts to match `workers` — hardware-matching
# config tweaks. Without this, with cpu_core_list=0-7 but workers=4 the
# PMD sets up cleanly but no traffic reaches any worker (lcore↔queue
# mismatch). Always run regardless of memory situation.
_cpu_list = cfg.get('eal', {}).get('cpu_core_list', '')
if _cpu_list and '-' in _cpu_list:
    try:
        _cpu_hi = int(_cpu_list.split('-')[1])
        cfg['eal']['cpu_core_list'] = f'0-{workers}'
    except (ValueError, IndexError):
        pass
cfg['port']['receive_queues'] = workers
cfg['port']['transmit_queues'] = workers
cfg['spi']['worker_count'] = workers

# No auto-scaling — workers stays at the user's value (CLI or config.yaml).
# ensure_hugepages tries to allocate enough hugepages before the Python
# heredoc runs. If memory cap still can't fit PMD's minimum, error out
# with a clear actionable message — don't silently reduce workers.
# Check uses the *padded* size (count + headroom) so we don't silently
# under-allocate and hit pool exhaustion at runtime (every rx_burst
# would return 0 — see pcap_ethdev.c eth_pcap_rx_infinite).
_mbuf_headroom = max(workers * 256 * 4, 50000)
_padded_min_total = _pmd_min_total + _mbuf_headroom
if _mbuf_cap_by_memory < _padded_min_total:
    raise SystemExit(
        f'bench-pcap: workers ({workers}) needs {_padded_min_total} mbufs '
        f'(PMD minimum {_pmd_min_total} + {_mbuf_headroom} runtime headroom) but '
        f'memory cap fits only {_mbuf_cap_by_memory} mbufs. Either free RAM '
        f'(close other apps, `sudo sh -c "echo 3 > /proc/sys/vm/drop_caches"`), '
        f'pre-allocate more hugepages (`sudo sysctl -w vm.nr_hugepages=N`), or '
        f'reduce worker_count in config.yaml. Aborting — no auto-scaling.'
    )

cfg['mempool']['memory_buffer_count'] = _padded_min_total

# Hot-path knobs that significantly affect throughput — same as bench-dpi
# (cmd_bench_dpi lines 412-422). Larger burst amortises per-iteration
# overhead, larger mempool cache cuts per-lcore mutex contention on the
# global pool, larger dispatch ring lets the main lcore feed workers
# without backpressuring on ring-full drops. All SAFE (pure speed knobs).
cfg['spi']['dispatch_queue_size'] = 65536
cfg['app']['burst_size'] = 256
cfg['mempool']['cache_size'] = 512

# Override 2: filter groups matching the synthetic pcap traffic. The bench shards
# are generated with specific destination IP / port values that match only these
# rules. User's own filter_groups would not match the bench traffic, so we
# replace them with the bench's rules. After the run, restore_config puts
# the user's original groups back.
cfg['spi']['filter_groups'] = filter_groups

# bench-spi: disable DPI entirely so the parser/cache path is skipped
# during the SPI-only run. Set via `BENCH_DISABLE_DPI=1` from the shell
# wrapper; the DPI toggle happens HERE (before run_app), not after — the
# previous ordering called cmd_bench_pcap first (which blocks on the
# running app) and only then flipped the flag, leaving the actual run
# with DPI still enabled.
if os.environ.get('BENCH_DISABLE_DPI') == '1':
    cfg['dpi']['enabled'] = False
    cfg['dpi']['filters'] = []
    print('bench-spi: forced dpi.enabled=false')

# Scale EAL memory_size with mempool: net_pcap PMD's per-queue ring +
# ACL classification tables need ~3 GB at 15 workers / 1 M mbufs.
# Cap at the actually-allocated hugepage count minus 256 MB margin — on
# memory-constrained hosts the kernel may allocate *fewer* hugepages than
# requested, and asking EAL for more heap than is available returns ENOMEM.
needed_mb = int(cfg.get('mempool', {}).get('memory_buffer_count', 32768)
               * cfg.get('mempool', {}).get('memory_buffer_size', 2176)
               / (1024 * 1024) * 1.5) + workers * 256 + 1024
# Honour user's explicit memory_size when SMALLER than the auto-computed
# `needed_mb` — they may be running on a memory-constrained host.
_user_memory_size = int(cfg.get('eal', {}).get('memory_size', '5000'))
_effective_memory_size = min(_user_memory_size, memory_size_cap)
if _user_memory_size < 2048:
    # User explicitly capped memory below the default 2 GB floor — keep
    # their value verbatim (don't auto-bump to fit auto-calculated need).
    cfg['eal']['memory_size'] = str(_user_memory_size)
else:
    cfg['eal']['memory_size'] = str(min(max(_user_memory_size, needed_mb), memory_size_cap))

with open(config_file, 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)

matched = count * match_percent // 100
print(f'PCAP benchmark: workers={workers}, match_percent={match_percent}, expected_match~={matched}')
mbuf_count = cfg.get('mempool', {}).get('memory_buffer_count', 32768)
print(f'Config: user settings preserved; mbufs={mbuf_count}')
PY

  # ensure_hugepages already ran (before the Python heredoc so nr_hugepages
  # was accurate when Python computed memory_size). Just copy the config.
  cp "$config_file" "$BUILD_DIR/config.yaml"

  echo "[*] Running app... (Ctrl+C to stop, check stats for throughput)"
  run_app

  restore_config
  echo "[OK] Benchmark done."
}

cmd_bench_afpacket() {
  local workers="${1:-$DEFAULT_WORKERS}"

  require_worker_lcores "$workers"

  echo "[*] Creating AF_PACKET config: workers=$workers qpairs=$workers..."
  begin_config_edit
  local config_file="$WORK_CONFIG"

  python3 - "$config_file" "$workers" <<'PY'
import re
import sys
import yaml

config_file, workers_arg = sys.argv[1:3]
workers = int(workers_arg)

def iface_for(devices, name, fallback):
    for dev in devices:
        if dev.startswith(name + ','):
            match = re.search(r'(?:^|,)iface=([^,]+)', dev)
            if match:
                return match.group(1)
    return fallback

with open(config_file) as f:
    cfg = yaml.safe_load(f)

devices = cfg['eal'].get('virtual_devices', [])
iface0 = iface_for(devices, 'net_af_packet0', 'virbr1')
iface1 = iface_for(devices, 'net_af_packet1', 'virbr2')
cfg['eal']['virtual_devices'] = [
    f'net_af_packet0,iface={iface0},qpairs={workers}',
    f'net_af_packet1,iface={iface1},qpairs={workers}',
]
cfg['eal']['cpu_core_list'] = f'0-{workers}'
cfg['port']['port_bitmask'] = '0x3'
cfg['port']['receive_queues'] = workers
cfg['port']['transmit_queues'] = workers
cfg['spi']['worker_count'] = workers
cfg['spi']['packet_distribution'] = 'auto'
cfg['spi']['dispatch_queue_size'] = 8192
if cfg.get('l3_forward', {}).get('enabled', False):
    cfg['l3_forward']['queue_mappings'] = [
        {'port_id': port_id, 'queue_id': queue_id, 'lcore_id': queue_id + 1}
        for port_id in (0, 1)
        for queue_id in range(workers)
    ]

with open(config_file, 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)

print(f'AF_PACKET benchmark: iface0={iface0}, iface1={iface1}, workers={workers}')
PY

  cp "$config_file" "$BUILD_DIR/config.yaml"

  echo "[*] Running app... generate many live flows from another terminal."
  run_app

  restore_config
  echo "[OK] AF_PACKET benchmark done."
}

case "${1:-}" in
  setup)    cmd_setup ;;
  run)      cmd_run ;;
  send)     shift; cmd_send "$@" ;;
  pcap)     shift; cmd_pcap "$@" ;;
  bench)    shift; cmd_bench "$@" ;;
  bench-spi) shift; cmd_bench_spi "$@" ;;
  bench-dpi) shift; cmd_bench_dpi "$@" ;;
  bench-pcap) shift; cmd_bench_pcap "$@" ;;
  bench-afpacket) shift; cmd_bench_afpacket "$@" ;;
  teardown) cmd_teardown ;;
  *)        usage ;;
esac
