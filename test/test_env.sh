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
APP_BINARY="${APP_BINARY:-$BUILD_DIR/FastAPI}"
DEFAULT_WORKERS="${DEFAULT_WORKERS:-6}"
DEFAULT_BENCH_COUNT="${DEFAULT_BENCH_COUNT:-300000}"
DEFAULT_MATCH_PERCENT="${DEFAULT_MATCH_PERCENT:-100}"
CONFIG_BACKUP=""

usage() {
  echo "Usage: $0 {setup|run|send|pcap|bench|bench-spi|bench-dpi|bench-pcap|bench-afpacket|teardown}"
  exit 1
}

restore_config() {
  local config_file="$PROJECT_DIR/config.yaml"
  if [ -n "${CONFIG_BACKUP:-}" ] && [ -f "$CONFIG_BACKUP" ]; then
    echo "[*] Restoring original config..."
    cp "$CONFIG_BACKUP" "$config_file"
    cp "$config_file" "$BUILD_DIR/config.yaml"
    rm -f "$CONFIG_BACKUP"
    CONFIG_BACKUP=""
  fi
}

begin_config_edit() {
  local config_file="$PROJECT_DIR/config.yaml"
  CONFIG_BACKUP="$config_file.bak"
  cp "$config_file" "$CONFIG_BACKUP"
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
ensure_hugepages() {
  local memory_mb="${1}"
  local current
  current="$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)"
  local current_mb=$((current * 2))
  if [ "$current_mb" -ge "$memory_mb" ]; then
    echo "[OK] Sufficient hugepages already allocated: ${current_mb}MB"
    return 0
  fi
  local pages=$(( (memory_mb + memory_mb / 4) / 2 ))  # 25% margin, 2MB pages
  echo "[*] Insufficient hugepages (${current_mb}MB < ${memory_mb}MB). Allocating ${pages} x 2MB hugepages (~$((pages * 2))MB)..."
  sudo sysctl -w "vm.nr_hugepages=${pages}" >/dev/null
  local free_pages
  free_pages="$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)"
  if [ "$free_pages" -lt "$pages" ]; then
    echo "[!] Warning: requested ${pages} hugepages but only got ${free_pages}."
    echo "    Try freeing memory or reducing worker count."
  fi
  echo "[OK] Hugepages allocated: $((free_pages * 2))MB"
}

run_app() {
  require_app_binary
  sudo setcap cap_net_raw,cap_ipc_lock,cap_net_admin+ep "$APP_BINARY"
  sudo "$APP_BINARY"
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
  local config_file="$PROJECT_DIR/config.yaml"

  echo "[*] Generating test pcap (5 HTTP + 5 HTTPS + 5 DNS + 5 GTP-U)..."
  python3 "$SCRIPT_DIR/gen_test_pcap.py" "$pcap_file"
  rm -f "$tx_pcap_file"

  echo "[*] Creating PCAP config..."
  begin_config_edit

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

# SPI-only throughput bench: forces `dpi.enabled: false` in the loaded
# config so the DPI parser / cache path is excluded entirely. Use this
# to measure pure SPI throughput without DPI overhead. Note that the
# existing `bench` (and thus `pixi run bench`) preserves the user's
# DPI rules via Cách 3 — DPI sees every packet but `hostname == nullptr`
# for the net_pcap PMD trunk because it strips L7, so the cost is just
# the empty MatchDpi early-return.
cmd_bench_spi() {
  cmd_bench_pcap "$@"
  if [ -f "$BUILD_DIR/config.yaml" ]; then
    python3 -c "
import sys, yaml
with open('$BUILD_DIR/config.yaml') as f:
    cfg = yaml.safe_load(f)
cfg['dpi']['enabled'] = False
cfg['dpi']['filters'] = []
with open('$BUILD_DIR/config.yaml', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)
print('bench-spi: forced dpi.enabled=false')
"
  fi
}

# Full SPI+DPI throughput bench using pcap_injector mode (bypasses the
# net_pcap PMD's L7-stripping bug). Generates shards with TLS ClientHello
# SNI records matching the production DPI filter groups, then runs
# FastAPI in pcap_injector mode. Produces non-zero dpi_cache_hits in
# the final stats — proving the DPI path actually runs end-to-end.
cmd_bench_dpi() {
  local count="${1:-1000000}"
  local workers="${2:-15}"
  local shard_dir="$SCRIPT_DIR/dpi_bench_shards"

  echo "[*] Generating DPI-enabled PCAP benchmark shards: count=$count workers=$workers..."
  rm -rf "$shard_dir"
  python3 "$SCRIPT_DIR/gen_dpi_bench_pcap.py" "$shard_dir" --count "$count" --shards "$workers"

  echo "[*] Creating config with pcap_injector + DPI rules..."
  local config_file="$PROJECT_DIR/config.yaml"
  begin_config_edit

  python3 - "$config_file" "$shard_dir" "$workers" <<'PY'
import os, sys
import yaml
config_file, shard_dir, workers = sys.argv[1], sys.argv[2], int(sys.argv[3])
with open(config_file) as f:
    cfg = yaml.safe_load(f)

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
cfg['spi']['filter_groups'] = [
    {'name': 'bench_fb', 'precedence': 100, 'action': 'forward', 'filters': [
        {'protocol': 'tcp', 'destination_ip_address': '31.13.64.0/18', 'label': 'fb_1'},
        {'protocol': 'tcp', 'destination_ip_address': '66.220.144.0/20', 'label': 'fb_2'},
        {'protocol': 'tcp', 'destination_ip_address': '69.63.176.0/20', 'label': 'fb_3'},
        {'protocol': 'tcp', 'destination_ip_address': '157.240.0.0/16', 'label': 'fb_4'},
        {'protocol': 'tcp', 'destination_ip_address': '69.220.144.5', 'label': 'fb_5'},
    ]},
    {'name': 'bench_yt', 'precedence': 101, 'action': 'forward', 'filters': [
        {'protocol': 'tcp', 'destination_ip_address': '142.250.0.0/15', 'destination_port': 443, 'label': 'yt_1'},
        {'protocol': 'tcp', 'destination_ip_address': '172.217.0.0/16', 'destination_port': 443, 'label': 'yt_2'},
        {'protocol': 'tcp', 'destination_ip_address': '216.58.192.0/19', 'destination_port': 443, 'label': 'yt_3'},
        {'protocol': 'tcp', 'destination_ip_address': '74.125.0.1', 'destination_port': 443, 'label': 'yt_4'},
    ]},
    {'name': 'bench_http', 'precedence': 102, 'action': 'forward', 'filters': [
        {'protocol': 'tcp', 'destination_port': 80, 'label': 'http'},
    ]},
    {'name': 'bench_https', 'precedence': 103, 'action': 'forward', 'filters': [
        {'protocol': 'tcp', 'destination_port': 443, 'label': 'https'},
    ]},
]

# DPI rules matching the SNIs embedded by gen_dpi_bench_pcap.py.
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
cfg['spi']['dispatch_queue_size'] = 32768

# Boost hot-path throughput: 2x burst amortizes per-iteration overhead,
# 2x mempool cache reduces per-lcore mutex contention on global pool.
# Both are SAFE (don't break correctness), pure speed knobs.
# NOTE: DPDK's RTE_MEMPOOL_CACHE_MAX_SIZE=512, so cache_size capped at 512
# (1024 returns EINVAL from rte_pktmbuf_pool_create).
cfg['app']['burst_size'] = 128
cfg['mempool']['cache_size'] = 512

# Auto-detect available hugepages and scale mbufs + memory_size to fit.
# Falls back to 1500 MB on hosts where detection fails (no hugepages
# configured yet, no sudo, etc.). To get full 1.05M mbufs at 5500 MB
# memory_size (matches bench), the user should pre-allocate at least
# 5500 MB of hugepages: `sudo sysctl -w vm.nr_hugepages=2750`.
import os
host_mem_cap_mb = 1500
try:
    with open('/sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages') as f:
        pages = int(f.read().strip())
        detected_mb = pages * 2
        # Reserve 10% for kernel overhead, use up to 90% for EAL.
        host_mem_cap_mb = max(800, int(detected_mb * 0.9))
except (OSError, ValueError):
    pass

mbuf_size = cfg['mempool']['memory_buffer_size']
cfg['mempool']['memory_buffer_count'] = min(
    max(200000, workers * 70000),  # ideal: 1.05M @ 15 workers
    (host_mem_cap_mb * 1024 * 1024) // (mbuf_size * 2),  # 50% for mbufs, 50% for EAL overhead
)
needed_mb = int(cfg['mempool']['memory_buffer_count'] * mbuf_size
               / (1024 * 1024) * 1.4) + workers * 64 + 256
cfg['eal']['memory_size'] = str(min(max(needed_mb, 800), host_mem_cap_mb))

with open(config_file, 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)
print(f'DPI benchmark: workers={workers}, pcap={shard_dir} (infinite loop)')
PY

  local memory_mb
  memory_mb="$(cat "$config_file.mem" 2>/dev/null || echo 1500)"
  rm -f "$config_file.mem"
  ensure_hugepages "$memory_mb"

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
  local config_file="$PROJECT_DIR/config.yaml"
  begin_config_edit

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

# net_pcap PMD requires at least ~66667 mbufs per RX queue (default
# rx_packets_per_burst) — scale memory_buffer_count with worker count
# so the PMD's eth_rx_queue_setup() doesn't fail with EINVAL.
cfg['mempool']['memory_buffer_count'] = max(
    int(cfg.get('mempool', {}).get('memory_buffer_count', 32768)),
    workers * 70000,
)

# Override 2: filter groups matching the synthetic pcap traffic. The bench shards
# are generated with specific destination IP / port values that match only these
# rules. User's own filter_groups would not match the bench traffic, so we
# replace them with the bench's rules. After the run, restore_config puts
# the user's original groups back.
cfg['spi']['filter_groups'] = filter_groups

# Scale EAL memory_size with mempool: net_pcap PMD's per-queue ring +
# ACL classification tables need ~3GB at 15 workers / 1M mbufs.
# The user's DPI-injector config sets memory_size=1500 which is too small
# for the 15-queue net_pcap path; bump to 5000 so EAL heap fits mbufs +
# EAL overhead (capped at 5500 since lab free hugepages is ~3GB).
needed_mb = int(cfg.get('mempool', {}).get('memory_buffer_count', 32768)
               * cfg.get('mempool', {}).get('memory_buffer_size', 2176)
               / (1024 * 1024) * 1.5) + workers * 256 + 1024
cfg['eal']['memory_size'] = str(min(max(int(cfg.get('eal', {}).get('memory_size', '5000')), needed_mb), 5500))

with open(config_file, 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)

# Compute hugepages needed from the user's mempool config (1.5x safety margin).
# If user's mbufs exceed free hugepages, ensure_hugepages will allocate more.
mbuf_count = cfg.get('mempool', {}).get('memory_buffer_count', 32768)
mbuf_size = cfg.get('mempool', {}).get('memory_buffer_size', 2176)
memory_mb = max(2048, int(mbuf_count * mbuf_size / (1024 * 1024) * 1.5) + workers * 64 + 512)
with open(config_file + '.mem', 'w') as mf:
    mf.write(str(memory_mb))

matched = count * match_percent // 100
print(f'PCAP benchmark: workers={workers}, match_percent={match_percent}, expected_match~={matched}')
print(f'Config: user settings preserved; mbufs={mbuf_count}, hugepages_needed={memory_mb}MB')
PY

  local memory_mb
  memory_mb="$(cat "$config_file.mem" 2>/dev/null || echo 2697)"
  rm -f "$config_file.mem"
  ensure_hugepages "$memory_mb"

  cp "$config_file" "$BUILD_DIR/config.yaml"

  echo "[*] Running app... (Ctrl+C to stop, check stats for throughput)"
  run_app

  restore_config
  echo "[OK] Benchmark done."
}

cmd_bench_afpacket() {
  local workers="${1:-$DEFAULT_WORKERS}"
  local config_file="$PROJECT_DIR/config.yaml"

  require_worker_lcores "$workers"

  echo "[*] Creating AF_PACKET config: workers=$workers qpairs=$workers..."
  begin_config_edit

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
