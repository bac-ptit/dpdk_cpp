#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

NS="dpdk_test"
MACVLAN="macvlan0"
HOST_IFACE="enp3s0"
APP_IP="192.168.1.12"
TEST_IP="192.168.1.13"
BUILD_DIR="${BUILD_DIR:-$PROJECT_DIR/build_debug}"
if [ ! -d "$BUILD_DIR" ] && [ -d "$PROJECT_DIR/cmake-build-debug" ]; then
  BUILD_DIR="$PROJECT_DIR/cmake-build-debug"
fi
APP_BINARY="${APP_BINARY:-$BUILD_DIR/FastAPI}"
DEFAULT_WORKERS="${DEFAULT_WORKERS:-6}"
DEFAULT_BENCH_COUNT="${DEFAULT_BENCH_COUNT:-300000}"
DEFAULT_MATCH_PERCENT="${DEFAULT_MATCH_PERCENT:-100}"
CONFIG_BACKUP=""

usage() {
  echo "Usage: $0 {setup|run|send|pcap|bench|bench-pcap|bench-afpacket|teardown}"
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

# Allocate hugepages if none are configured.
# Usage: ensure_hugepages <memory_mb>
ensure_hugepages() {
  local memory_mb="${1}"
  local current
  current="$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)"
  if [ "$current" -gt 0 ]; then
    return 0
  fi
  local pages=$(( (memory_mb + 1) / 2 + 64 ))  # 2MB pages + margin
  echo "[*] No hugepages found. Allocating ${pages} x 2MB hugepages (~$((pages * 2))MB)..."
  sudo sysctl -w "vm.nr_hugepages=${pages}" >/dev/null
  local free_pages
  free_pages="$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)"
  if [ "$free_pages" -lt "$pages" ]; then
    echo "[!] Warning: requested ${pages} hugepages but only got ${free_pages}."
  fi
  echo "[OK] Hugepages allocated: ${free_pages}"
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
rules = [
    {'protocol': 'tcp', 'source_ip_address': '10.17.50.1',
     'destination_ip_address': '10.17.50.12', 'destination_port': 80, 'label': 'HTTP'},
    {'protocol': 'tcp', 'source_ip_address': '10.17.50.2',
     'destination_ip_address': '10.17.50.12', 'destination_port': 443, 'label': 'HTTPS'},
    {'protocol': 'udp', 'source_ip_address': '10.17.50.3',
     'destination_ip_address': '10.17.50.53', 'destination_port': 53, 'label': 'DNS'},
    {'protocol': 'udp', 'source_ip_address': '10.17.50.4',
     'destination_ip_address': '10.17.50.215', 'destination_port': 2152, 'label': 'GTP_U'},
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
cfg['spi']['rules'] = rules
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

cmd_bench_pcap() {
  local count="${1:-$DEFAULT_BENCH_COUNT}"
  local workers="${2:-$DEFAULT_WORKERS}"
  local match_percent="${3:-$DEFAULT_MATCH_PERCENT}"
  local shard_dir="$SCRIPT_DIR/bench_pcap_shards"

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
rules = [
    {'protocol': 'tcp', 'source_ip_address': '10.17.50.1',
     'destination_ip_address': '10.17.50.12', 'destination_port': 80, 'label': 'HTTP'},
    {'protocol': 'tcp', 'source_ip_address': '10.17.50.2',
     'destination_ip_address': '10.17.50.12', 'destination_port': 443, 'label': 'HTTPS'},
    {'protocol': 'udp', 'source_ip_address': '10.17.50.3',
     'destination_ip_address': '10.17.50.53', 'destination_port': 53, 'label': 'DNS'},
    {'protocol': 'udp', 'source_ip_address': '10.17.50.4',
     'destination_ip_address': '10.17.50.215', 'destination_port': 2152, 'label': 'GTP_U'},
]
with open(config_file) as f:
    cfg = yaml.safe_load(f)
cache_size = cfg['mempool'].get('cache_size', 256)
extra = cache_size * (workers + 2) + workers * 512
# infinite_rx pre-allocates 1 mbuf per pcap packet PER QUEUE during setup
# Total = sum of all packets across all shards = count
mbuf_needed = count + extra
memory_mb = int(mbuf_needed * 2300 / (1024 * 1024) * 1.1 + 256)
rx_streams = [f'rx_pcap={os.path.join(shard_dir, f"bench_q{i}.pcap")}' for i in range(workers)]
cfg['eal']['virtual_devices'] = ['net_pcap0,' + ','.join(rx_streams) + ',infinite_rx=1']
cfg['eal']['cpu_core_list'] = f'0-{workers}'
cfg['eal']['memory_size'] = str(memory_mb)
cfg['eal']['legacy_memory'] = True
cfg['eal']['disable_hugepages'] = False
cfg['eal']['disable_pci'] = True
cfg['eal'].pop('numa_limit', None)
cfg['l3_forward']['enabled'] = False
cfg['mempool']['memory_buffer_size'] = 2176
cfg['mempool']['memory_buffer_count'] = mbuf_needed
cfg['port']['port_bitmask'] = '0x1'
cfg['port']['receive_queues'] = workers
cfg['port']['transmit_queues'] = workers
cfg['spi']['worker_count'] = workers
cfg['spi']['packet_distribution'] = 'auto'
cfg['spi']['dispatch_queue_size'] = 16384
cfg['spi']['drop_unmatched'] = True
cfg['l2_forward']['burst_size'] = 64
cfg['spi']['rules'] = rules
with open(config_file, 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)
matched = count * match_percent // 100
print(f'PCAP benchmark: workers={workers}, match_percent={match_percent}, expected_match~={matched}')
print(f'Config: {count} pkts, {mbuf_needed} mbufs ({extra} extra), {memory_mb}MB')
# Write memory_mb to a temp file for the shell script to read
with open(config_file + '.mem', 'w') as mf:
    mf.write(str(memory_mb))
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
  bench-pcap) shift; cmd_bench_pcap "$@" ;;
  bench-afpacket) shift; cmd_bench_afpacket "$@" ;;
  teardown) cmd_teardown ;;
  *)        usage ;;
esac
