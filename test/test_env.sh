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

usage() {
  echo "Usage: $0 {setup|run|send|pcap|bench|teardown}"
  exit 1
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
  if [ ! -f "$APP_BINARY" ]; then
    echo "[!] Binary not found. Run install.sh first."
    exit 1
  fi
  sudo setcap cap_net_raw,cap_ipc_lock,cap_net_admin+ep "$APP_BINARY"
  sudo "$APP_BINARY"
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
  cp "$config_file" "$config_file.bak" 2>/dev/null || true

  python3 -c "
import yaml
with open('$config_file') as f:
    cfg = yaml.safe_load(f)
cfg['eal']['virtual_devices'] = ['net_pcap0,rx_pcap=${pcap_file},tx_pcap=${tx_pcap_file},infinite_rx=0']
cfg['eal']['cpu_core_list'] = '0-1'
cfg['mempool']['memory_buffer_size'] = 2176
cfg['port']['receive_queues'] = 1
cfg['port']['transmit_queues'] = 1
cfg['spi']['worker_count'] = 1
with open('$config_file', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)
print('Config updated for PCAP PMD: cpu_core_list=0-1, receive_queues=1, transmit_queues=1, worker_count=1')
"

  echo "[*] Copying config to build dir..."
  cp "$config_file" "$BUILD_DIR/config.yaml"

  echo "[*] Running app..."
  sudo setcap cap_net_raw,cap_ipc_lock,cap_net_admin+ep "$APP_BINARY"
  sudo "$APP_BINARY"

  echo "[*] Restoring original config..."
  cp "$config_file.bak" "$config_file" 2>/dev/null || true
  cp "$config_file" "$BUILD_DIR/config.yaml"
  rm -f "$config_file.bak"
}

cmd_bench() {
  local count="${1:-100000}"
  local pcap_file="$SCRIPT_DIR/bench.pcap"

  echo "[*] Generating benchmark pcap with $count packets..."
  python3 "$SCRIPT_DIR/gen_test_pcap.py" "$pcap_file" --count "$count"

  echo "[*] Creating PCAP config with infinite loop..."
  local config_file="$PROJECT_DIR/config.yaml"
  cp "$config_file" "$config_file.bak" 2>/dev/null || true

  python3 -c "
import yaml
count = $count
with open('$config_file') as f:
    cfg = yaml.safe_load(f)
cache_size = cfg['mempool'].get('cache_size', 256)
# PCAP PMD pre-loads ALL pcap packets into an internal ring (count mbufs).
# Extra mbufs needed for mempool cache + RX/TX bursts + margin.
extra = cache_size * 2 + 512
mbuf_needed = count + extra
memory_mb = int(mbuf_needed * 2300 / (1024 * 1024) * 1.5 + 512)
cfg['eal']['virtual_devices'] = ['net_pcap0,rx_pcap=${pcap_file},infinite_rx=1']
cfg['eal']['cpu_core_list'] = '0-1'
cfg['eal']['memory_size'] = str(memory_mb)
cfg['eal']['legacy_memory'] = True
cfg['eal'].pop('numa_limit', None)
cfg['mempool']['memory_buffer_size'] = 2176
cfg['mempool']['memory_buffer_count'] = mbuf_needed
cfg['port']['receive_queues'] = 1
cfg['port']['transmit_queues'] = 1
cfg['spi']['worker_count'] = 1
with open('$config_file', 'w') as f:
    yaml.dump(cfg, f, default_flow_style=False)
print(f'Config: {count} pkts, {mbuf_needed} mbufs ({extra} extra), {memory_mb}MB')
print('PCAP PMD benchmark: forced cpu_core_list=0-1, receive_queues=1, transmit_queues=1, worker_count=1')
"

  cp "$config_file" "$BUILD_DIR/config.yaml"

  echo "[*] Running app... (Ctrl+C to stop, check stats for throughput)"
  sudo setcap cap_net_raw,cap_ipc_lock,cap_net_admin+ep "$APP_BINARY"
  sudo "$APP_BINARY"

  echo "[*] Restoring original config..."
  cp "$config_file.bak" "$config_file" 2>/dev/null || true
  cp "$config_file" "$BUILD_DIR/config.yaml"
  rm -f "$config_file.bak"
  echo "[OK] Benchmark done."
}

case "${1:-}" in
  setup)    cmd_setup ;;
  run)      cmd_run ;;
  send)     shift; cmd_send "$@" ;;
  pcap)     shift; cmd_pcap "$@" ;;
  bench)    shift; cmd_bench "$@" ;;
  teardown) cmd_teardown ;;
  *)        usage ;;
esac
