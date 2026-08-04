#!/usr/bin/env python3
"""
Test SPI rules: read from config.yaml, generate matching PCAP traffic,
run app, verify stats match expected results.
"""

import os
import shutil
import struct
import subprocess
import sys
import time
import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
BUILD_DIR = os.environ.get("BUILD_DIR", "cmake-build-debug")

PCAP_MAGIC = 0xa1b2c3d4
LINKTYPE_ETHERNET = 1
PKTS_PER_FILTER = 100


def ip_to_int(s):
    parts = s.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def parse_cidr(cidr):
    ip_str, prefix = cidr.split("/")
    ip = ip_to_int(ip_str)
    mask = (0xFFFFFFFF << (32 - int(prefix))) & 0xFFFFFFFF
    return ip & mask, mask


def build_tcp(src, dst, sp, dp, payload=None):
    if payload is None:
        payload = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n"
    th = struct.pack("!HHIIBBHHH", sp, dp, 0, 0, (5 << 4), 0, 0, 65535, 0)
    tl = len(th) + len(payload)
    ih = struct.pack("!BBHHHBBHII", 0x45, 0, 20 + tl, 0, 0, 64, 6, 0, src, dst)
    cs = sum((ih[i] << 8) | ih[i + 1] for i in range(0, 20, 2))
    cs = (cs >> 16) + (cs & 0xFFFF)
    cs = ~cs & 0xFFFF
    ih = ih[:10] + struct.pack("!H", cs) + ih[12:]
    eth = struct.pack("!6s6sH", b'\x00' * 6, b'\x00' * 6, 0x0800)
    return eth + ih + th + payload


def build_udp(src, dst, sp, dp):
    payload = b"\x00\x01\x00\x00\x00\x01"
    uh = struct.pack("!HHHH", sp, dp, 8 + len(payload), 0)
    ih = struct.pack("!BBHHHBBHII", 0x45, 0, 20 + 8 + len(payload), 0, 0, 64, 17, 0, src, dst)
    cs = sum((ih[i] << 8) | ih[i + 1] for i in range(0, 20, 2))
    cs = (cs >> 16) + (cs & 0xFFFF)
    cs = ~cs & 0xFFFF
    ih = ih[:10] + struct.pack("!H", cs) + ih[12:]
    eth = struct.pack("!6s6sH", b'\x00' * 6, b'\x00' * 6, 0x0800)
    return eth + ih + uh + payload


def write_pcap(packets, path):
    ts = int(time.time())
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        for p in packets:
            f.write(struct.pack("<IIII", ts, 0, len(p), len(p)))
            f.write(p)


def generate_packets(cfg):
    pkts = []
    details = []
    src = ip_to_int("192.168.1.1")
    for g in cfg.get("spi", {}).get("filter_groups", []):
        for flt in g.get("filters", []):
            proto = flt.get("protocol", "tcp")
            dp = flt.get("destination_port", 80)
            dip = flt.get("destination_ip_address", "10.0.0.1")
            if "/" in dip:
                net, _ = parse_cidr(dip)
                dst = net + 1
            else:
                dst = ip_to_int(dip)
            for i in range(PKTS_PER_FILTER):
                if proto == "tcp":
                    pkts.append(build_tcp(src, dst, 12345 + i, dp))
                else:
                    pkts.append(build_udp(src, dst, 12345 + i, dp))
            details.append({"group": g["name"], "label": flt.get("label", ""),
                           "action": g.get("action", "forward"), "count": PKTS_PER_FILTER})
    return pkts, details


def build_tls_hello(hostname):
    """Build TLS ClientHello with SNI extension."""
    sni = hostname.encode("ascii")
    ch = struct.pack("!H", 0x0303)  # TLS 1.2
    ch += os.urandom(32)  # random
    ch += b"\x00"  # session ID len
    ch += struct.pack("!HH", 2, 0x0000)  # 1 cipher suite
    ch += b"\x01\x00"  # compression
    sni_ext = struct.pack("!HH", 0x0000, len(sni) + 5)
    sni_ext += struct.pack("!HBH", len(sni) + 3, 0, len(sni))
    sni_ext += sni
    ch += struct.pack("!H", len(sni_ext)) + sni_ext
    handshake = b"\x01" + struct.pack("!I", len(ch))[1:] + ch
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record


def generate_dpi_packets(cfg):
    """Generate TLS ClientHello packets matching DPI hostname filters."""
    pkts = []
    details = []
    src = ip_to_int("192.168.1.1")
    dst = ip_to_int("10.0.0.1")
    for flt in cfg.get("dpi", {}).get("filters", []):
        pattern = flt.get("hostname_pattern", "")
        if pattern == "*" or not pattern:
            continue
        hostname = ("www" + pattern[1:]) if pattern.startswith("*.") else pattern
        for i in range(PKTS_PER_FILTER):
            pkts.append(build_tcp(src, dst, 12345 + i, 443, build_tls_hello(hostname)))
        details.append({"hostname": hostname, "group": flt.get("filter_group", ""),
                       "label": flt.get("label", ""), "count": PKTS_PER_FILTER})
    return pkts, details


def parse_stats(output):
    stats = {}
    for line in output.split("\n"):
        if "received=" in line:
            for pair in line.split():
                if "=" in pair and pair[0].isalpha():
                    k, v = pair.split("=", 1)
                    try: stats[k] = int(v)
                    except ValueError: pass
    return stats


def run_test(name, packets, cfg, pcap_path, tx_pcap):
    """Write config, run app, return (stats_dict, output_str)."""
    build_cfg = os.path.join(PROJECT_DIR, BUILD_DIR, "config.yaml")
    cfg["eal"]["virtual_devices"] = [f"net_pcap0,rx_pcap={pcap_path},tx_pcap={tx_pcap},infinite_rx=0"]
    cfg["eal"]["cpu_core_list"] = "0-1"
    cfg["eal"]["memory_size"] = "256"
    cfg["l3_forward"]["enabled"] = False
    cfg["mempool"]["memory_buffer_size"] = 2176
    cfg["mempool"]["memory_buffer_count"] = 8192
    cfg["port"]["port_bitmask"] = "0x1"
    cfg["port"]["receive_queues"] = 1
    cfg["port"]["transmit_queues"] = 1
    cfg["spi"]["worker_count"] = 1
    cfg["spi"]["packet_distribution"] = "auto"
    cfg["spi"]["drop_unmatched"] = True
    with open(build_cfg, "w") as f:
        yaml.dump(cfg, f, default_flow_style=False)

    subprocess.run(["sudo", "-S", "rm", "-rf", "/var/run/dpdk/"],
                   input=b"0000\n", capture_output=True, timeout=5)

    binary = os.path.join(PROJECT_DIR, BUILD_DIR, "FastAPI")
    print(f"\n[*] Running {name} ({len(packets)} packets)...")
    proc = subprocess.Popen(["sudo", "-S", binary],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, cwd=PROJECT_DIR)
    proc.stdin.write(b"0000\n")
    proc.stdin.flush()
    time.sleep(3)
    proc.send_signal(2)
    stdout, stderr = proc.communicate(timeout=10)
    output = stdout.decode(errors="replace") + stderr.decode(errors="replace")
    shutil.copy2(os.path.join(PROJECT_DIR, "config.yaml"), build_cfg)
    return parse_stats(output), output




def main():
    with open(os.path.join(PROJECT_DIR, "config.yaml")) as f:
        cfg = yaml.safe_load(f)

    total_ok, total_fail = 0, 0

    # === SPI TEST (forward rules) ===
    spi_pkts, spi_details = generate_packets(cfg)
    spi_expected = sum(d["count"] for d in spi_details if d["action"] == "forward")
    print(f"=== SPI TEST: {len(spi_details)} filters, {len(spi_pkts)} packets ===")
    for d in spi_details:
        print(f"  [{d['group']}] {d['label']} → {d['action']} ×{d['count']}")

    pcap = os.path.join(PROJECT_DIR, BUILD_DIR, "test_spi.pcap")
    tx = os.path.join(PROJECT_DIR, BUILD_DIR, "test_spi_tx.pcap")
    write_pcap(spi_pkts, pcap)
    stats, _ = run_test("SPI", spi_pkts, dict(cfg), pcap, tx)
    rcv, mtch, unkn = stats.get("received", 0), stats.get("matched", 0), stats.get("unknown", 0)
    print(f"  EXPECTED: received={len(spi_pkts)} matched≥{spi_expected} unknown=0")
    print(f"  ACTUAL:   received={rcv} matched={mtch} unknown={unkn}")
    if rcv == len(spi_pkts): print(f"  ✅ received"); total_ok += 1
    else: print(f"  ❌ received={rcv}"); total_fail += 1
    if mtch >= spi_expected: print(f"  ✅ matched"); total_ok += 1
    else: print(f"  ❌ matched={mtch}"); total_fail += 1
    if unkn == 0: print(f"  ✅ unknown=0"); total_ok += 1
    else: print(f"  ❌ unknown={unkn}"); total_fail += 1
    for f in [pcap, tx]:
        if os.path.exists(f): os.unlink(f)

    # === SPI DROP TEST ===
    drop_cfg = dict(cfg)
    drop_cfg["spi"] = dict(cfg["spi"])
    drop_cfg["spi"]["filter_groups"] = list(cfg["spi"].get("filter_groups") or []) + [{
        "name": "fg_l34_udp_sdf1006", "precedence": 106, "action": "drop",
        "filters": [{"protocol": "udp", "destination_port": 9999, "label": "udp_drop"}],
    }]
    drop_pkts = [build_udp(ip_to_int("192.168.1.1"), ip_to_int("10.0.0.1"), 12345 + i, 9999) for i in range(100)]
    print(f"\n=== SPI DROP TEST: 100 UDP packets → expect dropped ===")
    pcap = os.path.join(PROJECT_DIR, BUILD_DIR, "test_drop.pcap")
    tx = os.path.join(PROJECT_DIR, BUILD_DIR, "test_drop_tx.pcap")
    write_pcap(drop_pkts, pcap)
    stats, _ = run_test("DROP", drop_pkts, drop_cfg, pcap, tx)
    rcv, dropped = stats.get("received", 0), stats.get("dropped_by_rule", 0)
    print(f"  EXPECTED: received=100 dropped_by_rule=100")
    print(f"  ACTUAL:   received={rcv} dropped_by_rule={dropped}")
    if rcv == 100 and dropped == 100: print(f"  ✅ PASS"); total_ok += 3
    else: print(f"  ❌ FAIL"); total_fail += 3
    for f in [pcap, tx]:
        if os.path.exists(f): os.unlink(f)

    # === DPI TEST ===
    dpi_pkts, dpi_details = generate_dpi_packets(cfg)
    if dpi_pkts:
        print(f"\n=== DPI TEST: {len(dpi_details)} hostnames, {len(dpi_pkts)} packets ===")
        for d in dpi_details:
            print(f"  [{d['group']}] {d['hostname']} ×{d['count']}")

        pcap = os.path.join(PROJECT_DIR, BUILD_DIR, "test_dpi.pcap")
        tx = os.path.join(PROJECT_DIR, BUILD_DIR, "test_dpi_tx.pcap")
        write_pcap(dpi_pkts, pcap)
        stats, _ = run_test("DPI", dpi_pkts, dict(cfg), pcap, tx)
        rcv, mtch, unkn = stats.get("received", 0), stats.get("matched", 0), stats.get("unknown", 0)
        print(f"  EXPECTED: received={len(dpi_pkts)} matched≥{len(dpi_pkts)} unknown=0")
        print(f"  ACTUAL:   received={rcv} matched={mtch} unknown={unkn}")
        if rcv == len(dpi_pkts): print(f"  ✅ received"); total_ok += 1
        else: print(f"  ❌ received={rcv}"); total_fail += 1
        if mtch >= len(dpi_pkts): print(f"  ✅ matched"); total_ok += 1
        else: print(f"  ❌ matched={mtch}"); total_fail += 1
        if unkn == 0: print(f"  ✅ unknown=0"); total_ok += 1
        else: print(f"  ❌ unknown={unkn}"); total_fail += 1
        for f in [pcap, tx]:
            if os.path.exists(f): os.unlink(f)

    # === SUMMARY ===
    print(f"\n{'='*50}")
    print(f"  TOTAL: {total_ok} passed, {total_fail} failed")
    print(f"{'='*50}")
    sys.exit(0 if total_fail == 0 else 1)


if __name__ == "__main__":
    main()
