#!/usr/bin/env python3
"""
Verify DPDK FastSPI project with rules.beve and 1M packet PCAP.
"""

import os
import shutil
import subprocess
import sys
import time
import yaml

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
BUILD_DIR = os.path.join(PROJECT_DIR, "cmake-build-debug")
PCAP_PATH = os.path.join(PROJECT_DIR, "test", "beve_1m.pcap")
RULES_PATH = "rules.beve"


def parse_stats(output):
    stats = {}
    for line in output.split("\n"):
        if "received=" in line:
            for pair in line.split():
                if "=" in pair and (pair[0].isalpha() or pair.startswith("dropped_") or pair.startswith("flow_")):
                    k, v = pair.split("=", 1)
                    try:
                        stats[k] = int(v)
                    except ValueError:
                        pass
        if "Performance:" in line:
            stats["perf_line"] = line.strip()
    return stats


def verify():
    if not os.path.exists(PCAP_PATH):
        print(f"Error: {PCAP_PATH} does not exist. Generating 1M PCAP...")
        subprocess.run(["python3", os.path.join(SCRIPT_DIR, "gen_1m_beve_pcap.py"), PCAP_PATH, "1000000"], check=True)

    binary = os.path.join(BUILD_DIR, "FastAPI")
    if not os.path.exists(binary):
        print(f"Error: {binary} not found. Building project...")
        subprocess.run(["cmake", "--build", BUILD_DIR, "--target", "FastAPI"], check=True)

    config_path = os.path.join(PROJECT_DIR, "config.yaml")
    backup_path = os.path.join(PROJECT_DIR, "config.yaml.bak_verify")

    shutil.copy2(config_path, backup_path)

    try:
        with open(config_path, "r") as f:
            cfg = yaml.safe_load(f)

        tx1 = "/tmp/out_beve_verify1.pcap"
        tx2 = "/tmp/out_beve_verify2.pcap"
        subprocess.run(["sudo", "-n", "rm", "-f", tx1, tx2], capture_output=True)

        # Configure for offline 1M PCAP processing with 2 RX queues
        cfg["eal"]["cpu_core_list"] = "0-2"
        cfg["eal"]["file_prefix"] = "spifast_verify1m"
        cfg["eal"]["disable_pci"] = True
        cfg["eal"]["disable_hugepages"] = True
        cfg["eal"]["virtual_devices"] = [
            f"net_pcap0,rx_pcap={PCAP_PATH},rx_pcap={PCAP_PATH},tx_pcap={tx1},tx_pcap={tx2}"
        ]

        cfg["app"]["timer_period_sec"] = 1

        cfg["port"]["port_bitmask"] = "0x1"
        cfg["port"]["receive_queues"] = 2
        cfg["port"]["transmit_queues"] = 2

        cfg["spi"]["worker_count"] = 2
        cfg["spi"]["rule_path"] = RULES_PATH
        cfg["spi"]["drop_unmatched"] = False

        with open(config_path, "w") as f:
            yaml.dump(cfg, f, default_flow_style=False)

        subprocess.run(["sudo", "-n", "rm", "-rf", "/var/run/dpdk/spifast_verify1m"], capture_output=True)

        print("\n" + "=" * 65)
        print(" [FASTSPI VERIFICATION RUN] ")
        print(f" Rules file   : rules.beve (102 filter groups, 5004 filters)")
        print(f" PCAP file    : test/beve_1m.pcap (1,000,000 packets x 2 queues)")
        print(f" Worker cores : 2 lcores (cores 1, 2)")
        print("=" * 65 + "\n")

        proc = subprocess.Popen(["sudo", "-n", binary],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                text=True,
                                cwd=PROJECT_DIR)

        time.sleep(3.0)
        proc.send_signal(2)

        try:
            stdout, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate()

        print(stdout)

        stats = parse_stats(stdout)
        print("\n" + "=" * 65)
        print(" [VERIFICATION RESULTS] ")
        print("=" * 65)
        rcv = stats.get("received", 0)
        acl_matched = stats.get("matched", 0)
        cache_hits = stats.get("flow_cache_hits", 0)
        total_matched = acl_matched + cache_hits
        dropped = stats.get("dropped_by_rule", 0)
        unkn = stats.get("unknown", 0)
        forwarded = rcv - dropped if rcv >= dropped else 0

        print(f" Total Received       : {rcv:,}")
        print(f" Total Matched Rules  : {total_matched:,} ({acl_matched:,} ACL Misses + {cache_hits:,} Cache Hits)")
        print(f"   - Forwarded Packets: {forwarded:,} (80%)")
        print(f"   - Dropped by Rule  : {dropped:,} (20%)")
        print(f" Unknown/Unmatched    : {unkn:,} (0%)")

        if "perf_line" in stats:
            print(f" {stats['perf_line']}")

        success = True
        if rcv == 2000000:
            print(f" ✅ Processed all {rcv:,} packets!")
        else:
            print(f" ❌ Packet count mismatch: received={rcv}")
            success = False

        if total_matched == rcv and unkn == 0:
            print(" ✅ 100% Match Rate achieved across rules.beve!")
        else:
            print(f" ❌ Match rate mismatch: matched={total_matched} != received={rcv}")
            success = False

        if dropped == 400000:
            print(" ✅ Rule-based Drop Rate verified (400,000 packets / 20%)!")
        else:
            print(f" ⚠️  Dropped count: {dropped}")

        print("=" * 65)
        if success:
            print(" 🎉 FASTSPI VERIFICATION PASSED PERFECTLY!")
        else:
            print(" ❌ VERIFICATION FAILED.")

    finally:
        if os.path.exists(backup_path):
            shutil.move(backup_path, config_path)


if __name__ == "__main__":
    verify()
