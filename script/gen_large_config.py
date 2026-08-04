#!/usr/bin/env python3
"""
Generator script for DPDK SPI/DPI large-scale rule configuration.
Generates YAML configuration files with configurable number of filter groups
and rules per filter group to benchmark reload times, memory usage, and match throughput.

Usage:
  python3 script/gen_large_config.py --groups 100 --rules 100 --out config_large.yaml
  python3 script/gen_large_config.py --groups 4096 --rules 2048 --out config_8m.yaml
"""

import argparse
import sys

def main():
    parser = argparse.ArgumentParser(description="Generate large-scale DPDK SPI/DPI YAML config")
    parser.add_argument("--groups", type=int, default=100, help="Number of filter groups (default: 100)")
    parser.add_argument("--rules", type=int, default=50, help="Number of rules per filter group (default: 50)")
    parser.add_argument("--out", type=str, default="config_large.yaml", help="Output file path")
    args = parser.parse_args()

    total_rules = args.groups * args.rules
    print(f"[gen_large_config] Generating {args.groups} groups x {args.rules} rules = {total_rules:,} total rules...")

    with open(args.out, "w") as f:
        # Header & basic settings
        f.write("# ==============================================================================\n")
        f.write(f"# LARGE SCALE CONFIGURATION ({args.groups} groups x {args.rules} rules = {total_rules:,} rules)\n")
        f.write("# ==============================================================================\n\n")

        f.write("eal:\n")
        f.write("  cpu_core_list: 0-15\n")
        f.write("  file_prefix: spifast\n")
        f.write("  legacy_memory: false\n")
        f.write("  log_level: '8'\n")
        f.write("  memory_channels: 2\n")
        f.write("  memory_size: '5000'\n")
        f.write("  disable_hugepages: false\n")
        f.write("  disable_pci: true\n")
        f.write("  process_type: primary\n\n")

        f.write("app:\n")
        f.write("  burst_size: 512\n")
        f.write("  mac_updating: false\n")
        f.write("  timer_period_sec: 2\n\n")

        f.write("mempool:\n")
        f.write("  cache_size: 512\n")
        f.write("  memory_buffer_count: 2000000\n")
        f.write("  memory_buffer_size: 2176\n")
        f.write("  name: mbuf_pool\n\n")

        f.write("port:\n")
        f.write("  link_check_interval_ms: 100\n")
        f.write("  link_check_max_count: 90\n")
        f.write("  link_speed: 0\n")
        f.write("  port_bitmask: '0x1'\n")
        f.write("  promiscuous: true\n")
        f.write("  receive_descriptors: 1024\n")
        f.write("  receive_queues: 15\n")
        f.write("  transmit_descriptors: 2048\n")
        f.write("  transmit_queues: 15\n\n")

        f.write("spi:\n")
        f.write("  worker_count: 15\n")
        f.write("  packet_distribution: queue\n")
        f.write("  dispatch_queue_size: 8192\n")
        f.write(f"  max_concurrent_flows: 1000000\n")
        f.write("  flow_ttl_sec: 4\n")
        f.write("  flow_overflow_action: drop\n")
        f.write("  drop_unmatched: true\n")
        f.write("  filter_groups:\n")

        # Generate filter groups and rules
        for g in range(args.groups):
            precedence = 100 + (g % 500)
            action = "drop" if (g % 5 == 0) else "forward"
            f.write(f"  - name: fg_group_{g}\n")
            f.write(f"    precedence: {precedence}\n")
            f.write(f"    action: {action}\n")
            f.write("    filters:\n")

            for r in range(args.rules):
                # Generate pseudo-unique IP networks and ports
                ip_octet2 = (g // 256) % 256
                ip_octet3 = g % 256
                ip_octet4 = (r % 254) + 1
                proto = "tcp" if (r % 2 == 0) else "udp"
                port = 1024 + (r % 60000)

                f.write(f"    - destination_ip_address: \"10.{ip_octet2}.{ip_octet3}.{ip_octet4}\"\n")
                f.write(f"      destination_port: {port}\n")
                f.write(f"      protocol: {proto}\n")
                f.write(f"      label: rule_{g}_{r}\n")

    print(f"[gen_large_config] Successfully wrote {args.out}")

if __name__ == "__main__":
    main()
