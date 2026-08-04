#!/usr/bin/env python3
"""
Multi-Core Parallel Rule Binary Generator for DPDK SPI/DPI Pipeline.
Utilizes maximum system CPU cores (nproc) to generate 8.38+ Million rules
in parallel, outputting high-speed Glaze BEVE binary stream files (.beve).

Usage:
  python3 script/gen_rules.py --groups 100 --rules 50 --out rules.beve
  python3 script/gen_rules.py --groups 4096 --rules 2048 --out rules_8m.beve
"""

import argparse
import multiprocessing
import os
import subprocess
import time

def generate_group_chunk(start_g: int, end_g: int, rules_per_group: int) -> str:
    """Generate YAML snippet for a chunk of filter groups."""
    lines = []
    for g in range(start_g, end_g):
        precedence = 100 + (g % 500)
        action = "drop" if (g % 5 == 0) else "forward"
        lines.append(f"  - name: fg_group_{g}\n")
        lines.append(f"    precedence: {precedence}\n")
        lines.append(f"    action: {action}\n")
        lines.append("    filters:\n")

        for r in range(rules_per_group):
            ip_octet2 = (g // 256) % 256
            ip_octet3 = g % 256
            ip_octet4 = (r % 254) + 1
            proto = "tcp" if (r % 2 == 0) else "udp"
            port = 1024 + (r % 60000)

            lines.append(f"    - destination_ip_address: \"10.{ip_octet2}.{ip_octet3}.{ip_octet4}\"\n")
            lines.append(f"      destination_port: {port}\n")
            lines.append(f"      protocol: {proto}\n")
            lines.append(f"      label: rule_{g}_{r}\n")

    return "".join(lines)

def _worker_wrapper(args):
    return generate_group_chunk(*args)

def generate_binary_rules_parallel(groups: int, rules: int, rule_out: str):
    num_cpus = os.cpu_count() or 4
    total_rules = groups * rules
    start_time = time.time()
    print(f"[gen_rules] Parallel generator using {num_cpus} CPU cores...")
    print(f"[gen_rules] Target: {groups:,} groups x {rules:,} rules = {total_rules:,} total rules -> {rule_out}")

    temp_rules_yaml = "temp_rules.yaml"

    # Split work evenly across all CPU cores
    chunk_size = (groups + num_cpus - 1) // num_cpus
    tasks = []
    for c in range(num_cpus):
        sg = c * chunk_size
        eg = min(groups, (c + 1) * chunk_size)
        if sg < eg:
            tasks.append((sg, eg, rules))

    with multiprocessing.Pool(processes=num_cpus) as pool:
        chunk_results = pool.map(_worker_wrapper, tasks)

    # Write combined YAML header and chunks
    with open(temp_rules_yaml, "w") as f:
        f.write("# Temporary rules dump for conversion to Binary BEVE Stream\n")
        f.write("spi:\n")
        f.write("  filter_groups:\n")

        # Special Rule Group 1: IP Fragmented Traffic
        f.write("  - name: fg_fragmented_traffic\n")
        f.write("    precedence: 10\n")
        f.write("    action: forward\n")
        f.write("    filters:\n")
        f.write("    - destination_ip_address: \"192.168.100.0/24\"\n")
        f.write("      protocol: tcp\n")
        f.write("      label: ip_frag_tcp_subnet\n")
        f.write("    - destination_ip_address: \"192.168.200.0/24\"\n")
        f.write("      protocol: udp\n")
        f.write("      label: ip_frag_udp_subnet\n\n")

        # Special Rule Group 2: TCP Segmented HTTP & TLS Traffic
        f.write("  - name: fg_tcp_segmented_dpi\n")
        f.write("    precedence: 20\n")
        f.write("    action: forward\n")
        f.write("    l7_required: true\n")
        f.write("    dpi_filter_group: fg_l7_viettel\n")
        f.write("    filters:\n")
        f.write("    - destination_port: 80\n")
        f.write("      protocol: tcp\n")
        f.write("      label: tcp_seg_http\n")
        f.write("    - destination_port: 443\n")
        f.write("      protocol: tcp\n")
        f.write("      label: tcp_seg_tls\n\n")

        for chunk in chunk_results:
            f.write(chunk)

        # DPI Section
        f.write("\ndpi:\n")
        f.write("  enabled: true\n")
        f.write("  filters:\n")
        f.write("  - filter_group: fg_l7_viettel\n")
        f.write("    hostname_pattern: '*.viettel.vn'\n")
        f.write("    label: viettel_domain\n")
        f.write("    priority: 1\n")
        f.write("  - filter_group: fg_l7_facebook\n")
        f.write("    hostname_pattern: '*.facebook.com'\n")
        f.write("    label: facebook_domain\n")
        f.write("    priority: 10\n")
        f.write("  - filter_group: fg_l7_google\n")
        f.write("    hostname_pattern: '*.google.com'\n")
        f.write("    label: google_domain\n")
        f.write("    priority: 20\n")
        f.write("  - filter_group: fg_l7_catchall\n")
        f.write("    hostname_pattern: '*'\n")
        f.write("    label: catchall_domain\n")
        f.write("    priority: 999\n")

    # Step 2: Convert to binary BEVE stream using yaml2beve
    converter_bin = "./cmake-build-debug/yaml2beve"
    if os.path.exists(converter_bin):
        res = subprocess.run([converter_bin, temp_rules_yaml, rule_out, "--rules-only"], capture_output=True, text=True)
        if res.returncode == 0:
            elapsed = time.time() - start_time
            print(f"[gen_rules] Successfully generated {rule_out} in {elapsed:.2f} seconds!")
        else:
            print(f"[gen_rules] Error compiling BEVE: {res.stderr}")
            os.rename(temp_rules_yaml, rule_out)
    else:
        print(f"[gen_rules] Warning: yaml2beve binary not found, keeping {temp_rules_yaml}")
        os.rename(temp_rules_yaml, rule_out)

    if os.path.exists(temp_rules_yaml):
        os.remove(temp_rules_yaml)

def main():
    parser = argparse.ArgumentParser(description="Multi-core parallel DPDK SPI/DPI binary rule stream generator")
    parser.add_argument("--groups", type=int, default=100, help="Number of filter groups")
    parser.add_argument("--rules", type=int, default=50, help="Number of rules per filter group")
    parser.add_argument("--out", type=str, default="rules.beve", help="Output binary rule stream file (.beve)")
    args = parser.parse_args()

    generate_binary_rules_parallel(args.groups, args.rules, args.out)

if __name__ == "__main__":
    main()
