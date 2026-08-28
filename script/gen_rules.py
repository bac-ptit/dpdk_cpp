#!/usr/bin/env python3
"""
Multi-Core Parallel Rule Binary Generator for DPDK FastSPI / DPI Pipeline.
Tạo bộ quy tắc SPI (80 - 100 Filter Groups) và DPI phân cấp theo độ ưu tiên Precedence,
sau đó biên dịch thành định dạng nhị phân siêu tốc Glaze BEVE Stream (rules.beve).

Quy tắc thiết kế:
  1. Số nhóm SPI: 100 filter groups (Precedence tăng dần: 10, 20, 30, ... 1000).
  2. Số lượng SPI rule >> DPI rule (3,000+ SPI rules so với ~30 DPI rules).
  3. Tất cả các rule DPI đều có nhóm SPI tương ứng liên kết (qua dpi_filter_group).
  4. Phân bổ hành động: ~80% groups Forward và ~20% groups Drop (Blacklist/Threat).
"""

import argparse
import multiprocessing
import os
import subprocess
import sys
import time

# Danh sách các dịch vụ DPI (Layer 7) phổ biến
DPI_SERVICES = [
    ("fg_l7_viettel", "*.viettel.vn", "viettel_service", 1),
    ("fg_l7_facebook", "*.facebook.com", "facebook_app", 10),
    ("fg_l7_fbcdn", "*.fbcdn.net", "facebook_cdn", 12),
    ("fg_l7_youtube", "*.youtube.com", "youtube_video", 20),
    ("fg_l7_googlevideo", "*.googlevideo.com", "youtube_stream", 22),
    ("fg_l7_google", "*.google.com", "google_search", 30),
    ("fg_l7_dns_google", "dns.google", "dns_over_tls", 5),
    ("fg_l7_cloudflare", "cloudflare-dns.com", "cloudflare_dns", 6),
    ("fg_l7_tiktok", "*.tiktok.com", "tiktok_media", 40),
    ("fg_l7_netflix", "*.netflix.com", "netflix_ott", 50),
    ("fg_l7_nflxvideo", "*.nflxvideo.net", "netflix_cdn", 52),
    ("fg_l7_telegram", "*.telegram.org", "telegram_im", 60),
    ("fg_l7_zalo", "*.zalo.me", "zalo_chat", 70),
    ("fg_l7_zalocdn", "*.zadn.vn", "zalo_cdn", 72),
    ("fg_l7_shopee", "*.shopee.vn", "shopee_ecommerce", 80),
    ("fg_l7_banking", "*.vietcombank.com.vn", "banking_service", 90),
    ("fg_l7_vnpay", "*.vnpay.vn", "payment_gateway", 95),
    ("fg_l7_github", "*.github.com", "developer_tools", 100),
    ("fg_l7_spotify", "*.spotify.com", "music_streaming", 110),
    ("fg_l7_microsoft", "*.microsoft.com", "office_cloud", 120),
    ("fg_l7_apple", "*.apple.com", "apple_services", 130),
    ("fg_l7_amazon", "*.amazon.com", "aws_shopping", 140),
    ("fg_l7_speedtest", "*.speedtest.net", "network_test", 150),
    ("fg_l7_chatgpt", "*.openai.com", "ai_service", 160),
    ("fg_l7_catchall", "*", "general_web", 999),
]


def generate_group_chunk(start_g: int, end_g: int, rules_per_group: int) -> str:
    """Sinh chuỗi YAML cho một đoạn các nhóm SPI Filter Groups."""
    lines = []
    for g in range(start_g, end_g):
        # Precedence phân cấp tăng dần: 10, 20, 30, ...
        precedence = (g + 1) * 10
        # 80% Forward, 20% Drop (các nhóm chia hết cho 5 là Drop - Blacklist)
        is_drop_group = (g % 5 == 0)
        action = "drop" if is_drop_group else "forward"

        # Gán liên kết DPI cho các nhóm SPI (mỗi DPI service có nhiều nhóm SPI trỏ về)
        dpi_service = DPI_SERVICES[g % len(DPI_SERVICES)]
        dpi_group_name = dpi_service[0]
        l7_required = (g % 3 != 0)  # Một số group yêu cầu L7, một số link tĩnh

        lines.append(f"  - name: fg_spi_{g:02d}_{'drop' if is_drop_group else 'fwd'}\n")
        lines.append(f"    precedence: {precedence}\n")
        lines.append(f"    action: {action}\n")
        lines.append(f"    l7_required: {'true' if l7_required else 'false'}\n")
        lines.append(f"    dpi_filter_group: {dpi_group_name}\n")
        lines.append("    filters:\n")

        for r in range(rules_per_group):
            ip_b2 = (g // 256) % 256
            ip_b3 = g % 256
            ip_b4 = (r % 254) + 1
            proto = "tcp" if (r % 2 == 0) else "udp"
            # Cổng web (80, 443) hoặc cổng dịch vụ (1024..65535)
            if r % 4 == 0:
                port = 443
            elif r % 4 == 1:
                port = 80
            else:
                port = 1024 + (r * 137 % 60000)

            lines.append(f"    - destination_ip_address: \"10.{ip_b2}.{ip_b3}.{ip_b4}\"\n")
            lines.append(f"      destination_port: {port}\n")
            lines.append(f"      protocol: {proto}\n")
            lines.append(f"      label: rule_{g:02d}_{r:02d}\n")

    return "".join(lines)


def _worker_wrapper(args):
    return generate_group_chunk(*args)


def generate_binary_rules(groups: int = 100, rules_per_group: int = 30, rule_out: str = "rules.beve"):
    num_cpus = os.cpu_count() or 4
    total_spi_rules = groups * rules_per_group
    start_time = time.time()

    print(f"[*] Bắt đầu sinh bộ luật SPI/DPI ({num_cpus} CPU cores):")
    print(f"    - Số nhóm SPI (Filter Groups) : {groups} groups (Precedence 10..{groups*10})")
    print(f"    - Số luật mỗi nhóm SPI        : {rules_per_group} filters/group")
    print(f"    - Tổng số luật SPI            : {total_spi_rules:,} rules")
    print(f"    - Số dịch vụ DPI              : {len(DPI_SERVICES)} application patterns")
    print(f"    - File đầu ra                 : {rule_out}\n")

    temp_rules_yaml = "temp_rules.yaml"

    # Chia việc song song cho các core
    chunk_size = (groups + num_cpus - 1) // num_cpus
    tasks = []
    for c in range(num_cpus):
        sg = c * chunk_size
        eg = min(groups, (c + 1) * chunk_size)
        if sg < eg:
            tasks.append((sg, eg, rules_per_group))

    with multiprocessing.Pool(processes=num_cpus) as pool:
        chunk_results = pool.map(_worker_wrapper, tasks)

    # Ghi file YAML tạm
    with open(temp_rules_yaml, "w") as f:
        f.write("# FastSPI / DPI Hierarchical Rules Definition\n")
        f.write("spi:\n")
        f.write("  filter_groups:\n")
        for chunk in chunk_results:
            f.write(chunk)

        # Ghi mục DPI
        f.write("\ndpi:\n")
        f.write("  enabled: true\n")
        f.write("  filters:\n")
        for group_name, pattern, label, prio in DPI_SERVICES:
            f.write(f"  - filter_group: {group_name}\n")
            f.write(f"    hostname_pattern: '{pattern}'\n")
            f.write(f"    label: {label}\n")
            f.write(f"    priority: {prio}\n")

    # Biên dịch sang file nhị phân BEVE bằng yaml2beve
    converter_bin = "./cmake-build-debug/yaml2beve"
    if os.path.exists(converter_bin):
        res = subprocess.run([converter_bin, temp_rules_yaml, rule_out, "--rules-only"], capture_output=True, text=True)
        if res.returncode == 0:
            elapsed = time.time() - start_time
            print(f"[✓] Đã biên dịch thành công {rule_out} trong {elapsed:.2f} giây!")
        else:
            print(f"[!] Lỗi biên dịch BEVE: {res.stderr}")
            os.rename(temp_rules_yaml, rule_out)
    else:
        print(f"[!] Cảnh báo: không tìm thấy {converter_bin}, lưu dạng YAML: {rule_out}")
        os.rename(temp_rules_yaml, rule_out)

    if os.path.exists(temp_rules_yaml):
        os.remove(temp_rules_yaml)


def main():
    parser = argparse.ArgumentParser(description="Generate 80-100 SPI/DPI Filter Groups and compile to BEVE format")
    parser.add_argument("--groups", type=int, default=100, help="Số nhóm SPI Filter Groups (mặc định 100)")
    parser.add_argument("--rules", type=int, default=30, help="Số luật SPI mỗi nhóm (mặc định 30)")
    parser.add_argument("--out", type=str, default="rules.beve", help="Tên file BEVE đầu ra")
    args = parser.parse_args()

    generate_binary_rules(args.groups, args.rules, args.out)


if __name__ == "__main__":
    main()
