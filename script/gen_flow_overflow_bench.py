#!/usr/bin/env python3
"""
Flow Overflow & Continuous Session Traffic Generator for DPDK SPI/DPI Benchmark.

Mô phỏng lưu lượng truy cập thực tế tương ứng với bộ luật rules.beve (100 SPI groups, 25 DPI patterns).
Tỷ lệ gói tin:
  - 80% Session MATCH: Khớp với 100 SPI groups và DPI rules (Forward hoặc Drop theo rule).
  - 20% Session UNMATCHED: Lưu lượng lạ ngoài danh sách rule để kiểm tra cơ chế Drop gói tin (drop_unmatched).
"""

import argparse
import os
import struct
import sys
import time

PCAP_MAGIC = 0xa1b2c3d4
LINKTYPE_ETHERNET = 1

# 25 dịch vụ DPI tương ứng với rules.beve
DPI_SERVICES = [
    ("fg_l7_viettel", "*.viettel.vn", "tls", 443),
    ("fg_l7_facebook", "*.facebook.com", "tls", 443),
    ("fg_l7_fbcdn", "*.fbcdn.net", "tls", 443),
    ("fg_l7_youtube", "*.youtube.com", "tls", 443),
    ("fg_l7_googlevideo", "*.googlevideo.com", "tls", 443),
    ("fg_l7_google", "*.google.com", "tls", 443),
    ("fg_l7_dns_google", "dns.google", "tls", 443),
    ("fg_l7_cloudflare", "cloudflare-dns.com", "tls", 443),
    ("fg_l7_tiktok", "*.tiktok.com", "tls", 443),
    ("fg_l7_netflix", "*.netflix.com", "tls", 443),
    ("fg_l7_nflxvideo", "*.nflxvideo.net", "tls", 443),
    ("fg_l7_telegram", "*.telegram.org", "tls", 443),
    ("fg_l7_zalo", "*.zalo.me", "tls", 443),
    ("fg_l7_zalocdn", "*.zadn.vn", "tls", 443),
    ("fg_l7_shopee", "*.shopee.vn", "tls", 443),
    ("fg_l7_banking", "*.vietcombank.com.vn", "tls", 443),
    ("fg_l7_vnpay", "*.vnpay.vn", "tls", 443),
    ("fg_l7_github", "*.github.com", "tls", 443),
    ("fg_l7_spotify", "*.spotify.com", "tls", 443),
    ("fg_l7_microsoft", "*.microsoft.com", "tls", 443),
    ("fg_l7_apple", "*.apple.com", "tls", 443),
    ("fg_l7_amazon", "*.amazon.com", "tls", 443),
    ("fg_l7_speedtest", "*.speedtest.net", "http", 80),
    ("fg_l7_chatgpt", "*.openai.com", "tls", 443),
    ("fg_l7_catchall", "general-web.com", "http", 80),
]


def pcap_global_header() -> bytes:
    """Standard 24-byte PCAP header."""
    return struct.pack('<IHHiIII', PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)


def pcap_pkt_hdr(ts_sec: int, ts_usec: int, length: int) -> bytes:
    """16-byte PCAP packet record header."""
    return struct.pack('<IIII', ts_sec, ts_usec, length, length)


def mac_bytes(mac_str: str) -> bytes:
    return bytes.fromhex(mac_str.replace(':', ''))


def ip_bytes(ip_str: str) -> bytes:
    return bytes(map(int, ip_str.split('.')))


def ipv4_header(src_ip: str, dst_ip: str, proto: int, total_length: int, ident: int) -> bytes:
    return struct.pack(
        '!BBHHHBBH4s4s',
        0x45, 0, total_length, ident, 0x4000, 64, proto, 0,
        ip_bytes(src_ip), ip_bytes(dst_ip)
    )


def make_tls_client_hello(server_name: str) -> bytes:
    """Tạo payload TLS 1.2/1.3 ClientHello chuẩn có trường SNI."""
    # Nếu pattern có ký tự wildcard '*.' thì bỏ '*.' lấy domain thật
    clean_domain = server_name[2:] if server_name.startswith("*.") else server_name
    sni_bytes = clean_domain.encode('ascii')
    sni_entry = struct.pack('!BH', 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack('!H', len(sni_entry)) + sni_entry
    sni_ext = struct.pack('!HH', 0x0000, len(sni_list)) + sni_list

    cipher_suites = b'\x00\x02\x13\x01'
    compression = b'\x01\x00'
    random_bytes = b'\x01' * 32
    session_id = b'\x00'

    handshake_body = (
        struct.pack('!H', 0x0303) +
        random_bytes +
        session_id +
        struct.pack('!H', len(cipher_suites)) + cipher_suites +
        compression +
        struct.pack('!H', len(sni_ext)) + sni_ext
    )

    handshake_hdr = struct.pack('!B', 0x01) + struct.pack('!I', len(handshake_body))[1:] + handshake_body
    record_hdr = struct.pack('!BHH', 0x16, 0x0301, len(handshake_hdr))
    return record_hdr + handshake_hdr


def make_http_request(host: str, uri: str = "/") -> bytes:
    """Tạo HTTP GET Request payload có header Host."""
    clean_domain = host[2:] if host.startswith("*.") else host
    req = f"GET {uri} HTTP/1.1\r\nHost: {clean_domain}\r\nUser-Agent: FlowBench/1.0\r\nAccept: */*\r\n\r\n"
    return req.encode('ascii')


def make_tcp_packet(dst_mac: str, src_mac: str, src_ip: str, dst_ip: str,
                    sport: int, dport: int, flags: int, seq: int, ack: int,
                    payload: bytes = b'') -> bytes:
    eth = struct.pack('!6s6sH', mac_bytes(dst_mac), mac_bytes(src_mac), 0x0800)
    total_len = 20 + 20 + len(payload)
    ip = ipv4_header(src_ip, dst_ip, 6, total_len, (seq & 0xFFFF))
    tcp_hdr = struct.pack('!HHIIHHHH', sport, dport, seq, ack, (5 << 12) | (flags & 0x3F), 64240, 0, 0)
    return eth + ip + tcp_hdr + payload


def generate_flow_benchmark(
    out_dir: str,
    total_flows: int = 1_500_000,
    shards: int = 15,
    packets_per_session: int = 4,
    include_dpi: bool = True,
    match_ratio: float = 0.80,
    prefix: str = "bench_q"
):
    """
    Sinh các file PCAP shard khớp 80% rule (100 SPI groups) và 20% Unmatched Drop.
    """
    os.makedirs(out_dir, exist_ok=True)
    dst_mac = 'a0:36:bc:65:8f:11'
    src_mac = '00:00:00:00:00:01'

    flows_per_shard = (total_flows + shards - 1) // shards
    print(f"[*] Bắt đầu sinh PCAP:")
    print(f"    - Tổng số Flows / Sessions : {total_flows:,}")
    print(f"    - Số Shards (Worker Queues): {shards}")
    print(f"    - Số Flows mỗi Shard       : {flows_per_shard:,}")
    print(f"    - Tỷ lệ Khớp Rule (Match)  : {match_ratio*100:.0f}% Match, {(1-match_ratio)*100:.0f}% Drop Unmatched")
    print(f"    - Packets mỗi Session      : {packets_per_session}")
    print(f"    - Thư mục đầu ra           : {out_dir}")

    start_time = time.time()
    total_packets_written = 0

    for shard in range(shards):
        shard_path = os.path.join(out_dir, f"{prefix}{shard}.pcap")
        with open(shard_path, "wb") as f:
            f.write(pcap_global_header())
            ts_sec = 1000 + shard * 10
            ts_usec = 0

            for i in range(flows_per_shard):
                flow_idx = shard * flows_per_shard + i
                if flow_idx >= total_flows:
                    break

                # Client IP (nguồn)
                src_b3 = (flow_idx >> 8) & 0xFF
                src_b4 = flow_idx & 0xFF
                src_ip = f"172.16.{src_b3}.{src_b4}"
                sport = 1024 + (flow_idx % 64000)

                # Phân định 80% Match và 20% Unmatched
                is_match = ((flow_idx % 100) < int(match_ratio * 100))

                if is_match:
                    # 80% MATCH: Phân bổ đều qua 100 SPI Groups và 30 rules/group
                    group_idx = flow_idx % 100
                    rule_idx = (flow_idx // 100) % 30
                    dst_ip = f"10.0.{group_idx}.{(rule_idx % 254) + 1}"
                    if rule_idx % 4 == 0:
                        dport = 443
                    elif rule_idx % 4 == 1:
                        dport = 80
                    else:
                        dport = 1024 + (rule_idx * 137 % 60000)

                    dpi_info = DPI_SERVICES[group_idx % len(DPI_SERVICES)]
                    domain = dpi_info[1]
                    proto_type = dpi_info[2]
                else:
                    # 20% UNMATCHED: Địa chỉ ngoài danh sách rule -> Drop
                    dst_ip = f"198.51.100.{(flow_idx % 254) + 1}"
                    dport = 61000 + (flow_idx % 4000)
                    domain = f"unmatched-random-host-{flow_idx}.xyz"
                    proto_type = "tls"

                seq_client = 10000 + (flow_idx * 100)
                seq_server = 50000 + (flow_idx * 100)

                # Packet 1: TCP SYN (Client -> Server) - Khởi tạo phiên
                pkt_syn = make_tcp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, dport, 0x02, seq_client, 0)
                f.write(pcap_pkt_hdr(ts_sec, ts_usec, len(pkt_syn)))
                f.write(pkt_syn)
                ts_usec += 10
                total_packets_written += 1

                # Packet 2: TCP SYN-ACK (Server -> Client)
                pkt_synack = make_tcp_packet(src_mac, dst_mac, dst_ip, src_ip, dport, sport, 0x12, seq_server, seq_client + 1)
                f.write(pcap_pkt_hdr(ts_sec, ts_usec, len(pkt_synack)))
                f.write(pkt_synack)
                ts_usec += 10
                total_packets_written += 1

                # Packet 3: Payload L7 (Client -> Server)
                if include_dpi and packets_per_session >= 3:
                    if proto_type == "tls" or dport == 443:
                        payload = make_tls_client_hello(domain)
                    else:
                        payload = make_http_request(domain)
                    pkt_data = make_tcp_packet(
                        dst_mac, src_mac, src_ip, dst_ip, sport, dport, 0x18, seq_client + 1, seq_server + 1, payload
                    )
                    f.write(pcap_pkt_hdr(ts_sec, ts_usec, len(pkt_data)))
                    f.write(pkt_data)
                    ts_usec += 10
                    total_packets_written += 1
                    seq_client += len(payload)

                # Các Packet tiếp theo trong cùng Session (Streaming / Fetch chunks)
                pkts_generated = 3 if (include_dpi and packets_per_session >= 3) else 2
                while pkts_generated < packets_per_session:
                    if pkts_generated % 2 == 1:
                        client_req = f"GET /stream_{pkts_generated}.mp4 HTTP/1.1\r\nHost: {domain}\r\n\r\n".encode('ascii')
                        pkt_c = make_tcp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, dport, 0x18, seq_client, seq_server, client_req)
                        f.write(pcap_pkt_hdr(ts_sec, ts_usec, len(pkt_c)))
                        f.write(pkt_c)
                        seq_client += len(client_req)
                    else:
                        chunk_data = b"VIDEO_PAYLOAD_CHUNK_DATA_" * 4
                        pkt_s = make_tcp_packet(src_mac, dst_mac, dst_ip, src_ip, dport, sport, 0x18, seq_server, seq_client, chunk_data)
                        f.write(pcap_pkt_hdr(ts_sec, ts_usec, len(pkt_s)))
                        f.write(pkt_s)
                        seq_server += len(chunk_data)

                    ts_usec += 50
                    total_packets_written += 1
                    pkts_generated += 1

                if ts_usec >= 1_000_000:
                    ts_sec += ts_usec // 1_000_000
                    ts_usec %= 1_000_000

    elapsed = time.time() - start_time
    print(f"[✓] Đã tạo thành công {total_packets_written:,} gói tin ({total_flows:,} sessions) trong {elapsed:.2f} giây.")
    print(f"[✓] Đường dẫn shard: {out_dir}/{prefix}[0..{shards-1}].pcap\n")


def main():
    parser = argparse.ArgumentParser(
        description="DPDK Flow Overflow & Session Traffic Generator with 80% Match / 20% Unmatched Drop",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--flows", type=int, default=1_500_000,
                        help="Tổng số luồng/session độc lập cần tạo")
    parser.add_argument("--shards", type=int, default=15,
                        help="Số lượng shard PCAP tương ứng với số worker queues")
    parser.add_argument("--pkts-per-session", type=int, default=4,
                        help="Số lượng packet trong 1 session")
    parser.add_argument("--match-ratio", type=float, default=0.80,
                        help="Tỷ lệ khớp rule (mặc định 0.80 = 80%% Match, 20%% Drop)")
    parser.add_argument("--no-dpi", action="store_true",
                        help="Chỉ sinh packet 5-tuple không kèm payload L7")
    parser.add_argument("--out-dir", type=str, default="test/bench_pcap_shards",
                        help="Thư mục xuất file PCAP")
    parser.add_argument("--prefix", type=str, default="bench_q",
                        help="Tiền tố tên file PCAP")

    args = parser.parse_args()
    generate_flow_benchmark(
        out_dir=args.out_dir,
        total_flows=args.flows,
        shards=args.shards,
        packets_per_session=args.pkts_per_session,
        include_dpi=not args.no_dpi,
        match_ratio=args.match_ratio,
        prefix=args.prefix
    )


if __name__ == "__main__":
    main()
