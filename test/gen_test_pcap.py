#!/usr/bin/env python3
"""Generate test pcaps for DPDK SPI correctness and benchmark runs.

Rules from docs/lv3.csv — packet IPs/ports match the real SPI filter groups.
"""

import argparse
import os
import struct

PCAP_MAGIC = 0xa1b2c3d4
LINKTYPE_ETHERNET = 1
DEFAULT_MATCH_PERCENT = 70

# SPI rules from docs/lv3.csv / config.yaml
# (protocol, src_ip, dst_ip, dst_port, group_name)
SPI_MATCH_RULES = [
    # Facebook group (prec 100) — CIDR match, any port, TCP
    ('tcp', '192.168.1.1', '31.13.65.1', 80),        # 31.13.64.0/18
    ('tcp', '192.168.1.1', '66.220.145.1', 443),     # 66.220.144.0/20
    ('tcp', '192.168.1.1', '69.63.177.1', 80),       # 69.63.176.0/20
    ('tcp', '192.168.1.1', '157.240.1.1', 443),      # 157.240.0.0/16
    ('tcp', '192.168.1.1', '69.220.144.5', 443),     # exact IP match
    # YouTube group (prec 101) — CIDR + port 443, TCP
    ('tcp', '192.168.1.1', '142.250.1.1', 443),      # 142.250.0.0/15
    ('tcp', '192.168.1.1', '172.217.1.1', 443),      # 172.217.0.0/16
    ('tcp', '192.168.1.1', '216.58.193.1', 443),     # 216.58.192.0/19
    ('tcp', '192.168.1.1', '74.125.0.1', 443),       # exact IP
    # HTTP group (prec 102) — port 80, TCP
    ('tcp', '192.168.1.1', '10.0.0.1', 80),
    # HTTPS group (prec 103) — port 443, TCP
    ('tcp', '192.168.1.1', '10.0.0.1', 443),
    # DNS group (prec 104) — port 53, UDP
    ('udp', '192.168.1.1', '8.8.8.8', 53),
    # DNS group (prec 104) — port 53, TCP
    ('tcp', '192.168.1.1', '8.8.4.4', 53),
]

# Packets that should be DROPPED (match fg_l34_udp_sdf1006 at precedence 106)
SPI_DROP_RULES = [
    ('udp', '192.168.1.1', '10.0.0.1', 9999),   # UDP port 9999 → drop
]

# Packets that should NOT match any SPI rule
SPI_MISS_RULES = [
    ('tcp', '10.0.0.1', '10.0.0.2', 8080),     # unknown dst, unknown port
    ('udp', '10.0.0.1', '10.0.0.2', 5353),     # non-standard DNS port
    ('tcp', '10.0.0.1', '172.16.0.1', 9090),   # random IP/port
    ('udp', '10.0.0.1', '192.168.100.1', 1234), # random
]


def pcap_global_header():
    return struct.pack('<IHHiIII', PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)


def pcap_pkt_hdr(ts_sec, length):
    return struct.pack('<IIII', ts_sec, 0, length, length)


def mac_bytes(mac_str):
    return bytes.fromhex(mac_str.replace(':', ''))


def ip_bytes(ip_str):
    return bytes(map(int, ip_str.split('.')))


def ipv4_header(src_ip, dst_ip, proto, total_length, ident):
    return struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_length, ident, 0x4000,
                       64, proto, 0, ip_bytes(src_ip), ip_bytes(dst_ip))


def make_tcp_syn(dst_mac, src_mac, src_ip, dst_ip, sport, dport):
    eth = struct.pack('!6s6sH', mac_bytes(dst_mac), mac_bytes(src_mac), 0x0800)
    ip = ipv4_header(src_ip, dst_ip, 6, 40, 0x1234)
    tcp = struct.pack('!HHIIHHHH', sport, dport, 1000, 2000, (5 << 12) | 0x02, 0xFFFF, 0, 0)
    return eth + ip + tcp


def make_udp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, dport, payload=b'\x00\x01\x00\x00\x00\x01'):
    eth = struct.pack('!6s6sH', mac_bytes(dst_mac), mac_bytes(src_mac), 0x0800)
    udp_len = 8 + len(payload)
    ip = ipv4_header(src_ip, dst_ip, 17, 20 + udp_len, 0x2234)
    udp = struct.pack('!HHHH', sport, dport, udp_len, 0)
    return eth + ip + udp + payload


def make_packet(proto, dst_mac, src_mac, src_ip, dst_ip, sport, dport):
    if proto == 'tcp':
        return make_tcp_syn(dst_mac, src_mac, src_ip, dst_ip, sport, dport)
    if proto == 'udp':
        return make_udp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, dport)
    raise ValueError(f'Unsupported protocol: {proto}')


def build_small_pcap(path):
    """Generate one packet per SPI rule for correctness testing."""
    dst_mac = 'a0:36:bc:65:8f:11'
    src_mac = '00:00:00:00:00:01'
    pcap = bytearray(pcap_global_header())
    ts = 1000
    count = 0
    for proto, src_ip, dst_ip, port in SPI_MATCH_RULES:
        for i in range(5):
            pkt = make_packet(proto, dst_mac, src_mac, src_ip, dst_ip, 12345 + i, port)
            pcap.extend(pcap_pkt_hdr(ts, len(pkt)))
            pcap.extend(pkt)
            ts += 1
            count += 1
    with open(path, 'wb') as f:
        f.write(pcap)
    print(f"Generated {path}: {count} packets ({len(SPI_MATCH_RULES)} rules × 5)")


def build_bench_pcap(path, count):
    """Generate many packets for benchmarking using SPI rules from lv3.csv."""
    dst_mac = 'a0:36:bc:65:8f:11'
    src_mac = '00:00:00:00:00:01'
    pcap = bytearray(pcap_global_header())
    for i in range(count):
        rule = SPI_MATCH_RULES[i % len(SPI_MATCH_RULES)]
        proto, src_ip, dst_ip, port = rule
        sport = 1024 + (i % 60000)
        pkt = make_packet(proto, dst_mac, src_mac, src_ip, dst_ip, sport, port)
        pcap.extend(pcap_pkt_hdr(1000 + i, len(pkt)))
        pcap.extend(pkt)
        if (i + 1) % 100000 == 0:
            print(f"  ... {i + 1}/{count}")
    with open(path, 'wb') as f:
        f.write(pcap)
    size_mb = os.path.getsize(path) / (1024 * 1024)
    print(f"Generated {path}: {count} packets ({size_mb:.1f} MB)")


def should_match(index, total, target):
    """Return true for a stable spread of target matches across total packets."""
    if total <= 0:
        return False
    return ((index + 1) * target // total) > (index * target // total)


def bench_packet(index, matching):
    """Build one benchmark packet.
    Matching packets use SPI rules from lv3.csv; miss packets don't match.
    Drop packets match the drop rule (UDP port 9999).
    """
    dst_mac = 'a0:36:bc:65:8f:11'
    src_mac = '00:00:00:00:00:01'
    rules = SPI_MATCH_RULES if matching else SPI_MISS_RULES
    proto, src_ip, dst_ip, port = rules[index % len(rules)]
    sport = 1024 + (index % 60000)
    return make_packet(proto, dst_mac, src_mac, src_ip, dst_ip, sport, port), matching


def build_sharded_bench_pcaps(directory, count, shards, match_percent, prefix):
    """Generate benchmark PCAP shards for multi-queue net_pcap tests.
    Generates a mix of match, miss, and drop packets.
    Drop packets: 5% of total, match fg_l34_udp_sdf1006 (UDP port 9999).
    """
    if shards <= 0:
        raise ValueError('shards must be greater than 0')
    if not 0 <= match_percent <= 100:
        raise ValueError('match-percent must be between 0 and 100')

    os.makedirs(directory, exist_ok=True)
    handles = []
    paths = []
    for shard in range(shards):
        path = os.path.join(directory, f'{prefix}{shard}.pcap')
        paths.append(path)
        handle = open(path, 'wb')
        handle.write(pcap_global_header())
        handles.append(handle)

    # 5% drop, rest split between match and miss based on match_percent
    drop_count = count * 5 // 100
    remaining = count - drop_count
    match_count = remaining * match_percent // 100
    miss_count = remaining - match_count

    matched = 0
    dropped = 0
    missed = 0
    shard_counts = [0] * shards
    try:
        for index in range(count):
            shard = index % shards
            local_index = shard_counts[shard]
            shard_counts[shard] += 1

            # Determine packet type: drop (5%), match, or miss
            if index < drop_count:
                # Drop packet
                dst_mac = 'a0:36:bc:65:8f:11'
                src_mac = '00:00:00:00:00:01'
                proto, src_ip, dst_ip, port = SPI_DROP_RULES[local_index % len(SPI_DROP_RULES)]
                sport = 1024 + (local_index % 60000)
                packet = make_packet(proto, dst_mac, src_mac, src_ip, dst_ip, sport, port)
                dropped += 1
            elif index < drop_count + match_count:
                # Match packet
                packet, _ = bench_packet(local_index, True)
                matched += 1
            else:
                # Miss packet
                packet, _ = bench_packet(local_index, False)
                missed += 1

            handles[shard].write(pcap_pkt_hdr(1000 + index, len(packet)))
            handles[shard].write(packet)
            if (index + 1) % 100000 == 0:
                print(f"  ... {index + 1}/{count}")
    finally:
        for handle in handles:
            handle.close()

    size_mb = sum(os.path.getsize(path) for path in paths) / (1024 * 1024)
    print(
        f"Generated {shards} shards in {directory}: {count} packets "
        f"({matched} match, {missed} miss, {dropped} drop, {size_mb:.1f} MB)")


def main():
    parser = argparse.ArgumentParser(description='Generate test pcap for DPDK')
    default_path = os.path.join(os.path.dirname(__file__), 'spi_rules.pcap')
    parser.add_argument('path', nargs='?', default=default_path, help='Output pcap path')
    parser.add_argument('--count', type=int, default=0,
                        help='Packet count for benchmark (0 = small correctness test)')
    parser.add_argument('--shards', type=int, default=0,
                        help='Generate this many benchmark PCAP shards in path')
    parser.add_argument('--match-percent', type=int, default=DEFAULT_MATCH_PERCENT,
                        help='Percentage of generated packets that match SPI rules')
    parser.add_argument('--prefix', default='bench_q',
                        help='Filename prefix for sharded benchmark pcaps')
    args = parser.parse_args()
    if args.count > 0 and args.shards > 0:
        build_sharded_bench_pcaps(args.path, args.count, args.shards, args.match_percent, args.prefix)
    elif args.count > 0:
        build_bench_pcap(args.path, args.count)
    else:
        build_small_pcap(args.path)


if __name__ == '__main__':
    main()
