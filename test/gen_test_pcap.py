#!/usr/bin/env python3
"""Generate test pcaps for DPDK SPI correctness and benchmark runs."""

import argparse
import os
import struct

PCAP_MAGIC = 0xa1b2c3d4
LINKTYPE_ETHERNET = 1

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

def make_udp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, dport, payload=b'test'):
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
    """Generate 20 packets (5 per rule) for correctness testing."""
    dst_mac = 'a0:36:bc:65:8f:11'
    src_mac = '00:00:00:00:00:01'
    pcap = bytearray(pcap_global_header())
    ts = 1000
    rules = [
        ('tcp', '10.17.50.1', '10.17.50.12', 80),
        ('tcp', '10.17.50.2', '10.17.50.12', 443),
        ('udp', '10.17.50.3', '10.17.50.53', 53),
        ('udp', '10.17.50.4', '10.17.50.215', 2152),
    ]
    for proto, src_ip, dst_ip, port in rules:
        for i in range(5):
            pkt = make_packet(proto, dst_mac, src_mac, src_ip, dst_ip, 12345 + i, port)
            pcap.extend(pcap_pkt_hdr(ts, len(pkt)))
            pcap.extend(pkt)
            ts += 1
    with open(path, 'wb') as f:
        f.write(pcap)
    print(f"Generated {path}: 20 packets")

def build_bench_pcap(path, count):
    """Generate many identical TCP SYN packets to port 80 for benchmarking."""
    pkt = make_tcp_syn('a0:36:bc:65:8f:11', '00:00:00:00:00:01',
                       '10.17.50.1', '10.17.50.12', 12345, 80)
    hdr = pcap_pkt_hdr(1000, len(pkt))
    pkt_bytes = hdr + pkt

    CHUNK = 10000
    chunk = bytearray(pkt_bytes * CHUNK)

    with open(path, 'wb') as f:
        f.write(pcap_global_header())
        written = 0
        while written < count:
            if count - written >= CHUNK:
                f.write(chunk)
                written += CHUNK
            else:
                f.write(pkt_bytes * (count - written))
                written = count
    size_mb = os.path.getsize(path) / (1024 * 1024)
    print(f"Generated {path}: {count} packets ({size_mb:.1f} MB)")

def main():
    parser = argparse.ArgumentParser(description='Generate test pcap for DPDK')
    default_path = os.path.join(os.path.dirname(__file__), 'spi_rules.pcap')
    parser.add_argument('path', nargs='?', default=default_path, help='Output pcap path')
    parser.add_argument('--count', type=int, default=0,
                        help='Packet count for benchmark (0 = small correctness test)')
    args = parser.parse_args()
    if args.count > 0:
        build_bench_pcap(args.path, args.count)
    else:
        build_small_pcap(args.path)

if __name__ == '__main__':
    main()
