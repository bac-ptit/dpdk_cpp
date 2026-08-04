#!/usr/bin/env python3
"""
Generate 15 PCAP shards matching rules.beve for 15-worker net_pcap benchmark.
"""

import os
import struct
import sys
import time

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


def make_udp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, dport, payload=b'\x00\x01\x00\x00\x00\x01'):
    eth = struct.pack('!6s6sH', mac_bytes(dst_mac), mac_bytes(src_mac), 0x0800)
    udp_len = 8 + len(payload)
    ip = ipv4_header(src_ip, dst_ip, 17, 20 + udp_len, 0x2234)
    udp = struct.pack('!HHHH', sport, dport, udp_len, 0)
    return eth + ip + udp + payload


def generate_shards(out_dir, shards=15, pkts_per_shard=2000):
    os.makedirs(out_dir, exist_ok=True)
    dst_mac = 'a0:36:bc:65:8f:11'
    src_mac = '00:00:00:00:00:01'

    groups = 100
    rules_per_group = 50

    rule_packets = []
    for g in range(groups):
        for r in range(rules_per_group):
            ip_octet4 = (r % 254) + 1
            dst_ip = f"10.0.{g}.{ip_octet4}"
            proto = 'tcp' if (r % 2 == 0) else 'udp'
            dport = 1024 + (r % 60000)
            rule_packets.append((proto, dst_ip, dport))

    total_rules = len(rule_packets)

    for shard in range(shards):
        path = os.path.join(out_dir, f"shard_{shard}.pcap")
        with open(path, "wb") as f:
            f.write(pcap_global_header())
            ts = 1000
            for i in range(pkts_per_shard):
                idx = (shard * pkts_per_shard + i) % total_rules
                proto, dst_ip, dport = rule_packets[idx]
                src_ip = f"10.{shard}.0.1"
                sport = 80 if (i % 2 == 0) else 443
                if proto == 'tcp':
                    pkt = make_tcp_syn(dst_mac, src_mac, src_ip, dst_ip, sport, dport)
                else:
                    pkt = make_udp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, dport)
                f.write(pcap_pkt_hdr(ts, len(pkt)))
                f.write(pkt)
                ts += 1

    print(f"Generated {shards} PCAP shards in {out_dir} ({pkts_per_shard} packets per shard)")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "test/beve_shards"
    shards = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    generate_shards(out, shards)
