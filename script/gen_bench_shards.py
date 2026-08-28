#!/usr/bin/env python3
"""
Generate 15 PCAP shards matching rules from gen_rules.py (4096 groups x 2048 rules)
for 15-worker net_pcap benchmark with infinite_rx=1.

IP pattern mirrors gen_rules.py:
  dst_ip = 10.{(g//256)%256}.{g%256}.{(r%254)+1}
  proto  = tcp if r%2==0 else udp
  dport  = 1024 + (r % 60000)
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


def generate_shards(out_dir, num_shards=15, pkts_per_shard=200_000,
                    groups=4096, rules_per_group=2048):
    """Generate PCAP shards with traffic matching gen_rules.py IP patterns."""
    os.makedirs(out_dir, exist_ok=True)
    dst_mac = 'a0:36:bc:65:8f:11'
    src_mac = '00:00:00:00:00:01'

    start = time.time()
    total_rules = groups * rules_per_group
    print(f"[gen_bench_shards] Generating {num_shards} PCAP shards "
          f"({pkts_per_shard:,} pkts/shard) matching {groups} groups x "
          f"{rules_per_group} rules = {total_rules:,} rules ...")

    # Pre-build rule packet descriptors (proto, dst_ip, dport) using
    # the exact same IP formula as gen_rules.py
    rule_descs = []
    for g in range(groups):
        ip_octet2 = (g // 256) % 256
        ip_octet3 = g % 256
        for r in range(rules_per_group):
            ip_octet4 = (r % 254) + 1
            dst_ip = f"10.{ip_octet2}.{ip_octet3}.{ip_octet4}"
            proto = 'tcp' if (r % 2 == 0) else 'udp'
            dport = 1024 + (r % 60000)
            rule_descs.append((proto, dst_ip, dport))

    for shard in range(num_shards):
        path = os.path.join(out_dir, f"bench_q{shard}.pcap")
        with open(path, "wb") as f:
            f.write(pcap_global_header())
            ts = 1000
            for i in range(pkts_per_shard):
                # Round-robin across all rules, offset by shard index
                idx = (shard * pkts_per_shard + i) % total_rules
                proto, dst_ip, dport = rule_descs[idx]
                src_ip = f"172.16.{shard}.{(i % 254) + 1}"
                sport = 80 if (i % 2 == 0) else 443
                if proto == 'tcp':
                    pkt = make_tcp_syn(dst_mac, src_mac, src_ip, dst_ip, sport, dport)
                else:
                    pkt = make_udp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, dport)
                f.write(pcap_pkt_hdr(ts, len(pkt)))
                f.write(pkt)
                ts += 1

        sz_mb = os.path.getsize(path) / (1024 * 1024)
        print(f"  shard {shard:2d}: {path} ({sz_mb:.1f} MB)")

    elapsed = time.time() - start
    print(f"[gen_bench_shards] Done in {elapsed:.1f}s — "
          f"{num_shards} shards x {pkts_per_shard:,} pkts = "
          f"{num_shards * pkts_per_shard:,} total packets")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "test/bench_pcap_shards"
    shards = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    pkts = int(sys.argv[3]) if len(sys.argv) > 3 else 200_000
    generate_shards(out, shards, pkts)
