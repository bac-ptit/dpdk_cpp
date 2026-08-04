#!/usr/bin/env python3
"""
Generate 1,000,000 (1M) test packets matching rules.beve (102 filter groups, 5004 filters).

Matching pattern:
- 100 SPI groups (g=0..99) x 50 rules (r=0..49) = 5,000 rules
- g % 5 == 0 -> action: drop (20% of rules -> 200,000 packets dropped by rule)
- g % 5 != 0 -> action: forward (80% of rules -> 800,000 packets forwarded)
- dst_ip = 10.0.{g}.{(r % 254) + 1}
- proto = tcp (if r % 2 == 0) else udp
- dst_port = 1024 + (r % 60000)
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


def generate_1m_pcap(output_path, total_packets=1000000):
    start_time = time.time()
    print(f"[gen_1m] Generating {total_packets:,} packets matching rules.beve into {output_path}...")

    dst_mac = 'a0:36:bc:65:8f:11'
    src_mac = '00:00:00:00:00:01'

    rule_packets = []
    groups = 100
    rules_per_group = 50

    for g in range(groups):
        action_drop = (g % 5 == 0)
        for r in range(rules_per_group):
            ip_octet4 = (r % 254) + 1
            dst_ip = f"10.0.{g}.{ip_octet4}"
            proto = 'tcp' if (r % 2 == 0) else 'udp'
            dport = 1024 + (r % 60000)
            src_ip = "192.168.1.1"
            sport = 12345

            if proto == 'tcp':
                pkt = make_tcp_syn(dst_mac, src_mac, src_ip, dst_ip, sport, dport)
            else:
                pkt = make_udp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, dport)

            rule_packets.append((pkt, action_drop))

    total_rules = len(rule_packets)
    print(f"[gen_1m] Built {total_rules:,} rule packet templates (20% drop, 80% forward)")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    buffer = bytearray(pcap_global_header())
    ts = 1000

    with open(output_path, 'wb') as f:
        f.write(buffer)
        buffer.clear()

        written_pkts = 0
        written_forward = 0
        written_drop = 0

        while written_pkts < total_packets:
            pkt, is_drop = rule_packets[written_pkts % total_rules]
            hdr = pcap_pkt_hdr(ts, len(pkt))
            buffer.extend(hdr)
            buffer.extend(pkt)
            ts += 1
            written_pkts += 1

            if is_drop:
                written_drop += 1
            else:
                written_forward += 1

            if len(buffer) >= 65536:
                f.write(buffer)
                buffer.clear()

        if buffer:
            f.write(buffer)

    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    elapsed = time.time() - start_time
    print(f"[gen_1m] Successfully wrote {written_pkts:,} packets ({file_size_mb:.2f} MB) in {elapsed:.2f}s!")
    print(f"[gen_1m] Expected breakdown: {written_forward:,} FORWARDED, {written_drop:,} DROPPED_BY_RULE")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "test/beve_1m.pcap"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 1000000
    generate_1m_pcap(out, count)
