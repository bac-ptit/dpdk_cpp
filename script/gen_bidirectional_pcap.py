#!/usr/bin/env python3
"""
Generate a small PCAP file with Forward (Client -> Server) and Reverse (Server -> Client) packets.
"""

import os
import struct
import sys

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


def make_tcp_pkt(dst_mac, src_mac, src_ip, dst_ip, sport, dport, flags=0x02):
    eth = struct.pack('!6s6sH', mac_bytes(dst_mac), mac_bytes(src_mac), 0x0800)
    ip = ipv4_header(src_ip, dst_ip, 6, 40, 0x1234)
    tcp = struct.pack('!HHIIHHHH', sport, dport, 1000, 2000, (5 << 12) | flags, 0xFFFF, 0, 0)
    return eth + ip + tcp


def generate_bidirectional_pcap(out_path="test/bidirectional_small.pcap", count_pairs=50):
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    client_mac = "00:11:22:33:44:55"
    server_mac = "aa:bb:cc:dd:ee:ff"
    client_ip = "192.168.1.100"
    server_ip = "10.0.0.1"
    server_port = 1024  # Matches fg_group_0 rule 0 in rules.beve

    with open(out_path, "wb") as f:
        f.write(pcap_global_header())
        ts = 1000
        for i in range(count_pairs):
            client_port = 12345 + i

            # 1. Forward Packet (Client -> Server)
            pkt_fwd = make_tcp_pkt(server_mac, client_mac, client_ip, server_ip, client_port, server_port, flags=0x02)  # SYN
            f.write(pcap_pkt_hdr(ts, len(pkt_fwd)))
            f.write(pkt_fwd)
            ts += 1

            # 2. Reverse Swapped Packet (Server -> Client)
            pkt_rev = make_tcp_pkt(client_mac, server_mac, server_ip, client_ip, server_port, client_port, flags=0x12)  # SYN-ACK
            f.write(pcap_pkt_hdr(ts, len(pkt_rev)))
            f.write(pkt_rev)
            ts += 1

    print(f"Generated {count_pairs * 2} packets ({count_pairs} Forward + {count_pairs} Reverse) in {out_path}")


if __name__ == "__main__":
    generate_bidirectional_pcap()
