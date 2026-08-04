#!/usr/bin/env python3
"""
Zero-Dependency PCAP Generator for IP Fragmented Packets and TCP Segmented Flows.
Generates PCAP files containing actual IPv4 fragmented packets and TCP segmented TLS/HTTP streams.

Usage:
  python3 script/gen_test_fragments_pcap.py --count 100 --out test/bench_fragments.pcap
"""

import argparse
import struct
import socket

def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b'\x00'
    s = sum(struct.unpack(f">{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff

def make_pcap_header() -> bytes:
    # Magic 0xa1b2c3d4, Major 2, Minor 4, Zone 0, Sigfigs 0, Snaplen 65535, Network 1 (Ethernet)
    return struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def make_pcap_packet(data: bytes, ts_sec: int = 1, ts_usec: int = 0) -> bytes:
    length = len(data)
    hdr = struct.pack("<IIII", ts_sec, ts_usec, length, length)
    return hdr + data

def make_ethernet(src_mac: bytes = b'\x00\x11\x22\x33\x44\x55',
                  dst_mac: bytes = b'\x66\x77\x88\x99\xaa\xbb',
                  eth_type: int = 0x0800) -> bytes:
    return dst_mac + src_mac + struct.pack(">H", eth_type)

def make_ipv4(src_ip: str, dst_ip: str, proto: int, payload_len: int,
              ident: int = 12345, flags_offset: int = 0) -> bytes:
    version_ihl = (4 << 4) | 5 # Version 4, Header len 20 bytes
    tos = 0
    total_len = 20 + payload_len
    ttl = 64
    chksum = 0
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)

    hdr = struct.pack(">BBHHHBBH4s4s",
                      version_ihl, tos, total_len, ident,
                      flags_offset, ttl, proto, chksum,
                      src_bytes, dst_bytes)
    chksum = checksum(hdr)
    return struct.pack(">BBHHHBBH4s4s",
                       version_ihl, tos, total_len, ident,
                       flags_offset, ttl, proto, chksum,
                       src_bytes, dst_bytes)

def make_udp(src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    chksum = 0
    hdr = struct.pack(">HHHH", src_port, dst_port, length, chksum)
    return hdr + payload

def make_tcp(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    data_offset_reserved = (5 << 4) # 20 bytes header
    window = 8192
    chksum = 0
    urg_ptr = 0
    hdr = struct.pack(">HHIIBBHHH", src_port, dst_port, seq, ack, data_offset_reserved, flags, window, chksum, urg_ptr)
    return hdr + payload

def generate_fragmented_pcap(count: int, out_file: str):
    print(f"[gen_pcap] Generating PCAP with IP fragments and TCP segments -> {out_file}...")
    packets = []

    eth = make_ethernet()

    for i in range(count):
        src_ip = f"192.168.100.{(i % 200) + 1}"
        dst_ip = f"192.168.200.{(i % 200) + 1}"
        ident = 2000 + i

        # Scenario 1: IPv4 Fragmented Packet (2 fragments)
        # Fragment 1: MF bit set (0x2000), offset 0
        udp_header = make_udp(src_port=5000+i, dst_port=80, payload=b"PARTIAL_FRAG_1_PAYLOAD_" + b"A"*500)
        ip1 = make_ipv4(src_ip, dst_ip, proto=17, payload_len=len(udp_header), ident=ident, flags_offset=0x2000)
        packets.append(eth + ip1 + udp_header)

        # Fragment 2: MF bit clear (0x0000), offset 66 (66 * 8 = 528 bytes offset)
        frag2_payload = b"PARTIAL_FRAG_2_PAYLOAD_" + b"B"*500
        ip2 = make_ipv4(src_ip, dst_ip, proto=17, payload_len=len(frag2_payload), ident=ident, flags_offset=66)
        packets.append(eth + ip2 + frag2_payload)

        # Scenario 2: TCP Segmented Flow (TLS ClientHello split across 2 TCP segments)
        tcp_src_port = 10000 + (i % 5000)
        # TCP Segment 1: SYN / TLS header
        tcp1 = make_tcp(src_port=tcp_src_port, dst_port=443, seq=1000 + i*100, ack=0, flags=0x18, payload=b"\x16\x03\x01\x00\x80\x01\x00\x00\x7c")
        ip_tcp1 = make_ipv4(src_ip, dst_ip, proto=6, payload_len=len(tcp1), ident=ident+10000, flags_offset=0)
        packets.append(eth + ip_tcp1 + tcp1)

        # TCP Segment 2: TLS SNI Extension payload containing domain "*.viettel.vn"
        tls_sni_payload = b"\x00\x00\x00\x13\x00\x11\x00\x00\x0eserver.viettel.vn"
        tcp2 = make_tcp(src_port=tcp_src_port, dst_port=443, seq=1009 + i*100, ack=0, flags=0x18, payload=tls_sni_payload)
        ip_tcp2 = make_ipv4(src_ip, dst_ip, proto=6, payload_len=len(tcp2), ident=ident+10000, flags_offset=0)
        packets.append(eth + ip_tcp2 + tcp2)

    # Write PCAP file
    with open(out_file, "wb") as f:
        f.write(make_pcap_header())
        for p in packets:
            f.write(make_pcap_packet(p))

    print(f"[gen_pcap] Wrote {len(packets)} packets to {out_file}")

def main():
    parser = argparse.ArgumentParser(description="Generate IP fragment & TCP segment test PCAP")
    parser.add_argument("--count", type=int, default=50, help="Number of test scenarios")
    parser.add_argument("--out", type=str, default="test/bench_fragments.pcap", help="Output PCAP file path")
    args = parser.parse_args()

    generate_fragmented_pcap(args.count, args.out)

if __name__ == "__main__":
    main()
