#!/usr/bin/env python3
"""Generate DPI test pcap: TLS ClientHello (with SNI) + HTTP GET (with Host) packets.

Each packet uses a unique (src_ip, src_port) so the flow cache MISSES
and the DPI extraction path is exercised. Destinations match SPI rule
groups so the SPI Match step passes first.
"""

import argparse
import os
import struct
import zlib

PCAP_MAGIC = 0xa1b2c3d4
LINKTYPE_ETHERNET = 1

DST_MAC = bytes.fromhex('a036bc658f11')
SRC_MAC = bytes.fromhex('000000000001')


def pcap_global_header():
    return struct.pack('<IHHiIII', PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)


def pcap_pkt_hdr(ts_sec, pkt_len):
    return struct.pack('<IIII', ts_sec, 0, pkt_len, pkt_len)


def ip_csum(header):
    if len(header) % 2:
        header += b'\x00'
    s = 0
    for i in range(0, len(header), 2):
        s += (header[i] << 8) + header[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4_header(src_ip, dst_ip, proto, total_length, ident):
    base = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total_length, ident, 0x4000,
                       64, proto, 0,
                       bytes(map(int, src_ip.split('.'))),
                       bytes(map(int, dst_ip.split('.'))))
    csum = ip_csum(base)
    return base[:10] + struct.pack('!H', csum) + base[12:]


def tcp_header(sport, dport, flags=0x18, seq=1000, ack=2000):
    """Build a TCP header with PSH+ACK flags (data-ready)."""
    # Format: src_port(2) dst_port(2) seq(4) ack(4) data_offset+flags(2) window(2) checksum(2) urgent(2)
    # Wrap seq/ack to 32-bit to avoid H overflow on long runs.
    return struct.pack('!HHIIHHHH', sport, dport,
                        seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                        (5 << 12) | flags, 0xFFFF, 0, 0)


def make_tls_clienthello(sni_hostname):
    """Build a minimal TLS ClientHello record containing the SNI extension.

    Wire format (simplified):
      TLS record header: type=0x16 (handshake), version=0x0301, length
        Handshake header: type=0x01 (ClientHello), length
          ClientHello body:
            version (2) + random (32) + session_id_len (1) + session_id + cipher_suites_len + ...
            extensions_len + extensions:
              SNI extension:
                ext_type=0x0000, ext_len
                list_len, name_type=0x00, name_len, name
    """
    sni = sni_hostname.encode()
    # SNI extension: 2 type + 2 list_len + 1 name_type + 2 name_len + name
    sni_ext = struct.pack('!HH', 0x0000, 2 + 1 + 2 + len(sni))  # ext type, ext len
    sni_ext += struct.pack('!H', 1 + 2 + len(sni))  # server_name list length
    sni_ext += struct.pack('!B', 0x00)               # name_type = host_name
    sni_ext += struct.pack('!H', len(sni))           # name length
    sni_ext += sni

    # ClientHello body
    body = struct.pack('!H', 0x0303)  # version TLS 1.2
    body += b'\x00' * 32              # random
    body += b'\x00'                   # session_id length = 0
    body += struct.pack('!H', 2) + struct.pack('!H', 0x002F)  # cipher_suites (one)
    body += b'\x01\x00'               # compression methods (null)

    extensions = sni_ext
    body += struct.pack('!H', len(extensions)) + extensions

    # Handshake header
    hs = struct.pack('!B', 0x01) + struct.pack('!I', len(body))[1:]  # type=ClientHello, length (3 bytes)
    hs += body

    # TLS record
    record = struct.pack('!BHH', 0x16, 0x0301, len(hs)) + hs
    return record


def make_http_get(host):
    """Build a minimal HTTP GET request with Host header."""
    req = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: dpi-test\r\nAccept: */*\r\n\r\n"
    return req.encode()


def build_tls_packet(sni_host, src_ip, dst_ip, src_port, dst_port, seq):
    """Build full ethernet/IPv4/TCP/TLS frame with ClientHello SNI."""
    tcp_data = make_tls_clienthello(sni_host)
    tcp = tcp_header(src_port, dst_port, flags=0x18, seq=seq, ack=seq + len(tcp_data))
    tcp_segment = tcp + tcp_data

    ip_total = 20 + len(tcp_segment)
    ip = ipv4_header(src_ip, dst_ip, 6, ip_total, 0xBEEF)
    eth = DST_MAC + SRC_MAC + struct.pack('!H', 0x0800)
    return eth + ip + tcp_segment


def build_http_packet(host, src_ip, dst_ip, src_port, dst_port, seq):
    """Build full ethernet/IPv4/TCP/HTTP frame with Host header."""
    http_data = make_http_get(host)
    tcp = tcp_header(src_port, dst_port, flags=0x18, seq=seq, ack=seq + len(http_data))
    tcp_segment = tcp + http_data

    ip_total = 20 + len(tcp_segment)
    ip = ipv4_header(src_ip, dst_ip, 6, ip_total, 0xBEEF)
    eth = DST_MAC + SRC_MAC + struct.pack('!H', 0x0800)
    return eth + ip + tcp_segment


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('output', help='output pcap file')
    parser.add_argument('--count', type=int, default=200000,
                        help='total packet count')
    args = parser.parse_args()

    # DPI test traffic: each tuple = (hostname, dst_ip, dst_port)
    # These hostnames match the DPI filter patterns in config.yaml
    flows = [
        # (SNI/Host, dst_ip, dst_port)
        ('www.facebook.com', '157.240.1.1', 443),       # Facebook IP + SNI
        ('graph.facebook.com', '157.240.1.1', 443),
        ('static.xx.fbcdn.net', '157.240.1.1', 443),
        ('www.youtube.com', '142.250.1.1', 443),         # YouTube IP + SNI
        ('i.ytimg.com', '142.250.1.1', 443),
        ('www.google.com', '172.217.1.1', 443),         # Google IP + SNI
        ('mail.google.com', '172.217.1.1', 443),
        ('www.example.com', '10.0.0.1', 80),            # HTTP, no DPI match
        ('unknown-host-12345.io', '10.0.0.1', 443),     # TLS but no DPI match
    ]

    with open(args.output, 'wb') as f:
        f.write(pcap_global_header())
        n = 0
        seq = 1000
        while n < args.count:
            host, dst_ip, dst_port = flows[n % len(flows)]
            # Unique source per flow so each is a cache miss.
            # Use mod 55535 to keep src_port within uint16 range (max 65535).
            src_port = 40000 + (n % 25535)
            src_ip = f"10.{(n // 256) % 256}.{(n // 1) % 256}.1"

            if dst_port == 443:
                pkt = build_tls_packet(host, src_ip, dst_ip, src_port, dst_port, seq)
            else:
                pkt = build_http_packet(host, src_ip, dst_ip, src_port, dst_port, seq)

            f.write(pcap_pkt_hdr(n, len(pkt)))
            f.write(pkt)
            n += 1
            seq += 100

    size_mb = os.path.getsize(args.output) / 1024 / 1024
    print(f"Generated {args.count} packets to {args.output} ({size_mb:.1f} MB)")


if __name__ == '__main__':
    main()
