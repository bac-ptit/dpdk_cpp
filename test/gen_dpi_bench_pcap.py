#!/usr/bin/env python3
"""Generate DPI-enabled benchmark pcap shards for FastAPI.

Same traffic shape as `gen_test_pcap.py` (same SPI rules from lv3.csv
matched on dst_ip/dst_port) BUT TCP payloads carry real TLS ClientHello
records with SNI hostnames that match the production DPI filter groups.

Why this exists: `gen_test_pcap.py` only emits TCP SYN / UDP packets (no
payload). When those pcaps go through the net_pcap PMD into `MatchDpi`,
`metadata.hostname == nullptr` because L7 was never captured, so DPI cache
hits stay at zero and we can't measure the SPI+DPI path. This generator
adds the missing L7 bytes so DPI extraction actually runs.

Mapping rules:
  dst_ip ∈ {31.13.64.0/18, 66.220.144.0/20, 69.63.176.0/20,
             157.240.0.0/16, 69.220.144.5}              → facebook / fbcdn
  dst_ip ∈ {142.250.0.0/15, 172.217.0.0/16, 216.58.192.0/19,
             74.125.0.1}                                  → google / youtube
  dst_ip = 10.0.0.1, port=80                            → "example.com"
  dst_ip = 10.0.0.1, port=443                           → "www.example.com"

UDP packets stay payload-less (no DPI parser for UDP in this project).
"""

import argparse
import os
import struct

from gen_test_pcap import (  # reuse the SPI rule tables + pcap helpers
    LINKTYPE_ETHERNET, PCAP_MAGIC, SPI_DROP_RULES, SPI_MATCH_RULES,
    SPI_MISS_RULES, pcap_global_header, pcap_pkt_hdr,
)

# ──────────────────────────────────────────────────────────────────────
# L7 payload builders (reused from test/dpi_test/gen_dpi_pcap.py)
# ──────────────────────────────────────────────────────────────────────


def make_tls_clienthello(sni_hostname):
    """Build a minimal TLS ClientHello with a single SNI extension."""
    sni = sni_hostname.encode()
    sni_ext = struct.pack('!HH', 0x0000, 2 + 1 + 2 + len(sni))
    sni_ext += struct.pack('!H', 1 + 2 + len(sni))
    sni_ext += struct.pack('!B', 0x00)
    sni_ext += struct.pack('!H', len(sni))
    sni_ext += sni

    body = struct.pack('!H', 0x0303) + b'\x00' * 32 + b'\x00'
    body += struct.pack('!H', 2) + struct.pack('!H', 0x002F)
    body += b'\x01\x00'
    body += struct.pack('!H', len(sni_ext)) + sni_ext

    hs = struct.pack('!B', 0x01) + struct.pack('!I', len(body))[1:] + body
    record = struct.pack('!BHH', 0x16, 0x0301, len(hs)) + hs
    return record


def make_http_get(host):
    """Build a minimal HTTP GET request with the given Host header."""
    req = (f"GET / HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"User-Agent: dpi-bench\r\n"
           f"Accept: */*\r\n"
           f"\r\n").encode()
    return req


# ──────────────────────────────────────────────────────────────────────
# dst_ip → hostname mapping (must match the config.yaml DPI filter groups).
# Each SPI rule's destination cluster is hardcoded to a hostname that
# the production DPI rules (`*.facebook.com`, `*.google.com`, etc.) will
# match via suffix lookup. Miss packets get a benign name (no DPI match)
# so they exercise the negative-cache path too.
# ──────────────────────────────────────────────────────────────────────


def dst_to_hostname(dst_ip, dst_port):
    """Return the hostname to embed in the L7 payload for the given 5-tuple.

    Returns None for miss / drop packets (no L7 payload needed).

    Maps must match docs/spi_rules.csv exactly: every IP here is in a
    specific fg_l34_* SPI rule, and the hostname must align with the
    DPI group that rule's `dpi_filter_group` declares. Misaligned
    hostnames still get classified correctly via the SPI→DPI static
    link, but the wasted ExtractHostname work skews the dpi_cache_*
    counters in bench output.
    """
    # Facebook cluster — every IP below is in a fg_l34_facebook CIDR
    # rule (CSV rules 1–5: 31.13.64.0/18, 66.220.144.0/20,
    # 69.63.176.0/20, 157.240.0.0/16, exact 69.220.144.5).
    fb_ips = {
        '31.13.65.1', '66.220.145.1', '69.63.177.1', '157.240.1.1', '69.220.144.5',
    }
    # YouTube cluster — ALL four IPs in fg_l34_youtube (CSV rules 6–9:
    # 142.250.0.0/15, 172.217.0.0/16, 216.58.192.0/19, exact 74.125.0.1).
    # Note: 172.217.0.0/16 and 74.125.0.1 are in YouTube per the docs,
    # even though both ranges are owned by Google. config.yaml + the
    # CSV both label them as YouTube so the pcap must follow.
    yt_ips = {'142.250.1.1', '216.58.193.1', '172.217.1.1', '74.125.0.1'}
    # No google_ips set: docs/spi_rules.csv has no SPI rule that maps
    # to a Google-IP range, so the SPI→DPI link path can never land on
    # fg_l7_google. Packets to other IPs fall through to the catch-all
    # fg_l7_catchall DPI rule via the `*.example` miss hostnames below.

    if dst_ip in fb_ips:
        return ('www.facebook.com' if dst_port == 443 else 'facebook.com')
    if dst_ip in yt_ips:
        return ('www.youtube.com' if dst_port == 443 else 'youtube.com')
    # 10.0.0.1 (HTTP/HTTPS catch-all) — matches CSV's fg_l34_http_sdf1003
    # / fg_l34_https_sdf1004 (dst_ip=NA, port=80/443, tcp).
    if dst_ip == '10.0.0.1':
        return ('www.example.com' if dst_port == 443 else 'example.com')

    # Miss packets — give them a non-matching hostname so DPI cache
    # records negative results. Each miss rule gets a unique hostname
    # to avoid lucky collisions with DPI rules.
    return None


def make_tcp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, dport, payload):
    """TCP packet (PSH+ACK) carrying `payload`."""
    eth = struct.pack('!6s6sH', bytes.fromhex(dst_mac.replace(':', '')),
                     bytes.fromhex(src_mac.replace(':', '')), 0x0800)
    tcp_segment = struct.pack(
        '!HHIIHHHH', sport, dport, 1000, 2000, (5 << 12) | 0x18, 0xFFFF, 0, 0,
    ) + payload
    tcp_segment_no_payload = tcp_segment[:20]  # header only, for IP total_length
    ip_total = 20 + len(tcp_segment)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, ip_total, 0xBEEF, 0x4000,
                     64, 6, 0,
                     bytes(map(int, src_ip.split('.'))),
                     bytes(map(int, dst_ip.split('.'))))
    return eth + ip + tcp_segment


def make_udp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, dport, payload=b''):
    """UDP packet (no DPI parsing — payload optional)."""
    import gen_test_pcap
    return gen_test_pcap.make_udp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, dport, payload=payload)


# ──────────────────────────────────────────────────────────────────────
# Sharded benchmark generation (mirrors gen_test_pcap.build_sharded_*)
# ──────────────────────────────────────────────────────────────────────


def build_sharded_dpi_pcaps(directory, count, shards, match_percent, prefix, response_percent=100):
    """Generate benchmark PCAP shards with full L7 payload for DPI bench.

    Layout (matches `build_sharded_bench_pcaps`):
      - 5% drop (UDP port 9999, no payload)
      - match_percent% of the remaining match SPI rules; TCP packets
        carry TLS ClientHello (port 443) or HTTP GET (port 80) with a
        hostname matched by the production DPI filter groups
      - the rest are miss packets (TCP/UDP without DPI match)

    `response_percent` (0-100): for each match/miss packet, also emit a
    response counterpart with src/dst IP and ports swapped (MACs swapped
    too). The response shares the canonical FlowKey with its request, so
    the second packet of the pair triggers a flow cache hit. Response
    payload is empty (cache hit means DPI doesn't re-process the response
    anyway). Drop packets get NO response.
    """
    if shards <= 0:
        raise ValueError('shards must be greater than 0')
    if not 0 <= match_percent <= 100:
        raise ValueError('match-percent must be between 0 and 100')
    if not 0 <= response_percent <= 100:
        raise ValueError('response-percent must be between 0 and 100')

    os.makedirs(directory, exist_ok=True)
    handles = []
    paths = []
    for shard in range(shards):
        path = os.path.join(directory, f'{prefix}{shard}.pcap')
        paths.append(path)
        handle = open(path, 'wb')
        handle.write(pcap_global_header())
        handles.append(handle)

    drop_count = count * 5 // 100
    remaining = count - drop_count
    match_count = remaining * match_percent // 100
    miss_count = remaining - match_count

    matched = 0
    dropped = 0
    missed = 0
    responses = 0
    shard_counts = [0] * shards
    dst_mac = 'a0:36:bc:65:8f:11'
    src_mac = '00:00:00:00:00:01'

    try:
        ts = 1000
        for index in range(count):
            shard = index % shards
            local_index = shard_counts[shard]
            shard_counts[shard] += 1

            # Per-shard disjoint source-IP — `10.<shard>.0.1`. Without this
            # rewrite, every shard's local_index=j produces the same
            # 5-tuple, so under multi-worker load all workers hit the same
            # FlowTable slot and the same `last_seen_tsc` cache line —
            # true-sharing via MESI coherence caps scaling well below
            # linear (≈50% when going from 4 → 7 workers). SPI rules match
            # on dst_ip, so varying src_ip does not affect SPI matching.
            # Uses src_ip (full 32-bit space) rather than a sport shift so
            # shards > 10 don't wrap-around the 60 000 ephemeral-port range.
            src_ip = f'10.{shard}.0.1'
            sport = 1024 + (local_index % 60000)

            if index < drop_count:
                proto, _, dst_ip, port = SPI_DROP_RULES[local_index % len(SPI_DROP_RULES)]
                pkt = make_udp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, port)
                dropped += 1
                handles[shard].write(pcap_pkt_hdr(ts, len(pkt)))
                handles[shard].write(pkt)
                ts += 1
            elif index < drop_count + match_count:
                proto, _, dst_ip, port = SPI_MATCH_RULES[local_index % len(SPI_MATCH_RULES)]
                hostname = dst_to_hostname(dst_ip, port)
                if proto == 'tcp' and hostname is not None:
                    payload = (make_tls_clienthello(hostname) if port == 443
                               else make_http_get(hostname))
                    pkt = make_tcp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, port, payload)
                else:
                    # UDP or no hostname — fall back to plain packet (no DPI hit but still matches SPI).
                    import gen_test_pcap
                    pkt = gen_test_pcap.make_packet(proto, dst_mac, src_mac, src_ip, dst_ip, sport, port)
                matched += 1
                handles[shard].write(pcap_pkt_hdr(ts, len(pkt)))
                handles[shard].write(pkt)
                ts += 1

                # Optional response — swap IP/port + MACs. Empty payload
                # (cache hit, DPI doesn't re-process). Deterministic via
                # (local_index % 100) < response_percent for reproducible
                # runs.
                if response_percent > 0 and (local_index % 100) < response_percent:
                    if proto == 'tcp':
                        response = make_tcp_packet(src_mac, dst_mac, dst_ip, src_ip,
                                                   port, sport, b'')
                    else:
                        response = make_udp_packet(src_mac, dst_mac, dst_ip, src_ip,
                                                   port, sport)
                    handles[shard].write(pcap_pkt_hdr(ts, len(response)))
                    handles[shard].write(response)
                    ts += 1
                    responses += 1
            else:
                proto, _, dst_ip, port = SPI_MISS_RULES[local_index % len(SPI_MISS_RULES)]
                # Miss packets: include a non-matching hostname to exercise DPI cache negative path.
                if proto == 'tcp':
                    payload = make_tls_clienthello(f'unknown-host-{index}.example')
                    pkt = make_tcp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, port, payload)
                else:
                    pkt = make_udp_packet(dst_mac, src_mac, src_ip, dst_ip, sport, port)
                missed += 1
                handles[shard].write(pcap_pkt_hdr(ts, len(pkt)))
                handles[shard].write(pkt)
                ts += 1

                # Optional response for miss packets too (canonical key
                # still matches, exercises cache for non-SPI-matched flows).
                if response_percent > 0 and (local_index % 100) < response_percent:
                    if proto == 'tcp':
                        response = make_tcp_packet(src_mac, dst_mac, dst_ip, src_ip,
                                                   port, sport, b'')
                    else:
                        response = make_udp_packet(src_mac, dst_mac, dst_ip, src_ip,
                                                   port, sport)
                    handles[shard].write(pcap_pkt_hdr(ts, len(response)))
                    handles[shard].write(response)
                    ts += 1
                    responses += 1

            if (index + 1) % 100000 == 0:
                print(f'  ... {index + 1}/{count}')
    finally:
        for handle in handles:
            handle.close()

    size_mb = sum(os.path.getsize(path) for path in paths) / (1024 * 1024)
    total = count + responses
    print(
        f'Generated {shards} shards in {directory}: {count} requests + '
        f'{responses} responses = {total} packets '
        f'({matched} match, {missed} miss, {dropped} drop, {size_mb:.1f} MB)'
    )


def main():
    parser = argparse.ArgumentParser(
        description='Generate DPI-enabled benchmark pcap shards',
    )
    default_path = os.path.join(os.path.dirname(__file__), 'dpi_bench_shards')
    parser.add_argument('path', nargs='?', default=default_path,
                        help='Output directory path')
    parser.add_argument('--count', type=int, default=100000,
                        help='Packet count per run (default 100000)')
    parser.add_argument('--shards', type=int, default=15,
                        help='Number of shards (default 15)')
    parser.add_argument('--match-percent', type=int, default=70,
                        help='Percentage of generated packets that match SPI rules')
    parser.add_argument('--response-percent', type=int, default=100,
                        help='Percentage of match/miss packets that get a response '
                             'with swapped IP/port (default 100, set 0 to disable)')
    parser.add_argument('--prefix', default='dpi_bench_q',
                        help='Filename prefix for sharded DPI benchmark pcaps')
    args = parser.parse_args()

    if args.shards <= 0:
        raise ValueError('shards must be greater than 0')
    if not 0 <= args.match_percent <= 100:
        raise ValueError('match-percent must be between 0 and 100')
    if not 0 <= args.response_percent <= 100:
        raise ValueError('response-percent must be between 0 and 100')

    build_sharded_dpi_pcaps(args.path, args.count, args.shards,
                            args.match_percent, args.prefix,
                            args.response_percent)


if __name__ == '__main__':
    main()
