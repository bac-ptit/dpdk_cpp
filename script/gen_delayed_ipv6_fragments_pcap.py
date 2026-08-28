#!/usr/bin/env python3
"""Generate two IPv6 fragments containing one TCP segment."""

from __future__ import annotations

import argparse
import ipaddress
import struct
from pathlib import Path


PCAP_GLOBAL_HEADER = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
ETHERNET_HEADER = bytes.fromhex("02000000000202000000000186dd")
SOURCE_IP = "2001:db8::1"
DESTINATION_IP = "2001:db8::2"
SOURCE_PORT = 12345
DESTINATION_PORT = 8080
FRAGMENT_ID = 0x11223344
FIRST_FRAGMENT_BYTES = 32


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_segment() -> bytes:
    payload = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
    header = struct.pack("!HHIIBBHHH", SOURCE_PORT, DESTINATION_PORT, 1, 0,
                         5 << 4, 0x18, 8192, 0, 0)
    pseudo = (ipaddress.IPv6Address(SOURCE_IP).packed
              + ipaddress.IPv6Address(DESTINATION_IP).packed
              + struct.pack("!I3xB", len(header) + len(payload), 6))
    checksum_value = checksum(pseudo + header + payload)
    return struct.pack("!HHIIBBHHH", SOURCE_PORT, DESTINATION_PORT, 1, 0,
                       5 << 4, 0x18, 8192, checksum_value, 0) + payload


def ipv6_header(payload_length: int) -> bytes:
    return struct.pack("!IHBB16s16s", 0x60000000, payload_length, 44, 64,
                       ipaddress.IPv6Address(SOURCE_IP).packed,
                       ipaddress.IPv6Address(DESTINATION_IP).packed)


def fragment_header(more_fragments: bool, offset_bytes: int) -> bytes:
    fragment_data = (offset_bytes & 0xFFF8) | int(more_fragments)
    return struct.pack("!BBHI", 6, 0, fragment_data, FRAGMENT_ID)


def record(frame: bytes, timestamp: int) -> bytes:
    return struct.pack("<IIII", timestamp, 0, len(frame), len(frame)) + frame


def write_pcap(path: Path, records: list[tuple[bytes, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(PCAP_GLOBAL_HEADER + b"".join(record(frame, stamp) for frame, stamp in records))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=Path("test/fragment_delay"))
    parser.add_argument("--delay-sec", type=int, default=3)
    args = parser.parse_args()
    if args.delay_sec <= 0:
        parser.error("--delay-sec must be greater than zero")

    segment = tcp_segment()
    first_payload, second_payload = segment[:FIRST_FRAGMENT_BYTES], segment[FIRST_FRAGMENT_BYTES:]
    first = ETHERNET_HEADER + ipv6_header(8 + len(first_payload)) + fragment_header(True, 0) + first_payload
    second = ETHERNET_HEADER + ipv6_header(8 + len(second_payload)) + fragment_header(False, len(first_payload)) + second_payload
    write_pcap(args.output_dir / "first_ipv6_fragment.pcap", [(first, 1)])
    write_pcap(args.output_dir / "second_ipv6_fragment.pcap", [(second, 1)])
    write_pcap(args.output_dir / "delayed_ipv6_fragments_3s.pcap",
               [(first, 1), (second, 1 + args.delay_sec)])
    print(f"Generated two IPv6/TCP fragments in {args.output_dir}")


if __name__ == "__main__":
    main()
