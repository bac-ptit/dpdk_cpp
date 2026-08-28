#!/usr/bin/env python3
"""Generate a valid two-fragment IPv4/TCP reassembly test."""

from __future__ import annotations

import argparse
import socket
import struct
from pathlib import Path


PCAP_GLOBAL_HEADER = struct.pack(
    "<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1
)
ETHERNET_HEADER = bytes.fromhex("0200000000020200000000010800")
SOURCE_IP = "192.0.2.1"
DESTINATION_IP = "198.51.100.2"
SOURCE_PORT = 12345
DESTINATION_PORT = 8080
IP_IDENTIFICATION = 0x4242
FRAGMENT_PAYLOAD_BYTES = 32


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_tcp_segment() -> bytes:
    payload = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
    assert len(payload) == 44
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        SOURCE_PORT,
        DESTINATION_PORT,
        1,
        0,
        5 << 4,
        0x18,
        8192,
        0,
        0,
    )
    tcp_length = len(tcp_header) + len(payload)
    pseudo_header = (
        socket.inet_aton(SOURCE_IP)
        + socket.inet_aton(DESTINATION_IP)
        + struct.pack("!BBH", 0, socket.IPPROTO_TCP, tcp_length)
    )
    tcp_checksum = checksum(pseudo_header + tcp_header + payload)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        SOURCE_PORT,
        DESTINATION_PORT,
        1,
        0,
        5 << 4,
        0x18,
        8192,
        tcp_checksum,
        0,
    )
    return tcp_header + payload


def build_ipv4_header(payload_length: int, flags_and_offset: int) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + payload_length,
        IP_IDENTIFICATION,
        flags_and_offset,
        64,
        socket.IPPROTO_TCP,
        0,
        socket.inet_aton(SOURCE_IP),
        socket.inet_aton(DESTINATION_IP),
    )
    header_checksum = checksum(header)
    return header[:10] + struct.pack("!H", header_checksum) + header[12:]


def build_fragments() -> tuple[bytes, bytes]:
    tcp_segment = build_tcp_segment()
    first_payload = tcp_segment[:FRAGMENT_PAYLOAD_BYTES]
    second_payload = tcp_segment[FRAGMENT_PAYLOAD_BYTES:]
    assert len(first_payload) % 8 == 0

    first = (
        ETHERNET_HEADER
        + build_ipv4_header(len(first_payload), 0x2000)
        + first_payload
    )
    second_offset = len(first_payload) // 8
    second = (
        ETHERNET_HEADER
        + build_ipv4_header(len(second_payload), second_offset)
        + second_payload
    )
    return first, second


def pcap_record(frame: bytes, timestamp_seconds: int) -> bytes:
    return struct.pack(
        "<IIII", timestamp_seconds, 0, len(frame), len(frame)
    ) + frame


def write_pcap(path: Path, records: list[tuple[bytes, int]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = PCAP_GLOBAL_HEADER + b"".join(
        pcap_record(frame, timestamp) for frame, timestamp in records
    )
    path.write_bytes(content)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("test/fragment_delay"),
    )
    parser.add_argument("--delay-sec", type=int, default=3)
    args = parser.parse_args()
    if args.delay_sec <= 0:
        parser.error("--delay-sec must be greater than zero")

    first, second = build_fragments()
    write_pcap(args.output_dir / "first_fragment.pcap", [(first, 1)])
    write_pcap(args.output_dir / "second_fragment.pcap", [(second, 1)])
    write_pcap(
        args.output_dir / "delayed_fragments_3s.pcap",
        [(first, 1), (second, 1 + args.delay_sec)],
    )
    print(f"Generated two IPv4/TCP fragments in {args.output_dir}")
    print(f"Send delay represented in combined PCAP: {args.delay_sec}s")


if __name__ == "__main__":
    main()
