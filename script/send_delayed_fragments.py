#!/usr/bin/env python3
"""Send two Ethernet fragments with a real wall-clock delay."""

from __future__ import annotations

import argparse
import socket
import struct
import time
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PCAP_DIR = PROJECT_ROOT / "test" / "fragment_delay"


def read_first_frame(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) < 40:
        raise ValueError(f"{path} is not a valid one-packet PCAP")
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != 0xA1B2C3D4:
        raise ValueError(f"{path} has an unsupported PCAP byte order")
    captured_length = struct.unpack_from("<I", data, 32)[0]
    frame = data[40 : 40 + captured_length]
    if len(frame) != captured_length:
        raise ValueError(f"{path} contains a truncated packet")
    return frame


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", required=True)
    parser.add_argument("--delay-sec", type=float, default=3.0)
    parser.add_argument(
        "--first", type=Path, default=DEFAULT_PCAP_DIR / "first_fragment.pcap"
    )
    parser.add_argument(
        "--second", type=Path, default=DEFAULT_PCAP_DIR / "second_fragment.pcap"
    )
    args = parser.parse_args()
    if args.delay_sec <= 0:
        parser.error("--delay-sec must be greater than zero")

    first = read_first_frame(args.first)
    second = read_first_frame(args.second)
    protocol_all = socket.htons(0x0003)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, protocol_all) as sender:
        sender.bind((args.interface, 0))
        sender.send(first)
        print(f"Sent first fragment on {args.interface}; waiting {args.delay_sec:.1f}s")
        time.sleep(args.delay_sec)
        sender.send(second)
        print("Sent second fragment; reassembly can now complete")


if __name__ == "__main__":
    main()
