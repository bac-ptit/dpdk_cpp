# DPDK SPI Classifier

![C++26](https://img.shields.io/badge/C++-26-00599C?style=for-the-badge&logo=cplusplus)
![DPDK](https://img.shields.io/badge/DPDK-Packet%20Processing-00A86B?style=for-the-badge)
![Pixi](https://img.shields.io/badge/Pixi-Tasks-F7B731?style=for-the-badge)

High-speed shallow packet inspection with DPDK and modern C++.

The project receives packets, reads Ethernet/IPv4/TCP/UDP headers, matches
traffic against SPI rules with source/destination IP, source/destination port,
and protocol fields, updates L2 forwarding headers, and sends packets back out
through DPDK.

```text
RX -> Parse headers -> Match SPI rule -> Update L2 -> TX
```

## What It Classifies

| Traffic | Label |
|---------|-------|
| TCP `10.17.50.1 -> 10.17.50.12`, dst port `80` | `HTTP` |
| TCP `10.17.50.2 -> 10.17.50.12`, dst port `443` | `HTTPS` |
| UDP `10.17.50.3 -> 10.17.50.53`, dst port `53` | `DNS` |
| UDP `10.17.50.4 -> 10.17.50.215`, dst port `2152` | `GTP-U` |

## Project Shape

```text
.
├── config.yaml              # Runtime config
├── include/dpdk/            # DPDK wrapper + SPI pipeline
├── script/install.sh        # Configure, build, set capabilities
├── test/test_env.sh         # PCAP tests and benchmark helper
├── test/gen_test_pcap.py    # Test traffic generator
└── docs/doxygen/html/       # Generated API docs
```

## Requirements

Install Pixi plus DPDK development files, CMake, Ninja, Python, and PyYAML.

Fedora:

```bash
sudo dnf install dpdk-devel pkg-config cmake ninja-build python3-pyyaml hping3
```

Ubuntu:

```bash
sudo apt install libdpdk-dev pkg-config cmake ninja-build python3-yaml hping3
```

## Build

```bash
pixi run install
```

The binary is created at:

```text
cmake-build-debug/FastAPI
```

## Run

```bash
pixi run run
```

Stop with `Ctrl+C`. The app prints final counters and rule match totals.

## Test

Correctness test with 20 generated packets:

```bash
pixi run test-pcap
```

Expected shape:

```text
received=20 transmitted=20 parsed=20 matched=20 dropped=0
```

PCAP benchmark with 6 worker queues:

```bash
pixi run bench-pcap
```

The generator creates one `rx_pcap` stream per worker. By default the Pixi task
generates 300k packets and all packets match the configured SPI rules. The
PCAP benchmark disables L3 forwarding and omits
`tx_pcap`, so the PCAP PMD uses TX drop queues instead of measuring file output.
With `spi.packet_distribution: auto`, `net_pcap` uses the software flow-hash
dispatcher. Set `spi.packet_distribution: queue` to compare against the old
queue-per-worker path.

AF_PACKET virtual-NIC benchmark with 16 queue pairs:

```bash
pixi run bench-afpacket
```

This uses the current AF_PACKET interfaces from `config.yaml`, sets
`qpairs=16`, and keeps the live L3/SPI config. Generate many flows from another
terminal. With `spi.packet_distribution: auto`, `net_af_packet` uses the
software flow-hash dispatcher; a real RSS-capable NIC uses queue-per-worker.

Throughput is the delta between two stats lines divided by the timer interval
from `config.yaml`.

Example:

```text
SPI stats: received=21260416 ...
SPI stats: received=42572672 ...
```

With `timer_period_sec: 5`:

```text
(42572672 - 21260416) / 5 = 4.26 Mpps
```

## PCAP Benchmark Note

The test script uses DPDK PCAP PMD (`net_pcap`) for repeatable local testing.
One `rx_pcap` stream exposes one RX queue. For multi-worker tests the script
generates multiple PCAP shards:

```text
bench_q0.pcap ... bench_q15.pcap
```

The app prints final per-worker counters so you can verify that every worker
received traffic. In `flow_hash` mode these counters represent packets dequeued
from each worker ring, not packets read directly from RX queues.

## Docs

Regenerate API documentation:

```bash
pixi run docs
```

Open:

```text
docs/doxygen/html/index.html
```
