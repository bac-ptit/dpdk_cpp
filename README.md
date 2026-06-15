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

Benchmark with repeated TCP/80 packets:

```bash
pixi run bench
```

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
In this environment it supports one RX queue, so the script forces:

```text
rx_queues=1
tx_queues=1
worker_count=1
```

For real multi-core scaling, use a NIC/PMD with multiple RX queues and RSS.

## Docs

Regenerate API documentation:

```bash
pixi run docs
```

Open:

```text
docs/doxygen/html/index.html
```
