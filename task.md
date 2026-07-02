# DPDK Pipeline Enhancement Plan

## Project Structure
```
include/dpdk/
├── pcap/
│   ├── CMakeLists.txt
│   ├── pcap_replay.hpp          (PcapReader class)
│   └── pcap_replay.cpp
├── spi/
│   ├── spi_pipeline.hpp         (updated: add latency tracking)
│   └── spi_pipeline.cpp
└── ...

confd/
├── fastapi.yang                 (YANG model)
├── fastapi_confd.c              (ConfD CDB callback)
├── Makefile
└── README.md

script/
├── benchmark.sh                 (benchmark runner)
└── test_spi_rules.py            (existing)
```

---

## Phase 1: PCAP Replay — Performance Testing (Lab)

**Purpose**: Run pipeline without physical NIC, read from .pcap file, measure throughput + latency.

| Step | Content | File/Component |
|------|---------|----------------|
| 1.1 | PcapReader class — use libpcap to read packets and convert to rte_mbuf | `include/dpdk/pcap/pcap_replay.hpp/.cpp` |
| 1.2 | Inject into pipeline without RX (replay-only mode, or use `--vdev=net_pcap0`) | Modify `main.cpp`, add `--mode=pcap` |
| 1.3 | Measure per-packet TSC cycles (timestamp at read → timestamp after classify) | Add latency tracking to `PipelineStats` / `AtomicCounters` |
| 1.4 | Report: Mpps, Gbps, P99 latency, packet distribution | `PipelineStats::Format` |

**Result**: Run `./FastAPI --mode=pcap --pcap=test.pcap`, output throughput + latency table.

**Additional flags**:
- `--loop=N` — loop through pcap N times (stress test)
- `--pps=N` — rate limit to N packets per second

---

## Phase 2: ConfD Integration (NETCONF Configuration Management) ⭐ **REQUIRED**

**Purpose**: Allow OSS/NMS push config via NETCONF, app reload rule table.

| Step | Content | File/Component |
|------|---------|----------------|
| 2.1 | Write YANG model mirroring DpdkConfig structure (EAL, port, mempool, app, l3_forward, spi, dpi) | `confd/fastapi.yang` |
| 2.2 | ConfD CDB callback → write YAML file + `kill -USR1` (or call LoadConfig + Swap directly) | `confd/fastapi_confd.c` (C callback) |
| 2.3 | CMake build integration + ConfD startup script | `CMakeLists.txt`, `confd/Makefile` |

**Note**: ConfD does NOT touch hot path, only control plane.

**Flow**:
```
OSS/NMS → NETCONF → ConfD → CDB callback → Write YAML → kill -USR1
                                                         ↓
                                    Main lcore detects flag → LoadConfig() → CompileRuleTable() → Swap()
```

---

## Phase 3: Benchmark Scripts & Tuning

| Step | Content |
|------|---------|
| 3.1 | Run `test_spi_rules.py` — verify correctness |
| 3.2 | Run benchmark with PCAP replay — measure Mpps baseline |
| 3.3 | Tune `burst_size`, prefetch, flow table size based on results |

---

## Implementation Order

```
Week 1:
├── Day 1-2: Phase 1 (PCAP Replay)
│   ├── Create pcap_replay.hpp/.cpp
│   ├── Modify main.cpp
│   └── Add latency tracking
│
├── Day 3-4: Phase 2 (NETCONF/ConfD)
│   ├── Create YANG model
│   ├── Create ConfD callback
│   └── CMake integration
│
└── Day 5: Phase 3 (Benchmark)
    ├── Run tests
    └── Performance tuning
```

---

## Dependencies

| Component | Required |
|-----------|----------|
| libpcap | For PCAP replay |
| ConfD | For NETCONF integration |
| DPDK | Already have |
| Python (pytest) | For test scripts |

---

## Questions

1. **Phase 1**: Do you have libpcap installed? (`apt install libpcap-dev` or `pacman -S libpcap`)

2. **Phase 2**: Do you have ConfD license? If not, we can use open-source alternatives like `netopeer2` + `sysrepo`

3. **Priority**: Should I implement Phase 1 first (quick win), or jump to Phase 2 (NETCONF requirement)?

---

## Status

- [ ] Phase 1: PCAP Replay
- [ ] Phase 2: NETCONF/ConfD
- [ ] Phase 3: Benchmark & Tuning

---

*Created: 2026-07-02*
*Last Updated: 2026-07-02*
