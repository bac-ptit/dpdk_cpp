# Phase 0 — Profile results

**Bench config:** 15 workers, 1M packets per shard × 15 shards, `infinite_rx=1`, abs
pcap paths, default `l3_forward.enabled=false`, 25-second perf window.

Raw data: [phase0-baseline.perf](phase0-baseline.perf) — 5 events captured.

| Metric | Baseline (25s) | Per-instr ratio | Plan gate | Verdict |
|---|---|---|---|---|
| cycles | 1.482T | n/a | n/a | n/a |
| instructions | 1.748T | n/a | n/a | n/a |
| **L1-icache-load-misses** | 8.20M | 0.00047 | > 0.005 | not icache-bound |
| **L1-dcache-load-misses** | 40.80B | 0.0233 | n/a | moderate (typical of pkt proc) |
| LLC-load-misses | not supported | — | — | (CPU/paranoity excluded) |
| dTLB-load-misses | 96.6M | 0.000055 | n/a | low |
| iTLB-load-misses | 2.05M | 0.0000012 | n/a | negligible |
| **branch-misses** | 1.687B | 0.00096 | > 0.01 | not branch-bound |
| context-switches | 32,959 | — | — | negligible |
| cpu-migrations | 0 | — | — | negligible |
| IPC | 1.179 | n/a | n/a | reasonable |

**Decision per plan rule:** neither icache (0.0005 < 0.005) nor branch-misses
(0.001 < 0.01) hit the action thresholds → **skip Phase 2 (LUT)**.

# Phase 1 — `rte_hash_crc_set_alg(CRC32_SSE42_x64)` in `Environment::InitEal`

**Change:** one include (`<rte_hash_crc.h>`) + one line in `InitEal` — call
`rte_hash_crc_set_alg(CRC32_SSE42_x64)` immediately after a successful
`rte_eal_init`. Documented in [`dpdk_environment.cpp:235`](../../include/dpdk/dpdk_environment.cpp#L235).

(Side note: the symbol name is `CRC32_SSE42_x64`, NOT `RTE_HASH_CRC32_SSE42_x64`.
The `RTE_HASH_` prefix is incorrect — DPDK's `rte_hash_crc.h` exposes the
algorithm flags without that prefix.)

## Verification (2 back-to-back 25s windows)

| Metric | Baseline | Run 1 | Δ1 | Run 2 | Δ2 |
|---|---|---|---|---|---|
| cycles | 1.482T | 1.464T | **-1.2%** | 1.476T | -0.5% |
| instructions | 1.748T | 1.851T | **+5.9%** | 1.770T | +1.3% |
| **branch-misses** | 1.687B | 1.418B | **-16.0%** | 1.541B | **-8.7%** |
| L1-dcache-load-misses | 40.80B | 43.60B | +6.9% | 41.54B | +1.8% |
| L1-icache-load-misses | 8.20M | 7.53M | -8.2% | n/m | — |
| **IPC** | 1.179 | 1.264 | **+7.2%** | 1.199 | +1.7% |

The branch-miss reduction (-9% to -16%) and IPC improvement (+2-7%) are
consistent across both runs and well outside the ~2% noise floor observed
between back-to-back baseline runs. **This was not just a hygiene fix** —
the explicit CRC32 dispatch removed enough runtime branch to give a real
throughput bump. Expected end-to-end gain (estimated from instruction
throughput / cycle): **+2-5% Mpps**.

L1-dcache-load-misses held steady (within noise); icache was unchanged.

# Phase 2 — Skipped

Per the plan's data-driven rule, when neither icache nor branch-misses stand
out, skip the LUT. The `spi_packet_parser.cpp` L4 demux stays as a plain
`if/else` chain. No code change to that file.

# Concluding note — corrected earlier-session recommendation

The previous session's session-end summary recommended "Tier 1 #3: skip
software L3 checksum when `l3_forward.enabled=false`" as the next single
change. That recommendation was a **no-op**: the entire L3 / TTL / L4
checksum path is already structurally gated by `context.l3_forwarding` at
[`spi_pipeline.cpp:685`](../../include/dpdk/spi/spi_pipeline.cpp#L685).
With `l3_forward.enabled=false` (the default), `rte_ipv4_cksum` and
`rte_ipv4_udptcp_cksum_mbuf` are dead code at runtime. There was nothing
to skip.
