# Performance Knobs Survey — Code vs Config

**Date:** 2026-07-05
**Goal:** Identify performance-related constants in the codebase and
decide which should be moved to `config.yaml` for tunability.

## 1. Currently in `config.yaml` (already tunable)

| Key | Default | Range | What it controls |
|---|---|---|---|
| `app.burst_size` | 32 | 1-256 | Packets per `rte_eth_rx_burst` call |
| `app.mac_updating` | true | bool | Whether to rewrite MAC on forward |
| `app.timer_period_sec` | 10 | uint32 | Seconds between stats prints |
| `spi.worker_count` | 1 | uint16 | Number of worker lcores |
| `spi.packet_distribution` | "auto" | enum | "auto" / "queue" / "flow_hash" |
| `spi.dispatch_queue_size` | 32768 | uint32 | rte_ring size for flow_hash mode |
| `spi.drop_unmatched` | false | bool | Drop packets matching no rule |
| `spi.flow_ttl_sec` | 300 | uint32 | Cache entry lifetime (0 = forever) |
| `spi.filter_groups` | (none) | list | SPI rules |
| `mempool.memory_buffer_count` | 65536 | size_t | mbuf pool size |
| `mempool.memory_buffer_size` | (none) | size_t | Per-mbuf size |
| `mempool.cache_size` | 256 | size_t | Per-core mbuf cache |
| `port.receive_descriptors` / `transmit_descriptors` | 1024 | uint16 | Ring sizes |
| `l3_forward.receive_burst_size` / `transmit_burst_size` | 32 | uint16 | (L3 forward path only) |

## 2. Hardcoded in code, performance-relevant

| Constant | File:line | Default | What it controls | Impact |
|---|---|---|---|---|
| `kAtomicFlushBurstInterval` | spi_pipeline.cpp:52 | 256 | Drain pending counters every N bursts | **Medium** — less frequent = less cache-line bouncing, but more lag in stats |
| `kPrefetchDistance` | spi_pipeline.cpp:829 | 4 | L1 prefetch K packets ahead | **Small** — higher = more mem traffic, lower = more dcache misses |
| `kFlowTableSize` | spi_flow_table.cpp:30 | 1M (2²⁰) | Flow cache slots | **High** — 1M=24MB, 8M=192MB; bigger cache = more hits but more L3 pressure |
| `kMaxTlsInspect` | spi_packet_parser.cpp:95 | 512 | TLS SNI buffer size | **Tiny** — only matters for DPI on TLS traffic |
| `kMaxHttpInspect` | spi_packet_parser.cpp:158 | 256 | HTTP Host buffer size | **Tiny** — only matters for DPI on HTTP traffic |

## 3. Hardcoded in code, NOT performance-relevant (don't expose)

| Constant | Reason |
|---|---|
| `kMaxBurstCapacity{256}` | Compile-time clamp on burst_size, hard DPDK limit |
| `kBulkChunkMax{64}` | `RTE_HASH_LOOKUP_BULK_MAX`, fixed by DPDK |
| `kFnvPrime, kFnvOffset` | FNV hash constants, math |
| `kLocalAdminMacPrefix{0x02}` | IEEE 802 MAC prefix |
| `kTlsPort{443}, kHttpPort{80}` | Protocol constants, not perf |
| `kMinBurstCapacity{1}` | Lower clamp on burst_size |
| `kHexBase{10}` | Hex parsing constant |
| `kBitsPerByte{8}` | Bit math |
| `kPortMacByteIndex{5}` | Ethernet MAC byte layout |
| `kUnmapped{UINT16_MAX}` | Sentinel for "not parsed" |

## 4. Recommendation

### Should move to config.yaml (priority order)

1. **`spi.flow_table_size`** (was `kFlowTableSize`) — **HIGHEST impact**
   - Default 1M, can be 256k / 512k / 1M / 2M / 4M / 8M
   - Each 1M = 24 MB extra memory
   - At 8M: 99% hit rate even for huge flow counts, but 192 MB L3 pressure
   - At 256k: tighter cache, lower latency, but 1M+ flows will thrash
   - **Est. impact**: 5-15% throughput depending on flow count

2. **`spi.atomic_flush_interval`** (was `kAtomicFlushBurstInterval`)
   - Default 256, range 64-1024 reasonable
   - Lower = more accurate stats but more cross-core cache traffic
   - Higher = less cache traffic but laggy stats
   - **Est. impact**: 1-3% (mostly cross-core contention)

3. **`spi.prefetch_distance`** (was `kPrefetchDistance`)
   - Default 4, range 2-8 reasonable
   - Lower = less memory bandwidth used, more dcache misses
   - Higher = more memory traffic, fewer dcache misses
   - **Est. impact**: 1-2% (L1-dcache pressure dependent)

### Should NOT move (defer / keep internal)

4. **`dpi.tls_inspect_size`** / **`dpi.http_inspect_size`** (was `kMaxTlsInspect`/`kMaxHttpInspect`)
   - Only matter if DPI is enabled (currently `dpi.enabled: false` in HEAD)
   - Tiny perf impact — DPI is rare path
   - **Est. impact**: 0% in default config, < 1% even with DPI on
   - **Defer**: not worth a config knob until DPI is enabled by default

## 5. Proposed config additions

```yaml
spi:
  # ... existing fields ...
  
  # Number of slots in the flow cache. Each slot = 24 B.
  # 1M = 24 MB; 8M = 192 MB. Bigger cache holds more flows before eviction.
  flow_table_size: 1000000       # default; was kFlowTableSize constexpr
  
  # Drain pending per-worker counters to shared atomics every N bursts.
  # Lower = more accurate stats + more cross-core cache traffic.
  # Higher = less cache traffic, stats lag by N bursts.
  atomic_flush_interval: 256     # default; was kAtomicFlushBurstInterval constexpr
  
  # L1 prefetch distance — touch packet header K packets ahead of current loop.
  # Lower = less memory bandwidth, more dcache misses.
  # Higher = more memory traffic, fewer dcache misses.
  prefetch_distance: 4           # default; was kPrefetchDistance constexpr
```

## 6. Implementation plan

For each of the 3 recommended moves:

1. Add field to `SpiConfig` struct in `include/dpdk/config/dpdk_config.hpp`
2. Pass through `Pipeline` constructor → `WorkerContext` → wherever used
3. Replace `constexpr` with the field
4. Add `kDefault*` constant in `dpdk_config.hpp` for the default value
5. Update `report/result.md` to mention the new tunables
6. Verify with bench

Estimated total change:
- ~50 lines added across 3 files (header, pipeline, flow_table)
- No hot-path regression (defaults match current constexpr)
- User can now tune from config.yaml without recompiling

## 7. Open questions

- Should `flow_table_size` use a power-of-2 hint (DPDK requirement) and round up?
- Should we validate the values (e.g., atomic_flush_interval < 65536) at config-load time?
- Should we add a `--tune=low-latency` / `--tune=high-throughput` preset that sets sensible values for common cases?
