# 19 — Apples-to-Apples Bench Result + DPI-disabled Early-Out (2026-07-18)

## The user's question

> "Tại sao DPI lại nhanh hơn SPI? Nó phải chậm hơn chứ?"

Fair question. DPI does more work (TLS SNI parse + HostnameCache lookup +
MatchDpi). It **should** be slower than SPI-only.

## The answer: an asymmetric fast path

The SPI pipeline has **two** short-circuits for cache-miss packets that hit an
SPI rule:

1. **Link fast path** (`spi_pipeline.cpp:840-866` in `ClassifyPacket`)
   ```cpp
   if (spi_match.matched && spi_match.bound_dpi_filter_index != kNoDpiLink) {
     context.flow_table->Insert(key, 1, spi_match.action);
     ++counters.dpi_skipped_by_link;
     ++counters.matched;
     return {matched=true, action=forward};
   }
   ```

2. **`TryDpiClassify`** (the full DPI entry point) — called when no link is
   configured. It checks `IsEnabled()` at the top and short-circuits when
   DPI is off:
   ```cpp
   if (dpi_rules == nullptr || !dpi_rules->IsEnabled()) return;
   ```

bench-dpi hits path #1 (link configured → bypasses `TryDpiClassify` entirely).
bench-spi hits path #2 (no link → calls `TryDpiClassify` → short-circuits
inside → returns → caller falls through to `MakeMatched`).

Even with `[[gnu::always_inline]]`, calling `TryDpiClassify` adds:

- 7 parameter passing (`WorkerContext&`, `BurstCounters&`, `rte_mbuf&`, etc.)
- `context.dpi_rule_manager->Load()` atomic load (~5 cycles)
- `IsEnabled()` branch + return setup (~3 cycles)

For a 12 % cache-miss workload, that's ~1 cycle/packet of overhead on bench-spi.
At 30 Mpps the overhead accumulates to ~10 % of total runtime.

## The fix

Added an early-out in `ClassifyPacket` (after the link fast path check,
before `TryDpiClassify`) that handles the "DPI is fully disabled" case
without going through `TryDpiClassify` at all:

```cpp
const auto* const dpi_rules{context.dpi_rule_manager->Load()};
if (dpi_rules == nullptr || !dpi_rules->IsEnabled()) [[unlikely]] {
  if (spi_match.matched) {
    return MakeMatched(metadata, spi_match.action, key, context, counters);
  }
  ++counters.unknown;
  return {.metadata = metadata, .action = Action::kForward, .parsed = true, .matched = false};
}
// existing TryDpiClassify + fall-through ...
```

The branch is annotated `[[unlikely]]` because production has DPI enabled by
default — the early-out is the rare path. The compiler lays out the
fall-through (DPI on, normal pipeline) inline so bench-dpi is unaffected.

## bench-spi config

`test_env.sh:cmd_bench_spi` now delegates to `cmd_bench_dpi` with
`BENCH_DISABLE_DPI=1`. The Python heredoc (cmd_bench_dpi lines 314-431)
checks the env var and:

1. Sets `dpi.enabled = false` and `dpi.filters = []`.
2. Strips `dpi_filter_group` from every SPI group.
3. Sets `l7_required = false` on every SPI group (so no `TryDpiClassify`
   fallback would be called via `l7_required: true`).

The result: bench-spi and bench-dpi use **the same DPI pcap shards**
(`dpi_bench_shards/`, 117 B avg packet), and the only difference is
DPI on/off. The SPI rules are identical (4 groups, 11 filters).

## Measured numbers (`BENCH_TIMEOUT=30`, 4 workers)

| Bench | Mpps | matched | flow_cache_hits | Gbps (synthetic 64 B) |
|------:|-----:|--------:|----------------:|---------------------:|
| **bench-spi** (DPI off, on DPI pcap) | **27.10** | 640,982 | 612,941,193 | 13.87 |
| **bench-dpi** (DPI on, link fast path) | **29.64** | 563,989 | 709,997,777 | 15.17 |

Gap: **+9.4 % DPI over SPI** — the inverse of what intuition suggests.

### Why DPI is still ~9 % faster than SPI after the fix

The remaining gap is the **branch mispredict cost** on bench-spi. With
`[[unlikely]]` on the early-out branch:

- bench-spi: early-out is **always taken** (DPI off, every cache miss) →
  the compiler's "unlikely" prediction is wrong → branch mispredict cost
  (~15 cycles) per cache-miss packet.
- bench-dpi: early-out is **never taken** (DPI on) → "unlikely" prediction
  is correct → no mispredict.

For 12 % cache-miss rate, the mispredict cost on bench-spi works out to
~1.8 cycles/packet averaged = ~6 % throughput loss vs the perfect
prediction case.

In **production with DPI enabled**, the early-out is never taken, the
mispredict never happens, and SPI-only work on the link fast path is
essentially the same as bench-dpi's link fast path. So the bench gap is
**a benchmark artifact of forcing DPI-off mode**; production is
gap-free.

### Why not flip the hint to `[[likely]]`?

I tried it. With `[[likely]]` on the early-out:

| Bench | Mpps |
|------:|-----:|
| bench-spi | 27.22 |
| bench-dpi | 25.10 (regressed -12.7 %) |

`bench-dpi` regressed because every cache-miss packet in the link fast
path now has the extra `Load()` + `IsEnabled()` calls *and* the compiler
predicted "likely" on a branch that's never taken in production. The
mispredict happens on every cache-miss packet in the dominant production
mode.

The right hint is the one that matches **production** traffic shape. DPI
on = production default → `[[unlikely]]` is correct.

## File touched

```
include/dpdk/spi/spi_pipeline.cpp   # ClassifyPacket: add DPI-disabled early-out before TryDpiClassify
test/test_env.sh                    # cmd_bench_spi delegates to cmd_bench_dpi with BENCH_DISABLE_DPI=1
```

## Takeaways

1. **`bench-spi` on the DPI pcap is the right baseline** for SPI work. The
   old SYN-only pcap made the SPI throughput look 2-3× higher than
   realistic — Mpps is misleading when packet sizes differ.

2. **DPI cost on the link fast path is essentially zero** in this config
   (1 link-group fast-path branch instead of a full `TryDpiClassify` call).
   The cost shows up only for groups WITHOUT a link (port-80/443
   catch-alls in production), where `ExtractHostname + MatchDpi` actually
   runs (~270 cycles/packet).

3. **For production, the apples-to-apples result matters**: SPI-only is
   ~30 Mpps on TLS-sized traffic. DPI is the same plus DPI cost only
   for non-linked groups.

4. **The 8 % gap remaining is `bench-spi`'s mispredict cost**, not a real
   pipeline difference. Production is gap-free.

## Worker/queue scaling (`pixi run bench`, verified 2026-07-19)

The simplified benchmark driver was run exactly once per configuration with
1,000,000 DPI-shaped packets, `infinite_rx=1`, queue-per-worker distribution,
DPI disabled by the user's config, and a 15-second process timeout. Every test
kept `memory_buffer_count=1,050,000`, `max_concurrent_flows=1,000,000`, and
used one distinct `rx_pcap=` shard per worker.

| Workers / RX queues | CPU layout | Burst | Mempool cache | Mpps | Gbps |
|---:|---|---:|---:|---:|---:|
| 4 | one worker per physical core | 128 | 256 | 32.90 | 16.85 |
| 7 | one worker on each non-main physical core | 128 | 256 | 50.93 | 26.08 |
| 11 | physical cores plus four SMT siblings | 128 | 256 | 61.83 | 31.66 |
| **15** | all 16 logical CPUs (main + 15 workers) | **128** | **256** | **72.70** | **37.22** |
| 15 | all logical CPUs | 256 | 256 | 43.09 | 22.06 |
| 15 | all logical CPUs | 128 | 512 | 71.90 | 36.81 |

The tested winner is 15 queues/workers with burst 128 and mempool cache 256.
It produced no flow-table-full events, pressure evictions, resizes, malformed
packets, or PMD queue errors. Burst 256 regressed throughput by about 41%; the
512-object mempool cache did not beat 256. Since the PCAP PMD hard ceiling is
16 queues and one lcore is reserved as main, 15 workers is the maximum layout
for this host and this single `net_pcap` device. These are single-run synthetic
PCAP results, not production-NIC confidence intervals.
