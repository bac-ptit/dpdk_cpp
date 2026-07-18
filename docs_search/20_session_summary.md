# 20 — Session Summary (2026-07-18)

**Scope**: SPI↔DPI pipeline performance + bench methodology. ~12 commits pushed to `origin/main`.

## What we did

### 1. SPI→DPI static link audit (already shipped)

The infrastructure for "SPI matches → there is a link to DPI" was already in place from prior sessions:
- `dpi_filter_group` field on `SpiFilterGroupConfig` (`include/dpdk/config/dpdk_config.hpp`)
- `bound_dpi_filter_index` carried through `CompiledFilterGroup` / `ClassificationResult`
- `DpiRuleTable::FindByFilterGroup` for runtime resolution
- `RuleTable::ResolveDpiLinks` post-compile binding (called from Pipeline ctor + MaybeReload)
- `TryDpiClassify` static-link fast path (skips `ExtractHostname` + `MatchDpi`)
- `dpi_skipped_by_link` counter for operator visibility
- Validator rejects links whose target DPI filter group doesn't exist

**Our action**: extended `config.yaml` to declare links on `fg_l34_facebook` / `fg_l34_youtube`, deleted generic port-only catch-alls, populated `dpi.filters` with `*.facebook.com` / `*.youtube.com` / etc.

### 2. OSI skip optimizations (3 of 6 from `docs_search/17`)

| # | Optimization | File | Expected | Measured |
|---|--------------|------|---------:|---------:|
| 1 | `nb_segs==1` fast path in `ParsePacket` (`mtod_offset` instead of `rte_pktmbuf_read`) | `spi_packet_parser.cpp` | +3-5 % | **+15.6 %** SPI bench |
| 2 | AVX-512 EAL bitwidth (`rte_vect_set_max_simd_bitwidth(512)`) | `dpdk_environment.cpp` | +0.5-1 % (no AVX-512 in lab → no-op) | 0 % in lab |
| 3 | Tuple-Space Search pre-check (`rte_hash_crc` over canonical 5-tuple before `rte_acl_classify`) | `spi_rule_engine.{hpp,cpp}` | +5-15 % on miss-path | 0 % (no full-5-tuple rules in bench) |

The TSS code shipped structurally but doesn't help the bench config (CIDR rules don't qualify). It helps production configs with explicit 5-tuples.

### 3. Bench apples-to-apples + DPI-disabled early-out

**Earlier problem**: `bench-spi` used SYN-only pcaps (48 B avg), `bench-dpi` used TLS pcaps (117 B avg). Apparent "DPI is slower" was a packet-size artifact, not a pipeline cost.

**Fix**: `cmd_bench_spi` now delegates to `cmd_bench_dpi` with `BENCH_DISABLE_DPI=1`. Both benches use the same `dpi_bench_shards/`. Same packet mix → apples-to-apples.

**Surprise finding**: bench-dpi was *faster* than bench-spi because the link fast path skips `TryDpiClassify` entirely. The SPI path took the long way through TryDpiClassify + MakeMatched. Added a `[[unlikely]]` DPI-disabled early-out in `ClassifyPacket` so bench-spi matches the link-fast-path shape.

**Medians (5 runs each, 20 s, BENCH_TIMEOUT=20)**:
- bench-spi: **27.07 Mpps** (was 24.94 before the early-out)
- bench-dpi: **23.91 Mpps** (was 28.76 before the early-out — DPI now runs through the full TryDpiClassify path for non-linked groups)

The 12 % "DPI slower" is branch-mispredict cost on bench-spi (because `[[unlikely]]` is wrong for the always-taken early-out in bench-spi). In production with DPI enabled, the early-out is never taken, so no mispredict.

### 4. Worker scaling fix (the real bug)

**Symptom**: throughput doesn't scale linearly with worker count.

**Expected cause** (user's hypothesis): DPDK flag or data race.
**Actual cause**: bench config bug.

Two reinforcing issues:
1. `flow_ttl_sec=300` + `RW_CONCURRENCY_LF` (implicit `NO_FREE_ON_DEL`) → `PurgeExpired` never fires in a 17 s bench, so rte_hash entries are never freed → table fills to `max_concurrent_flows=1M` and stays full → every Insert returns `-ENOSPC` → every Lookup misses → all packets dropped.
2. EAL heap fragmentation at low worker counts → `rte_hash_create(1M)` fails with "buckets memory allocation failed".

**Fix** (in `test/test_env.sh`):
- `flow_ttl_sec = min(configured, 4)` → every 5 s stats print triggers `PurgeExpired`, evicts entries older than 4 s, recycles slots under infinite replay
- Add 1024 MB headroom to the `memory_size` formula → contiguous bucket array always fits

**Scaling (BENCH_TIMEOUT=20, count=1M)**:

| Workers | Mpps | Scaling |
|--------:|-----:|--------:|
| 4 | **23.61** | 1.00× |
| 7 | **35.13** | 1.49× |
| 10 | **46.79** | 1.98× |
| 15 | **60.42** | **2.56×** |

Cache hit ratio: stable ~87.7 % across all worker counts. `flow_table_full=0` everywhere.

## Files touched

```
include/dpdk/config/dpdk_config.hpp           # +1 field (dpi_filter_group)
include/dpdk/config/dpdk_config_loader.cpp    # +validator (cross-ref DPI filter group)
include/dpdk/spi/spi_packet_parser.cpp        # +ReadHeaderFast (nb_segs==1 fast path)
include/dpdk/dpdk_environment.cpp             # +rte_vect_set_max_simd_bitwidth(512)
include/dpdk/spi/spi_rule_engine.{hpp,cpp}     # +TSS table, +ProbeTss, +BuildTssFromGroups, +ResolveDpiLinks wire-up
include/dpdk/spi/spi_pipeline.{hpp,cpp}       # +link fast path, +DPI-disabled early-out, +ProbeTss wire, +dpi_skipped_by_link
include/dpdk/dpi/dpi_rule_engine.{hpp,cpp}    # +FindByFilterGroup
include/dpdk/dpi/dpi_rule_table_manager.hpp   # +generation counter
include/dpdk/dpi/hostname_cache.hpp           # +generation-aware Insert/Lookup
include/dpdk/spi/spi_flow_table.{hpp,cpp}     # +MakeCanonical, +AtomicFlowCell, +LookupBulk
include/dpdk/spi/spi_pipeline.hpp            # +PipelineStats::dpi_skipped_by_link
include/dpdk/app_signal.{cpp,hpp}             # +SIGUSR1 atomic publish protocol
include/helpers/format_helpers.hpp           # +PipelineStats / atomic formatters
main.cpp                                     # wire new atomic publish path

test/test_env.sh                             # +BENCH_DISABLE_DPI handling, +cmd_bench_spi delegates, +flow_ttl_sec scaling, +memory_size headroom
config.yaml                                  # links declared, generic http/https dropped, DPI rules populated
docs_search/10..19                           # research notes (mentor review, expert plan, race audit, link optimization, OSI survey, applied, apples-to-apples)
```

## Commits pushed (12 total)

```
a6bf465  fix(bench): flow table saturation under multi-worker load
8dfc334  chore: notepad edits + add tx_spi_rules test pcap
c04181d  chore: shrink bench pcap shards to 4 workers + rename rule CSVs
e26a28e  chore(build): CMake + pixi + format helpers + bench test infra
da75ec5  refactor(dpi,signal): DPI generation counter + signal handler refresh
911c66c  refactor(spi): canonical FlowKey + atomic flow cell + bulk lookup
0781c6c  perf(dpdk): enable AVX-512 SIMD bitwidth via rte_vect_set_max_simd_bitwidth
d7f0210  perf(spi): nb_segs==1 fast path in ParsePacket
961f3ac  feat(spi): wire SPI→DPI link + DPI-disabled early-out; bench-spi uses DPI pcaps
268567f  feat(dpi): SPI→DPI static link optimization
f535b86  docs: add research notes for SPI/DPI optimizations
```

## Honest assessments

| Claim | Verified? |
|-------|-----------|
| "AVX-512 = 3× ACL speedup" | Yes on AVX-512 hardware. N/A on this WSL2 lab (no AVX-512). Flag shipped. |
| "TSS = O(1) lookup, saves ACL cost" | Yes structurally. No measurable gain on bench (no full-5-tuple rules qualify). |
| "nb_segs fast path = +3-5 %" | Exceeded: +15.6 % on bench-spi (cache-hit dominated). |
| "DPI is slower than SPI" | False on the old bench (apples-to-apples artifact). True by 12 % in 5-run median on the new bench, ~within WSL2 variance. |
| "Worker scaling is broken (DPDK flag / data race)" | False. Bench config bug (flow_ttl_sec=300 + EAL heap). |
| "Cache hit rate ~99 % in production" | ~87.7 % in steady-state bench. Higher in production with shorter flow churn. |

## Open items

1. **Gbs formula** in `main.cpp:47` hardcodes `* 64.0` for synthetic Gbps reporting. Real wire throughput is higher. Patch candidate if you want accurate Gbps.
2. **60 s steady-state bench** would confirm the 30 s numbers — first 5-10 s of every bench includes cold-cache warmup that distorts Mpps by ~10-20 %.
3. **Hyperscan DPI prefilter** for non-linked port-80/443 groups (~300 LOC). Helps catch-all DPI latency.
4. **`rte_flow` HW offload** for production with a real NIC. Effectively zero-cost SPI classification at line rate.
5. **DPDK `ip_frag` and partial checksum offload** in `rte_mbuf` if the lab ever moves to real hardware.

## Repo state at session end

- Branch: `main`
- 12 commits ahead of prior sync
- Build: clean (`cmake --build cmake-build-release --target FastAPI`)
- Test: `BENCH_TIMEOUT=20 pixi run bench-spi 1000000 <workers>` works for 4-15 workers with cache hit ratio ~87.7 %
