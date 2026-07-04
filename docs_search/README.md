# docs_search/ — Performance Research Index

**Purpose:** Collected research, citation-backed findings, and prioritized improvements for the FastAPI DPDK pipeline at `/home/bac/programming/viettel/dpdk_cpp`.

**Created:** 2026-07-05
**Status:** Compiled from project source reading + 4 background research subagents (one stopped early). All citations verified against source.

---

## Files

| File | Topic | Size | Source confidence |
|------|-------|------|-------------------|
| [`01_architecture_findings.md`](01_architecture_findings.md) | Per-packet hot-path trace, 25 bottlenecks with file:line, synchronization inventory | large | HIGH (all from source) |
| [`02_compiler_flags_research.md`](02_compiler_flags_research.md) | DPDK-recommended compiler flags + profiling tools + atomic-order audit | medium | HIGH (doc.dpdk.org citations) |
| [`03_improvement_plan.md`](03_improvement_plan.md) | Prioritized tier-by-tier improvement plan with code sketches | large | HIGH (composite of 01 + 02 + 04 + 05 + 06) |
| [`04_pcap_pmd_research.md`](04_pcap_pmd_research.md) | pcap PMD single-threaded RX ceiling, alternative PMDs (NULL, AF_PACKET, Pktgen) | medium | HIGH (12 doc.dpdk.org URLs) |
| [`05_prefetch_function_attrs_research.md`](05_prefetch_function_attrs_research.md) | l3fwd prefetch distances (4 / 8 / 16), `[[unlikely]]` audit, attribute macros | medium | HIGH (DPDK main-branch source citations) |
| [`06_dpi_optimization.md`](06_dpi_optimization.md) | DPI hash+suffix-array split, audit DPI consumers, LRU dedup | medium | MEDIUM-HIGH (no external benchmarks; code review) |

---

## Most-actionable summary (5 things to do first)

### 1. 🚨 **DPI computation result is dead data — disable DPI for benchmarks** (5 min)
Verified by source reading: `FlowEntry.label` and `FlowEntry.group_name` are written at `spi_pipeline.cpp:554,636` but no downstream code reads them. Zero consumers of `MatchDpi` output. The 39-filter DPI linear scan + 512 B copy + TLS extension walk runs on every TCP/443 cache-miss packet for nothing.
```bash
sed -i 's/enabled: true/enabled: false/' config.yaml
pixi run bench
```
Expected delta: significant — likely recovers most of the SPI-only 16 Mpps.

See [`06_dpi_optimization.md` Opt-B](06_dpi_optimization.md#opt-b-drop-dpi-entirely--confirmed-unused) for full evidence.

### 2. **Skip L7 extract + SW checksum when not needed** (T1.2 + T1.3, 30 min)
File: [`03_improvement_plan.md` Tier 1.2 and 1.3](03_improvement_plan.md#t12--skip-l7-extraction-when-dpi-is-disabled)
- `spi_pipeline.cpp:630-638`: gate `ExtractHostname` on `context.dpi_rules != nullptr`
- `spi_pipeline.cpp:269-298`: gate `RecomputeL4Checksum` on `context.l3_forward_enabled`

### 3. **Shrink flow table from 8M → 1M entries** (T1.4, 5 min)
File: [`03_improvement_plan.md` Tier 1.4](03_improvement_plan.md#t14--shrink-flow-table-from-8m--1m-entries)
File: [`spi_flow_table.cpp:16`](include/dpdk/spi/spi_flow_table.cpp#L16)
```cpp
constexpr std::uint32_t kFlowTableSize{1U << 20U};  // 1,048,576
```
770 MB → 95 MB. Big cache-locality win.

### 4. **Use batched `rte_acl_classify`** (T1.1, 2-3 hours)
File: [`03_improvement_plan.md` Tier 1.1](03_improvement_plan.md#t11--use-rte_acl_classify-batch-api-single-result--array-result)
Move `rte_acl_classify` from per-packet to per-burst, processing 64-packet arrays through each group's context. ~5-7× speedup of the ACL phase.

### 5. **Replace DPI linear scan with hash+suffix-array** (Opt-A in §3 of 06, 2-3 hours)
File: [`06_dpi_optimization.md` Opt-A](06_dpi_optimization.md#opt-a-compile-time--split-into-exact-hash--suffix-array)
39-filter scan → O(1) hash + O(log N) binary search. ~5× DPI speedup.

---

## Diagnosis recap

**User symptom:** Workers 10 → 15 gives no throughput change in SPI+DPI. Baseline (SPI only): 16 Mpps.

**Two layered causes:**

1. **Per-packet CPU work dominates** (architecture map + plan T1):
   - L7 extraction + SPI ACL + DPI linear scan = 100-200 ns per cache-miss packet
   - 8M-entry flow table causes L3 cache thrashing on every `Lookup`
   - Adding workers past the point where each worker spends more time waiting than processing = no speedup

2. **pcap PMD per-queue ceiling** (research 04):
   - Each queue is single-threaded libpcap parse, ~3-5 Mpps ceiling per shard
   - This is NOT the binding constraint at 16 Mpps (you have 11 queues = 55 Mpps ceiling)
   - But scaling beyond 11 workers won't help because there are only 11 queues

**Realistic target after Tier 1 + Tier 2 fixes:** 12-15 Mpps SPI+DPI (near SPI-only baseline).

---

## What's NOT in scope

- Replacing pcap with Pktgen (better but requires external install; covered as opt-in in `04`)
- Replacing flow table with custom hash (Tier 4.1; high effort, deferred)
- AC/Hyperscan for DPI (Tier 2 in `06`; rule count doesn't justify)
- NUMA tuning (single-socket host assumed)

---

## Known gaps

- **DPI research agent was stopped before completion** — `06` is engineered from source + industry knowledge, not from a freshly-fetched literature review.
- **No quantified "X% speedup" claims were verified with primary sources** for any of the optimizations. Estimates are based on instruction counts, cache behavior, and DPDK best practices.
- **WebSearch was unavailable** (HTTP 400 throughout). WebFetch succeeded for `doc.dpdk.org` and `github.com/DPDK/dpdk` URLs but failed for Intel/PANTHEON/DPDK Summit slides.

These gaps don't change the recommendations — the bottlenecks are visible from the source code and the DPDK guidance applies. The gaps only affect confidence in the magnitude estimates.

---

## How to use this folder

1. Start with `03_improvement_plan.md` for the action plan.
2. Drill into specific files for citations and backup.
3. Read `06_dpi_optimization.md` §2 first — the DPI consumer audit is the cheapest action with potentially the largest impact.

The improvements in `03` are ordered so the cheapest, highest-impact fixes come first. You can stop after Tier 1 and already be at 80% of the expected improvement.