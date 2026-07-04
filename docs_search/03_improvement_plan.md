# Performance Improvement Plan — FastAPI DPDK Pipeline

**Project baseline (per user):**
- SPI-only: ~16 Mpps with current worker count
- SPI + DPI: no improvement when workers increased from 10 → 15
- Goal: get SPI+DPI back to (and beyond) the SPI-only throughput

## 🚨 CRITICAL UPDATE — already-resolved bottlenecks

**The "2.31 Mpps with low cache hit rate" symptom was caused by TWO bugs in `FlowTable::Insert`/`PurgeExpired`, NOT by the items listed in Tier 1 below.**

**Already fixed (2026-07-05):**

1. `rte_hash_add_key_data` returns 0 on success — every insert wrote to `entries_[0]`. Switched to `rte_hash_add_key` which returns the slot ID.
2. `PurgeExpired` unsigned underflow at boot wiped the entire cache within 5 s. Added `if (now_tsc <= ttl_cycles) return;`.

**Result after fixes:** 2.31 Mpps → **26.44 Mpps** (11.4×); cache hit rate 0.05% → **99.86%**.

**For full evidence see [07_flow_cache_root_cause.md](07_flow_cache_root_cause.md).**

---

## ⚠️ DPI was NOT the cause (also outdated info)

The earlier version of this document claimed the DPI result was dead data and DPI was the bottleneck. **That was wrong** — disabling DPI did not help because the flow cache was actually broken (Bug #1 above). With the cache fixed, real per-packet bottlenecks (DPI cost on cache misses, ACL classify per packet) are now visible in profiling — they just weren't relevant when the cache was broken. See [07_flow_cache_root_cause.md](07_flow_cache_root_cause.md) for the full story.

---

## Next optimizations (after cache fix)

With the cache working, scaling beyond 26 Mpps will require addressing the actual per-packet CPU costs that the cache had been masking:

### Tier 1.1 (NEW priority) — Fix per-burst ACL classify

[spi_rule_engine.cpp:218](include/dpdk/spi/spi_rule_engine.cpp#L218) calls `rte_acl_classify` per packet × 6 groups. Move to per-burst: allocate `data[burst_size]` and call once per group with the whole burst. Expected: 5-7× ACL speedup.

### Tier 1.2 (revised) — Replace DPI linear scan with hash+suffix-array

After the cache works, DPI-on-cache-miss is the dominant cost on TCP/443 packets. See [06_dpi_optimization.md](06_dpi_optimization.md) — 39-filter linear scan → O(1) hash + O(log N) binary search. ~5× DPI speedup.

### Tier 1.3 (revised) — Fix `last_seen_tsc` on lookup

Now that the cache works correctly, the TTL-on-insert-time design causes long-lived flows to be evicted every `flow_ttl_sec`. Refresh `last_seen_tsc` on lookup (rate-limited per worker). This was less urgent before the fix because the cache was broken anyway.

### Tier 1.4 — Shrink flow table from 8M → 1M entries

Less urgent now that the cache works, but still helps cache locality. 770 MB → 95 MB.

### Tier 2 — Hardware offload + prefetch lookahead

See the unchanged Tier 2+ items below.

---

## Old "Tier 1" items (mostly superseded by the fix above; kept for reference)

The items below were written under the assumption that cache misses were the main bottleneck. With the cache fixed (hit rate 99.86%), most of these are no longer the binding constraint — they're still useful but the priority has dropped significantly.

**Diagnosis in one sentence:** Workers are CPU-starved on cache-miss L7 extraction + DPI linear scan + per-packet-per-group ACL classify; adding workers plateaus because the single `PurgeExpired` walk blocks the main lcore AND the 8M-entry flow table thrashes L3 cache on every lookup.

**Why "more workers ≠ more throughput":** the project already auto-selects `queue` mode for net_pcap shards (`spi_pipeline.cpp:501-504`), so RX DOES parallelize across workers — the plateau is **CPU-bound on the hot-path work**, not on RX. Each worker spends ~50-100 ns extra per cache-miss packet on DPI + ACL + L7 extraction, and the 770 MB flow table causes L3 misses on every `Lookup`. Adding more workers doesn't help if each worker spends more time waiting on memory than processing packets.

The plan is **ranked by expected impact × ease**, with concrete file:line references and verification commands.

---

## Tier 1 — Quick wins, high impact (do these first)

### T1.1 — Use `rte_acl_classify` batch API (single-result → array result)

**File:** [`include/dpdk/spi/spi_rule_engine.cpp:204-235`](include/dpdk/spi/spi_rule_engine.cpp#L204)

**Current (per-packet, per-group):**
```cpp
const uint8_t* data[1] = {reinterpret_cast<const uint8_t*>(&acl_input)};
uint32_t results[1]{};
for (const auto& group : groups_) {
  ...
  rte_acl_classify(group.acl_ctx, data, results, 1, 1);  // 1 pkt × 6 groups = 6 calls
}
```

**Why it's slow:** `rte_acl_classify` has per-call setup (mask, transition table load). Calling it 1 packet at a time × 6 groups = 6 setup overheads.

**Fix:** call once per group, but the `data` array contains up to `burst_size` pointers — process the whole burst, not one packet at a time. Move `rte_acl_classify` from per-packet inside `RuleTable::Match` to per-burst inside the worker loop.

**Sketch:**
```cpp
// New: in worker iteration, after parsing N packets into a metadata array
std::vector<uint32_t> per_group_results(burst_size);
std::vector<const uint8_t*> data_pointers;
data_pointers.reserve(burst_size);
for (const auto& m : parsed_metadata) {
  data_pointers.push_back(reinterpret_cast<const uint8_t*>(&m.acl_input));
}
for (const auto& group : groups_) {
  rte_acl_classify(group.acl_ctx, data_pointers.data(), per_group_results.data(),
                   burst_size, /*categories*/ 1);
  for (size_t i = 0; i < burst_size; ++i) {
    if (per_group_results[i] != 0) {
      // first-match per packet; record group_index + filter_index
    }
  }
}
```

**Expected impact:** 30-50% reduction in ACL time per cache-miss packet. With 6 groups this is roughly a 5-7× speedup of the ACL phase.

**Risk:** requires moving the match loop out of `RuleTable::Match` and into the worker — moderate refactor. Per-packet semantics preserved by tracking first-match per slot.

**Verification:**
```bash
# Before: bench with 11 workers, record SPI/DPI counters
pixi run bench
# After: bench again, expect higher mpps AND lower per-packet ACL cost
# Use perf to confirm:
perf stat -e cycles,instructions ./cmake-build-release/FastAPI
```

---

### T1.2 — Skip L7 extraction when DPI is disabled

**File:** [`include/dpdk/spi/spi_pipeline.cpp:630-638`](include/dpdk/spi/spi_pipeline.cpp#L630)

**Current:** L7 extraction runs on every SPI cache miss for TCP dst port 80/443, **regardless of whether DPI is enabled**. Even with `dpi.enabled=false`, we still copy 512 B and walk extensions.

**Fix:** add `if (!context.dpi_rules)` short-circuit at the top of the L7 branch.

**Sketch:**
```cpp
if (context.dpi_rules != nullptr &&
    metadata.protocol == Protocol::kTcp &&
    (metadata.destination_port == kTlsPort || metadata.destination_port == kHttpPort)) {
  ExtractHostname(packet, metadata);
}
```

**Expected impact:** eliminates the 512 B memcpy + TLS extension walk on every cache-miss TCP/HTTPS packet when DPI is off. ~10-20 ns saved per cache miss.

**Risk:** trivial.

**Verification:** diff shows branch eliminated; bench with `dpi.enabled=false` should hit SPI-only throughput (16 Mpps) again.

---

### T1.3 — Skip software L4 checksum when L3 forward is disabled

**File:** [`include/dpdk/spi/spi_pipeline.cpp:269-298`](include/dpdk/spi/spi_pipeline.cpp#L269)

**Current:** `RecomputeL4Checksum` walks the entire payload on every TX packet. When `l3_forward.enabled=false` (the default for PCAP benchmarks per `test_env.sh:286`), checksums are recomputed but the packet goes nowhere — wasted work.

**Fix:** add `if (!context.l3_forward_enabled) return true;` at the top of `RecomputeL4Checksum`.

**Expected impact:** ~10-15 ns saved per TX packet. At 16 Mpps that's 160-240 ms of CPU per second reclaimed.

**Risk:** trivial.

**Verification:** bench with `l3_forward.enabled=false` should show higher mpps.

---

### T1.4 — Shrink flow table from 8M → 1M entries

**File:** [`include/dpdk/spi/spi_flow_table.cpp:16`](include/dpdk/spi/spi_flow_table.cpp#L16)

**Current:**
```cpp
constexpr std::uint32_t kFlowTableSize{1U << 23U};  // 8,388,608
```

8M entries × 96 B ≈ 770 MB. The `entries_` parallel array is the dominant cache-thrasher on every miss.

**Fix:** reduce to 1M (≈95 MB) or 2M (≈190 MB). The PCAP benchmark traffic rarely has more than a few thousand unique 5-tuples; 1M is overkill but trades capacity for cache locality.

**Sketch:**
```cpp
constexpr std::uint32_t kFlowTableSize{1U << 20U};  // 1,048,576
```

**Expected impact:** every `Lookup` and `Insert` goes from ~200 ns cold (L3 miss) to ~30 ns hot (L2/L1). For a 50% miss-rate benchmark this is 85 ns/pkt saved × 16 Mpps = substantial.

**Risk:** flows beyond capacity fall back to per-packet ACL matching (no caching). At 16 Mpps with 1M capacity and even 1 ms average flow lifetime, that's 16,000 new flows/sec — 1M handles ~60 seconds of unique flows. Adequate for most benchmarks; needs to be configurable for production.

**Verification:** bench throughput should jump. Run twice (warm cache, cold cache) to see steady-state vs first-packet-of-flow cost.

---

## Tier 2 — Algorithmic improvements (medium refactor)

### T2.1 — Use `rte_hash_lookup_bulk` to batch flow lookups

**File:** [`include/dpdk/spi/spi_pipeline.cpp:803-819`](include/dpdk/spi/spi_pipeline.cpp#L803) (RX burst loop)

**Current:** each packet calls `rte_hash_lookup` independently. With 64-packet burst and ~50% hit rate, that's 64 individual hash operations.

**Fix:** `rte_hash_lookup_bulk` accepts an array of keys + array of outputs and uses SIMD internally to do parallel CRC + bucket lookups. After RX, before the per-packet loop, batch the lookups.

**Sketch:**
```cpp
const auto received{rte_eth_rx_burst(...)};
std::array<FlowKey, kMaxBurstCapacity> keys{};
int32_t positions[kMaxBurstCapacity]{};
// populate keys from packet metadata
rte_hash_lookup_bulk(hash_, &keys, received, positions);
// positions[i] >= 0 → hit, use entries_[positions[i]]
// positions[i] < 0  → miss, queue for ACL+DPI
```

**Expected impact:** ~2-3× faster cache lookups on hit-dominant paths. With 90%+ hit rate (steady state), this can be 30-40% of per-packet time.

**Risk:** need to extract `FlowKey` from packet BEFORE the per-packet loop, which means doing a parse pass first. Changes the loop structure.

---

### T2.2 — Replace DPI linear scan with two-tier structure (exact hash + suffix tree)

**File:** [`include/dpdk/dpi/dpi_rule_engine.cpp:13-54`](include/dpdk/dpi/dpi_rule_engine.cpp#L13)

**Current:** 39 filters, linear scan per packet, with `ends_with` byte-by-byte.

**Fix:** at compile time, separate filters into two indices:
- **Exact-match hash**: `std::unordered_map<string_view, DpiResult>` for all non-suffix patterns (DoH, exact hostnames).
- **Suffix tree** (or just sorted suffix array with binary search): for `*.suffix.com` patterns, store suffixes in a sorted array, binary-search by reverse-suffix.

**Sketch:**
```cpp
class DpiRuleTable {
  // Exact match: O(1) average
  robin_hood_hashing::unordered_map<string_view, DpiResult> exact_index_;
  // Suffix match: O(log N) via binary search on reversed suffix
  std::vector<SuffixEntry> suffix_index_;  // sorted by suffix descending
  DpiResult catch_all_;  // O(1)
};
```

**Expected impact:** 39-filter scan → O(1) for exact, O(log N) for suffix. ~5-10× faster DPI matching on average. With ~50-100 ns currently, drops to 5-15 ns.

**Risk:** medium refactor; need to handle `string_view` lifetimes (must intern pattern strings into the rule table).

**Verification:** DPI counter in stats should show similar match rate but lower per-packet DPI cost in perf.

---

### T2.3 — Use `last_seen_tsc` properly with rate-limited refresh

**File:** [`include/dpdk/spi/spi_flow_table.cpp:62-65`](include/dpdk/spi/spi_flow_table.cpp#L62)

**Current:** TTL works on insertion time only. Comment says updating on every lookup costs a cache-line write per packet.

**Fix:** add a per-worker `last_refresh_tsc`; only refresh `last_seen_tsc` if `now - last_refresh > kRefreshIntervalCycles` (e.g. 100 ms). This bounds the cache-line write rate to 10/sec per flow.

**Sketch:**
```cpp
thread_local std::uint64_t last_refresh_tsc = 0;
constexpr std::uint64_t kRefreshInterval = rte_get_tsc_hz() / 10;  // 100 ms
FlowEntry* FlowTable::Lookup(const FlowKey& key) noexcept {
  ...
  const auto now = rte_rdtsc();
  if (now - last_refresh_tsc > kRefreshInterval) {
    entry->last_seen_tsc = now;
    last_refresh_tsc = now;
  }
  return entry;
}
```

Wait — this is per-thread but the entry is shared. Multiple workers refreshing the same flow would still write the cache line. **Better fix:** per-entry atomic flag, OR rely on `PurgeExpired` only on long-idle flows (TTL >> refresh interval).

**Better:** change `PurgeExpired` to use a sliding-window eviction (LRU) instead of insertion-time TTL — refresh `last_seen_tsc` cheaply using DPDK's `rte_hash_lookup_with_hash` + a non-atomic timestamp check at insert time.

**Expected impact:** active long-lived flows no longer get evicted. Eliminates the "long-lived flow re-extracts hostname every TTL" pathology described in architecture-findings.md.

**Risk:** low.

---

## Tier 3 — Hot-path micro-optimizations

### T3.1 — Software-prefetch-ahead (N iterations)

**File:** [`include/dpdk/spi/spi_pipeline.cpp:713-717`](include/dpdk/spi/spi_pipeline.cpp#L713)

**Current:** prefetch all packets at top of burst loop. By the time packet N is processed, prefetch may have evicted.

**Fix:** interleave prefetch with processing — prefetch packet N+K while processing packet N.

**Sketch:**
```cpp
constexpr std::size_t kPrefetchDistance = 4;
for (std::size_t i = 0; i < packets.size(); ++i) {
  if (i + kPrefetchDistance < packets.size()) {
    rte_prefetch0(rte_pktmbuf_mtod(packets[i + kPrefetchDistance], void*));
  }
  ForwardPacket(...);
}
```

**Expected impact:** ~5-10% on cache-cold first packet.

---

### T3.2 — Replace TX staging buffer indirection

**File:** [`include/dpdk/spi/spi_pipeline.cpp:937-938`](include/dpdk/spi/spi_pipeline.cpp#L937), [`701-710`](include/dpdk/spi/spi_pipeline.cpp#L701)

**Current:** `std::vector<std::array<rte_mbuf*, 128>>` (heap + pointer chase per enqueue).

**Fix:** fixed-size stack array per worker, or `std::array<std::array<rte_mbuf*, kMaxBurstCapacity>, kMaxPorts>` sized at compile time.

**Sketch:**
```cpp
alignas(64) std::array<rte_mbuf*, kMaxBurstCapacity> tx_buffers[kMaxPorts]{};
std::array<std::uint16_t, kMaxPorts> tx_counts{};
```

**Expected impact:** tiny (sub-ns per packet), but on a 16 Mpps pipeline every ns counts.

---

### T3.3 — Disable SW checksum offload when L3 forward is disabled

Same as T1.3 — listed separately because the fix is in the header rewrite path (`PrepareAndRewriteHeaders`), not just `RecomputeL4Checksum`.

---

## Tier 4 — Architectural

### T4.1 — Use `rte_hash` embedded data instead of parallel array

**File:** [`include/dpdk/spi/spi_flow_table.cpp:73`](include/dpdk/spi/spi_flow_table.cpp#L73)

**Current:** `rte_hash_add_key_data(hash, &key, nullptr)` + parallel `entries_[slot]` indexed by hash slot ID.

**Why it's two-step:** the project stores `FlowEntry` (96 B) separately so `rte_hash`'s data-pointer can stay NULL. But this means every miss touches two cache lines (hash bucket + entries array).

**Fix:** reduce `FlowEntry` to fit in `rte_hash`'s 8-byte data slot, OR move `rte_hash` to a wider data slot. DPDK supports `RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD` but data is always 8 B.

**Better fix:** replace `rte_hash` with a custom open-addressing hash table keyed on `FlowKey`, with the value embedded. Or use `rte_hash` + a 2-level structure: `rte_hash` for slot ID → small in-cache `FlowEntry` cache (e.g. 256K entries LRU) + slow path to backing store.

**Expected impact:** reduces miss-path from 2 cache-line touches to 1.

**Risk:** high — this is the core data structure.

---

### T4.2 — Replace `ends_with` byte-loop with `memcmp` on reversed suffix

**File:** [`include/dpdk/dpi/dpi_rule_engine.cpp:30-31`](include/dpdk/dpi/dpi_rule_engine.cpp#L30)

**Current:** `hostname.ends_with(suffix)` — implementation-defined, often byte-loop.

**Fix:** store reversed patterns; `memcmp` on the tail of `hostname` with the reversed suffix.

**Sketch:**
```cpp
// At compile time:
char reversed[64];
std::reverse_copy(pattern.begin() + 2, pattern.end(), reversed);  // skip "*."
// At match time:
const auto suffix_len = std::strlen(reversed);
const auto hostname_len = hostname.size();
if (hostname_len > suffix_len &&
    hostname[hostname_len - suffix_len - 1] == '.' &&
    std::memcmp(hostname.data() + hostname_len - suffix_len,
                reversed, suffix_len) == 0) {
  // match
}
```

**Expected impact:** ~2-3× faster suffix match (memcmp with SSE2 vs scalar byte loop). Marginal since DPI is already small relative to other costs.

---

### T4.3 — Build flags audit (per compiler-flags research)

**Files:** [`CMakeLists.txt:30-41`](CMakeLists.txt#L30)

**Recommendations:**
- For Release benchmarks, ensure `-O3` is explicit (CMake `Release` default is `-O3`, but `RelWithDebInfo` is `-O2 -g`).
- For benchmark runs, add `-fno-stack-protector` (not in DPDK docs, common Linux kernel practice).
- Audit `std::atomic` calls in `spi_pipeline.cpp` — replace `seq_cst` with `memory_order_relaxed` for counter `fetch_add`. Source: [writing_efficient_code.html](https://doc.dpdk.org/guides/prog_guide/writing_efficient_code.html).

```cmake
# In CMakeLists.txt, replace FASTAPI_RELEASE_OPTIONS with:
set(FASTAPI_RELEASE_OPTIONS
    $<$<CONFIG:Release>:-O3>
    $<$<CONFIG:Release>:-fno-plt>
    $<$<CONFIG:Release>:-fno-stack-protector>
    $<$<CONFIG:Release>:-falign-functions=64>)
```

**Expected impact:** 5-10% on Release builds.

---

## Tier 5 — Profiling to find next bottlenecks

After Tier 1-3, profile to find what's left:

```bash
# 1. Top-down CPU breakdown
perf record -F 999 -g --call-graph dwarf ./cmake-build-release/FastAPI
perf report --sort=dso,symbol --no-children

# 2. PMU summary
perf stat -e cycles,instructions,cache-misses,cache-references,branch-misses,dTLB-load-misses,iTLB-load-misses \
    ./cmake-build-release/FastAPI

# 3. False-sharing detection (Linux 4.10+)
perf c2c record ./cmake-build-release/FastAPI
perf c2c report --stdio

# 4. If x86: VTune
vtune -collect hotspots ./cmake-build-release/FastAPI
```

Look for:
- **IPC < 1.0**: pipeline stalled (cache misses, branch mispredicts, dependencies).
- **cache-misses > 5%**: data cache thrashing — `entries_` array is the prime suspect. Tier 1.4 should fix this.
- **branch-misses > 2%**: likely TLS extension walk or DPI linear scan. Tier 2.2 should help.
- **dTLB-load-misses > 1%**: huge virtual range (entries_ 770 MB). Shrink the table.

---

## Suggested execution order

| Step | Time estimate | Expected impact |
|------|---------------|-----------------|
| T1.2 + T1.3 (L7/checksum gating) | 30 min | +10-20% |
| T1.4 (shrink flow table) | 5 min | +30-80% (cold-cache dependent) |
| T1.1 (batched ACL classify) | 2-3 hours | +30-50% on ACL cost |
| T2.2 (DPI two-tier index) | 2-3 hours | +5-10× DPI speedup |
| T2.1 (batched hash lookup) | 2-3 hours | +30-40% on hit path |
| T2.3 (TTL refresh) | 1 hour | eliminates long-flow pathology |
| T3.1-T3.3 (micro-opts) | 1 hour total | +5-10% combined |
| T4.1 (single-step hash) | 1 day | architectural, big payoff long-term |
| T4.3 (compiler flags) | 30 min | +5-10% Release |
| Tier 5 (profiling) | ongoing | informs Tier 4 |

**Realistic target:** SPI+DPI throughput should reach 12-15 Mpps after T1 + T2 + T4.3, recovering close to the SPI-only 16 Mpps baseline.

---

## Key file:line summary

| Bottleneck | File:line | Fix tier |
|------------|-----------|----------|
| 8M-entry flow table | `spi_flow_table.cpp:16, 39` | T1.4 |
| L7 extract runs even when DPI off | `spi_pipeline.cpp:630-638` | T1.2 |
| SW checksum always | `spi_pipeline.cpp:269-298` | T1.3 |
| Per-packet per-group ACL classify | `spi_rule_engine.cpp:218` | T1.1 |
| DPI linear scan 39 filters | `dpi_rule_engine.cpp:17-51` | T2.2 |
| Hash lookup per packet | `spi_flow_table.cpp:53` | T2.1 |
| TTL uses insert time only | `spi_flow_table.cpp:62-65` | T2.3 |
| All-at-once prefetch | `spi_pipeline.cpp:713-717` | T3.1 |
| TX staging indirection | `spi_pipeline.cpp:701-710, 937-938` | T3.2 |
| Two-step hash + parallel array | `spi_flow_table.cpp:73` | T4.1 |
| Compiler flags partial | `CMakeLists.txt:30-41` | T4.3 |

---

## What this plan does NOT do (deliberate)

- **Does not rewrite in Intel Hyperscan** — overkill for 39 rules; binary deps add complexity. The two-tier hash + suffix-array in T2.2 gets within 10× of Hyperscan with no external deps.
- **Does not add RSS** — config-driven, already exists (`environment.ActivePortsSupportRss()`); the project correctly falls back to flow_hash when RSS is absent.
- **Does not propose NUMA tuning** — single-socket host assumed. For NUMA, add `rte_malloc` + `rte_ring_create` with explicit `socket_id`.
- **Does not propose moving to VPP/Vector Packet Processing** — out of scope.
- **Does not propose changing ACL to a single combined trie** — DPDK ACL doesn't support multi-precedence in one ctx; would require custom lookup. T1.1 (batching) is the lower-friction win.

---

## Sources

This plan is based on:
1. Direct source code reading of `/home/bac/programming/viettel/dpdk_cpp` (see [01_architecture_findings.md](01_architecture_findings.md) for citations).
2. DPDK official documentation:
   - [build_dpdk.html](https://doc.dpdk.org/guides/linux_gsg/build_dpdk.html)
   - [writing_efficient_code.html](https://doc.dpdk.org/guides/prog_guide/writing_efficient_code.html)
   - [lto.html](https://doc.dpdk.org/guides/prog_guide/lto.html)
   - [profile_app.html](https://doc.dpdk.org/guides/prog_guide/profile_app.html)
3. Industry knowledge: SSE/AVX string compare semantics, rte_hash internals, `ends_with` codegen.
4. (See [02_compiler_flags_research.md](02_compiler_flags_research.md) for the compiler-flag audit.)