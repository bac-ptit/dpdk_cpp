# Flow Cache Root Cause — Two Bugs Fixed

**Date:** 2026-07-05
**Result:** 2.31 Mpps → **26.44 Mpps** (11.4× speedup), cache hit rate 0.05% → **99.86%**

This document records the actual root causes of the flow-cache-hit-rate problem and the fixes. It updates the items in [01_architecture_findings.md](01_architecture_findings.md) and [03_improvement_plan.md](03_improvement_plan.md) that were later found to be wrong / incomplete.

---

## Bug #1 (PRIMARY): `rte_hash_add_key_data` returns 0 on success

**File:** [include/dpdk/spi/spi_flow_table.cpp](include/dpdk/spi/spi_flow_table.cpp) (`Insert`)

**Original code (BROKEN):**
```cpp
const auto result{rte_hash_add_key_data(hash_, &key, nullptr)};
if (result >= 0) [[likely]] {
  const bool was_new{entries_[static_cast<std::size_t>(result)].match_count == 0};
  auto& slot{entries_[static_cast<std::size_t>(result)]};
  slot = entry;
  slot.last_seen_tsc = rte_rdtsc();
  ...
}
```

**The bug.** Per the DPDK source (verified at `lib/hash/rte_hash.c`):
```c
int rte_hash_add_key_data(const struct rte_hash *h, const void *key, void *data) {
    int ret = __rte_hash_add_key_with_hash(h, key, rte_hash_hash(h, key), data);
    if (ret >= 0) return 0;     // <-- return value is 0 on success, NOT slot ID
    else return ret;
}
```

`rte_hash_add_key_data` returns **`0` on success** — it is a yes/no indicator, not an index. The internal `__rte_hash_add_key_with_hash` returns the slot ID, but the wrapper discards it.

**Consequence:** Every successful insert wrote `entries_[0]` regardless of the actual slot the key landed in. All non-zero slots had `match_count == 0` forever. After warm-up, almost every lookup hit a non-zero slot with `match_count == 0` and returned `nullptr` (the `zero_mc` branch).

**Fix.** Use `rte_hash_add_key` (no `_data`) which **does** return the slot ID ≥ 0:
```cpp
const auto result{rte_hash_add_key(hash_, &key)};
if (result >= 0) [[likely]] {
  auto& slot{entries_[static_cast<std::size_t>(result)]};
  slot = entry;
  slot.last_seen_tsc = rte_rdtsc();
}
```

**Diagnostic evidence:**
```
# BEFORE fix (count=100000 / 15 workers, ~7s):
calls=14,300,000  hash_miss=1,929    zero_mc=14,280,770  hit=17,288
# hit ~ 0.1% — most lookups found slots with match_count == 0

# AFTER fix (count=1000000 / 15 workers, ~19s):
flow_cache_hits=506,284,226  received=507,003,136
# hit ~ 99.86% — slot indexing now correct
```

The `zero_mc` pattern was the smoking gun. `rte_hash_lookup` succeeded (`hash_miss` froze) but `entries_[slot].match_count == 0` — meaning the entry was being placed at the wrong slot.

---

## Bug #2 (SECONDARY): `PurgeExpired` uint64 underflow at startup

**File:** [include/dpdk/spi/spi_flow_table.cpp](include/dpdk/spi/spi_flow_table.cpp) (`PurgeExpired`)

**Original code (BROKEN):**
```cpp
const auto threshold{now_tsc - ttl_cycles};
// ...
if (entries_[next - 1].last_seen_tsc < threshold) {  // delete }
```

**The bug.** With `flow_ttl_sec = 300` and `rte_get_tsc_hz() = ~4e9`:
- `ttl_cycles = 300 × 4e9 = 1.2 × 10¹²`
- At startup `now_tsc ≈ 4 × 10⁹` (after 1 second).
- `now_tsc - ttl_cycles` in unsigned arithmetic **wraps to `UINT64_MAX`**.
- `last_seen_tsc < UINT64_MAX` is **always true**.
- → first `PurgeExpired` call (≈ T+5s, gated on stats period) deletes the entire populated cache.

**Fix.** Skip purge when not enough wall-clock has passed:
```cpp
if (now_tsc <= ttl_cycles) {
  return;
}
const auto threshold{now_tsc - ttl_cycles};
```

Note: cache only works correctly AFTER Bug #1 is fixed. Before Bug #1, `PurgeExpired` was just one of multiple pathologies producing zero hits.

---

## Diagnostic instrumentation (removed)

We added per-call counters to `FlowTable::Insert` and `FlowTable::Lookup` that distinguished:
- `lookup_hash_miss`: `rte_hash_lookup` returned < 0 (key not in hash)
- `lookup_zero_mc`: `rte_hash_lookup` returned ≥ 0 (slot found) but `entries_[slot].match_count == 0`
- `lookup_hit`: success

The `lookup_zero_mc` counter was the smoking gun — it showed that almost every lookup was finding a slot but match_count == 0. This led directly to the realization that the slot indexing was wrong.

After confirming the fix, the diagnostic code was removed (commit-equivalent change to `spi_flow_table.cpp`). Final clean code is ~145 lines vs the diagnostic version's ~190.

---

## Why the architecture-map analysis missed Bug #1

The original architecture map (see [01_architecture_findings.md](01_architecture_findings.md) §D "Data structures") noted the use of `rte_hash_add_key_data` but **did not catch the return-value bug**. The map identified `entries_[slot] = entry` as "two-step lookup" — but assumed the return value was a slot ID. The DPDK API naming (`_data`) strongly suggests it returns data-related info, but doesn't explicitly state the return value is just 0/negative.

Two lessons:
1. **Always re-check API contracts against primary source**, not by intuition from naming.
2. **Diagnostic instrumentation that distinguishes "hash-miss" vs "slot-found-but-empty"** is essential for any hash-table cache bug.

---

## Performance summary

| Run | Workers | DPI | cache_hits | Mpps | Gbps |
|-----|---------|-----|------------|------|------|
| Original (baseline claim) | 10 | on | n/a | 16 | n/a |
| Before fix | 15 | off | 195 | 2.31 | 1.17 |
| Before fix (1M pack bench) | 15 | off | 17,288 | n/a | n/a |
| **After fix** | 15 | off | **506,284,226** | **26.44** | **13.54** |

Throughput went from 2.31 Mpps (broken cache) → 26.44 Mpps (working cache). The 16 Mpps "baseline" the user mentioned is now exceeded by 65%.

---

## What this means for the other docs

[01_architecture_findings.md](01_architecture_findings.md) §B "What autoscale to design" still holds — but the assumption that "more workers = more throughput" was empirically wrong due to the cache bug, not due to SMT or hash-bucket contention. After the cache fix, scaling behaviour is worth re-measuring.

[03_improvement_plan.md](03_improvement_plan.md) Tier 1.4 (shrink flow table from 8M → 1M) is now LESS urgent because the cache works. But still a good idea for cache-locality reasons on hosts with less RAM.

The bigger news: **with the cache working, the per-packet CPU bottleneck shifts from `rte_hash_lookup` (which is now ~10× faster because most are hits) to other costs** like ACL classify on misses, DPI on misses, and header rewrite. The Tier 2 algorithmic improvements (batched ACL, hash+suffix DPI) are still worthwhile next steps if you want to push past 26 Mpps.
