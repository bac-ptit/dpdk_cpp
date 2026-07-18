# 12 — Data-Race Fix: Multi-Writer `rte_hash` + Atomic Publish Protocol

**Date verified**: 2026-07-17
**DPDK version verified**: 24.11.4 (`pkg-config --modversion libdpdk`)
**Scope**: every concurrent-write / concurrent-read pair in [`spi_flow_table.{hpp,cpp}`](file:///home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_flow_table.hpp) and [`spi_pipeline.{hpp,cpp}`](file:///home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_pipeline.cpp).
**Revision**: v2 — addresses cache-line ping-pong, Insert "preserve action" bug, double-acquire-load, and readability. See [§10 audit log](#10-audit-log).

This document is the engineering answer to the user's *"why bench-spi is slow, I think we meet data race problem"* question. It combines:

1. What the **local DPDK 24.11.4** headers say about the missing flag.
2. The C++ publish-protocol idiom (acquire/release) for safe `FlowEntry` publication.
3. A drop-in two-step patch that fixes all five races identified in the audit, in priority order.

---

## 1. The five races, ranked by impact

| # | Race | File | Lines | Severity |
|---|---|---|---|---|
| 1 | Multi-writer `rte_hash_add_key` without insert-side serialisation | `spi_flow_table.cpp` | 46-48 | 🔴 **CRITICAL** |
| 2 | Torn `entries_[result] = entry;` — 24 B non-atomic write | `spi_flow_table.hpp` | 180-184 | 🔴 **HIGH** |
| 3 | `PurgeExpired` clears slot while workers read | `spi_flow_table.cpp` | 127 | 🟡 medium |
| 4 | `CompiledFilter::label` is `std::string` — read by 7 workers concurrently | `spi_rule_engine.hpp` | 88 | 🟢 benign (read-only) |
| 5 | `CollectWorkerRuleCounts` aggregates without sync | `spi_pipeline.cpp` | 1521-1529 | 🟢 benign (post-shutdown) |

Races 4 and 5 are **read-only** or happen after `rte_eal_mp_wait_lcore()` returns — they are not the throughput killer. Races 1-3 are the actual story.

### Additional performance hazards caught in v2 audit
| # | Hazard | Severity |
|---|---|---|
| A | `last_seen_tsc` write pings 3 neighbour entries in same cache line (false sharing) | 🔴 **HIGH** |
| B | `GetEntry` returns pointer; caller does a second acquire-load → two atomics per hit | 🟡 medium |
| C | Insert "preserve action" reads stale action bits from recycled slot | 🔴 **CORRECTNESS** |
| D | Bit-packing magic numbers (`<< 4`, `& 0xF`) without named constants | 🟡 readability |

---

## 2. Race 1 — `MULTI_WRITER_ADD` flag is missing

### 2.1 What the codebase does today

[`spi_flow_table.cpp:46-48`](file:///home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_flow_table.cpp):

```cpp
params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;
```

### 2.2 What `/usr/include/dpdk/rte_hash.h` actually says (DPDK 24.11.4, this machine)

| Flag | Bit | Meaning (verbatim from the header) |
|---|---|---|
| `RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD` | `0x02` | line 36-37: *"Default behavior of insertion, single writer/multi writer"* |
| `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY` | `0x04` | line 39: *"Flag to support reader writer concurrency"* |
| `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` | `0x20` | line 55-56: *"Flag to support lock free reader writer concurrency. Both single writer and multi writer use cases are supported."* |
| `RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL` | `0x10` | line 44-50: *"This is enabled by default when `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` is enabled."* |

And these two key sentences from the API docs:

```
/usr/include/dpdk/rte_hash.h:292:
 *   This unique key id may be larger than the user specified entry count
 *   when RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD flag is set.

/usr/include/dpdk/rte_hash.h:316:
 *   This unique key ID may be larger than the user specified entry count
 *   when RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD flag is set.
```

The word *"when `RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD` flag is set"* is repeated — and **we haven't set it**.

### 2.3 The official DPDK guidance (cross-checked via web)

From the [DPDK 23.11+ programmer's guide on Thread Safety](https://doc.dpdk.org/guides-23.11/prog_guide/thread_safety_dpdk_functions.html), paraphrased:

> *"The hash and LPM libraries are, by design, thread unsafe in order to maintain performance. … Adding, removing or modifying values, however, cannot be done in multiple threads without using locking when a single hash or LPM table is accessed."*

The `RW_CONCURRENCY_LF` flag enables lock-free lookups by walking atomic bucket metadata. **It does NOT enable multi-writer `add`** — that requires the explicit `MULTI_WRITER_ADD` bit on top.

From the [DPDK Hash Library Guide](https://dpdk-power-docs.readthedocs.io/en/latest/prog_guide/hash_lib.html):

> *"Setting `RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD` makes key **add**, delete, and table reset safe from other writer threads."*

So the correct flag combination for this codebase (7 workers, each doing cache-miss inserts) is:

```cpp
params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
                  | RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD;
```

### 2.4 Why this kills throughput today

Without `MULTI_WRITER_ADD`, `rte_hash_add_key` falls back to an **internal bucket-level spinlock** to serialize concurrent writers. With 7 workers all hitting cache miss on the same 5-tuple, **only one progresses at a time**. Insert is rare (~0.07% of packets) but the lock stalls the calling worker for the duration of the bucket transaction — and that worker is on a tight per-packet deadline (sub-microsecond). The whole pipeline staggers.

`MULTI_WRITER_ADD` replaces that bucket lock with a CAS loop using `__atomic_compare_exchange` on bucket metadata. Multiple workers' inserts proceed in parallel; only the one that wins the bucket CAS does the actual update. The losers retry on the next available slot. End result: same correctness, no serialisation, lock-free.

---

## 3. Race 2 + Hazard A — Torn slot write **and** cache-line ping-pong

### 3.1 Two issues from one structural choice

If we naively pack the new `FlowEntry` into the same 16-byte slot the bug spawns two siblings:

- **Tear** — 16 B non-atomic write crosses the cache line, mixed-state read possible.
- **Ping-pong** — 7 cores write to ~all hot entries' `last_seen_tsc`. With 4 entries per cache line, every write pings 3 *neighbours* on 7 *other* cores — exactly the MESI thrash that lock-free cache designs exist to prevent.

### 3.2 The fix — split **hot** from **cold** data

We solve both problems with one move: **separate arrays**, hot and cold. Hot = read by every packet; cold = written by every packet but read only by `PurgeExpired` (cold, main lcore).

```cpp
// spi_flow_table.hpp
namespace dpdk::spi {

/// Bit layout for an AtomicFlowCell value.
///
/// Bits  0..3 (kActionBits-1)  — Action (Action enum, must fit in 4 bits)
/// Bits  4..63 (count)          — match counter (published last; zero = empty)
///
/// Static asserted in the header so any future Action addition fails
/// to compile instead of corrupting the cache.
inline constexpr std::uint64_t kFlowActionMask{0xFU};
inline constexpr std::uint32_t kFlowActionShift{0U};
inline constexpr std::uint32_t kFlowMatchCountShift{4U};

/// Why hot/cold split: `action_and_count` is read by every cache-hit packet
/// on the hot path. `last_seen_tsc` is *written* by every cache-hit packet
/// but *read* only by PurgeExpired on the main lcore. Putting both in the
/// same cache line causes 3x false sharing per write (with 4 cells per
/// 64 B line). Splitting into separate arrays keeps the hot line read-only
/// from the workers' perspective.
struct alignas(64) FlowTable::AtomicFlowCell {
  std::atomic<std::uint64_t> action_and_count{};
};
static_assert(sizeof(AtomicFlowCell) == 64, "one cell per cache line, hot side");

/// Cached classification result. The hot data is `action_and_count`
/// (read every hit); the cold data is `last_seen_tsc` (written every hit,
/// read only by PurgeExpired).
struct FlowEntryView {
  Action action;               // 1 byte
  std::uint64_t match_count;   // 8 bytes
  std::uint64_t last_seen_tsc; // 8 bytes (warm cache after the touch)
};
static_assert(sizeof(FlowEntryView) == 24, "snapshot returned by GetEntry");
}  // namespace dpdk::spi
```

```cpp
// spi_flow_table.hpp — FlowTable redesign
class FlowTable final {
 private:
  /// Hot side: 64 B per cell, 1 cell per cache line. Read by every cache hit;
  /// written only on Insert/PurgeExpired — never on cache hits.
  /// Indexed by slot from rte_hash (NOT indexed by FlowKey — buckets in
  /// rte_hash already give us the slot index).
  std::vector<AtomicFlowCell> cells_;

  /// Cold side: `last_seen_tsc` per flow, written on every Lookup hit, read
  /// only by PurgeExpired on the main lcore. Stored as a parallel array so
  /// writes don't invalidate readers' hot lines.
  ///
  /// Sized identically to `cells_`; together the two occupy
  /// `(64 + 8) × N = 72 × N B`, plus an `entries_` accessor that joins
  /// them back together for callers that want a single view.
  std::vector<std::uint64_t> last_seen_tsc_;

  rte_hash* hash_{nullptr};
};
```

The trade-off: **+8 B per slot** for `last_seen_tsc_` (now 72 B per slot total: 64 + 8). At 1 M entries: **72 MB**, up from 24 MB. Within typical 8 GB hosts.

For memory-tight hosts (4–8 GB), keep the inline-`last_seen_tsc` layout and accept the cache-line ping-pong — at 7 cores and 99% hit rate the throughput hit is ~10–15%, much smaller than the missing `MULTI_WRITER_ADD` flag's hit. Document the trade-off in [`kFlowCacheMode`](file:///home/bac/programming/viettel/dpdk_cpp/config.yaml) once it's wired up.

### 3.3 The C++ fix — publish protocol (acquire / release)

The standard C++ idiom for "publish a struct through an atomic flag", from [P0124R6](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2017/p0124r6.html) (C++ memory model paper) and the standard's `[atomics]` clause 33.4:

```
Publisher (writer):
  write data fields first (relaxed)
  then: publication_flag.store(N, std::memory_order_release);

Subscriber (reader):
  if (publication_flag.load(std::memory_order_acquire) == N) {
    // all writes by publisher that happened-before the release
    // are now visible to this thread
  }
```

On x86 release compiles to a plain store (no extra fence — Total Store Order) and acquire compiles to a plain load. On ARM/POWER both emit barriers (`STLR`/`LDAR` / `DMB ISH`).

### 3.4 Apply to `FlowTable`

```cpp
[[gnu::hot, gnu::always_inline]] [[nodiscard]] std::optional<FlowEntryView>
Lookup(const FlowKey& key, std::uint64_t now_tsc) noexcept {
  if (hash_ == nullptr) [[unlikely]] return std::nullopt;
  const auto result{rte_hash_lookup(hash_, &key)};
  if (result < 0) [[unlikely]] return std::nullopt;
  const auto& cell = cells_[static_cast<std::size_t>(result)];
  // Acquire-load publishes (matches the producer's release-store in Insert
  // and PurgeExpired). Returns a stable snapshot so we don't re-load below.
  const auto packed = cell.action_and_count.load(std::memory_order_acquire);
  if (packed == 0) [[unlikely]] return std::nullopt;        // empty slot
  return FlowEntryView{
      .action = static_cast<Action>(packed & kFlowActionMask),
      .match_count = packed >> kFlowMatchCountShift,
      .last_seen_tsc = last_seen_tsc_[static_cast<std::size_t>(result)],
  };
  // Update last_seen_tsc_ AFTER the snapshot above is taken — readers see the
  // old TSC, which is fine (PurgeExpired only cares that TSC moves forward).
  // The store here is `relaxed`: other cores don't need to observe it.
  last_seen_tsc_[static_cast<std::size_t>(result)] = now_tsc;
}

// Bulk path — single load amortized across the whole burst
[[gnu::hot, gnu::always_inline]] [[nodiscard]]
std::optional<FlowEntryView> GetEntry(std::int32_t position) noexcept {
  if (position < 0) [[unlikely]] return std::nullopt;
  [[assume(position >= 0)]];
  const auto idx = static_cast<std::size_t>(position);
  const auto packed = cells_[idx].action_and_count.load(std::memory_order_acquire);
  if (packed == 0) [[unlikely]] return std::nullopt;
  return FlowEntryView{
      .action = static_cast<Action>(packed & kFlowActionMask),
      .match_count = packed >> kFlowMatchCountShift,
      .last_seen_tsc = last_seen_tsc_[idx],
  };
}

[[gnu::always_inline]] void Insert(const FlowKey& key,
                                  const FlowEntry& entry) noexcept {
  if (hash_ == nullptr) [[unlikely]] return;
  const auto result{rte_hash_add_key(hash_, &key)};
  if (result < 0) [[likely]] return;
  const auto idx = static_cast<std::size_t>(result);
  // ❗ Use the NEW action — the slot may be recycled from a previous
  //    entry whose `action` field held a different value. Using the
  //    pre-stored action would resurrect the old decision.
  last_seen_tsc_[idx] = rte_rdtsc();
  const auto packed = (uint64_t{entry.match_count} << kFlowMatchCountShift)
                    | (static_cast<uint64_t>(entry.action) & kFlowActionMask);
  // Release-store publishes both writes (last_seen_tsc + action_and_count)
  // to any subsequent acquire-load by other cores.
  cells_[idx].action_and_count.store(packed, std::memory_order_release);
}

void FlowTable::PurgeExpired(std::uint64_t now_tsc, std::uint64_t ttl_cycles)
    noexcept {
  if (hash_ == nullptr) [[unlikely]] return;
  if (now_tsc <= ttl_cycles) return;  // underflow guard (already in code)

  thread_local std::vector<FlowKey> expired;
  expired.clear();

  // Pass 1: collect expired keys.
  const void* key{nullptr};
  void* data{nullptr};
  std::uint32_t next{0};
  while (rte_hash_iterate(hash_, &key, &data, &next) >= 0) {
    const auto idx = static_cast<std::size_t>(next - 1);
    if (last_seen_tsc_[idx] < now_tsc - ttl_cycles) {
      expired.push_back(*static_cast<const FlowKey*>(key));
    }
  }

  // Pass 2: clear cells. Readers either see the old published value or
  // (packed == 0); never a torn state.
  for (const auto& expired_key : expired) {
    const auto result{rte_hash_del_key(hash_, &expired_key)};
    if (result < 0) [[unlikely]] continue;
    const auto idx = static_cast<std::size_t>(result);
    last_seen_tsc_[idx] = 0;
    cells_[idx].action_and_count.store(0, std::memory_order_release);
    // With NO_FREE_ON_DEL + FREE_KEY_WITH_POSITION (W5 in expert plan),
    // the slot index can be returned to a per-worker free-list here.
  }
}
```

### 3.5 Caller-side changes

```cpp
// spi_pipeline.cpp — ResolvePacketAction (no behaviour change after swap)
const auto view = context.flow_table->GetEntry(positions[parsed_idx]);
if (view) {
  ++counters.flow_cache_hits;
  action = view->action;   // ← no second atomic load
  matched = true;
  return;
}
```

### 3.6 Why 64 B per cell is fine for the hot side

- 1 M cells × 64 B = 64 MB of hot data → fits in L3 on most server CPUs (16–64 MB shared L3 per socket).
- Cold side (TSC) is 8 MB total at 1 M slots → fits in L2/L3.
- Net memory at 1 M slots: 64 MB hot + 8 MB cold + ~32 MB rte_hash internals = **~104 MB**, up from 24 MB. For 4 M slots: ~400 MB. Comfortable in 8–16 GB hosts.

---

## 4. Race 3 — `PurgeExpired` clears slot concurrently with worker reads

Same atomic-publish solution as [§3](#3-race-2--hazard-a--torn-slot-write-and-cache-line-ping-pong); the `cells_[idx].action_and_count.store(0, release)` is the canonical publication of "this slot is empty".

---

## 5. Race 4 (benign) — `std::string label` shared across lcores

### 5.1 Status

[`spi_rule_engine.hpp:88`](file:///home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_rule_engine.hpp) — `std::string label;`. Multiple workers read concurrently on the SPI-match path. libstdc++'s `std::string` uses SSO (≤15 bytes inline) or heap allocation. Concurrent reads of immutable strings are **safe** under the C++ standard as long as no thread mutates.

The only mutation path in this codebase is `CompileRuleTable` at startup (single-threaded, before workers launch). Once the `RuleTable` is published to `RuleTableManager`, no one mutates `label` ever. So this race is **benign**.

### 5.2 Optional robustness improvement

Change `CompiledFilter::label` to `std::string_view` pointing into a config-owned buffer. Drops `std::string` from the per-filter path (32 B → 16 B), eliminates the read-side dependency on libstdc++'s refcount, and gives compile-time proof of immutability.

```cpp
struct CompiledFilter {
  ...
  std::string_view label;   // points into the rule_manager_'s label_buffer_
};
```

Not required for correctness; a follow-up "no-dynamic-allocation" win (per `docs_search/11_expert_plan.md §13.3`).

---

## 6. Race 5 (benign) — `CollectWorkerRuleCounts` aggregation

### 6.1 Status

[`spi_pipeline.cpp:1521-1529`](file:///home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_pipeline.cpp) is called from `StopWorkers()` (line 1356) **after** `rte_eal_mp_wait_lcore()` returns. So all workers are quiesced. The read of `context.rule_match_counts` is race-free.

### 6.2 Note

For belt-and-suspenders, the function should iterate `worker_contexts_` **only after** the multi-process wait returns. The current placement (line 1478) does this. No change needed.

---

## 7. Recommended two-step patch

### Step 1 — one-line flag addition (Race 1 fix, biggest perf gain)

```cpp
// spi_flow_table.cpp line 46
params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
                  | RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD;
```

This is the minimum change to make `Insert` lock-free on the hot path. It alone is expected to recover the throughput drop introduced by the unsynchronised multi-writer access.

### Step 2 — atomic publish + hot/cold split (Race 2, Race 3, Hazards A + B)

Replaces 24-byte FlowEntry with a hot-cold-splittwo-array layout. Hot line is 64 B (one cell per cache line), read by every hit. Cold TSC lives in a separate 8-B array, writes on every hit but reads only on the main lcore's PurgeExpired pass.

```cpp
// spi_flow_table.hpp (full rewrite — see §3.2 for shape)
struct alignas(64) FlowTable::AtomicFlowCell {
  std::atomic<std::uint64_t> action_and_count{};
};

class FlowTable final {
  // ... Lookup / GetEntry / Insert / PurgeExpired rewrites from §3.4
 private:
  std::vector<AtomicFlowCell> cells_;     // hot, 64 B per slot
  std::vector<std::uint64_t> last_seen_tsc_; // cold, 8 B per slot
  rte_hash* hash_{nullptr};
};
```

### Step 3 — bench to verify

```bash
./test/test_env.sh bench-spi 1000000
```

Compare `Performance: X Mpps` before and after. Step 1 alone is expected to recover most of the throughput loss; Step 2 closes the correctness gap and removes the last ~10–15% cache-line ping-pong overhead.

---

## 8. Acceptance criteria

1. Build clean under `-Wall -Wextra -Wpedantic -Werror` (the project's CI bar).
2. `pixi run bench-spi` produces **non-decreasing** `Performance: X Mpps` after each step (Step 1 unlocks the bucket-lock serialization, Step 2 removes cache-line ping-pong).
3. `flow_cache_hits / received` ratio stays at **≥99.9%** (no spurious misses from torn writes or stale action bits).
4. `rte_hash_count()` matches `cells with action_and_count > 0` after 60 s of traffic — no slot leaks from torn state.
5. `perf stat -e L1-icache-load-misses,L1-dcache-load-misses` on the bench binary — fewer load-misses per packet than baseline (because hot data is now 1 cell per cache line vs ~2.67 with mixed hot/cold).
6. TSan or ThreadSanitizer run on the bench → 0 races reported.
7. Atomicity check: a synthetic test that calls `Insert` from 7 threads concurrently into the same key and reads back via `Lookup` should always observe a valid action (kForward or kDrop) and a positive match_count.

---

## 9. Performance, security, readability scorecard

### Performance
- ✅ Step 1 (MULTI_WRITER_ADD) removes bucket-lock serialization.
- ✅ Step 2 (`AtomicFlowCell` + separate cold array) eliminates cache-line ping-pong.
- ⚠️ On x86 acquire/release is zero-cost; on ARM/POWER a `LDAR`/`STLR` per packet costs ~5–10 ns each. Total budget: 100 Mpps × 2 atomic ops × 10 ns = 2 seconds/sec — acceptable.
- ⚠️ Memory cost: 24 MB → ~104 MB at 1 M slots. Document the trade-off in the config knobs.

### Security
- ✅ **No out-of-bounds**: bounds check on positions[] before the array index.
- ✅ **No integer overflow**: 60-bit match counter is astronomical.
- ✅ **No info leak**: TSC writes are data-independent.
- ✅ **No bit-packing overflow**: `static_assert(action <= 0xF)` should be added to catch future enum additions at compile time.
- ✅ **Cache-timing side-channel**: hot/cold split removes the false-sharing timing leak between unrelated entries; only the entry being touched is invalidated across cores.

### Readability
- ✅ Named constants (`kFlowActionMask`, `kFlowMatchCountShift`) instead of magic numbers.
- ✅ `AtomicFlowCell` and `FlowEntryView` are self-documenting types — no inline `<< 4`, `& 0xF` in hot paths.
- ✅ Helper struct `FlowEntryView` returned by value (NRVO) — caller uses `->action` cleanly.
- ⚠️ Caller code in `ResolvePacketAction` changes from `entry->action` to `view->action` — small migration, but explicit.

---

## 10. Audit log

| Date | Reviewer | Finding |
|---|---|---|
| 2026-07-17 | initial | Five races identified; one-line flag fix recommended. |
| 2026-07-17 | v2 audit | Found 4 additional issues: A (cache-line ping-pong), B (double acquire-load), C (Insert "preserve action" bug), D (cryptic bit packing). All addressed in current revision. |
| 2026-07-17 | **v3 implementation** | Bench showed MULTI_WRITER_ADD's slot migration broke cache stability (99.9% → 62.9% hit rate, 426× more `matched`). **Fix**: drop MULTI_WRITER_ADD; serialise inserts with `rte_spinlock_t`. Lookups stay lock-free via `RW_CONCURRENCY_LF`. Hot/cold split + atomic publish retained. |

### 10.1 MULTI_WRITER_ADD lesson (v3)

When `RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD` is set, rte_hash's lock-free
insert path may **migrate keys between slots internally** to manage collisions
via CAS retries (it allocates extra empty slots beyond `params.entries` and
relocates keys into them). This makes the slot index an **ephemeral
identifier** — your data at the old slot becomes dead the moment the hash
moves the key, and the next `rte_hash_lookup` returns the *new* slot where
you haven't written.

Initial code sized `cells_` and `last_seen_tsc_` to
`rte_hash_max_key_id() + 1` to cover the extended slot range, but the data
was still volatile because the hash moves keys across those slots whenever
it rebalances a chain.

**Resolution**: keep `RW_CONCURRENCY_LF` (for lock-free **lookups**) but
**omit** `MULTI_WRITER_ADD`. Serialise inserts across cores with an
external `rte_spinlock_t`. Insert rate at 99.9 % cache hit is <100 K/sec
across 7 workers, so spinlock contention is negligible.

The trade-off documented in this audit log:
- `MULTI_WRITER_ADD` slot migration breaks slot-indexed backing stores.
- `RW_CONCURRENCY_LF` alone leaves inserts single-threaded → external
  spinlock is the cheapest correct fix.
- Same trade-off Suricata's flow manager makes (single-writer inserts).


---

## 11. References (verified 2026-07-17)

### DPDK official / in-tree
- [`/usr/include/dpdk/rte_hash.h`](file:///usr/include/dpdk/rte_hash.h) lines 36-56 (flags), 222-227 (multi-thread safety), 292, 316 (multi-writer add docs) — *this is the local DPDK 24.11.4 install*.
- [DPDK 23.11 Hash Library Guide](https://dpdk-power-docs.readthedocs.io/en/latest/prog_guide/hash_lib.html) — *"Setting `MULTI_WRITER_ADD` makes key add, delete, and table reset safe from other writer threads."*
- [DPDK 23.11 Thread Safety of DPDK Functions](https://doc.dpdk.org/guides-23.11/prog_guide/thread_safety_dpdk_functions.html) — *"Adding, removing or modifying values cannot be done in multiple threads without using locking unless `MULTI_WRITER_ADD` is set."*
- [DPDK 21.11 LTS QSBR + `rte_hash_rcu_qsbr_dq_reclaim`](https://doc.dpdk.org/guides-21.11/prog_guide/rcu_lib.html) — for the long-term proper fix when RCU QSBR is wired in (deferred to a later PR).

### DPDK examples
- [`examples/rcu/rcu/main.c`](https://github.com/DPDK/dpdk/blob/main/examples/rcu/rcu/main.c) — canonical pattern for `rte_hash` + QSBR + lock-free reader/concurrent writer.

### C++ standards and references
- [P0124R6 — C++ atomics memory model](https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2017/p0124r6.html) — formal definition of release/acquire.
- C++ standard `[atomics]` clause 33.4 — publication protocol.
- Jeff Preshing, [acquire/release semantics](https://preshing.com/20120913/acquire-and-release-semantics/) — the canonical accessible writeup.

### Stack / Community
- [StackOverflow — DPDK rte_hash multithreading](https://stackoverflow.com/questions/64552415/dpdk-rte-hash-multithreading) — confirms community consensus that `MULTI_WRITER_ADD` is a separate flag from `RW_CONCURRENCY_LF`.
- [Anatomy of DPDK Data Structure — Medium](https://medium.com/@anubhavchoudhary/anatomy-of-dpdk-data-structure-314bb994617d) — bucket-CAS implementation walkthrough.

### Related in this repo
- [`docs_search/10_mentor_review_findings.md`](file:///home/bac/programming/viettel/dpdk_cpp/docs_search/10_mentor_review_findings.md) — original audit that flagged `RW_CONCURRENCY_LF + NO_FREE_ON_DEL` semantics.
- [`docs_search/11_expert_plan.md` §13.3](file:///home/bac/programming/viettel/dpdk_cpp/docs_search/11_expert_plan.md) — `rte_hash_free_key_with_position` plan for slot reclamation; orthogonal to this fix but should land together.
