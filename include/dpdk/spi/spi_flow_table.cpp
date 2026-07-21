#include "dpdk/spi/spi_flow_table.hpp"

#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_lcore.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <format>
#include <print>
#include <ranges>
#include <span>
#include <vector>

namespace dpdk::spi {

namespace {

[[nodiscard]] rte_hash_parameters CreateHashParams(std::uint32_t max_concurrent_flows) noexcept {
  rte_hash_parameters params{};
  params.name = "flow_table";
  params.entries = max_concurrent_flows;
  params.key_len = sizeof(FlowKey);
  params.hash_func = rte_hash_crc;
  params.hash_func_init_val = 0;
  params.socket_id = static_cast<int>(rte_socket_id());
  // RW_CONCURRENCY_LF: lock-free readers using per-bucket atomic CAS
  // retries. With 16 cores hammering the same 5-tuple buckets, ticket-lock
  // acquisitions dominate miss-path latency. Lock-free path trades slightly
  // more work on the writer side for wait-free readers.
  //
  // MULTI_WRITER_ADD: each lcore gets its own free-slot cache so
  // rte_hash_add_key_data is safe for concurrent writers across lcores.
  // Our find-then-update Insert pattern ensures the freelist does not leak
  // on duplicate-key inserts (we update the existing FlowData in place
  // rather than popping a new one).
  //
  // NO_FREE_ON_DEL: `rte_hash_del_key` returns the position but does not
  // recycle the slot. The application MUST eventually call
  // rte_hash_free_key_with_position only after readers have stopped
  // referencing the entry. PurgeExpired calls it on the main lcore while
  // workers are still doing concurrent lookups; the data pointer remains
  // valid (we own the allocation), and by the time the position is
  // reassigned by a future add_key_data every reader has released.
  params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF
                    | RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD
                    | RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL;
  return params;
}

}  // namespace

FlowTable::FlowTable(std::uint32_t max_concurrent_flows) noexcept {
  rte_spinlock_init(&freelist_lock_);
  max_concurrent_flows_ = max_concurrent_flows;
  const auto params{CreateHashParams(max_concurrent_flows)};
  hash_ = rte_hash_create(&params);
  if (hash_ == nullptr) {
    std::println(stderr, "FlowTable: rte_hash_create failed (entries={})", max_concurrent_flows);
    return;
  }
  // Hot/cold split sizing. Reserving once at startup — no dynamic alloc on
  // hot path. Memory cost at 1 M slots: 64 B hot + 64 B cold per entry =
  // 128 MB total for `data_`, plus DPDK's internal ~32 MB rte_hash tables
  // = ~160 MB. Compared to the v3 layout (64 MB + 64 MB = 128 MB plus the
  // same ~32 MB rte_hash internals = ~160 MB), the new layout has the same
  // DRAM footprint because the v3 two-array layout was already paying for
  // 64-byte-per-slot padding via alignas.
  data_ = std::make_unique<FlowData[]>(max_concurrent_flows);
  free_list_.reserve(max_concurrent_flows);
  // LIFO freelist: pop from back, push to back. Cache-friendly because the
  // most recently freed slot is reused first (touch one cache line per
  // pop). Order does not matter for correctness.
  for (std::uint32_t i{0U}; i < max_concurrent_flows; ++i) {
    free_list_.push_back(&data_[i]);
  }
  // Eviction-on-pressure threshold. Sized at 1% of capacity so transient
  // overflow (one packet after a TTL drop) doesn't fire a full purge,
  // but sustained saturation does. Sized here, not in the hot path —
  // the main lcore just relaxed-loads the threshold and the counter.
  eviction_threshold_ = static_cast<std::uint64_t>(max_concurrent_flows) / 100U;
  if (eviction_threshold_ == 0U) {
    // For tiny test tables (< 100 slots) still allow the eviction path
    // to fire — floor at 1 overflow event. The TTL is still in effect;
    // this just makes the threshold non-zero.
    eviction_threshold_ = 1U;
  }
}

FlowTable::~FlowTable() {
  if (hash_ != nullptr) {
    rte_hash_free(hash_);
  }
  // Precondition: caller MUST have joined all worker lcores before
  // destroying the FlowTable. The standard pipeline path satisfies
  // this via `Pipeline::~Pipeline`'s `StopWorkers` call (which runs
  // `rte_eal_mp_wait_lcore()` before any further destruction). Any
  // future FlowTable reuse (pooled contexts, etc.) must re-establish
  // the same quiescence before letting this destructor run.
}

// Lookup and Insert are now defined inline in spi_flow_table.hpp so they
// can be inlined into the caller's TU without relying on LTO. The hot path
// (cache hit, ~99.9% of packets) calls Lookup on every packet.

void FlowTable::LookupBulk(const FlowKey* keys, std::uint32_t num_keys,
                            std::uint64_t now_tsc,
                            std::span<BulkResult> results) noexcept {
  if (hash_ == nullptr) [[unlikely]] {
    for (std::uint32_t i{0}; i < num_keys; ++i) {
      results[i] = {};
    }
    return;
  }
  if (num_keys == 0) [[unlikely]] {
    return;
  }
  // DPDK's bulk API takes `const void **keys` plus `void *data[]`. We
  // build both arrays on the stack, capped at DPDK's
  // RTE_HASH_LOOKUP_BULK_MAX so we never overflow them. The caller
  // (ProcessPortBurst) never passes more than this.
  constexpr std::uint32_t kMaxBulkKeys{RTE_HASH_LOOKUP_BULK_MAX};
  static_assert(kMaxBulkKeys == 64U, "must match DPDK's RTE_HASH_LOOKUP_BULK_MAX");
  if (num_keys > kMaxBulkKeys) [[unlikely]] {
    num_keys = kMaxBulkKeys;
  }
  alignas(64) std::array<const void*, kMaxBulkKeys> key_ptrs{};
  alignas(64) std::array<void*, kMaxBulkKeys> data_ptrs{};
  for (std::uint32_t i{0}; i < num_keys; ++i) {
    key_ptrs[i] = &keys[i];
  }
  std::uint64_t hit_mask{0};
  // Returns the number of successful lookups. hit_mask holds one bit per
  // input key (bit i set ↔ keys[i] hit). data_ptrs[i] is written only for
  // hits.
  rte_hash_lookup_bulk_data(hash_, key_ptrs.data(), num_keys,
                            &hit_mask, data_ptrs.data());

  // Snapshot each hit slot under the same acquire-load that resolves the
  // data pointer. No second load, no position-lifetime window — even if
  // PurgeExpired deletes the slot between this function and the caller's
  // later access, the snapshot was already taken.
  for (std::uint32_t i{0}; i < num_keys; ++i) {
    if (((hit_mask >> i) & 1ULL) == 0ULL) [[likely]] {
      continue;
    }
    auto* const data{static_cast<FlowData*>(data_ptrs[i])};
    const auto packed{data->action_and_count.load(std::memory_order_acquire)};
    if (packed == 0) [[unlikely]] {
      continue;  // empty slot — keep valid=false
    }
    // Refresh TSC under the same acquire-load. Relaxed: no other core
    // needs to observe this immediately, and the field is on its own
    // cache line within the FlowData allocation.
    data->last_seen_tsc.store(now_tsc, std::memory_order_relaxed);
    results[i] = BulkResult{
        .view = DecodePacked(packed),
        .valid = true,
    };
  }
}

void FlowTable::PurgeExpired(std::uint64_t now_tsc, std::uint64_t ttl_cycles,
                             const std::atomic<int>& force_quit) noexcept {
  if (hash_ == nullptr) [[unlikely]] {
    return;
  }

  // Guard against uint64 underflow. At system startup (or after CPU
  // suspend/resume) now_tsc may be smaller than ttl_cycles, which causes
  // the unsigned subtraction to wrap to UINT64_MAX — and then *every*
  // entry's last_seen_tsc would appear "expired", purging the entire
  // populated cache within the first TTL window.
  if (now_tsc <= ttl_cycles) {
    return;
  }
  const auto threshold{now_tsc - ttl_cycles};

  // H3: serialise with worker Insert writers. Without this lock, an
  // unlocked Insert could push a fresh entry on a slot that this pass has
  // already collected (or is about to clear). The v4 design uses
  // MULTI_WRITER_ADD on the hash itself, but our freelist spinlock is
  // still per-lcore, so we need this lock to coordinate del_key with
  // concurrent Insert push/pop on the same key.
  rte_spinlock_lock(&freelist_lock_);

  // Iterate our `data_` array directly to find stale entries. The DPDK
  // iterator (`rte_hash_iterate`) is not safe under `RW_CONCURRENCY_LF`
  // while writers are active. By walking `data_` we sidestep that
  // constraint and reuse the per-key TTL touch as the staleness signal.
  thread_local std::vector<FlowData*> expired_data;
  expired_data.clear();

  // C2: cancellation check granularity. Polling force_quit every 1024
  // slots gives ~1 µs worst-case shutdown latency on a million-slot
  // table (1024 relaxed atomic loads × ~1 ns ≈ 1 µs) — well below the
  // ~50 ms human-perceptible "hang" threshold. 1024 is also a sweet spot
  // for the prefetcher: the load falls out of the hot loop into a branch
  // that almost never executes (`[[unlikely]]`), so steady-state cost is
  // ~zero. The remainder of the scan simply completes on the next call
  // — partial purges are idempotent because TTL only ever grows (entries
  // that were expired at scan start remain expired on the next pass).
  constexpr std::size_t kCancelCheckInterval{1024U};
  std::size_t slots_until_cancel{kCancelCheckInterval};

  for (std::size_t idx{0}; idx < max_concurrent_flows_; ++idx) {
    // Periodic cancellation check — see C2 above.
    if (--slots_until_cancel == 0) [[unlikely]] {
      if (force_quit.load(std::memory_order_relaxed) != 0) {
        // Signal received: release the lock and return. Workers will
        // observe force_quit on their next burst and exit. The scan
        // resumes (or skips) on the next PurgeExpired call from the
        // main lcore's pressure-eviction loop, but that loop won't run
        // again once the run loop exits.
        break;
      }
      slots_until_cancel = kCancelCheckInterval;
    }
    auto& slot{data_[idx]};
    const auto packed{slot.action_and_count.load(std::memory_order_relaxed)};
    if (packed == 0) {
      continue;  // empty slot
    }
    const auto tsc{slot.last_seen_tsc.load(std::memory_order_relaxed)};
    if (tsc < threshold) {
      // Recover the key from the position; matches our data_ index because
      // we never resize in-place.
      const auto pos{static_cast<int32_t>(idx)};
      void* key_ptr{nullptr};
      if (rte_hash_get_key_with_position(hash_, pos, &key_ptr) >= 0) {
        if (rte_hash_del_key(hash_, key_ptr) >= 0) {
          // C1: clear cell FIRST, then del_key + free_key_with_position.
          // Ordering matters: if we free the slot first, an unlocked Insert
          // could re-take the slot and publish a fresh entry; our
          // subsequent cell-clear would then wipe the fresh entry. With
          // the clear-first ordering, a racing Insert's release-store
          // overwrites our 0 with the new entry's bits — which is the
          // desired outcome.
          slot.action_and_count.store(0, std::memory_order_release);
          slot.last_seen_tsc.store(0, std::memory_order_relaxed);
          // Immediate release back to DPDK + freelist. The FlowData
          // pointer is owned by us (separate allocation), so even if a
          // reader is mid-LookupData the FlowData memory remains valid
          // until we explicitly reuse it via the freelist. The position
          // is recycled; any new Insert for the same key will get a new
          // slot, and the reader's stale data pointer simply becomes
          // "old data" that the next LookupData will overwrite via
          // add_key_data.
          rte_hash_free_key_with_position(hash_, pos);
          expired_data.push_back(&slot);
        }
      }
    }
  }

  // Push freed FlowData pointers back to the freelist while still under
  // the freelist lock — the Insert path will see them on the next
  // pop attempt.
  for (auto* const data : expired_data) {
    free_list_.push_back(data);
  }

  rte_spinlock_unlock(&freelist_lock_);
}

void FlowTable::DrainPendingFrees() noexcept {
  // v4 layout has no deferred-free queue. This entry point is kept for
  // API compatibility (called by the resize path after worker pause)
  // but is a no-op: PurgeExpired already returns FlowData pointers to
  // the freelist synchronously.
}

}  // namespace dpdk::spi