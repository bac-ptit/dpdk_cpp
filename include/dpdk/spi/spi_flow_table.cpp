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
  // RW_CONCURRENCY_LF replaces the per-bucket rwlock with atomic CAS retries.
  // With 16 cores hammering the same 5-tuple buckets, ticket-lock
  // acquisitions dominate miss-path latency. Lock-free path trades
  // slightly more work on the writer side for wait-free readers.
  //
  // We deliberately do NOT set RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD here.
  // MULTI_WRITER_ADD lets `rte_hash_add_key` return slot indices beyond
  // `params.entries` and the hash migrates keys between slots to manage
  // collisions in lock-free CAS retries. That makes the slot index an
  // ephemeral identifier for our `cells_[idx]` backing store — when the
  // hash moves a key, our cached `action_and_count` becomes stale and
  // the next lookup, which returns the NEW slot index, misses.
  //
  // Instead, we hold an external spinlock around the rare insert path
  // (~12 K inserts/sec across 7 workers at 99.9% cache hit rate;
  // <100 µs of expected spinlock acquisition per second). Lookups stay
  // lock-free via LW_CONCURRENCY_LF. This is the same trade-off the
  // Suricata flow table makes — they pin inserts to a single writer
  // for exactly this reason.
  //
  // Note: RW_CONCURRENCY_LF implicitly enables NO_FREE_ON_DEL. The
  // explicit `rte_hash_free_key_with_position` call in PurgeExpired
  // returns the slot to DPDK's internal free list so the next
  // `rte_hash_add_key` reuses it without growing past
  // `max_concurrent_flows`.
  params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;
  return params;
}

}  // namespace

FlowTable::FlowTable(std::uint32_t max_concurrent_flows) noexcept {
  rte_spinlock_init(&insert_lock_);
  max_concurrent_flows_ = max_concurrent_flows;
  const auto params{CreateHashParams(max_concurrent_flows)};
  hash_ = rte_hash_create(&params);
  if (hash_ == nullptr) {
    std::println(stderr, "FlowTable: rte_hash_create failed (entries={})", max_concurrent_flows);
    return;
  }
  // Hot/cold split sizing. Reserving once at startup — no dynamic alloc on
  // hot path. Memory cost at 1 M slots: 64 MB hot + 64 MB cold + ~32 MB
  // rte_hash internals = ~160 MB total. The cold side is 64 B/slot (not
  // 8 B/slot) because each ColdTsc is `alignas(64)`-padded to eliminate
  // false sharing between worker TSC writes. For larger deployments
  // (`max_concurrent_flows: 4_000_000`), this scales linearly (~640 MB);
  // operator can dial it down to keep L3 footprint small.
  //
  // AtomicFlowCell / ColdTsc both hold std::atomic<>, which is neither
  // copyable nor movable, so storage uses std::unique_ptr<T[]> (zero-
  // overhead indexing, no indirection on the hot path).
  cells_ = std::make_unique<AtomicFlowCell[]>(max_concurrent_flows);
  last_seen_tsc_ = std::make_unique<ColdTsc[]>(max_concurrent_flows);
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
  // DPDK's bulk API takes `const void **keys` — a contiguous pointer-to-array.
  // We build that on the stack, capped at DPDK's RTE_HASH_LOOKUP_BULK_MAX so
  // we never overflow it. Caller (ProcessPortBurst) never passes more than
  // this.
  constexpr std::uint32_t kMaxBulkKeys{RTE_HASH_LOOKUP_BULK_MAX};
  static_assert(kMaxBulkKeys == 64U, "must match DPDK's RTE_HASH_LOOKUP_BULK_MAX");
  if (num_keys > kMaxBulkKeys) [[unlikely]] {
    num_keys = kMaxBulkKeys;
  }
  alignas(64) std::array<const void*, kMaxBulkKeys> key_ptrs{};
  alignas(64) std::array<std::int32_t, kMaxBulkKeys> positions{};
  for (std::uint32_t i{0}; i < num_keys; ++i) {
    key_ptrs[i] = &keys[i];
    positions[i] = -1;
  }
  rte_hash_lookup_bulk(hash_, key_ptrs.data(), num_keys, positions.data());

  // H4: snapshot each hit slot under the same acquire-load that resolves
  // the position. No second load, no position-lifetime window — even if
  // PurgeExpired deletes the slot between this function and the caller's
  // later access, the snapshot was already taken.
  for (std::uint32_t i{0}; i < num_keys; ++i) {
    const auto pos{positions[i]};
    if (pos < 0) [[unlikely]] {
      continue;
    }
    const auto idx{static_cast<std::size_t>(pos)};
    const auto packed{cells_[idx].action_and_count.load(std::memory_order_acquire)};
    if (packed == 0) [[unlikely]] {
      continue;  // empty slot
    }
    // H7: refresh TSC under the same acquire-load. Relaxed: no other
    // core needs to observe this immediately, and the element is
    // alignas(64) so the write doesn't ping-pong cold lines.
    last_seen_tsc_[idx].value.store(now_tsc, std::memory_order_relaxed);
    results[i] = BulkResult{
        .view = DecodePacked(packed, now_tsc),
        .valid = true,
    };
  }
}

void FlowTable::PurgeExpired(std::uint64_t now_tsc, std::uint64_t ttl_cycles) noexcept {
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
  // unlocked Insert could publish a fresh entry on a slot that this
  // pass has already collected (or is about to clear). The v3 design
  // intentionally omits MULTI_WRITER_ADD so all hash writers go through
  // `insert_lock_`; PurgeExpired must honour that contract too.
  rte_spinlock_lock(&insert_lock_);

  // H6: don't rely on rte_hash_iterate. The DPDK 24.11 iterator writes
  // `*next` as the bucket-cursor (incremented through the bucket chain)
  // and returns the slot index as the function's return value, not via
  // `*next`. The previous code read `last_seen_tsc_[next]` — which is
  // one off the actual slot and can land on a slot that a concurrent
  // Insert just published to. The iterator also lacks the LF retry on
  // the table-change counter that `rte_hash_lookup` has, so it is not
  // safe under `RW_CONCURRENCY_LF` while writers are active.
  //
  // Instead, iterate our parallel `last_seen_tsc_` array directly. For
  // each stale slot, recover the key via `rte_hash_get_key_with_position`
  // and collect it for the delete pass.
  thread_local std::vector<FlowKey> expired;
  expired.clear();
  for (std::size_t idx{0}; idx < max_concurrent_flows_; ++idx) {
    const auto tsc{last_seen_tsc_[idx].value.load(std::memory_order_relaxed)};
    if (tsc == 0) {
      continue;  // empty slot
    }
    if (tsc < threshold) {
      const auto pos{static_cast<int32_t>(idx)};
      void* key_ptr{nullptr};
      if (rte_hash_get_key_with_position(hash_, pos, &key_ptr) >= 0) {
        expired.push_back(*static_cast<const FlowKey*>(key_ptr));
      }
    }
  }

  // C1: clear cell FIRST, then del_key + free_key_with_position.
  //
  // Ordering matters: if we free the slot first, an unlocked Insert
  // could re-take the slot and publish a fresh entry; our subsequent
  // cell-clear would then wipe the fresh entry. With the clear-first
  // ordering, a racing Insert's release-store overwrites our 0 with
  // the new entry's bits — which is the desired outcome.
  for (const auto& expired_key : expired) {
    const auto deleted{rte_hash_del_key(hash_, &expired_key)};
    if (deleted < 0) {
      continue;
    }
    const auto idx{static_cast<std::size_t>(deleted)};
    // 1. Hide from Lookup (atomic publish of "empty").
    cells_[idx].action_and_count.store(0, std::memory_order_release);
    last_seen_tsc_[idx].value.store(0, std::memory_order_relaxed);
    // 2. THEN return the slot to the free list (slow).
    rte_hash_free_key_with_position(hash_, deleted);
  }

  rte_spinlock_unlock(&insert_lock_);
}

}  // namespace dpdk::spi