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

/// Number of entries in the flow hash table.
///
/// 1M entries × ~24 B = ~24 MB → fits comfortably in L3 cache on most server
/// CPUs (typically 16-64 MB). Previously this was 8 M entries × ~96 B =
/// ~770 MB which caused L3 thrashing and slowed every `rte_hash_lookup`.
///
/// 1 M is the minimum needed for the standard bench traffic (15 shards × ~67 k
/// unique 5-tuples ≈ 1 M unique flows). For larger production deployments
/// bump this to 4 M-8 M at the cost of cache locality.
constexpr std::uint32_t kFlowTableSize{1U << 20U};

[[nodiscard]] rte_hash_parameters CreateHashParams() noexcept {
  rte_hash_parameters params{};
  params.name = "flow_table";
  params.entries = static_cast<std::uint32_t>(kFlowTableSize);
  params.key_len = sizeof(FlowKey);
  params.hash_func = rte_hash_crc;
  params.hash_func_init_val = 0;
  params.socket_id = static_cast<int>(rte_socket_id());
  // RW_CONCURRENCY_LF replaces the per-bucket rwlock with atomic CAS retries.
  // With 16 cores hammering the same 5-tuple buckets, ticket-lock
  // acquisitions dominate miss-path latency. Lock-free path trades
  // slightly more work on the writer side for wait-free readers.
  // Note: this implicitly enables NO_FREE_ON_DEL — `rte_hash_del_key`
  // (used by PurgeExpired) does not reclaim the slot; we don't rely
  // on slot reuse in steady-state, and PurgeExpired is gated by
  // `flow_ttl_sec` (default 300s, never reached during bench).
  params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;
  return params;
}

}  // namespace

FlowTable::FlowTable() {
  const auto params{CreateHashParams()};
  hash_ = rte_hash_create(&params);
  if (hash_ == nullptr) {
    std::println(stderr, "FlowTable: rte_hash_create failed");
    return;
  }
  entries_.resize(kFlowTableSize);
}

FlowTable::~FlowTable() {
  if (hash_ != nullptr) {
    rte_hash_free(hash_);
  }
}

// Lookup and Insert are now defined inline in spi_flow_table.hpp so they
// can be inlined into the caller's TU without relying on LTO. The hot path
// (cache hit, ~99.9% of packets) calls Lookup on every packet.

void FlowTable::LookupBulk(const FlowKey* keys, std::uint32_t num_keys,
                            std::int32_t* positions) noexcept {
  if (hash_ == nullptr) [[unlikely]] {
    std::ranges::fill(std::span{positions, num_keys}, -1);
    return;
  }
  if (num_keys == 0) [[unlikely]] {
    return;
  }
  // DPDK's bulk API takes `const void **keys` — a contiguous pointer-to-array.
  // We build that on the stack, capped at the per-burst maximum so we never
  // overflow it. Caller (ProcessPortBurst) never passes more than this.
  constexpr std::uint32_t kMaxBulkKeys{256};  // matches kMaxBurstCapacity
  if (num_keys > kMaxBulkKeys) [[unlikely]] {
    num_keys = kMaxBulkKeys;
  }
  alignas(64) std::array<const void*, kMaxBulkKeys> key_ptrs{};
  for (std::uint32_t i{0}; i < num_keys; ++i) {
    key_ptrs[i] = &keys[i];
  }
  rte_hash_lookup_bulk(hash_, key_ptrs.data(), num_keys, positions);
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

  // Pass 1: collect expired keys (don't mutate during iteration).
  thread_local std::vector<FlowKey> expired;
  expired.clear();
  const void* key{nullptr};
  void* data{nullptr};
  std::uint32_t next{0};
  while (rte_hash_iterate(hash_, &key, &data, &next) >= 0) {
    if (entries_[next - 1].last_seen_tsc < threshold) {
      expired.push_back(*static_cast<const FlowKey*>(key));
    }
  }

  // Pass 2: delete collected keys.
  for (const auto& expired_key : expired) {
    if (const auto result{rte_hash_del_key(hash_, &expired_key)}; result >= 0) {
      entries_[static_cast<std::size_t>(result)] = {};
    }
  }
}

}  // namespace dpdk::spi