#include "dpdk/spi/spi_flow_table.hpp"

#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_lcore.h>

#include <cstdio>
#include <format>
#include <print>
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
  params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY;
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

FlowEntry* FlowTable::Lookup(const FlowKey& key) noexcept {
  if (hash_ == nullptr) [[unlikely]] {
    return nullptr;
  }

  const auto result{rte_hash_lookup(hash_, &key)};
  if (result < 0) [[unlikely]] {
    return nullptr;
  }

  auto* entry = &entries_[static_cast<std::size_t>(result)];
  if (entry->match_count == 0) [[unlikely]] {
    return nullptr;  // empty slot
  }

  // Refresh `last_seen_tsc` so long-lived flows don't get TTL-purged.
  // Rate-limit per worker (not per slot) to bound cache-line writes.
  // Without this, flows inserted at boot would be purged at T+flow_ttl_sec
  // (~5 min default) and the next packet would pay the full insert cost
  // (ACL classify + L7 extract + DPI match + Insert).
  static thread_local std::uint64_t last_refresh_tsc{0};
  static thread_local std::uint64_t refresh_interval{0};
  if (refresh_interval == 0) [[unlikely]] {
    refresh_interval = rte_get_tsc_hz();  // refresh at most once per second
  }
  const auto now{rte_rdtsc()};
  if (now - last_refresh_tsc > refresh_interval) {
    entry->last_seen_tsc = now;
    last_refresh_tsc = now;
  }
  return entry;
}

void FlowTable::Insert(const FlowKey& key, const FlowEntry& entry) noexcept {
  if (hash_ == nullptr) [[unlikely]] {
    return;
  }

  // Use rte_hash_add_key (NOT rte_hash_add_key_data) which returns the slot
  // ID (0-based, ≥ 0 on success). rte_hash_add_key_data returns just 0/-EINVAL/
  // -ENOSPC and is intended for "update the value" rather than as an index.
  const auto result{rte_hash_add_key(hash_, &key)};
  if (result >= 0) [[likely]] {
    auto& slot{entries_[static_cast<std::size_t>(result)]};
    slot = entry;
    slot.last_seen_tsc = rte_rdtsc();
  } else {
    std::println(stderr, "FlowTable: hash full, drop insert (ret={})", result);
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
