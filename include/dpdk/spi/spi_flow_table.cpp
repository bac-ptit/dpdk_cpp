#include "dpdk/spi/spi_flow_table.hpp"

#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_lcore.h>

#include <format>
#include <print>
#include <vector>

namespace dpdk::spi {
namespace {

/// Number of entries in the flow hash table (64K).
constexpr std::uint32_t kFlowTableSize{1U << 16U};

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
  entry->last_seen_tsc = rte_rdtsc();  // update access time
  return entry;
}

void FlowTable::Insert(const FlowKey& key, const FlowEntry& entry) noexcept {
  if (hash_ == nullptr) [[unlikely]] {
    return;
  }

  if (const auto result{rte_hash_add_key_data(hash_, &key, nullptr)}; result >= 0) { [[likely]] {
    auto& slot{entries_[static_cast<std::size_t>(result)]};
    slot = entry;
    slot.last_seen_tsc = rte_rdtsc();
  } } else {
    std::println(stderr, "FlowTable: hash full, drop insert (ret={})", result);
  }
}

void FlowTable::PurgeExpired(std::uint64_t now_tsc, std::uint64_t ttl_cycles) noexcept {
  if (hash_ == nullptr) [[unlikely]] {
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
