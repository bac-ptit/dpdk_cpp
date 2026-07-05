#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include <rte_hash.h>

#include "dpdk/spi/spi_rule_engine.hpp"

struct rte_hash;

namespace dpdk::spi {

/// Number of bytes in a FlowKey (5-tuple + padding).
inline constexpr std::size_t kFlowKeySize{16};

/// Expected sizeof(FlowEntry) = 1 (action) + 7 (auto-pad) + 8 (match_count) + 8 (last_seen_tsc) = 24.
/// ~2.67 entries fit in a 64 B cache line.
inline constexpr std::size_t kFlowEntrySize{24};

/// 5-tuple flow key for cache lookup. Padded to kFlowKeySize bytes.
/// Layout: [src_ip:4][dst_ip:4][src_port:2][dst_port:2][proto:1][pad:3]
/// The 3-byte pad MUST remain zero — garbage in pad breaks rte_hash_crc.
struct FlowKey {
  std::uint32_t src_ip{};
  std::uint32_t dst_ip{};
  std::uint16_t src_port{};
  std::uint16_t dst_port{};
  Protocol protocol{};
  std::array<std::uint8_t, 3> pad{};
};
static_assert(sizeof(FlowKey) == kFlowKeySize);

/// Cached flow classification result.
///
/// Only `action` is read by the hot path (the cached hit returns the action
/// to `ForwardPacket`). `match_count` is checked to detect empty slots.
/// `last_seen_tsc` is used only by the cold-path `PurgeExpired`.
///
/// The previous version held `group_name` and `label` (32 B each) that were
/// written but never read by any downstream code (verified by grep). With
/// the dead fields removed the entry fits in 24 B and `entries_[]` for 1 M
/// entries is ~24 MB (vs ~770 MB before).
struct FlowEntry {
  Action action{Action::kForward};        // offset 0
  std::uint64_t match_count{};             // offset 8 (auto-pad 7 B before)
  std::uint64_t last_seen_tsc{};           // offset 16
  // total sizeof = 24 B; ~2.67 entries per 64 B cache line.
};
static_assert(sizeof(FlowEntry) == kFlowEntrySize, "FlowEntry size drifted from kFlowEntrySize");

/**
 * @brief Per-flow classification cache backed by rte_hash.
 *
 * Stores the SPI match result for each 5-tuple. Subsequent packets
 * in the same flow skip rule evaluation (cache hit).
 */
class FlowTable final {
 public:
  FlowTable();
  ~FlowTable();

  FlowTable(const FlowTable&) = delete;
  FlowTable& operator=(const FlowTable&) = delete;
  FlowTable(FlowTable&&) = delete;
  FlowTable& operator=(FlowTable&&) = delete;

  /**
   * @brief Lookup a flow in the cache.
   * @param key  5-tuple flow key.
   * @return Pointer to cached entry, or nullptr on cache miss.
   *
   * Defined inline in the header so the hot path is inlined into the
   * caller's TU without relying on LTO. With 99%+ cache hit rate, this
   * function is on the per-packet critical path.
   */
  [[gnu::hot, gnu::always_inline]] [[nodiscard]] FlowEntry* Lookup(
      const FlowKey& key) noexcept {
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
    return entry;
  }

  /**
   * @brief Bulk lookup for a contiguous batch of keys.
   * @param keys       Pointer to N FlowKey entries.
   * @param num_keys   Number of keys (>= 0).
   * @param positions  Output array of `num_keys` int32_t; positions[i] is
   *                   the slot index in `entries_[]` (>= 0) or negative on miss.
   *
   * Pipelined version of `Lookup` for the per-burst hot path. With Clang's
   * SSE4.2 CRC32 pin (from `Environment::InitEal`) the bulk API computes
   * all N CRC32 hashes in vectorised form and pipelines bucket loads.
   * Returns void; callers walk `positions[]` to fetch each entry via
   * `GetEntry` and verify `match_count > 0`.
   */
  [[gnu::hot]] void LookupBulk(const FlowKey* keys, std::uint32_t num_keys,
                                std::int32_t* positions) noexcept;

  /**
   * @brief Get a FlowEntry by slot index (output of LookupBulk).
   *
   * Caller must pass a position from `LookupBulk` (>= 0). The `[[assume]]`
   * documents the contract so the compiler can elide the bounds check.
   * Returns nullptr if position is negative.
   */
  [[gnu::hot, gnu::always_inline]] [[nodiscard]] FlowEntry* GetEntry(
      std::int32_t position) noexcept {
    if (position < 0) [[unlikely]] {
      return nullptr;
    }
    [[assume(position >= 0)]];
    return &entries_[static_cast<std::size_t>(position)];
  }

  /**
   * @brief Insert or update a flow entry.
   * @param key    5-tuple flow key.
   * @param entry  Classification result to cache.
   *
   * Defined inline in the header to avoid a function call on the miss path.
   */
  [[gnu::always_inline]] void Insert(const FlowKey& key, const FlowEntry& entry) noexcept {
    if (hash_ == nullptr) [[unlikely]] {
      return;
    }
    const auto result{rte_hash_add_key(hash_, &key)};
    if (result >= 0) [[likely]] {
      auto& slot{entries_[static_cast<std::size_t>(result)]};
      slot = entry;
      slot.last_seen_tsc = rte_rdtsc();
    }
  }

  /**
   * @brief Remove entries not seen since the given TSC threshold.
   * @param now_tsc     Current TSC value.
   * @param ttl_cycles  Entries older than (now_tsc - ttl_cycles) are purged.
   */
  void PurgeExpired(std::uint64_t now_tsc, std::uint64_t ttl_cycles) noexcept;

 private:
  rte_hash* hash_{nullptr};
  std::vector<FlowEntry> entries_;
};

}  // namespace dpdk::spi
