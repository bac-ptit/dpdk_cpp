#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "dpdk/spi/spi_rule_engine.hpp"

struct rte_hash;

namespace dpdk::spi {

/// Number of bytes in a FlowKey (5-tuple + padding).
inline constexpr std::size_t kFlowKeySize{16};

/// Maximum length of a null-terminated name string in FlowEntry.
inline constexpr std::size_t kFlowNameMaxLen{32};

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
struct FlowEntry {
  Action action{Action::kForward};
  std::uint32_t group_precedence{};
  /// Null-terminated group name. Truncated if source exceeds kFlowNameMaxLen - 1 chars.
  std::array<char, kFlowNameMaxLen> group_name{};
  /// Null-terminated label. Truncated if source exceeds kFlowNameMaxLen - 1 chars.
  std::array<char, kFlowNameMaxLen> label{};
  std::uint64_t match_count{};
  std::uint64_t last_seen_tsc{};
};

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
   */
  [[nodiscard]] FlowEntry* Lookup(const FlowKey& key) noexcept;

  /**
   * @brief Insert or update a flow entry.
   * @param key    5-tuple flow key.
   * @param entry  Classification result to cache.
   */
  void Insert(const FlowKey& key, const FlowEntry& entry) noexcept;

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
