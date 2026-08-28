#pragma once

#include <hs/hs.h>

#include <cstdint>
#include <expected>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "dpdk/config/dpdk_config.hpp"

namespace dpdk::dpi {

/// Compiled DPI filter — hostname pattern for L7 classification.
struct CompiledDpiFilter {
  /// Hostname pattern string.
  char hostname_pattern[64]{};
  /// Length of hostname pattern.
  std::uint16_t hostname_pattern_length{};
  /// Whether pattern starts with "*." (suffix match).
  bool is_suffix_match{false};
  /// Whether pattern is "*" (catch-all).
  bool is_catch_all{false};
  /// Filter group name.
  std::string filter_group;
  /// Priority — lower value = higher priority.
  std::uint32_t priority{100};
  /// Human-readable label.
  std::string label;
};

/// Classification result from DPI rule matching.
struct DpiResult {
  std::string_view filter_group;
  std::string_view label;
  std::uint32_t priority{0};
  bool matched{false};
};

/// Compact, cache-friendly lookup entry for suffix-match rules.
/// Sorted by priority ASC (smallest first) so the first match wins.
struct DpiSuffixEntry {
  std::string_view domain;  // e.g. "facebook.com" — the "*." stripped part
  std::uint16_t filter_index;
};

/**
 * @brief Immutable table of compiled DPI filters with Hyperscan SIMD acceleration.
 *
 * Uses Intel Hyperscan / Vectorscan multi-pattern block database for O(1) multi-regex matching,
 * combined with an in-place fallback for exact/suffix matching.
 */
class DpiRuleTable final {
 public:
  explicit DpiRuleTable(std::vector<CompiledDpiFilter> filters, hs_database_t* hs_db = nullptr) noexcept;

  DpiRuleTable(const DpiRuleTable&) = delete;
  DpiRuleTable& operator=(const DpiRuleTable&) = delete;
  DpiRuleTable(DpiRuleTable&& other) noexcept;
  DpiRuleTable& operator=(DpiRuleTable&& other) noexcept;
  ~DpiRuleTable() noexcept;

  /// Match hostname against DPI filters using Hyperscan. Returns highest-priority (lowest value) match.
  [[nodiscard]] DpiResult Match(std::string_view hostname) const noexcept;

  /// Match hostname using an explicitly provided Hyperscan scratch buffer.
  [[nodiscard]] DpiResult Match(std::string_view hostname, hs_scratch_t* scratch) const noexcept;

  /// Get the DpiResult for a filter by its index (from a prior `Match()`).
  /// Used by the hostname cache to reconstruct result without re-running Match.
  [[nodiscard, gnu::always_inline]] DpiResult ResultAt(std::uint16_t index) const noexcept {
    const auto& f = filters_[index];
    return DpiResult{
        .filter_group = f.filter_group,
        .label = f.label,
        .priority = f.priority,
        .matched = true,
    };
  }

  /// Look up the filter index for a given DPI filter group name.
  [[nodiscard]] std::optional<std::uint32_t> FindByFilterGroup(
      std::string_view name) const noexcept;

  /// Whether DPI is enabled and filters are loaded.
  [[nodiscard]] bool IsEnabled() const noexcept { return !filters_.empty(); }

  [[nodiscard]] std::size_t FilterCount() const noexcept { return filters_.size(); }

  /// Monotonic generation counter — incremented on each reload via DpiRuleTableManager::Swap.
  [[nodiscard]] std::uint32_t Generation() const noexcept { return generation_; }

  /// Set the generation.
  void SetGeneration(std::uint32_t gen) noexcept { generation_ = gen; }

  /// Access underlying Hyperscan database.
  [[nodiscard]] hs_database_t* HyperscanDb() const noexcept { return hs_db_; }

  /// Allocate a Hyperscan scratch buffer for this database.
  [[nodiscard]] hs_scratch_t* AllocScratch() const noexcept;

  /// Free a Hyperscan scratch buffer.
  void FreeScratch(hs_scratch_t* scratch) const noexcept;

 private:
  /// Fallback matcher in case Hyperscan database is not compiled.
  [[nodiscard]] DpiResult MatchFallback(std::string_view hostname) const noexcept;

  /// Original filter list sorted by priority ASC.
  std::vector<CompiledDpiFilter> filters_;

  /// Exact-match lookup map.
  std::unordered_map<std::string_view, std::uint16_t> exact_map_;

  /// Suffix-match lookup map.
  std::unordered_map<std::string_view, std::uint16_t> suffix_map_;

  /// Exact-match rules list.
  std::vector<std::pair<std::string_view, std::uint16_t>> exact_list_;

  /// Suffix-match rules list.
  std::vector<DpiSuffixEntry> suffix_list_;

  /// Index into `filters_` of the `*` catch-all rule, or sentinel if none.
  std::uint16_t catch_all_idx_{std::numeric_limits<std::uint16_t>::max()};
  /// Generation counter.
  std::uint32_t generation_{0U};

  /// Hyperscan compiled database.
  hs_database_t* hs_db_{nullptr};
};

/// Compile DPI config into a rule table with Hyperscan compilation.
[[nodiscard]] std::expected<DpiRuleTable, std::string> CompileDpiRuleTable(const DpiConfig& config) noexcept;

}  // namespace dpdk::dpi
