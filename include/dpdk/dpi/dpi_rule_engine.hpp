#pragma once

#include <cstdint>
#include <expected>
#include <limits>
#include <string>
#include <string_view>
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

/// Immutable table of compiled DPI filters, sorted by priority.
///
/// Lookup indexes:
///   - `exact_list_` — small sorted vector of (hostname, filter_index).
///     Linear scan because there are usually < 5 exact-match rules
///     ("dns.google", "cloudflare-dns.com", "dns.quad9.net"); a hash map
///     is overkill for so few entries.
///   - `suffix_list_` — small sorted vector of (domain, filter_index),
///     sorted by `domain` so we can stop at the first mismatch. For ~25
///     suffix rules this is faster than a hash map (no hash compute,
///     fits in 2-3 cache lines).
///   - `catch_all_idx_` — single `*` catch-all rule, or sentinel if none.
///
/// Keeping both indexes as `std::vector` (data-only) avoids the
/// unordered_map bucket array that was causing 656M cache-misses/sec in
/// earlier hash-map experiments. With 30 rules total, the working set
/// fits in a single L1 cache line and stays hot.
class DpiRuleTable final {
 public:
  explicit DpiRuleTable(std::vector<CompiledDpiFilter> filters) noexcept;

  DpiRuleTable(const DpiRuleTable&) = delete;
  DpiRuleTable& operator=(const DpiRuleTable&) = delete;
  DpiRuleTable(DpiRuleTable&&) = default;
  DpiRuleTable& operator=(DpiRuleTable&&) = default;
  ~DpiRuleTable() = default;

  /// Match hostname against DPI filters. Returns highest-priority (lowest value) match.
  [[nodiscard]] DpiResult Match(std::string_view hostname) const noexcept;

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

  /// Look up the filter index for a given DPI filter group name (e.g.
  /// `"fg_l7_facebook"`). Returns the index of the FIRST filter with that
  /// `filter_group` value, or `std::nullopt` if none match. Used by the
  /// SPI→DPI static link resolver at compile / reload time, NOT on the
  /// hot path. Linear scan over `filters_` is acceptable because
  ///   (a) typical filter count is ≤30, fits in one cache line, and
  ///   (b) this runs once per config load / SIGUSR1, not per packet.
  [[nodiscard]] std::optional<std::uint32_t> FindByFilterGroup(
      std::string_view name) const noexcept;

  /// Whether DPI is enabled and filters are loaded.
  [[nodiscard]] bool IsEnabled() const noexcept { return !filters_.empty(); }

  [[nodiscard]] std::size_t FilterCount() const noexcept { return filters_.size(); }

  /// Monotonic generation counter — incremented on each reload via
  /// `DpiRuleTableManager::Swap`. Workers compare the cached generation
  /// against `Generation()` on every Lookup; mismatch is treated as a
  /// miss and triggers a re-scan. See docs_search/13 §M1.
  [[nodiscard]] std::uint32_t Generation() const noexcept { return generation_; }

  /// Set the generation. Used by `DpiRuleTableManager::Swap` when the
  /// new table replaces the old.
  void SetGeneration(std::uint32_t gen) noexcept { generation_ = gen; }

 private:
  /// Original filter list — provides filter_group / label for results.
  /// Sorted by priority ASC so the first match in Match() is also the
  /// highest-priority match.
  std::vector<CompiledDpiFilter> filters_;

  /// Exact-match rules (small, < 10 entries typical). Linear scan.
  std::vector<std::pair<std::string_view, std::uint16_t>> exact_list_;

  /// Suffix-match rules sorted by domain ASC for early-exit on mismatch.
  /// ~25 entries typical, fits in 1-2 cache lines.
  std::vector<DpiSuffixEntry> suffix_list_;

  /// Index into `filters_` of the `*` catch-all rule, or sentinel if none.
  std::uint16_t catch_all_idx_{std::numeric_limits<std::uint16_t>::max()};
  /// Generation counter — see `Generation()`.
  std::uint32_t generation_{0U};
};

/// Compile DPI config into a rule table.
[[nodiscard]] std::expected<DpiRuleTable, std::string> CompileDpiRuleTable(const DpiConfig& config) noexcept;

}  // namespace dpdk::dpi

