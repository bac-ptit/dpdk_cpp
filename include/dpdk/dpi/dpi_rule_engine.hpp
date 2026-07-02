#pragma once

#include <cstdint>
#include <expected>
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

/// Immutable table of compiled DPI filters, sorted by priority.
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

  /// Whether DPI is enabled and filters are loaded.
  [[nodiscard]] bool IsEnabled() const noexcept { return !filters_.empty(); }

  [[nodiscard]] std::size_t FilterCount() const noexcept { return filters_.size(); }

 private:
  std::vector<CompiledDpiFilter> filters_;
};

/// Compile DPI config into a rule table.
[[nodiscard]] std::expected<DpiRuleTable, std::string> CompileDpiRuleTable(const DpiConfig& config) noexcept;

}  // namespace dpdk::dpi
