#include "dpdk/dpi/dpi_rule_engine.hpp"

#include <algorithm>
#include <cstring>
#include <format>
#include <ranges>
#include <string_view>

namespace dpdk::dpi {

DpiRuleTable::DpiRuleTable(std::vector<CompiledDpiFilter> filters) noexcept : filters_{std::move(filters)} {}

DpiResult DpiRuleTable::Match(std::string_view hostname) const noexcept {
  if (hostname.empty()) [[unlikely]]
    return {};

  for (const auto& filter : filters_) {
    if (filter.is_catch_all) {
      return DpiResult{
          .filter_group = filter.filter_group,
          .label = filter.label,
          .priority = filter.priority,
          .matched = true,
      };
    }

    if (filter.is_suffix_match) {
      // Pattern: "*.facebook.com" — match suffix after "*."
      const std::string_view suffix{filter.hostname_pattern + 1};  // skip '*'
      if (hostname.size() > suffix.size() && hostname.ends_with(suffix) &&
          hostname[hostname.size() - suffix.size() - 1] == '.') {
        return DpiResult{
            .filter_group = filter.filter_group,
            .label = filter.label,
            .priority = filter.priority,
            .matched = true,
        };
      }
    } else {
      // Exact match
      const std::string_view pattern{filter.hostname_pattern, filter.hostname_pattern_length};
      if (hostname == pattern) {
        return DpiResult{
            .filter_group = filter.filter_group,
            .label = filter.label,
            .priority = filter.priority,
            .matched = true,
        };
      }
    }
  }

  return {};
}

std::expected<DpiRuleTable, std::string> CompileDpiRuleTable(const DpiConfig& config) noexcept {
  std::vector<CompiledDpiFilter> filters;
  filters.reserve(config.filters.size());

  for (const auto& [fi, filter_config] : config.filters | std::views::enumerate) {
    CompiledDpiFilter filter;

    const auto& pattern{filter_config.hostname_pattern};
    if (pattern.size() >= sizeof(filter.hostname_pattern)) {
      return std::unexpected(std::format("dpi.filters[{}].hostname_pattern too long", fi));
    }

    std::strncpy(filter.hostname_pattern, pattern.c_str(), sizeof(filter.hostname_pattern) - 1);
    filter.hostname_pattern_length = static_cast<std::uint16_t>(pattern.size());
    filter.is_catch_all = (pattern == "*");
    filter.is_suffix_match = (pattern.starts_with("*."));
    filter.filter_group = filter_config.filter_group;
    filter.priority = filter_config.priority;
    filter.label = filter_config.label;

    filters.push_back(std::move(filter));
  }

  // Sort by priority (ascending — smallest = highest priority).
  std::ranges::sort(filters,
                    [](const CompiledDpiFilter& a, const CompiledDpiFilter& b) { return a.priority < b.priority; });

  return DpiRuleTable{std::move(filters)};
}

}  // namespace dpdk::dpi
