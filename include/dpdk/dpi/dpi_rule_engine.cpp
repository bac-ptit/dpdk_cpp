#include "dpdk/dpi/dpi_rule_engine.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <expected>
#include <format>
#include <limits>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace dpdk::dpi {

namespace {

/// Compute the "domain key" for suffix-match lookup: the last two
/// dot-separated components of `hostname`. For example
/// "static.xx.fbcdn.net" -> "fbcdn.net". Returns a view into the input.
[[nodiscard]] std::string_view ExtractDomainKey(std::string_view hostname) noexcept {
  if (hostname.empty()) {
    return {};
  }
  const auto last_dot = hostname.rfind('.');
  if (last_dot == std::string_view::npos || last_dot == 0) {
    return {};
  }
  std::size_t start{};
  for (std::size_t i{last_dot}; i > 0; --i) {
    if (hostname[i - 1] == '.') {
      start = i;
      break;
    }
  }
  return hostname.substr(start);
}

/// Build the suffix-map key: the part of `pattern` after "*." (without
/// the leading "*."), or empty if not a suffix pattern.
[[nodiscard]] std::string_view SuffixKeyOf(std::string_view pattern) noexcept {
  if (pattern.size() >= 2 && pattern[0] == '*' && pattern[1] == '.') {
    return pattern.substr(2);
  }
  return {};
}

}  // namespace

DpiRuleTable::DpiRuleTable(std::vector<CompiledDpiFilter> filters) noexcept
    : filters_{std::move(filters)} {
  // Sort by priority ASC so the first match is the highest-priority match.
  std::ranges::sort(filters_,
                     [](const CompiledDpiFilter& lhs, const CompiledDpiFilter& rhs) {
                       return lhs.priority < rhs.priority;
                    });

  // Populate both list and hash map indexes for small and large N scaling.
  for (std::size_t i{}; i < filters_.size(); ++i) {
    const auto& filter = filters_[i];
    const std::string_view pattern{&filter.hostname_pattern[0], filter.hostname_pattern_length};
    const auto idx = static_cast<std::uint16_t>(i);
    if (filter.is_catch_all) {
      catch_all_idx_ = idx;
    } else if (filter.is_suffix_match) {
      const auto key = SuffixKeyOf(pattern);
      if (!key.empty()) {
        suffix_list_.push_back(DpiSuffixEntry{.domain = key, .filter_index = idx});
        suffix_map_.try_emplace(key, idx);
      }
    } else {
      exact_list_.emplace_back(pattern, idx);
      exact_map_.try_emplace(pattern, idx);
    }
  }

  std::ranges::sort(suffix_list_,
                     [](const DpiSuffixEntry& lhs, const DpiSuffixEntry& rhs) {
                       return lhs.domain < rhs.domain;
                    });
}

DpiResult DpiRuleTable::Match(std::string_view hostname) const noexcept {
  if (hostname.empty()) [[unlikely]] {
    return {};
  }

  // 1. Exact-match rules — O(1) map lookup for scale, linear scan for small N
  if (exact_map_.size() > 16) {
    if (auto it = exact_map_.find(hostname); it != exact_map_.end()) {
      const auto& filter = filters_[it->second];
      return DpiResult{
          .filter_group = filter.filter_group,
          .label = filter.label,
          .priority = filter.priority,
          .matched = true,
      };
    }
  } else {
    for (const auto& [pattern, idx] : exact_list_) {
      if (hostname == pattern) {
        const auto& filter = filters_[idx];
        return DpiResult{
            .filter_group = filter.filter_group,
            .label = filter.label,
            .priority = filter.priority,
            .matched = true,
        };
      }
    }
  }

  // 2. Suffix-match — O(1) map lookup for scale, linear scan for small N
  if (const auto domain = ExtractDomainKey(hostname); !domain.empty()) {
    if (suffix_map_.size() > 16) {
      if (auto it = suffix_map_.find(domain); it != suffix_map_.end()) {
        const auto& filter = filters_[it->second];
        return DpiResult{
            .filter_group = filter.filter_group,
            .label = filter.label,
            .priority = filter.priority,
            .matched = true,
        };
      }
    } else {
      for (const auto& entry : suffix_list_) {
        if (entry.domain > domain) {
          break;
        }
        if (entry.domain == domain) {
          const auto& filter = filters_[entry.filter_index];
          return DpiResult{
              .filter_group = filter.filter_group,
              .label = filter.label,
              .priority = filter.priority,
              .matched = true,
          };
        }
      }
    }
  }

  // 3. Catch-all fallback (only one — "*" — and lowest priority 999).
  if (catch_all_idx_ != std::numeric_limits<std::uint16_t>::max()) {
    const auto& filter = filters_[catch_all_idx_];
    return DpiResult{
        .filter_group = filter.filter_group,
        .label = filter.label,
        .priority = filter.priority,
        .matched = true,
    };
  }

  return {};
}

std::optional<std::uint32_t> DpiRuleTable::FindByFilterGroup(
    std::string_view name) const noexcept {
  if (name.empty()) {
    return std::nullopt;
  }
  for (std::uint32_t i{0}; i < filters_.size(); ++i) {
    if (filters_[i].filter_group == name) {
      return i;
    }
  }
  return std::nullopt;
}

// std::format is safe with -fno-exceptions; DpiConfig comes from dpi_rule_engine.hpp
// NOLINTNEXTLINE(bugprone-exception-escape, misc-include-cleaner)
std::expected<DpiRuleTable, std::string> CompileDpiRuleTable(const DpiConfig& config) noexcept {
  std::vector<CompiledDpiFilter> filters;
  filters.reserve(config.filters.size());

  for (const auto& [filter_idx, filter_config] : config.filters | std::views::enumerate) {
    CompiledDpiFilter filter;

    const auto& pattern{filter_config.hostname_pattern};
    if (pattern.size() >= sizeof(filter.hostname_pattern)) {
      return std::unexpected(std::format("dpi.filters[{}].hostname_pattern too long", filter_idx));
    }

    std::strncpy(&filter.hostname_pattern[0], pattern.c_str(), sizeof(filter.hostname_pattern) - 1);
    filter.hostname_pattern_length = static_cast<std::uint16_t>(pattern.size());
    filter.is_catch_all = (pattern == "*");
    filter.is_suffix_match = (pattern.starts_with("*."));
    filter.filter_group = filter_config.filter_group;
    filter.priority = filter_config.priority;
    filter.label = filter_config.label;

    filters.push_back(std::move(filter));
  }

  return DpiRuleTable{std::move(filters)};
}

}  // namespace dpdk::dpi
