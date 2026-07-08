#include "dpdk/dpi/dpi_rule_engine.hpp"

#include <algorithm>
#include <cstring>
#include <format>
#include <limits>
#include <ranges>
#include <string_view>

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
  std::size_t start = 0;
  for (std::size_t i = last_dot; i > 0; --i) {
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
                    [](const CompiledDpiFilter& a, const CompiledDpiFilter& b) {
                      return a.priority < b.priority;
                    });

  const auto kNoIdx = std::numeric_limits<std::uint16_t>::max();
  catch_all_idx_ = kNoIdx;

  // Populate the small lookup indexes (vector-backed for cache locality).
  for (std::uint16_t i = 0; i < filters_.size(); ++i) {
    const auto& f = filters_[i];
    const std::string_view pattern{f.hostname_pattern, f.hostname_pattern_length};
    if (f.is_catch_all) {
      catch_all_idx_ = i;
    } else if (f.is_suffix_match) {
      const auto key = SuffixKeyOf(pattern);
      if (!key.empty()) {
        suffix_list_.push_back(DpiSuffixEntry{.domain = key, .filter_index = i});
      }
    } else {
      exact_list_.emplace_back(pattern, i);
    }
  }

  // Sort suffix_list_ by domain ASC for early-exit linear scan. For ~25
  // entries this fits in 1-2 cache lines and beats unordered_map on
  // small N (no hash compute, no bucket indirection).
  std::ranges::sort(suffix_list_,
                    [](const DpiSuffixEntry& a, const DpiSuffixEntry& b) {
                      return a.domain < b.domain;
                    });
}

DpiResult DpiRuleTable::Match(std::string_view hostname) const noexcept {
  if (hostname.empty()) [[unlikely]] {
    return {};
  }

  // 1. Exact-match rules — usually < 5 entries, linear scan wins.
  for (const auto& [pattern, idx] : exact_list_) {
    if (hostname == pattern) {
      const auto& f = filters_[idx];
      return DpiResult{
          .filter_group = f.filter_group,
          .label = f.label,
          .priority = f.priority,
          .matched = true,
      };
    }
  }

  // 2. Suffix-match — extract last 2 dot-segments, linear-scan the
  //    sorted suffix list. Stops early when the suffix key exceeds the
  //    current entry (because list is sorted ASC by domain key).
  if (const auto domain = ExtractDomainKey(hostname); !domain.empty()) {
    for (const auto& entry : suffix_list_) {
      if (entry.domain > domain) {
        break;  // sorted ASC — past all possible matches
      }
      if (entry.domain == domain) {
        const auto& f = filters_[entry.filter_index];
        return DpiResult{
            .filter_group = f.filter_group,
            .label = f.label,
            .priority = f.priority,
            .matched = true,
        };
      }
    }
  }

  // 3. Catch-all fallback (only one — "*" — and lowest priority 999).
  if (catch_all_idx_ != std::numeric_limits<std::uint16_t>::max()) {
    const auto& f = filters_[catch_all_idx_];
    return DpiResult{
        .filter_group = f.filter_group,
        .label = f.label,
        .priority = f.priority,
        .matched = true,
    };
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

  return DpiRuleTable{std::move(filters)};
}

}  // namespace dpdk::dpi
