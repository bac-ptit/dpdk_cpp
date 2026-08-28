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

/// Escape regular expression metacharacters in a string literal.
[[nodiscard]] std::string EscapeRegex(std::string_view str) noexcept {
  std::string escaped;
  escaped.reserve(str.size() * 2);
  for (const char c : str) {
    if (c == '.' || c == '\\' || c == '+' || c == '*' || c == '?' ||
        c == '[' || c == '^' || c == ']' || c == '$' || c == '(' ||
        c == ')' || c == '{' || c == '}' || c == '=' || c == '!' ||
        c == '<' || c == '>' || c == '|' || c == ':') {
      escaped.push_back('\\');
    }
    escaped.push_back(c);
  }
  return escaped;
}

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

/// Context passed to the Hyperscan match callback.
struct HsMatchContext {
  uint32_t matched_filter_idx{std::numeric_limits<uint32_t>::max()};
  uint32_t best_priority{std::numeric_limits<uint32_t>::max()};
  const std::vector<CompiledDpiFilter>* filters{nullptr};
};

/// Hyperscan match callback: selects the rule with the highest priority (lowest numerical value).
static int OnHyperscanMatch(unsigned int id, unsigned long long /*from*/,
                            unsigned long long /*to*/, unsigned int /*flags*/,
                            void* ctx) noexcept {
  auto* context = static_cast<HsMatchContext*>(ctx);
  const auto filter_idx = static_cast<std::size_t>(id);
  if (context != nullptr && context->filters != nullptr && filter_idx < context->filters->size()) {
    const auto prio = (*context->filters)[filter_idx].priority;
    if (prio < context->best_priority) {
      context->best_priority = prio;
      context->matched_filter_idx = static_cast<uint32_t>(filter_idx);
    }
  }
  return 0;  // Continue matching to find the absolute highest priority match
}

}  // namespace

DpiRuleTable::DpiRuleTable(std::vector<CompiledDpiFilter> filters, hs_database_t* hs_db) noexcept
    : filters_{std::move(filters)}, hs_db_{hs_db} {
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

DpiRuleTable::DpiRuleTable(DpiRuleTable&& other) noexcept
    : filters_{std::move(other.filters_)},
      exact_map_{std::move(other.exact_map_)},
      suffix_map_{std::move(other.suffix_map_)},
      exact_list_{std::move(other.exact_list_)},
      suffix_list_{std::move(other.suffix_list_)},
      catch_all_idx_{other.catch_all_idx_},
      generation_{other.generation_},
      hs_db_{std::exchange(other.hs_db_, nullptr)} {}

DpiRuleTable& DpiRuleTable::operator=(DpiRuleTable&& other) noexcept {
  if (this != &other) {
    if (hs_db_ != nullptr) {
      hs_free_database(hs_db_);
    }
    filters_ = std::move(other.filters_);
    exact_map_ = std::move(other.exact_map_);
    suffix_map_ = std::move(other.suffix_map_);
    exact_list_ = std::move(other.exact_list_);
    suffix_list_ = std::move(other.suffix_list_);
    catch_all_idx_ = other.catch_all_idx_;
    generation_ = other.generation_;
    hs_db_ = std::exchange(other.hs_db_, nullptr);
  }
  return *this;
}

DpiRuleTable::~DpiRuleTable() noexcept {
  if (hs_db_ != nullptr) {
    hs_free_database(hs_db_);
    hs_db_ = nullptr;
  }
}

hs_scratch_t* DpiRuleTable::AllocScratch() const noexcept {
  if (hs_db_ == nullptr) return nullptr;
  hs_scratch_t* scratch{nullptr};
  if (hs_alloc_scratch(hs_db_, &scratch) != HS_SUCCESS) {
    return nullptr;
  }
  return scratch;
}

void DpiRuleTable::FreeScratch(hs_scratch_t* scratch) const noexcept {
  if (scratch != nullptr) {
    hs_free_scratch(scratch);
  }
}

DpiResult DpiRuleTable::Match(std::string_view hostname, hs_scratch_t* scratch) const noexcept {
  if (hostname.empty()) [[unlikely]] {
    return {};
  }

  if (hs_db_ != nullptr && scratch != nullptr) [[likely]] {
    HsMatchContext match_ctx{
        .filters = &filters_,
    };

    const auto ret = hs_scan(
        hs_db_,
        hostname.data(),
        static_cast<unsigned int>(hostname.size()),
        0,
        scratch,
        OnHyperscanMatch,
        &match_ctx);

    if (ret == HS_SUCCESS && match_ctx.matched_filter_idx < filters_.size()) {
      const auto& filter = filters_[match_ctx.matched_filter_idx];
      return DpiResult{
          .filter_group = filter.filter_group,
          .label = filter.label,
          .priority = filter.priority,
          .matched = true,
      };
    }
    return {};
  }

  return MatchFallback(hostname);
}

DpiResult DpiRuleTable::Match(std::string_view hostname) const noexcept {
  if (hostname.empty()) [[unlikely]] {
    return {};
  }

  if (hs_db_ != nullptr) [[likely]] {
    static thread_local hs_scratch_t* tl_scratch{nullptr};
    if (tl_scratch == nullptr) [[unlikely]] {
      if (hs_alloc_scratch(hs_db_, &tl_scratch) != HS_SUCCESS) [[unlikely]] {
        return MatchFallback(hostname);
      }
    }
    return Match(hostname, tl_scratch);
  }

  return MatchFallback(hostname);
}

DpiResult DpiRuleTable::MatchFallback(std::string_view hostname) const noexcept {
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

  // Sort filters by priority ascending before compiling Hyperscan patterns
  std::ranges::sort(filters,
                     [](const CompiledDpiFilter& lhs, const CompiledDpiFilter& rhs) {
                       return lhs.priority < rhs.priority;
                    });

  std::vector<const char*> hs_patterns;
  std::vector<unsigned int> hs_flags;
  std::vector<unsigned int> hs_ids;
  std::vector<std::string> regex_strings;

  hs_patterns.reserve(filters.size());
  hs_flags.reserve(filters.size());
  hs_ids.reserve(filters.size());
  regex_strings.reserve(filters.size());

  for (std::size_t i{0}; i < filters.size(); ++i) {
    const auto& f = filters[i];
    std::string_view raw_pattern{&f.hostname_pattern[0], f.hostname_pattern_length};
    std::string regex;

    if (f.is_catch_all) {
      regex = ".*";
    } else if (f.is_suffix_match) {
      // "*.facebook.com" -> "(^|\.)facebook\.com$"
      const auto domain = (raw_pattern.size() >= 2) ? raw_pattern.substr(2) : raw_pattern;
      regex = std::format(R"((^|\.)({})$)", EscapeRegex(domain));
    } else {
      // Exact match e.g. "dns.google" -> "^dns\.google$"
      regex = std::format(R"(^({})$)", EscapeRegex(raw_pattern));
    }

    regex_strings.push_back(std::move(regex));
    hs_patterns.push_back(regex_strings.back().c_str());
    hs_flags.push_back(HS_FLAG_CASELESS | HS_FLAG_DOTALL | HS_FLAG_ALLOWEMPTY);
    hs_ids.push_back(static_cast<unsigned int>(i));
  }

  hs_database_t* hs_db{nullptr};
  if (!hs_patterns.empty()) {
    hs_compile_error_t* compile_err{nullptr};
    const auto compile_res = hs_compile_multi(
        hs_patterns.data(),
        hs_flags.data(),
        hs_ids.data(),
        static_cast<unsigned int>(hs_patterns.size()),
        HS_MODE_BLOCK,
        nullptr,
        &hs_db,
        &compile_err);

    if (compile_res != HS_SUCCESS) {
      std::string err_msg = "Unknown Hyperscan compile error";
      if (compile_err != nullptr) {
        if (compile_err->message != nullptr) {
          err_msg = compile_err->message;
        }
        hs_free_compile_error(compile_err);
      }
      return std::unexpected(std::format("Hyperscan compilation failed: {}", err_msg));
    }
  }

  return DpiRuleTable{std::move(filters), hs_db};
}

}  // namespace dpdk::dpi
