#include "dpdk/spi/spi_rule_engine.hpp"
#include "dpdk/spi/spi_flow_table.hpp"

#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <format>
#include <memory>
#include <numeric>
#include <print>
#include <ranges>
#include <string_view>
#include <utility>

#include "dpdk/dpi/dpi_rule_engine.hpp"
#include "dpdk/spi/spi_ip_address.hpp"

namespace dpdk::spi {

// ---------------------------------------------------------------------------
// RuleTable lifecycle
// ---------------------------------------------------------------------------

RuleTable::~RuleTable() {
  if (acl_ctx_ != nullptr) {
    rte_acl_free(acl_ctx_);
  }
}

// ---------------------------------------------------------------------------
// CompiledFilterGroup rule-of-five
// ---------------------------------------------------------------------------
//
// PR4 removed `acl_ctx` from the struct, so the destructor is now trivial.
// The move ctor and assignment are still required because the struct owns
// `std::vector<CompiledFilter> filters;` (heap-allocated strings).

CompiledFilterGroup::CompiledFilterGroup(CompiledFilterGroup&& other) noexcept
    : name{std::move(other.name)},
      precedence{other.precedence},
      action{other.action},
      filters{std::move(other.filters)},
      category_index{other.category_index},
      l7_required{other.l7_required},
      bound_dpi_filter_index{other.bound_dpi_filter_index},
      bound_dpi_name{std::move(other.bound_dpi_name)} {}

CompiledFilterGroup& CompiledFilterGroup::operator=(CompiledFilterGroup&& other) noexcept {
  if (this != &other) {
    name = std::move(other.name);
    precedence = other.precedence;
    action = other.action;
    filters = std::move(other.filters);
    category_index = other.category_index;
    l7_required = other.l7_required;
    bound_dpi_filter_index = other.bound_dpi_filter_index;
    bound_dpi_name = std::move(other.bound_dpi_name);
  }
  return *this;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

[[nodiscard]] constexpr std::optional<Protocol> ParseProtocol(std::string_view protocol) noexcept {
  if (protocol == "tcp") {
    return Protocol::kTcp;
  }
  if (protocol == "udp") {
    return Protocol::kUdp;
  }
  return std::nullopt;
}

[[nodiscard]] constexpr Action ParseAction(const std::string& action) noexcept {
  if (action == "drop") {
    return Action::kDrop;
  }
  return Action::kForward;
}

/// IP protocol number for TCP (RFC 793).
constexpr uint8_t kIpProtoTcp{6};
/// IP protocol number for UDP (RFC 768).
constexpr uint8_t kIpProtoUdp{17};

[[nodiscard]] constexpr uint8_t ProtocolToIpProto(Protocol protocol) noexcept {
  return protocol == Protocol::kTcp ? kIpProtoTcp : kIpProtoUdp;
}

/// Base for decimal number parsing.
constexpr int kDecimalBase{10};

[[nodiscard]] bool IsCidr(std::string_view address) noexcept { return address.contains('/'); }

/// Build one rte_acl_rule from a parsed CompiledFilter.
/// MASK type with bitmask values. Port/protocol also set but verified in C++.
///
/// `category_index` is the bit position in the combined ctx's category_mask:
/// only rules with this bit set in their category_mask participate in
/// `results[category_index]`. `priority` is `RTE_ACL_MAX_PRIORITY -
/// category_index` so that within a category the userdata encoding wins via
/// the ACL priority resolution (defensive — we use category_index for the
/// actual precedence walk in Match()).
void BuildAclRule(struct rte_acl_rule* rule, const CompiledFilter& filter, uint32_t rule_index,
                  std::uint32_t category_index) noexcept {
  std::memset(rule, 0, static_cast<std::size_t>(RTE_ACL_RULE_SZ(kAclNumFields)));

  rule->data.userdata = rule_index + 1;
  rule->data.priority = RTE_ACL_MAX_PRIORITY - static_cast<int32_t>(category_index);
  rule->data.category_mask = 1ULL << category_index;

  // src_ip
  rule->field[static_cast<uint8_t>(AclFieldIndex::kSrcIp)].value.u32 = rte_cpu_to_be_32(filter.source_ip_address);
  rule->field[static_cast<uint8_t>(AclFieldIndex::kSrcIp)].mask_range.u32 = filter.match_source_ip ? UINT32_MAX : 0;

  // dst_ip
  if (filter.match_destination_cidr) {
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstIp)].value.u32 = rte_cpu_to_be_32(filter.destination_network);
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstIp)].mask_range.u32 = rte_cpu_to_be_32(filter.destination_prefix_mask);
  } else if (filter.match_destination_ip) {
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstIp)].value.u32 = rte_cpu_to_be_32(filter.destination_ip_address);
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstIp)].mask_range.u32 = UINT32_MAX;
  } else {
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstIp)].value.u32 = 0;
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstIp)].mask_range.u32 = 0;
  }

  // src_port
  rule->field[static_cast<uint8_t>(AclFieldIndex::kSrcPort)].value.u16 = rte_cpu_to_be_16(filter.source_port);
  rule->field[static_cast<uint8_t>(AclFieldIndex::kSrcPort)].mask_range.u16 = filter.match_source_port ? UINT16_MAX : 0;

  // dst_port
  rule->field[static_cast<uint8_t>(AclFieldIndex::kDstPort)].value.u16 = rte_cpu_to_be_16(filter.destination_port);
  rule->field[static_cast<uint8_t>(AclFieldIndex::kDstPort)].mask_range.u16 = filter.match_destination_port ? UINT16_MAX : 0;

  // protocol
  rule->field[static_cast<uint8_t>(AclFieldIndex::kProtocol)].value.u8 = ProtocolToIpProto(filter.protocol);
  rule->field[static_cast<uint8_t>(AclFieldIndex::kProtocol)].mask_range.u8 = UINT8_MAX;
}

[[nodiscard]] std::expected<CompiledFilter, std::string> CompileFilter(const SpiFilterConfig& filter_config,
                                                                        std::size_t group_index,
                                                                        std::size_t filter_index) noexcept {
  const auto protocol{ParseProtocol(filter_config.protocol)};
  if (!protocol) {
    return std::unexpected(
        std::format("filter_groups[{}].filters[{}].protocol must be 'tcp' or 'udp'", group_index, filter_index));
  }

  std::uint32_t source_ip{};
  if (filter_config.source_ip_address) {
    const auto parsed{ParseIpv4Address(*filter_config.source_ip_address)};
    if (!parsed) {
      return std::unexpected(
          std::format("filter_groups[{}].filters[{}].source_ip_address {}", group_index, filter_index, parsed.error()));
    }
    source_ip = *parsed;
  }

  std::uint32_t dest_ip{};
  std::uint32_t dest_network{};
  std::uint32_t dest_mask{};
  std::uint32_t dest_prefix_len{};
  bool is_cidr{false};

  if (filter_config.destination_ip_address) {
    if (IsCidr(*filter_config.destination_ip_address)) {
      const auto parsed{ParseCidr(*filter_config.destination_ip_address)};
      if (!parsed) {
        return std::unexpected(std::format("filter_groups[{}].filters[{}].destination_ip_address {}", group_index,
                                           filter_index, parsed.error()));
      }
      dest_network = parsed->first;
      dest_mask = parsed->second;
      // Extract prefix length from CIDR string (e.g. "31.13.64.0/18" → 18).
      const auto slash{filter_config.destination_ip_address->find('/')};
      const auto prefix_str{filter_config.destination_ip_address->substr(slash + 1)};
      dest_prefix_len = static_cast<std::uint32_t>(std::strtoul(prefix_str.c_str(), nullptr, kDecimalBase));
      is_cidr = true;
    } else {
      const auto parsed{ParseIpv4Address(*filter_config.destination_ip_address)};
      if (!parsed) {
        return std::unexpected(std::format("filter_groups[{}].filters[{}].destination_ip_address {}", group_index,
                                           filter_index, parsed.error()));
      }
      dest_ip = *parsed;
    }
  }

  return CompiledFilter{
      .protocol = *protocol,
      .source_ip_address = source_ip,
      .destination_ip_address = dest_ip,
      .destination_network = dest_network,
      .destination_prefix_mask = dest_mask,
      .destination_prefix_length = dest_prefix_len,
      .source_port = filter_config.source_port.value_or(0),
      .destination_port = filter_config.destination_port.value_or(0),
      .match_source_ip = filter_config.source_ip_address.has_value(),
      .match_destination_ip = filter_config.destination_ip_address.has_value() && !is_cidr,
      .match_destination_cidr = is_cidr,
      .match_source_port = filter_config.source_port.has_value(),
      .match_destination_port = filter_config.destination_port.has_value(),
      .label = filter_config.label,
  };
}

}  // namespace

// ---------------------------------------------------------------------------
// RuleTable
// ---------------------------------------------------------------------------

RuleTable::RuleTable(std::vector<CompiledFilterGroup> groups, rte_acl_ctx* acl_ctx,
                       std::vector<std::uint32_t> precedence_order) noexcept
    : groups_{std::move(groups)}, acl_ctx_{acl_ctx}, precedence_order_{std::move(precedence_order)} {
  // Build the Tuple-Space Search pre-check table once at compile time. The
  // groups vector is already sorted by precedence and each `category_index`
  // is the position in the sorted vector, so the values we store here
  // match the category_index that `Match()` walks in precedence order.
  BuildTssFromGroups();
}

RuleTable::RuleTable(RuleTable&& other) noexcept
    : groups_{std::move(other.groups_)}, acl_ctx_{other.acl_ctx_},
      precedence_order_{std::move(other.precedence_order_)} {
  // Null the source so the moved-from RuleTable's destructor doesn't free
  // the acl_ctx_ that we now own.
  other.acl_ctx_ = nullptr;
}

RuleTable& RuleTable::operator=(RuleTable&& other) noexcept {
  if (this != &other) {
    if (acl_ctx_ != nullptr) {
      rte_acl_free(acl_ctx_);
    }
    groups_ = std::move(other.groups_);
    acl_ctx_ = other.acl_ctx_;
    precedence_order_ = std::move(other.precedence_order_);
    other.acl_ctx_ = nullptr;
  }
  return *this;
}

/// Check if a filter's port/protocol constraints match the packet.
[[nodiscard, gnu::always_inline]] inline bool FilterMatchesPortProtocol(const CompiledFilter& filter,
                                                                        const PacketMetadata& packet) noexcept {
  if (filter.protocol != packet.protocol) {
    return false;
  }
  if (filter.match_destination_port && filter.destination_port != packet.destination_port) {
    return false;
  }
  if (filter.match_source_port && filter.source_port != packet.source_port) {
    return false;
  }
  return true;
}

ClassificationResult RuleTable::Match(const PacketMetadata& packet) const noexcept {
  if (acl_ctx_ == nullptr) [[unlikely]] {
    return {};
  }

  AclInputData acl_input{};
  acl_input.src_ip_be = rte_cpu_to_be_32(packet.source_ip_address);
  acl_input.dst_ip_be = rte_cpu_to_be_32(packet.destination_ip_address);
  acl_input.src_port_be = rte_cpu_to_be_16(packet.source_port);
  acl_input.dst_port_be = rte_cpu_to_be_16(packet.destination_port);
  acl_input.protocol = packet.protocol == Protocol::kTcp ? kIpProtoTcp : kIpProtoUdp;

  const uint8_t* data[1] = {reinterpret_cast<const uint8_t*>(&acl_input)};
  std::array<std::uint32_t, kMaxCategories> results{};

  // rte_acl_classify requires `categories` to be either 1 or a multiple of
  // RTE_ACL_RESULTS_MULTIPLIER (= XMM_SIZE / sizeof(uint32_t) = 4 on x86-64)
  // and ≤ RTE_ACL_MAX_CATEGORIES (= 16). Passing `kMaxCategories = 64`
  // violates both constraints and causes DPDK's classify path to scribble
  // past its internal scratch buffer — that's the source of the "stack
  // smashing detected" we were chasing through ProcessPortBurst /
  // ResolvePacketAction / Match. Round up to a valid multiple of 4 and
  // cap at RTE_ACL_MAX_CATEGORIES. We don't read past `groups_.size()` in
  // the precedence walk below, so over-allocating the results span is
  // safe.
  constexpr std::uint32_t kAclResultsMultiplier{4U};
  constexpr std::uint32_t kAclMaxCategoriesHard{16U};
  const auto classify_categories{
      std::min<std::uint32_t>(
          ((static_cast<std::uint32_t>(groups_.size()) + kAclResultsMultiplier - 1U)
           / kAclResultsMultiplier) * kAclResultsMultiplier,
          kAclMaxCategoriesHard)};

  const int ret{rte_acl_classify(acl_ctx_, data, results.data(), 1, classify_categories)};
  if (ret != 0) [[unlikely]] {
    return {};
  }

  // Walk categories in precedence order (ascending — lowest value wins).
  // `results[cat]` is the userdata of the matching rule in that category,
  // or 0 if no rule in that category matched. `category_index` doubles as
  // the position in `groups_` because we sorted groups by precedence
  // before assigning category_index = position.
  for (const auto cat : precedence_order_) {
    const auto userdata{results[cat]};
    if (userdata == 0) [[likely]] {
      continue;
    }
    const auto& group{groups_[cat]};
    const auto filter_index{userdata - 1};
    if (filter_index < group.filters.size() &&
        FilterMatchesPortProtocol(group.filters[filter_index], packet)) [[likely]] {
      return ClassificationResult{
          .group_name = group.name,
          .label = group.filters[filter_index].label,
          .action = group.action,
          .group_precedence = group.precedence,
          .matched = true,
          .l7_required = group.l7_required,
          .bound_dpi_filter_index = group.bound_dpi_filter_index,
      };
    }
  }

  return {};
}

std::size_t RuleTable::FilterCount() const noexcept {
  std::size_t count{0};
  for (const auto& group : groups_) {
    count += group.filters.size();
  }
  return count;
}

std::expected<void, std::string> RuleTable::RebuildInPlace(
    std::vector<CompiledFilterGroup> new_groups,
    std::vector<std::uint32_t> new_precedence_order) noexcept {
  if (acl_ctx_ == nullptr) [[unlikely]] {
    return std::unexpected("RebuildInPlace called on RuleTable with no acl_ctx_");
  }
  if (new_groups.size() > kMaxCategories) {
    return std::unexpected(std::format("rebuild group count {} exceeds RTE_ACL_MAX_CATEGORIES={}", new_groups.size(),
                                       kMaxCategories));
  }

  // Reset the existing ctx's rules — this frees the rule trie storage
  // inside rte_acl but keeps the surrounding allocation, so the next
  // rte_acl_add_rules can reuse the same backing store up to max_rule_num.
  // `rte_acl_reset_rules` returns void.
  rte_acl_reset_rules(acl_ctx_);

  // Compute total rules + build rule buffer in pre-allocated storage. We
  // allocate the rule buffer *once* per RebuildInPlace call (per-reload);
  // the underlying rte_acl ctx is reused. To eliminate even this
  // per-reload alloc, callers should pre-size a worker-side rule arena
  // and copy into it (future optimisation).
  std::size_t total_rules{0};
  for (const auto& group : new_groups) {
    total_rules += group.filters.size();
  }
  if (total_rules == 0) {
    return std::unexpected("rebuild got zero rules (config invalid)");
  }

  const auto rule_size{static_cast<std::size_t>(RTE_ACL_RULE_SZ(kAclNumFields))};
  auto rule_buf{std::make_unique<uint8_t[]>(rule_size * total_rules)};
  std::size_t rule_offset{0};
  for (std::uint32_t cat{0}; cat < new_groups.size(); ++cat) {
    const auto& group{new_groups[cat]};
    for (std::uint32_t f{0}; f < group.filters.size(); ++f) {
      auto* rule{reinterpret_cast<struct rte_acl_rule*>(rule_buf.get() + (rule_offset * rule_size))};
      BuildAclRule(rule, group.filters[f], f, cat);
      ++rule_offset;
    }
  }

  auto* rules{reinterpret_cast<struct rte_acl_rule*>(rule_buf.get())};
  if (const int add_ret{rte_acl_add_rules(acl_ctx_, rules, static_cast<uint32_t>(total_rules))}; add_ret != 0) {
    return std::unexpected(std::format("rte_acl_add_rules failed during rebuild: {}", -add_ret));
  }

  struct rte_acl_config acl_cfg{};
  acl_cfg.num_categories = static_cast<uint32_t>(new_groups.size());
  acl_cfg.num_fields = kAclNumFields;
  std::memcpy(acl_cfg.defs, kAclFieldDefs.data(), sizeof(rte_acl_field_def) * kAclNumFields);

  if (const int build_ret{rte_acl_build(acl_ctx_, &acl_cfg)}; build_ret != 0) {
    return std::unexpected(std::format("rte_acl_build failed during rebuild: {}", -build_ret));
  }

  // Publish: replace the contents. After this, workers resuming their
  // Match() calls will see the new groups and precedence_order_.
  groups_ = std::move(new_groups);
  precedence_order_ = std::move(new_precedence_order);
  return {};
}

// ---------------------------------------------------------------------------
// CompileRuleTable
// ---------------------------------------------------------------------------

std::expected<RuleTable, std::string> CompileRuleTable(const SpiConfig& config) noexcept {
  std::vector<CompiledFilterGroup> groups;
  groups.reserve(config.filter_groups.size());

  // First pass: validate and compile each group's filters. We need this
  // done before we can size the combined rte_acl_ctx.
  for (const auto& [group_index, group_config] : config.filter_groups | std::views::enumerate) {
    if (group_config.filters.empty()) {
      continue;
    }

    CompiledFilterGroup group;
    group.name = group_config.name;
    group.precedence = group_config.precedence;
    group.action = ParseAction(group_config.action);
    group.l7_required = group_config.l7_required;
    // Carry the SPI→DPI link target as a transient string. `ResolveDpiLinks`
    // consumes it after BOTH the SPI rule table and the DPI rule table are
    // compiled, then clears the string. The runtime hot path only reads
    // `bound_dpi_filter_index` (uint32_t).
    group.bound_dpi_name = group_config.dpi_filter_group;
    group.bound_dpi_filter_index = kNoDpiLink;
    group.category_index = static_cast<std::uint32_t>(groups.size());

    group.filters.reserve(group_config.filters.size());
    for (const auto& [filter_index, filter_config] : group_config.filters | std::views::enumerate) {
      auto filter{CompileFilter(filter_config, group_index, filter_index)};
      if (!filter) {
        return std::unexpected(filter.error());
      }
      group.filters.push_back(std::move(*filter));
    }

    groups.push_back(std::move(group));
  }

  // Sort groups by precedence (ascending — smallest = highest priority).
  // After this sort, `groups_[i].category_index == i` (we re-assign below).
  std::ranges::sort(
      groups, [](const CompiledFilterGroup& lhs, const CompiledFilterGroup& rhs) { return lhs.precedence < rhs.precedence; });
  for (std::uint32_t i{0}; i < groups.size(); ++i) {
    groups[i].category_index = i;
  }

  if (groups.size() > kMaxCategories) {
    return std::unexpected(std::format("filter group count {} exceeds RTE_ACL_MAX_CATEGORIES={}", groups.size(),
                                       kMaxCategories));
  }

  // Build one combined rte_acl_ctx with all groups as categories.
  const auto rule_size{static_cast<std::size_t>(RTE_ACL_RULE_SZ(kAclNumFields))};
  std::size_t total_rules{0};
  for (const auto& group : groups) {
    total_rules += group.filters.size();
  }
  if (total_rules == 0) {
    return std::unexpected(std::format("no filters to compile (filter_groups size={})", config.filter_groups.size()));
  }

  auto rule_buf{std::make_unique<uint8_t[]>(rule_size * total_rules)};
  std::size_t rule_offset{0};
  for (std::uint32_t cat{0}; cat < groups.size(); ++cat) {
    const auto& group{groups[cat]};
    for (std::uint32_t f{0}; f < group.filters.size(); ++f) {
      auto* rule{reinterpret_cast<struct rte_acl_rule*>(rule_buf.get() + (rule_offset * rule_size))};
      BuildAclRule(rule, group.filters[f], f, cat);
      ++rule_offset;
    }
  }

  const struct rte_acl_param acl_param{
      .name = "spi_rules_combined",
      .socket_id = static_cast<int>(rte_socket_id()),
      .rule_size = static_cast<uint32_t>(rule_size),
      .max_rule_num = static_cast<uint32_t>(total_rules),
  };

  rte_acl_ctx* acl_ctx{rte_acl_create(&acl_param)};
  if (acl_ctx == nullptr) {
    return std::unexpected(std::format("rte_acl_create failed for combined ctx: {} (rte_errno={})", rte_strerror(rte_errno),
                                       rte_errno));
  }

  auto* rules{reinterpret_cast<struct rte_acl_rule*>(rule_buf.get())};
  const int add_ret{rte_acl_add_rules(acl_ctx, rules, static_cast<uint32_t>(total_rules))};
  if (add_ret != 0) {
    rte_acl_free(acl_ctx);
    return std::unexpected(std::format("rte_acl_add_rules failed for combined ctx: {}", -add_ret));
  }

  struct rte_acl_config acl_cfg{};
  acl_cfg.num_categories = static_cast<uint32_t>(groups.size());
  acl_cfg.num_fields = kAclNumFields;
  std::memcpy(acl_cfg.defs, kAclFieldDefs.data(), sizeof(rte_acl_field_def) * kAclNumFields);

  const int build_ret{rte_acl_build(acl_ctx, &acl_cfg)};
  if (build_ret != 0) {
    rte_acl_free(acl_ctx);
    return std::unexpected(std::format("rte_acl_build failed for combined ctx: {}", -build_ret));
  }

  // precedence_order_ is just [0, 1, 2, ..., groups.size()-1] because the
  // groups vector is already sorted by precedence ASC; each element is the
  // category_index (= position in the sorted groups_ vector).
  std::vector<std::uint32_t> precedence_order(groups.size());
  std::iota(precedence_order.begin(), precedence_order.end(), 0U);

  return RuleTable{std::move(groups), acl_ctx, std::move(precedence_order)};
}

std::expected<void, std::string> RuleTable::ResolveDpiLinks(
    const dpdk::dpi::DpiRuleTable& dpi) noexcept {
  for (auto& group : groups_) {
    if (group.bound_dpi_name.empty()) {
      // No link declared in config. `bound_dpi_filter_index` is already
      // `kNoDpiLink` from `CompileRuleTable`. Free the empty string to
      // keep the groups vector small after resolution.
      std::string empty;
      group.bound_dpi_name.swap(empty);
      continue;
    }
    const auto idx{dpi.FindByFilterGroup(group.bound_dpi_name)};
    if (!idx) {
      return std::unexpected(std::format(
          "SPI group '{}' links to DPI group '{}' which was not found in the "
          "active DPI rule table (it may have been removed by a SIGUSR1 "
          "reload — revert the config or restart the pipeline)",
          group.name, group.bound_dpi_name));
    }
    group.bound_dpi_filter_index = *idx;
    // Free the transient string — the hot path only reads the uint32_t index.
    std::string empty;
    group.bound_dpi_name.swap(empty);
  }
  return {};
}

// ---------------------------------------------------------------------------
// Tuple-Space Search (TSS) pre-check
// ---------------------------------------------------------------------------
//
// Many cache-miss packets match a small set of explicit 5-tuple rules
// (e.g. traffic to a specific (src, dst, port, protocol) tuple). For these,
// walking the ACL multi-bit trie is overkill — a single hash probe suffices.
//
// Build pass (`BuildTssFromGroups`):
//   Walk every filter in every group. Insert into TSS only those filters
//   whose FULL 5-tuple is specified (no CIDR, no "any source", no "any
//   port"). Anything less specific falls back to the regular ACL path.
//
// Hot path (`ProbeTss`):
//   rte_hash_crc on the canonical 5-tuple → linear probe in the open-
//   addressed table. ~3-5 cycles on hit, ~15-25 cycles on miss.

namespace {

/// True iff the filter's 5-tuple is fully specified (no CIDR, no wildcards).
/// Such filters are eligible for the O(1) TSS pre-check.
[[nodiscard]] constexpr bool IsTssEligible(const CompiledFilter& filter) noexcept {
  return filter.match_source_ip && filter.match_destination_ip &&
         !filter.match_destination_cidr && filter.match_source_port &&
         filter.match_destination_port;
}

}  // namespace

void RuleTable::BuildTssFromGroups() noexcept {
  tss_size_ = 0;
  for (auto& group : groups_) {
    for (const auto& filter : group.filters) {
      if (!IsTssEligible(filter)) {
        continue;
      }
      const FlowKey filter_key{
          .src_ip = filter.source_ip_address,
          .dst_ip = filter.destination_ip_address,
          .src_port = filter.source_port,
          .dst_port = filter.destination_port,
          .protocol = filter.protocol,
          .pad = {},
      };
      const uint32_t hash{
          rte_hash_crc(reinterpret_cast<const void*>(&filter_key), sizeof(filter_key), 0U)};
      TssEntry new_entry{};
      std::memcpy(new_entry.key.data(), &filter_key, sizeof(filter_key));
      new_entry.group_idx = group.category_index;
      // Linear probe with power-of-two wrap. Stop at first unused slot.
      for (std::size_t probe{0}; probe < kTssCapacity; ++probe) {
        const auto slot{(hash + probe) & (kTssCapacity - 1U)};
        auto& entry{tss_[slot]};
        if (entry.group_idx == kNoTssHit) {
          entry.key = new_entry.key;
          entry.group_idx = new_entry.group_idx;
          ++tss_size_;
          break;
        }
        // Duplicate key — just overwrite the existing slot. The earlier
        // insert wins precedence (insertion order is already sorted by
        // group precedence ASC).
      }
    }
  }
}

[[gnu::hot]] std::uint32_t RuleTable::ProbeTss(const FlowKey& key) const noexcept {
  if (tss_size_ == 0) [[unlikely]] {
    return kNoTssHit;
  }
  const uint32_t hash{rte_hash_crc(reinterpret_cast<const void*>(&key), sizeof(key), 0U)};
  for (std::size_t probe{0}; probe < kTssCapacity; ++probe) {
    const auto slot{(hash + probe) & (kTssCapacity - 1U)};
    const auto& entry{tss_[slot]};
    if (entry.group_idx == kNoTssHit) [[unlikely]] {
      return kNoTssHit;
    }
    // Compare the FULL 16-byte key including the 3-byte pad (always zero
    // in canonical FlowKeys produced by MakeCanonical). memcmp on 16 bytes
    // is one SIMD load + a couple of compares — fits in the same cache line
    // as the entry itself.
    if (std::memcmp(entry.key.data(), &key, sizeof(FlowKey)) == 0) [[likely]] {
      return entry.group_idx;
    }
  }
  return kNoTssHit;
}

}  // namespace dpdk::spi