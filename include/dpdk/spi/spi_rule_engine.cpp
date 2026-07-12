#include "dpdk/spi/spi_rule_engine.hpp"

#include <rte_byteorder.h>
#include <rte_errno.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <format>
#include <memory>
#include <ranges>
#include <string_view>
#include <utility>

#include "dpdk/spi/spi_ip_address.hpp"

namespace dpdk::spi {

// ---------------------------------------------------------------------------
// CompiledFilterGroup rule-of-five
// ---------------------------------------------------------------------------

CompiledFilterGroup::CompiledFilterGroup(CompiledFilterGroup&& other) noexcept
    : name{std::move(other.name)},
      precedence{other.precedence},
      action{other.action},
      filters{std::move(other.filters)},
      acl_ctx{other.acl_ctx} {
  other.acl_ctx = nullptr;
}

CompiledFilterGroup& CompiledFilterGroup::operator=(CompiledFilterGroup&& other) noexcept {
  if (this != &other) {
    name = std::move(other.name);
    precedence = other.precedence;
    action = other.action;
    filters = std::move(other.filters);
    if (acl_ctx != nullptr) {
      rte_acl_free(acl_ctx);
    }
    acl_ctx = other.acl_ctx;
    other.acl_ctx = nullptr;
  }
  return *this;
}

CompiledFilterGroup::~CompiledFilterGroup() {
  if (acl_ctx != nullptr) {
    rte_acl_free(acl_ctx);
  }
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
void BuildAclRule(struct rte_acl_rule* rule, const CompiledFilter& filter, uint32_t rule_index) noexcept {
  std::memset(rule, 0, static_cast<std::size_t>(RTE_ACL_RULE_SZ(kAclNumFields)));

  rule->data.userdata = rule_index + 1;
  rule->data.priority = RTE_ACL_MAX_PRIORITY - static_cast<int32_t>(rule_index);
  rule->data.category_mask = 1;

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

RuleTable::RuleTable(std::vector<CompiledFilterGroup> groups) noexcept : groups_{std::move(groups)} {}

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
  AclInputData acl_input{};
  acl_input.src_ip_be = rte_cpu_to_be_32(packet.source_ip_address);
  acl_input.dst_ip_be = rte_cpu_to_be_32(packet.destination_ip_address);

  const uint8_t* data[1] = {reinterpret_cast<const uint8_t*>(&acl_input)};
  uint32_t results[1]{};

  for (const auto& group : groups_) {
    if (group.acl_ctx == nullptr) [[unlikely]] {
      continue;
    }

    results[0] = 0;
    const int ret{rte_acl_classify(group.acl_ctx, data, results, 1, 1)};
    if (ret == 0 && results[0] != 0) [[likely]] {
      const auto filter_index{results[0] - 1};
      if (filter_index < group.filters.size() &&
          FilterMatchesPortProtocol(group.filters[filter_index], packet)) [[likely]] {
        return ClassificationResult{
            .group_name = group.name,
            .label = group.filters[filter_index].label,
            .action = group.action,
            .group_precedence = group.precedence,
            .matched = true,
        };
      }
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

// ---------------------------------------------------------------------------
// CompileRuleTable
// ---------------------------------------------------------------------------

std::expected<RuleTable, std::string> CompileRuleTable(const SpiConfig& config) noexcept {
  std::vector<CompiledFilterGroup> groups;
  groups.reserve(config.filter_groups.size());

  for (const auto& [group_index, group_config] : config.filter_groups | std::views::enumerate) {
    if (group_config.filters.empty()) {
      continue;
    }

    CompiledFilterGroup group;
    group.name = group_config.name;
    group.precedence = group_config.precedence;
    group.action = ParseAction(group_config.action);

    // Build filters with validation.
    std::vector<CompiledFilter> filters;
    filters.reserve(group_config.filters.size());

    const auto rule_size{static_cast<std::size_t>(RTE_ACL_RULE_SZ(kAclNumFields))};
    auto rule_buf{std::make_unique<uint8_t[]>(rule_size * group_config.filters.size())};

    for (const auto& [filter_index, filter_config] : group_config.filters | std::views::enumerate) {
      auto filter{CompileFilter(filter_config, group_index, filter_index)};
      if (!filter) {
        return std::unexpected(filter.error());
      }

      auto* rule{reinterpret_cast<struct rte_acl_rule*>(rule_buf.get() + (filter_index * rule_size))};
      BuildAclRule(rule, *filter, static_cast<uint32_t>(filter_index));
      filters.push_back(std::move(*filter));
    }

    // Create ACL context.
    const auto acl_name{std::format("{}_g{}", group_config.name, group_index)};
    const struct rte_acl_param acl_param{
        .name = acl_name.c_str(),
        .socket_id = static_cast<int>(rte_socket_id()),
        .rule_size = static_cast<uint32_t>(rule_size),
        .max_rule_num = static_cast<uint32_t>(group_config.filters.size()),
    };

    struct rte_acl_ctx* acl_ctx{rte_acl_create(&acl_param)};
    if (acl_ctx == nullptr) {
      return std::unexpected(
          std::format("rte_acl_create failed for group '{}': {} (rte_errno={})", group_config.name, rte_strerror(rte_errno), rte_errno));
    }

    // Add rules.
    auto* rules{reinterpret_cast<struct rte_acl_rule*>(rule_buf.get())};
    const int add_ret{rte_acl_add_rules(acl_ctx, rules, static_cast<uint32_t>(group_config.filters.size()))};
    if (add_ret != 0) {
      rte_acl_free(acl_ctx);
      return std::unexpected(
          std::format("rte_acl_add_rules failed for group '{}': {}", group_config.name, -add_ret));
    }

    // Build ACL trie.
    struct rte_acl_config acl_cfg{};
    acl_cfg.num_categories = 1;
    acl_cfg.num_fields = kAclNumFields;
    std::memcpy(acl_cfg.defs, kAclFieldDefs.data(), sizeof(rte_acl_field_def) * kAclNumFields);

    const int build_ret{rte_acl_build(acl_ctx, &acl_cfg)};
    if (build_ret != 0) {
      rte_acl_free(acl_ctx);
      return std::unexpected(
          std::format("rte_acl_build failed for group '{}': {}", group_config.name, -build_ret));
    }

    group.acl_ctx = acl_ctx;
    group.filters = std::move(filters);
    groups.push_back(std::move(group));
  }

  // Sort groups by precedence (ascending — smallest = highest priority).
  std::ranges::sort(
      groups, [](const CompiledFilterGroup& lhs, const CompiledFilterGroup& rhs) { return lhs.precedence < rhs.precedence; });

  return RuleTable{std::move(groups)};
}

}  // namespace dpdk::spi