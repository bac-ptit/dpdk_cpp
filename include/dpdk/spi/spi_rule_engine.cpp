#include "dpdk/spi/spi_rule_engine.hpp"
#include "dpdk/spi/spi_flow_table.hpp"

#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#include <rte_fib.h>
#include <rte_member.h>

#include <algorithm>
#include <coroutine>
#include <cstddef>
#include <cstring>
#include <format>
#include <future>
#include <memory>
#include <numeric>
#include <print>
#include <pthread.h>
#include <ranges>
#include <string_view>
#include <thread>
#include <utility>

#include "dpdk/dpi/dpi_rule_engine.hpp"
#include "dpdk/spi/spi_ip_address.hpp"

namespace dpdk::spi {

// ---------------------------------------------------------------------------
// RuleTable lifecycle
// ---------------------------------------------------------------------------

RuleTable::~RuleTable() {
  for (auto& chunk : acl_chunks_) {
    if (chunk.ctx != nullptr) {
      rte_acl_free(chunk.ctx);
      chunk.ctx = nullptr;
    }
  }
  if (fib_ctx_ != nullptr) {
    rte_fib_free(fib_ctx_);
    fib_ctx_ = nullptr;
  }
  if (member_ctx_ != nullptr) {
    rte_member_free(member_ctx_);
    member_ctx_ = nullptr;
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

struct MemberKey {
  uint32_t dst_ip_be;
  uint16_t dst_port_be;
  uint8_t protocol;
} __attribute__((packed));
static_assert(sizeof(MemberKey) == 7);

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
/// actual precedence walk in Match())
void BuildAclRule(struct rte_acl_rule* rule, const CompiledFilter& filter, uint32_t group_index,
                  uint32_t filter_index, uint32_t precedence) noexcept {
  std::memset(rule, 0, static_cast<std::size_t>(RTE_ACL_RULE_SZ(kAclNumFields)));

  // Encoded userdata: upper 16 bits = group_index + 1, lower 16 bits = filter_index + 1
  const uint32_t encoded_userdata = ((group_index + 1) << 16) | ((filter_index + 1) & 0xFFFF);
  rule->data.userdata = encoded_userdata;

  // Higher priority number = higher precedence. Precedence 0 = highest priority.
  rule->data.priority = static_cast<int32_t>(RTE_ACL_MAX_PRIORITY - precedence);
  rule->data.category_mask = 1ULL;

  // protocol (BITMASK)
  rule->field[static_cast<uint8_t>(AclFieldIndex::kProtocol)].value.u8 = ProtocolToIpProto(filter.protocol);
  rule->field[static_cast<uint8_t>(AclFieldIndex::kProtocol)].mask_range.u8 = 0xFF;

  // src_ip (MASK)
  rule->field[static_cast<uint8_t>(AclFieldIndex::kSrcIp)].value.u32 = filter.source_ip_address;
  rule->field[static_cast<uint8_t>(AclFieldIndex::kSrcIp)].mask_range.u32 = filter.match_source_ip ? 32 : 0;

  // dst_ip (MASK)
  if (filter.match_destination_cidr) {
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstIp)].value.u32 = filter.destination_network;
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstIp)].mask_range.u32 = filter.destination_prefix_length;
  } else if (filter.match_destination_ip) {
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstIp)].value.u32 = filter.destination_ip_address;
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstIp)].mask_range.u32 = 32;
  } else {
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstIp)].value.u32 = 0;
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstIp)].mask_range.u32 = 0;
  }

  // src_port (RANGE)
  if (filter.match_source_port) {
    rule->field[static_cast<uint8_t>(AclFieldIndex::kSrcPort)].value.u16 = filter.source_port;
    rule->field[static_cast<uint8_t>(AclFieldIndex::kSrcPort)].mask_range.u16 = filter.source_port;
  } else {
    rule->field[static_cast<uint8_t>(AclFieldIndex::kSrcPort)].value.u16 = 0;
    rule->field[static_cast<uint8_t>(AclFieldIndex::kSrcPort)].mask_range.u16 = 65535;
  }

  // dst_port (RANGE)
  if (filter.match_destination_port) {
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstPort)].value.u16 = filter.destination_port;
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstPort)].mask_range.u16 = filter.destination_port;
  } else {
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstPort)].value.u16 = 0;
    rule->field[static_cast<uint8_t>(AclFieldIndex::kDstPort)].mask_range.u16 = 65535;
  }
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

RuleTable::RuleTable(std::vector<CompiledFilterGroup> groups, std::vector<AclChunk> acl_chunks,
                       std::vector<std::uint32_t> precedence_order,
                       struct rte_fib* fib_ctx,
                       struct rte_member_setsum* member_ctx) noexcept
    : groups_{std::move(groups)}, acl_chunks_{std::move(acl_chunks)}, precedence_order_{std::move(precedence_order)},
      fib_ctx_{fib_ctx}, member_ctx_{member_ctx} {
  if (!acl_chunks_.empty()) {
    acl_ctx_ = acl_chunks_[0].ctx;
  }
  BuildTssFromGroups();
}

RuleTable::RuleTable(std::vector<CompiledFilterGroup> groups, rte_acl_ctx* acl_ctx,
                       std::vector<std::uint32_t> precedence_order) noexcept
    : groups_{std::move(groups)}, acl_ctx_{acl_ctx}, precedence_order_{std::move(precedence_order)} {
  if (acl_ctx != nullptr) {
    acl_chunks_.push_back(AclChunk{.ctx = acl_ctx, .start_group_index = 0, .group_count = 1});
  }
  BuildTssFromGroups();
}

RuleTable::RuleTable(RuleTable&& other) noexcept
    : groups_{std::move(other.groups_)},
      acl_chunks_{std::move(other.acl_chunks_)},
      acl_ctx_{other.acl_ctx_},
      precedence_order_{std::move(other.precedence_order_)},
      fib_ctx_{other.fib_ctx_},
      member_ctx_{other.member_ctx_} {
  other.acl_ctx_ = nullptr;
  other.fib_ctx_ = nullptr;
  other.member_ctx_ = nullptr;
}

RuleTable& RuleTable::operator=(RuleTable&& other) noexcept {
  if (this != &other) {
    for (auto& chunk : acl_chunks_) {
      if (chunk.ctx != nullptr) {
        rte_acl_free(chunk.ctx);
      }
    }
    if (fib_ctx_ != nullptr) {
      rte_fib_free(fib_ctx_);
    }
    if (member_ctx_ != nullptr) {
      rte_member_free(member_ctx_);
    }
    acl_chunks_ = std::move(other.acl_chunks_);
    groups_ = std::move(other.groups_);
    acl_ctx_ = other.acl_ctx_;
    precedence_order_ = std::move(other.precedence_order_);
    fib_ctx_ = other.fib_ctx_;
    member_ctx_ = other.member_ctx_;
    other.acl_ctx_ = nullptr;
    other.fib_ctx_ = nullptr;
    other.member_ctx_ = nullptr;
  }
  return *this;
}

/// Check if a filter's port/protocol constraints match the packet.
[[nodiscard, gnu::always_inline]] inline bool FilterMatchesPortProtocol(const CompiledFilter& filter,
                                                                        const PacketMetadata& packet) noexcept {
  if (filter.protocol != packet.protocol) {
    return false;
  }
  if (filter.match_destination_port && filter.destination_port != rte_be_to_cpu_16(packet.destination_port_be)) {
    return false;
  }
  if (filter.match_source_port && filter.source_port != rte_be_to_cpu_16(packet.source_port_be)) {
    return false;
  }
  return true;
}

ClassificationResult RuleTable::Match(const PacketMetadata& packet) const noexcept {
  if (acl_chunks_.empty() && acl_ctx_ == nullptr) [[unlikely]] {
    return {};
  }

  AclInputData acl_input{};
  if (packet.ip_version == IpVersion::kIpv4) [[likely]] {
    acl_input.src_ip_be = packet.source_ip_be;
    acl_input.dst_ip_be = packet.destination_ip_be;
  } else {
    std::uint32_t s6_head{}, d6_head{};
    std::memcpy(&s6_head, packet.source_ip6_address.data(), sizeof(std::uint32_t));
    std::memcpy(&d6_head, packet.destination_ip6_address.data(), sizeof(std::uint32_t));
    acl_input.src_ip_be = s6_head;
    acl_input.dst_ip_be = d6_head;
  }
  acl_input.src_port_be = packet.source_port_be;
  acl_input.dst_port_be = packet.destination_port_be;
  acl_input.protocol = packet.protocol == Protocol::kTcp ? kIpProtoTcp : kIpProtoUdp;

  const uint8_t* data[1] = {reinterpret_cast<const uint8_t*>(&acl_input)};

  for (const auto& chunk : acl_chunks_) {
    if (chunk.ctx == nullptr) continue;
    std::array<std::uint32_t, kMaxCategories> results{};
    const int ret{rte_acl_classify(chunk.ctx, data, results.data(), 1, 1)};
    if (ret != 0) [[unlikely]] continue;

    const auto userdata = results[0];
    if (userdata == 0) [[likely]] continue;

    const std::uint32_t group_idx = (userdata >> 16) - 1;
    const std::uint32_t filter_idx = (userdata & 0xFFFF) - 1;

    if (group_idx < groups_.size()) [[likely]] {
      const auto& group{groups_[group_idx]};
      if (filter_idx < group.filters.size() &&
          FilterMatchesPortProtocol(group.filters[filter_idx], packet)) [[likely]] {
        return ClassificationResult{
            .group_name = group.name,
            .label = group.filters[filter_idx].label,
            .group_precedence = group.precedence,
            .bound_dpi_filter_index = group.bound_dpi_filter_index,
            .action = group.action,
            .matched = true,
            .l7_required = group.l7_required,
        };
      }
    }
  }

  return {};
}

[[gnu::hot]] void RuleTable::MatchBulk(std::span<const PacketMetadata> packets,
                              std::span<ClassificationResult> results) const noexcept {
  if (packets.empty()) [[unlikely]] return;
  if (acl_chunks_.empty() && acl_ctx_ == nullptr) [[unlikely]] {
    for (std::size_t i{0}; i < packets.size(); ++i) {
      results[i] = {};
    }
    return;
  }

  const std::size_t burst_size{std::min<std::size_t>(packets.size(), 64)};
  std::array<AclInputData, 64> acl_inputs{};
  std::array<const uint8_t*, 64> data{};

  for (std::size_t i{0}; i < burst_size; ++i) {
    const auto& packet{packets[i]};
    if (packet.ip_version == IpVersion::kIpv4) [[likely]] {
      acl_inputs[i].src_ip_be = packet.source_ip_be;
      acl_inputs[i].dst_ip_be = packet.destination_ip_be;
    } else {
      std::uint32_t s6_head{}, d6_head{};
      std::memcpy(&s6_head, packet.source_ip6_address.data(), sizeof(std::uint32_t));
      std::memcpy(&d6_head, packet.destination_ip6_address.data(), sizeof(std::uint32_t));
      acl_inputs[i].src_ip_be = s6_head;
      acl_inputs[i].dst_ip_be = d6_head;
    }
    acl_inputs[i].src_port_be = packet.source_port_be;
    acl_inputs[i].dst_port_be = packet.destination_port_be;
    acl_inputs[i].protocol = packet.protocol == Protocol::kTcp ? kIpProtoTcp : kIpProtoUdp;
    data[i] = reinterpret_cast<const uint8_t*>(&acl_inputs[i]);
    results[i] = {};
  }

  for (const auto& chunk : acl_chunks_) {
    if (chunk.ctx == nullptr) continue;
    std::array<std::uint32_t, 64> results_flat{};
    const int ret{rte_acl_classify(chunk.ctx, data.data(), results_flat.data(), static_cast<uint32_t>(burst_size), 1)};
    if (ret != 0) [[unlikely]] continue;

    for (std::size_t p{0}; p < burst_size; ++p) {
      if (results[p].matched) continue;

      const auto userdata = results_flat[p];
      if (userdata == 0) [[likely]] continue;

      const std::uint32_t group_idx = (userdata >> 16) - 1;
      const std::uint32_t filter_idx = (userdata & 0xFFFF) - 1;

      if (group_idx < groups_.size()) [[likely]] {
        const auto& group{groups_[group_idx]};
        if (filter_idx < group.filters.size() &&
            FilterMatchesPortProtocol(group.filters[filter_idx], packets[p])) [[likely]] {
          results[p] = ClassificationResult{
              .group_name = group.name,
              .label = group.filters[filter_idx].label,
              .group_precedence = group.precedence,
              .bound_dpi_filter_index = group.bound_dpi_filter_index,
              .action = group.action,
              .matched = true,
              .l7_required = group.l7_required,
          };
        }
      }
    }

    bool all_matched{true};
    for (std::size_t p{0}; p < burst_size; ++p) {
      if (!results[p].matched) {
        all_matched = false;
        break;
      }
    }
    if (all_matched) break;
  }
}

void RuleTable::FibLookupBulk(std::span<const PacketMetadata> packets,
                              std::span<ClassificationResult> results) const noexcept {
  if (fib_ctx_ == nullptr) return;
  const auto n{std::min<std::size_t>(packets.size(), 64)};
  std::array<uint32_t, 64> dst_ips{};
  std::array<uint64_t, 64> next_hops{};
  for (std::size_t i{0}; i < n; ++i) {
    dst_ips[i] = packets[i].destination_ip_be;  // already network byte order
  }
  rte_fib_lookup_bulk(fib_ctx_, dst_ips.data(), next_hops.data(), static_cast<int>(n));
  for (std::size_t i{0}; i < n; ++i) {
    if (next_hops[i] == kFibDefaultNh) continue;  // FIB miss
    const auto group_idx{static_cast<uint32_t>((next_hops[i] >> 32) - 1)};
    const auto filter_idx{static_cast<uint32_t>((next_hops[i] & 0xFFFFFFFF) - 1)};
    if (group_idx < groups_.size()) {
      const auto& group{groups_[group_idx]};
      if (filter_idx < group.filters.size() &&
          FilterMatchesPortProtocol(group.filters[filter_idx], packets[i])) {
        results[i] = ClassificationResult{
            .group_name = group.name,
            .label = group.filters[filter_idx].label,
            .group_precedence = group.precedence,
            .bound_dpi_filter_index = group.bound_dpi_filter_index,
            .action = group.action,
            .matched = true,
            .l7_required = group.l7_required,
        };
      }
    }
  }
}

void RuleTable::MemberFilterBulk(std::span<const PacketMetadata> packets,
                                 std::span<bool> skip_acl) const noexcept {
  if (member_ctx_ == nullptr || has_wildcard_ip_rules_) return;
  const auto n{std::min<std::size_t>(packets.size(), 64)};
  std::array<MemberKey, 64> keys{};
  std::array<const void*, 64> key_ptrs{};
  std::array<member_set_t, 64> set_ids{};

  // Pass 1: Exact lookup (dst_ip, dst_port, proto)
  for (std::size_t i{0}; i < n; ++i) {
    keys[i] = MemberKey{
        .dst_ip_be = packets[i].destination_ip_be,
        .dst_port_be = packets[i].destination_port_be,
        .protocol = packets[i].protocol == Protocol::kTcp ? static_cast<uint8_t>(6) : static_cast<uint8_t>(17),
    };
    key_ptrs[i] = &keys[i];
  }
  rte_member_lookup_bulk(member_ctx_, key_ptrs.data(), static_cast<uint32_t>(n), set_ids.data());

  // Pass 2: Wildcard port lookup (dst_ip, 0, proto) for packets that missed Pass 1
  std::array<MemberKey, 64> wild_keys{};
  std::array<const void*, 64> wild_key_ptrs{};
  std::array<member_set_t, 64> wild_set_ids{};
  std::size_t n_wild{0};
  std::array<std::size_t, 64> wild_indices{};

  for (std::size_t i{0}; i < n; ++i) {
    if (set_ids[i] == RTE_MEMBER_NO_MATCH) {
      wild_keys[n_wild] = MemberKey{
          .dst_ip_be = packets[i].destination_ip_be,
          .dst_port_be = 0,
          .protocol = packets[i].protocol == Protocol::kTcp ? static_cast<uint8_t>(6) : static_cast<uint8_t>(17),
      };
      wild_key_ptrs[n_wild] = &wild_keys[n_wild];
      wild_indices[n_wild] = i;
      ++n_wild;
    }
  }

  if (n_wild > 0) {
    rte_member_lookup_bulk(member_ctx_, wild_key_ptrs.data(), static_cast<uint32_t>(n_wild), wild_set_ids.data());
    for (std::size_t w{0}; w < n_wild; ++w) {
      if (wild_set_ids[w] != RTE_MEMBER_NO_MATCH) {
        set_ids[wild_indices[w]] = wild_set_ids[w];
      }
    }
  }

  for (std::size_t i{0}; i < n; ++i) {
    if (set_ids[i] == RTE_MEMBER_NO_MATCH) {
      skip_acl[i] = true;  // Definitely no match — skip ACL
    }
  }
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

  rte_acl_reset_rules(acl_ctx_);

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
      BuildAclRule(rule, group.filters[f], cat, f, group.precedence);
      ++rule_offset;
    }
  }

  auto* rules{reinterpret_cast<struct rte_acl_rule*>(rule_buf.get())};
  if (const int add_ret{rte_acl_add_rules(acl_ctx_, rules, static_cast<uint32_t>(total_rules))}; add_ret != 0) {
    return std::unexpected(std::format("rte_acl_add_rules failed during rebuild: {}", -add_ret));
  }

  struct rte_acl_config acl_cfg{};
  acl_cfg.num_categories = 1;
  acl_cfg.num_fields = kAclNumFields;
  std::memcpy(acl_cfg.defs, kAclFieldDefs.data(), sizeof(rte_acl_field_def) * kAclNumFields);

  if (const int build_ret{rte_acl_build(acl_ctx_, &acl_cfg)}; build_ret != 0) {
    return std::unexpected(std::format("rte_acl_build failed during rebuild: {}", -build_ret));
  }

  groups_ = std::move(new_groups);
  precedence_order_ = std::move(new_precedence_order);
  BuildTssFromGroups();
  return {};
}

// ---------------------------------------------------------------------------
// CompileRuleTable
// ---------------------------------------------------------------------------

std::expected<RuleTable, std::string> CompileRuleTable(
    const SpiConfig& config) noexcept {
  std::vector<CompiledFilterGroup> groups;
  groups.reserve(config.filter_groups.size());

  for (const auto& [group_index, group_config] : config.filter_groups | std::views::enumerate) {
    CompiledFilterGroup group;
    group.name = group_config.name;
    group.precedence = group_config.precedence;
    group.action = ParseAction(group_config.action);
    group.l7_required = group_config.l7_required;
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
  std::ranges::sort(
      groups, [](const CompiledFilterGroup& lhs, const CompiledFilterGroup& rhs) { return lhs.precedence < rhs.precedence; });
  for (std::uint32_t i{0}; i < groups.size(); ++i) {
    groups[i].category_index = i;
  }

  const auto rule_size{static_cast<std::size_t>(RTE_ACL_RULE_SZ(kAclNumFields))};
  std::size_t total_rules{0};
  for (const auto& group : groups) {
    total_rules += group.filters.size();
  }

  if (total_rules == 0) {
    return std::unexpected("No SPI rules found in config");
  }

  constexpr std::size_t kAclMaxCategoriesChunk{256};

  struct ChunkTaskSpec {
    std::size_t start_group_index;
    std::size_t chunk_count;
    std::size_t chunk_id;
  };

  std::vector<ChunkTaskSpec> task_specs;
  for (std::size_t start_idx{0}; start_idx < groups.size(); start_idx += kAclMaxCategoriesChunk) {
    const std::size_t chunk_count{std::min<std::size_t>(kAclMaxCategoriesChunk, groups.size() - start_idx)};
    std::size_t total_rules_chunk{0};
    for (std::size_t i = 0; i < chunk_count; ++i) {
      total_rules_chunk += groups[start_idx + i].filters.size();
    }
    if (total_rules_chunk > 0) {
      task_specs.push_back(ChunkTaskSpec{
          .start_group_index = start_idx,
          .chunk_count = chunk_count,
          .chunk_id = task_specs.size(),
      });
    }
  }

  const std::size_t num_threads{std::max<std::size_t>(1, std::thread::hardware_concurrency())};
  std::println("[SPI] Compiling {} ACL chunks (256 groups/chunk) in parallel across {} CPU cores...", task_specs.size(), num_threads);

  auto compile_chunk_fn = [&](const ChunkTaskSpec spec) -> std::expected<AclChunk, std::string> {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    const auto cpu_target{spec.chunk_id % num_threads};
    CPU_SET(cpu_target, &cpuset);
    (void)::pthread_setaffinity_np(::pthread_self(), sizeof(cpu_set_t), &cpuset);

    const std::size_t start_idx{spec.start_group_index};
    const std::size_t chunk_count{spec.chunk_count};

    std::size_t total_rules_chunk{0};
    for (std::size_t i = 0; i < chunk_count; ++i) {
      total_rules_chunk += groups[start_idx + i].filters.size();
    }

    auto rule_buf{std::make_unique<uint8_t[]>(rule_size * total_rules_chunk)};
    std::size_t rule_offset{0};
    for (std::uint32_t cat{0}; cat < chunk_count; ++cat) {
      const auto& group{groups[start_idx + cat]};
      for (std::uint32_t f{0}; f < group.filters.size(); ++f) {
        auto* rule{reinterpret_cast<struct rte_acl_rule*>(rule_buf.get() + (rule_offset * rule_size))};
        BuildAclRule(rule, group.filters[f], static_cast<uint32_t>(start_idx + cat), f, group.precedence);
        ++rule_offset;
      }
    }

    const std::string chunk_name = std::format("spi_chunk_{}", spec.chunk_id);
    const struct rte_acl_param acl_param{
        .name = chunk_name.c_str(),
        .socket_id = static_cast<int>(rte_socket_id()),
        .rule_size = static_cast<uint32_t>(rule_size),
        .max_rule_num = static_cast<uint32_t>(total_rules_chunk),
    };

    rte_acl_ctx* chunk_ctx{rte_acl_create(&acl_param)};
    if (chunk_ctx == nullptr) {
      return std::unexpected(std::format("rte_acl_create failed for chunk {}: {}", spec.chunk_id, rte_strerror(rte_errno)));
    }

    auto* rules{reinterpret_cast<struct rte_acl_rule*>(rule_buf.get())};
    if (const int add_ret{rte_acl_add_rules(chunk_ctx, rules, static_cast<uint32_t>(total_rules_chunk))}; add_ret != 0) {
      rte_acl_free(chunk_ctx);
      return std::unexpected(std::format("rte_acl_add_rules failed for chunk {}: {}", spec.chunk_id, -add_ret));
    }

    struct rte_acl_config acl_cfg{};
    acl_cfg.num_categories = 1;
    acl_cfg.num_fields = kAclNumFields;
    std::memcpy(acl_cfg.defs, kAclFieldDefs.data(), sizeof(rte_acl_field_def) * kAclNumFields);

    if (const int build_ret{rte_acl_build(chunk_ctx, &acl_cfg)}; build_ret != 0) {
      rte_acl_free(chunk_ctx);
      return std::unexpected(std::format("rte_acl_build failed for chunk {}: {}", spec.chunk_id, -build_ret));
    }

    return AclChunk{.ctx = chunk_ctx, .start_group_index = start_idx, .group_count = chunk_count};
  };

  std::vector<std::future<std::expected<AclChunk, std::string>>> futures;
  futures.reserve(task_specs.size());

  for (const auto& spec : task_specs) {
    futures.push_back(std::async(std::launch::async, compile_chunk_fn, spec));
  }

  std::vector<AclChunk> acl_chunks;
  acl_chunks.reserve(task_specs.size());

  for (auto& fut : futures) {
    auto res{fut.get()};
    if (!res) {
      for (auto& c : acl_chunks) {
        if (c.ctx != nullptr) rte_acl_free(c.ctx);
      }
      return std::unexpected(res.error());
    }
    acl_chunks.push_back(*res);
  }

  std::vector<std::uint32_t> precedence_order(groups.size());
  std::iota(precedence_order.begin(), precedence_order.end(), 0U);

  // Build FIB and Member structures
  struct rte_fib_conf fib_conf{};
  fib_conf.type = RTE_FIB_DIR24_8;
  fib_conf.default_nh = 0;
  fib_conf.max_routes = static_cast<int>(total_rules + 1);
  fib_conf.dir24_8.nh_sz = RTE_FIB_DIR24_8_8B;
  fib_conf.dir24_8.num_tbl8 = 1 << 20;
  fib_conf.flags = RTE_FIB_F_LOOKUP_NETWORK_ORDER;

  struct rte_fib* fib_ctx = rte_fib_create("spi_fib", static_cast<int>(rte_socket_id()), &fib_conf);

  std::size_t total_member_keys = 0;
  for (const auto& group : groups) {
    for (const auto& filter : group.filters) {
      if (filter.match_destination_ip || filter.match_destination_cidr) {
        ++total_member_keys;
      }
    }
  }

  struct rte_member_setsum* member_ctx = nullptr;
  if (total_member_keys > 0) {
    struct rte_member_parameters member_params{};
    member_params.name = "spi_member";
    member_params.type = RTE_MEMBER_TYPE_HT;
    member_params.num_keys = static_cast<uint32_t>(total_member_keys);
    member_params.key_len = 7;
    member_params.is_cache = 0;
    member_params.socket_id = static_cast<int>(rte_socket_id());
    member_params.prim_hash_seed = 0x12345678;
    member_params.sec_hash_seed = 0x87654321;
    member_ctx = rte_member_create(&member_params);
  }

  if (member_ctx) {
    for (std::size_t g = 0; g < groups.size(); ++g) {
      const auto& group = groups[g];
      for (std::size_t f = 0; f < group.filters.size(); ++f) {
        const auto& filter = group.filters[f];
        if (filter.match_destination_ip) {
          MemberKey key{
            .dst_ip_be = rte_cpu_to_be_32(filter.destination_ip_address),
            .dst_port_be = filter.match_destination_port ? rte_cpu_to_be_16(filter.destination_port) : static_cast<uint16_t>(0),
            .protocol = filter.protocol == Protocol::kTcp ? static_cast<uint8_t>(6) : static_cast<uint8_t>(17),
          };
          if (int res = rte_member_add(member_ctx, &key, static_cast<member_set_t>(g + 1)); res < 0) {
            std::println(stderr, "[SPI] rte_member_add failed for group {} filter {}: {}", g, f, res);
          }
        } else if (filter.match_destination_cidr && filter.destination_prefix_length >= 20) {
          const uint32_t net = filter.destination_network;
          const uint32_t host_count = 1U << (32U - filter.destination_prefix_length);
          for (uint32_t host = 0; host < host_count; ++host) {
            MemberKey key{
              .dst_ip_be = rte_cpu_to_be_32(net + host),
              .dst_port_be = filter.match_destination_port ? rte_cpu_to_be_16(filter.destination_port) : static_cast<uint16_t>(0),
              .protocol = filter.protocol == Protocol::kTcp ? static_cast<uint8_t>(6) : static_cast<uint8_t>(17),
            };
            rte_member_add(member_ctx, &key, static_cast<member_set_t>(g + 1));
          }
        }
      }
    }
  }

  if (fib_ctx) {
    for (std::size_t g = 0; g < groups.size(); ++g) {
      const auto& group = groups[g];
      for (std::size_t f = 0; f < group.filters.size(); ++f) {
        const auto& filter = group.filters[f];
        if (filter.match_destination_cidr || filter.match_destination_ip) {
          uint32_t ip = filter.match_destination_cidr ? filter.destination_network : filter.destination_ip_address;
          uint8_t depth = filter.match_destination_cidr ? static_cast<uint8_t>(filter.destination_prefix_length) : 32;
          uint64_t next_hop = ((static_cast<uint64_t>(g) + 1) << 32) | (static_cast<uint64_t>(f) + 1);

          uint32_t ip_be = rte_cpu_to_be_32(ip);
          int ret = rte_fib_add(fib_ctx, ip_be, depth, next_hop);
          if (ret == -EEXIST) {
            uint64_t existing_nh;
            rte_fib_lookup_bulk(fib_ctx, &ip_be, &existing_nh, 1);
            if (existing_nh != 0) {
              uint32_t exist_g = (existing_nh >> 32) - 1;
              if (exist_g < groups.size() && group.precedence < groups[exist_g].precedence) {
                rte_fib_delete(fib_ctx, ip_be, depth);
                rte_fib_add(fib_ctx, ip_be, depth, next_hop);
              }
            }
          }
        }
      }
    }
  }

  return RuleTable{std::move(groups), std::move(acl_chunks), std::move(precedence_order), fib_ctx, member_ctx};
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
  has_wildcard_ip_rules_ = false;
  for (auto& group : groups_) {
    for (const auto& filter : group.filters) {
      if (!filter.match_destination_ip && (!filter.match_destination_cidr || filter.destination_prefix_length < 20)) {
        has_wildcard_ip_rules_ = true;
      }
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