#pragma once

#include <rte_acl.h>

#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "dpdk/config/dpdk_config.hpp"

namespace dpdk::spi {

/// Number of 5-tuple fields for ACL matching.
constexpr uint32_t kAclNumFields{5};

/// ACL field indices in the 5-tuple.
enum AclFieldIndex : uint8_t {
  kAclFieldSrcIp = 0,
  kAclFieldDstIp,
  kAclFieldSrcPort,
  kAclFieldDstPort,
  kAclFieldProtocol,
};

/// 5-tuple input for rte_acl_classify (all fields in network byte order).
/// Each member is naturally aligned — no padding between fields.
struct AclInputData {
  uint32_t src_ip_be;
  uint32_t dst_ip_be;
  uint16_t src_port_be;
  uint16_t dst_port_be;
  uint8_t protocol;
};

/// L4 protocols supported by the SPI classifier.
enum class Protocol : std::uint8_t {
  /// Transmission Control Protocol.
  kTcp,
  /// User Datagram Protocol.
  kUdp,
};

/// Action to take when a filter group matches.
enum class Action : std::uint8_t {
  kForward,
  kDrop,
};

/// Minimal parsed packet fields needed by the classifier.
struct PacketMetadata {
  /// Parsed L4 protocol.
  Protocol protocol{};
  /// IPv4 source address in host byte order.
  std::uint32_t source_ip_address{};
  /// IPv4 destination address in host byte order.
  std::uint32_t destination_ip_address{};
  /// TCP/UDP source port in host byte order.
  std::uint16_t source_port{};
  /// TCP/UDP destination port in host byte order.
  std::uint16_t destination_port{};
  /// L7 hostname extracted from TLS SNI or HTTP Host header (nullptr if not extracted).
  const char* hostname{nullptr};
  /// Length of hostname string (not null-terminated in mbuf).
  std::uint16_t hostname_length{};
};

/// Compiled filter — hot-path representation of a single SpiFilterConfig.
struct CompiledFilter {
  Protocol protocol;
  std::uint32_t source_ip_address{};
  std::uint32_t destination_ip_address{};
  std::uint32_t destination_network{};
  std::uint32_t destination_prefix_mask{};
  std::uint16_t source_port{};
  std::uint16_t destination_port{};
  bool match_source_ip{false};
  bool match_destination_ip{false};
  bool match_destination_cidr{false};
  bool match_source_port{false};
  bool match_destination_port{false};
  std::string label;
};

/// Compiled filter group — hot-path representation of a SpiFilterGroupConfig.
struct CompiledFilterGroup {
  std::string name;
  std::uint32_t precedence{100};
  Action action{Action::kForward};
  std::vector<CompiledFilter> filters;
  rte_acl_ctx* acl_ctx{nullptr};

  CompiledFilterGroup() = default;
  CompiledFilterGroup(CompiledFilterGroup&&) noexcept;
  CompiledFilterGroup& operator=(CompiledFilterGroup&&) noexcept;
  CompiledFilterGroup(const CompiledFilterGroup&) = delete;
  CompiledFilterGroup& operator=(const CompiledFilterGroup&) = delete;
  ~CompiledFilterGroup();
};

/// Shared ACL field definitions used by all filter groups.
inline constexpr rte_acl_field_def kAclFieldDefs[kAclNumFields]{
    {.type = RTE_ACL_FIELD_TYPE_BITMASK, .size = sizeof(uint32_t), .field_index = kAclFieldSrcIp, .input_index = 0,
     .offset = offsetof(AclInputData, src_ip_be)},
    {.type = RTE_ACL_FIELD_TYPE_BITMASK, .size = sizeof(uint32_t), .field_index = kAclFieldDstIp, .input_index = 0,
     .offset = offsetof(AclInputData, dst_ip_be)},
    {.type = RTE_ACL_FIELD_TYPE_BITMASK, .size = sizeof(uint16_t), .field_index = kAclFieldSrcPort, .input_index = 0,
     .offset = offsetof(AclInputData, src_port_be)},
    {.type = RTE_ACL_FIELD_TYPE_BITMASK, .size = sizeof(uint16_t), .field_index = kAclFieldDstPort, .input_index = 0,
     .offset = offsetof(AclInputData, dst_port_be)},
    {.type = RTE_ACL_FIELD_TYPE_BITMASK, .size = sizeof(uint8_t), .field_index = kAclFieldProtocol, .input_index = 0,
     .offset = offsetof(AclInputData, protocol)},
};

/// Classification result returned by RuleTable::Match.
struct ClassificationResult {
  std::string_view group_name;
  std::string_view label;
  Action action{Action::kForward};
  std::uint32_t group_precedence{0};
  bool matched{false};
};

/**
 * @brief Immutable table of compiled filter groups.
 *
 * Groups are sorted by precedence (ascending). Matching iterates groups
 * in order; first group with any matching filter wins.
 */
class RuleTable final {
 public:
  explicit RuleTable(std::vector<CompiledFilterGroup> groups) noexcept;

  RuleTable(const RuleTable&) = delete;
  RuleTable& operator=(const RuleTable&) = delete;
  RuleTable(RuleTable&&) = default;
  RuleTable& operator=(RuleTable&&) = default;
  ~RuleTable() = default;

  /**
   * @brief Match packet against all groups in precedence order.
   *
   * For each group, any matching filter means the group matches.
   * Returns the first (highest-precedence) matching group.
   */
  [[nodiscard]] ClassificationResult Match(const PacketMetadata& packet) const noexcept;

  /// Return the number of filter groups.
  [[nodiscard]] std::size_t GroupCount() const noexcept { return groups_.size(); }

  /// Return the total number of filters across all groups.
  [[nodiscard]] std::size_t FilterCount() const noexcept;

 private:
  std::vector<CompiledFilterGroup> groups_;
};

/**
 * @brief Compile YAML SPI filter group config into a runtime rule table.
 *
 * Sorts groups by precedence. Parses CIDR, protocols, and actions.
 * @param config  SPI configuration loaded from config.yaml.
 * @return A RuleTable on success, or an error string.
 */
[[nodiscard]] std::expected<RuleTable, std::string> CompileRuleTable(const SpiConfig& config) noexcept;

}  // namespace dpdk::spi
