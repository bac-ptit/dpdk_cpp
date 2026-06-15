#include "spi_rule_engine.hpp"

#include <cstddef>
#include <format>
#include <ranges>
#include <string_view>
#include <utility>

#include "spi_ip_address.hpp"

namespace dpdk::spi {
namespace {

/**
 * @brief Convert YAML protocol string to compact enum.
 * @param protocol  Protocol string ("tcp" or "udp").
 * @return Protocol enum value, or nullopt for unknown strings.
 */
[[nodiscard]] constexpr std::optional<Protocol> ParseProtocol(std::string_view protocol) noexcept {
  if (protocol == "tcp") {
    return Protocol::kTcp;
  }
  if (protocol == "udp") {
    return Protocol::kUdp;
  }
  return std::nullopt;
}

/**
 * @brief Check whether a rule field matches its packet counterpart.
 *
 * When the match flag is false the field is treated as a wildcard (always
 * matches). This avoids optional and runtime branching on match semantics.
 * @tparam T  Field type (uint32_t, uint16_t, etc.).
 * @param enabled   Whether this field is constrained by the rule.
 * @param rule_value    Compiled value from the rule.
 * @param packet_value  Extracted value from the packet.
 * @return true if the field matches (or is wildcarded).
 */
template <typename T>
[[nodiscard]] constexpr bool FieldMatches(bool enabled, T rule_value, T packet_value) noexcept {
  return !enabled || rule_value == packet_value;
}

}  // namespace

RuleTable::RuleTable(std::vector<CompiledRule> rules) noexcept : rules_{std::move(rules)} {}

/**
 * @brief First-match-wins scan of compiled rules against packet metadata.
 *
 * Each rule must pass protocol check and all enabled field comparisons.
 * Wildcard fields (match_* == false) are always accepted.
 * @param packet  Parsed packet metadata.
 * @return ClassificationResult on match, or nullopt.
 */
std::optional<ClassificationResult> RuleTable::Match(const PacketMetadata& packet) const noexcept {
  for (std::size_t i{0}; i < rules_.size(); ++i) {
    const auto& rule{rules_[i]};
    if (rule.protocol != packet.protocol) {
      continue;
    }

    if (!FieldMatches(rule.match_source_ip_address, rule.source_ip_address, packet.source_ip_address)) {
      continue;
    }

    if (!FieldMatches(rule.match_destination_ip_address, rule.destination_ip_address, packet.destination_ip_address)) {
      continue;
    }

    if (!FieldMatches(rule.match_source_port, rule.source_port, packet.source_port)) {
      continue;
    }

    if (!FieldMatches(rule.match_destination_port, rule.destination_port, packet.destination_port)) {
      continue;
    }

    return ClassificationResult{
        .rule_index = static_cast<std::uint16_t>(i),
        .label = rule.label,
    };
  }

  return std::nullopt;
}

/**
 * @brief Convert YAML-friendly SpiRuleConfig into hot-path CompiledRule values.
 *
 * Parses protocol strings, validates IPv4 addresses via ParseIpv4Address,
 * and encodes optional YAML fields as match_* flags + zero-default values.
 * @param config  SPI configuration from config.yaml.
 * @return RuleTable on success, or an error string describing the invalid rule.
 */
std::expected<RuleTable, std::string> CompileRuleTable(const SpiConfig& config) noexcept {
  std::vector<CompiledRule> rules;
  rules.reserve(config.rules.size());

  for (const auto& [rule_index, rule_config] : config.rules | std::views::enumerate) {
    const auto protocol{ParseProtocol(rule_config.protocol)};
    if (!protocol) {
      return std::unexpected(std::format("spi.rules[{}].protocol must be 'tcp' or 'udp'", rule_index));
    }

    std::uint32_t source_ip_address{};
    if (rule_config.source_ip_address) {
      const auto parsed{ParseIpv4Address(*rule_config.source_ip_address)};
      if (!parsed) {
        return std::unexpected(std::format("spi.rules[{}].source_ip_address {}", rule_index, parsed.error()));
      }
      source_ip_address = *parsed;
    }

    std::uint32_t destination_ip_address{};
    if (rule_config.destination_ip_address) {
      const auto parsed{ParseIpv4Address(*rule_config.destination_ip_address)};
      if (!parsed) {
        return std::unexpected(std::format("spi.rules[{}].destination_ip_address {}", rule_index, parsed.error()));
      }
      destination_ip_address = *parsed;
    }

    rules.emplace_back(CompiledRule{
        .protocol = *protocol,
        .source_ip_address = source_ip_address,
        .destination_ip_address = destination_ip_address,
        .source_port = rule_config.source_port.value_or(0),
        .destination_port = rule_config.destination_port.value_or(0),
        .match_source_ip_address = rule_config.source_ip_address.has_value(),
        .match_destination_ip_address = rule_config.destination_ip_address.has_value(),
        .match_source_port = rule_config.source_port.has_value(),
        .match_destination_port = rule_config.destination_port.has_value(),
        .label = rule_config.label,
    });
  }

  return RuleTable{std::move(rules)};
}

}  // namespace dpdk::spi
