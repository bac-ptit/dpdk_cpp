#include "spi_rule_engine.hpp"

#include <cstddef>
#include <format>
#include <ranges>
#include <utility>

namespace {

// Convert YAML protocol string to compact enum — startup only.
[[nodiscard]] std::optional<spi::Protocol> ParseProtocol(
    const std::string& protocol) noexcept {
  if (protocol == "tcp") {
    return spi::Protocol::kTcp;
  }
  if (protocol == "udp") {
    return spi::Protocol::kUdp;
  }
  return std::nullopt;
}

// Match a compiled rule port against a packet port; 0 = wildcard.
[[nodiscard]] bool PortMatches(std::uint16_t rule_port,
                                std::uint16_t packet_port) noexcept {
  return rule_port == 0 || rule_port == packet_port;
}

}  // namespace

namespace spi {

RuleTable::RuleTable(std::vector<CompiledRule> rules) noexcept
    : rules_{std::move(rules)} {}

// First-match-wins scan of compiled rules against packet metadata.
std::optional<ClassificationResult> RuleTable::Match(
    const PacketMetadata& packet) const noexcept {
  for (std::size_t i{0}; i < rules_.size(); ++i) {
    const auto& rule{rules_[i]};
    if (rule.protocol != packet.protocol) {
      continue;
    }

    if (!PortMatches(rule.src_port, packet.src_port)) {
      continue;
    }

    if (!PortMatches(rule.dst_port, packet.dst_port)) {
      continue;
    }

    return ClassificationResult{
        .rule_index = static_cast<std::uint16_t>(i),
        .label = rule.label,
    };
  }

  return std::nullopt;
}

// Convert YAML-friendly SpiRuleConfig into hot-path CompiledRule values.
std::expected<RuleTable, std::string> CompileRuleTable(
    const SpiConfig& config) noexcept {
  std::vector<CompiledRule> rules;
  rules.reserve(config.rules.size());

  for (const auto& [rule_index, rule_config] :
       config.rules | std::views::enumerate) {
    const auto protocol{ParseProtocol(rule_config.protocol)};
    if (!protocol) {
      return std::unexpected(std::format(
          "spi.rules[{}].protocol must be 'tcp' or 'udp'", rule_index));
    }

    rules.emplace_back(CompiledRule{
        .protocol = *protocol,
        .src_port = rule_config.src_port.value_or(0),
        .dst_port = rule_config.dst_port.value_or(0),
        .workers = rule_config.workers,
        .label = rule_config.label,
    });
  }

  return RuleTable{std::move(rules)};
}

}  // namespace spi
