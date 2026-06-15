#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "dpdk_config.hpp"

namespace spi {

/// L4 protocols supported by the SPI classifier.
enum class Protocol : std::uint8_t {
  /// Transmission Control Protocol.
  kTcp,
  /// User Datagram Protocol.
  kUdp,
};

/// Minimal parsed packet fields needed by the classifier.
struct PacketMetadata {
  /// Parsed L4 protocol.
  Protocol protocol{};
  /// TCP/UDP source port in host byte order.
  std::uint16_t src_port{};
  /// TCP/UDP destination port in host byte order.
  std::uint16_t dst_port{};
};

/**
 * @brief Startup-compiled classification rule used by the hot path.
 *
 * @note Port value 0 is an internal wildcard generated from an omitted YAML
 *       source or destination port. Runtime matching avoids std::optional.
 */
struct CompiledRule {
  /// L4 protocol that must match.
  Protocol protocol;
  /// Source port to match, or 0 for any source port.
  std::uint16_t src_port{};
  /// Destination port to match, or 0 for any destination port.
  std::uint16_t dst_port{};
  /// Worker targets selected when the rule matches.
  std::vector<std::uint16_t> workers;
  /// Human-readable classification label.
  std::string label;
};

/**
 * @brief Non-owning classification result returned by RuleTable::Match.
 *
 * @note `label` refers to storage owned by the RuleTable and is valid until the
 *       table is destroyed or moved.
 */
struct ClassificationResult {
  /// Index of the matching compiled rule.
  std::uint16_t rule_index{};
  /// Non-owning view of the matching rule label.
  std::string_view label;
};

/**
 * @brief Immutable table of compiled SPI rules.
 *
 * The table owns its rules and is safe to read from the packet hot path after
 * construction. It does not allocate during Match().
 */
class RuleTable final {
public:
  /**
   * @brief Take ownership of compiled rules.
   *
   * @param rules Rules already converted from YAML-friendly config into
   *        hot-path values.
   */
  explicit RuleTable(std::vector<CompiledRule> rules) noexcept;

  /// Return the compiled rule storage owned by this table.
  [[nodiscard]] const std::vector<CompiledRule>& GetRules() const noexcept {
    return rules_;
  }

  /// Return the number of compiled rules.
  [[nodiscard]] std::size_t Size() const noexcept { return rules_.size(); }
  /// Return worker targets configured for the rule at `rule_index`.
  [[nodiscard]] const std::vector<std::uint16_t>& GetRuleWorkers(
      std::size_t rule_index) const noexcept {
    return rules_[rule_index].workers;
  }

  /**
   * @brief Find the first rule matching parsed packet metadata.
   *
   * @param packet Metadata extracted from a packet header.
   * @return Classification result for the first matching rule, or std::nullopt
   *         when no rule matches.
   */
  [[nodiscard]] std::optional<ClassificationResult> Match(
      const PacketMetadata& packet) const noexcept;

private:
  std::vector<CompiledRule> rules_;
};

/**
 * @brief Compile YAML SPI rule configuration into a runtime rule table.
 *
 * @param config SPI configuration loaded from config.yaml.
 * @return A RuleTable on success, or an error string describing the invalid
 *         rule that prevented compilation.
 *
 * @note This function performs allocations during startup only. The resulting
 *       RuleTable is allocation-free during Match().
 */
[[nodiscard]] std::expected<RuleTable, std::string> CompileRuleTable(
    const SpiConfig& config) noexcept;

}  // namespace spi
