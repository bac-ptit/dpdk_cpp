#include "dpdk_config_loader.hpp"

#include <cstddef>
#include <format>
#include <glaze/yaml.hpp>
#include <optional>
#include <string>
#include <string_view>

#include "spi_ip_address.hpp"

namespace dpdk {
namespace {

/**
 * @brief Validate a semantic condition and return an error string on failure.
 *
 * Used to check SPI rule constraints before / after YAML loading.
 * @param condition  The boolean condition to assert.
 * @param ...        Format string and arguments for the error message.
 */
#define CONFIG_VALIDATE(condition, ...)                 \
do {                                                  \
if (!(condition)) {                                 \
return std::unexpected(std::format(__VA_ARGS__)); \
}                                                   \
} while (0)

/// Whether the protocol string is "tcp" or "udp".
[[nodiscard]] constexpr bool IsSupportedProtocol(std::string_view protocol) noexcept {
  return protocol == "tcp" || protocol == "udp";
}

/// Whether an optional port value is present but zero (invalid).
[[nodiscard]] constexpr bool HasInvalidPort(const std::optional<std::uint16_t>& port) noexcept {
  return port.has_value() && *port == 0;
}

/// Whether the rule has at least one match field configured.
[[nodiscard]] constexpr bool HasMatchField(const SpiRuleConfig& rule) noexcept {
  return rule.source_ip_address || rule.destination_ip_address || rule.source_port || rule.destination_port;
}

/// Whether an optional IP field is absent or a valid IPv4 address.
[[nodiscard]] bool HasValidIp(const std::optional<std::string>& address) noexcept {
  return !address || spi::ParseIpv4Address(*address).has_value();
}

/**
 * @brief Validate a single SPI rule entry.
 * @param rule   The rule config to validate.
 * @param index  Index of the rule for error messages.
 * @return Void on success, or an error string.
 */
[[nodiscard]] std::expected<void, std::string> ValidateRuleConfig(const SpiRuleConfig& rule,
                                                                   std::size_t index) noexcept {
  CONFIG_VALIDATE(IsSupportedProtocol(rule.protocol), "spi.rules[{}].protocol must be 'tcp' or 'udp'", index);
  CONFIG_VALIDATE(HasMatchField(rule),
                  "spi.rules[{}] must set source_ip_address, destination_ip_address, source_port, "
                  "or dst_port",
                  index);
  CONFIG_VALIDATE(HasValidIp(rule.source_ip_address), "spi.rules[{}].source_ip_address must be a valid IPv4 address",
                  index);
  CONFIG_VALIDATE(HasValidIp(rule.destination_ip_address),
                  "spi.rules[{}].destination_ip_address must be a valid IPv4 address", index);
  CONFIG_VALIDATE(!HasInvalidPort(rule.source_port), "spi.rules[{}].source_port must be greater than 0", index);
  CONFIG_VALIDATE(!HasInvalidPort(rule.destination_port), "spi.rules[{}].destination_port must be greater than 0", index);
  CONFIG_VALIDATE(!rule.label.empty(), "spi.rules[{}].label must not be empty", index);

  return {};
}

}  // namespace

/**
 * @brief Validate all configuration sections.
 *
 * Checks worker_count, rule list non-empty, and per-rule semantic
 * constraints.
 * @param config  The fully-loaded configuration struct.
 * @return Void on success, or an error string.
 */
std::expected<void, std::string> ValidateConfig(const DpdkConfig& config) noexcept {
  const auto& [worker_count, rules]{config.spi};
  CONFIG_VALIDATE(worker_count > 0, "spi.worker_count must be greater than 0");
  CONFIG_VALIDATE(!rules.empty(), "spi.rules must contain at least one rule");

  for (std::size_t i{0}; i < rules.size(); ++i) {
    if (const auto valid{ValidateRuleConfig(rules[i], i)}; !valid) {
      return std::unexpected(valid.error());
    }
  }

  return {};
}

/**
 * @brief Load and validate YAML configuration from file.
 *
 * Uses Glaze (glz::read_file_yaml) to parse into the auto-reflected
 * DpdkConfig struct, then runs ValidateConfig.
 * @param path  Filesystem path to the YAML configuration file.
 * @return A validated DpdkConfig on success, or an error string.
 */
std::expected<DpdkConfig, std::string> LoadConfig(const std::string& path) noexcept {
  // Parse YAML into the auto-reflected DpdkConfig struct.
  DpdkConfig config;
  if (const auto parse_error{glz::read_file_yaml(config, path)}; parse_error) {
    return std::unexpected(std::format("Failed to parse '{}': {}", path, glz::format_error(parse_error)));
  }

  // Validate semantic constraints before use.
  if (const auto valid{ValidateConfig(config)}; !valid) {
    return std::unexpected(valid.error());
  }

  return config;
}

}  // namespace dpdk
