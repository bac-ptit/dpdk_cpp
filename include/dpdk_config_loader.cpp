#include "dpdk_config_loader.hpp"

#include <cstddef>
#include <format>
#include <optional>

#include <glaze/yaml.hpp>

namespace {

[[nodiscard]] bool IsSupportedProtocol(const std::string& protocol) noexcept {
  return protocol == "tcp" || protocol == "udp";
}

[[nodiscard]] bool HasInvalidPort(
    const std::optional<std::uint16_t>& port) noexcept {
  return port.has_value() && *port == 0;
}

// Validation macro: return an error string if condition is false.
#define CONFIG_VALIDATE(condition, ...)                  \
  do {                                                   \
    if (!(condition)) {                                  \
      return std::unexpected(std::format(__VA_ARGS__));  \
    }                                                    \
  } while (0)

[[nodiscard]] std::expected<void, std::string> ValidateRuleConfig(
    const SpiRuleConfig& rule, std::uint16_t worker_count,
    std::size_t index) noexcept {
  CONFIG_VALIDATE(IsSupportedProtocol(rule.protocol),
                  "spi.rules[{}].protocol must be 'tcp' or 'udp'", index);
  CONFIG_VALIDATE(rule.src_port || rule.dst_port,
                  "spi.rules[{}] must set src_port or dst_port", index);
  CONFIG_VALIDATE(!HasInvalidPort(rule.src_port),
                  "spi.rules[{}].src_port must be greater than 0", index);
  CONFIG_VALIDATE(!HasInvalidPort(rule.dst_port),
                  "spi.rules[{}].dst_port must be greater than 0", index);
  CONFIG_VALIDATE(!rule.label.empty(),
                  "spi.rules[{}].label must not be empty", index);
  for (const auto worker : rule.workers) {
    CONFIG_VALIDATE(worker_count > 0,
                    "spi.worker_count must be greater than 0 when workers are "
                    "configured");
    CONFIG_VALIDATE(worker < worker_count,
                    "spi.rules[{}].workers contains {} but worker_count is {}",
                    index, worker, worker_count);
  }

  return {};
}

}  // namespace

std::expected<void, std::string> ValidateConfig(
    const DpdkConfig& config) noexcept {
  const auto& [worker_count, rules]{config.spi};
  CONFIG_VALIDATE(worker_count > 0,
                  "spi.worker_count must be greater than 0");
  CONFIG_VALIDATE(!rules.empty(),
                  "spi.rules must contain at least one rule");

  for (std::size_t i{0}; i < rules.size(); ++i) {
    if (const auto valid{ValidateRuleConfig(rules[i], worker_count, i)};
        !valid) {
      return std::unexpected(valid.error());
    }
  }

  return {};
}

std::expected<DpdkConfig, std::string> LoadConfig(
    const std::string& path) noexcept {
  // Parse YAML into the auto-reflected DpdkConfig struct.
  DpdkConfig config;
  if (const auto parse_error{glz::read_file_yaml(config, path)}; parse_error) {
    return std::unexpected(std::format(
        "Failed to parse '{}': {}", path, glz::format_error(parse_error)));
  }

  // Validate semantic constraints before use.
  if (const auto valid{ValidateConfig(config)}; !valid) {
    return std::unexpected(valid.error());
  }

  return config;
}
