#pragma once

#include <expected>
#include <string>

#include "dpdk_config.hpp"

namespace dpdk {

/**
 * @brief Validate all configuration sections (EAL, port, mempool, SPI rules).
 *
 * Checks semantic constraints such as non-empty rule lists, valid protocols,
 * and non-zero ports. Does NOT parse YAML.
 * @param config  The fully-loaded configuration struct.
 * @return Void on success, or a human-readable error string.
 */
[[nodiscard]] std::expected<void, std::string> ValidateConfig(const DpdkConfig& config) noexcept;

/**
 * @brief Load and validate YAML configuration from the given file path.
 *
 * Parses config.yaml via Glaze reflection, then runs semantic validation
 * through @ref ValidateConfig.
 * @param path  Filesystem path to the YAML configuration file.
 * @return A validated DpdkConfig on success, or an error string.
 */
[[nodiscard]] std::expected<DpdkConfig, std::string> LoadConfig(const std::string& path) noexcept;

}  // namespace dpdk
