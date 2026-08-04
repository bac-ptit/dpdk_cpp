#pragma once

#include <expected>
#include <string>

#include "dpdk/config/dpdk_config.hpp"

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
 * @brief Load and validate configuration from YAML or binary BEVE file.
 *
 * Supports both text `.yaml` and high-performance binary `.beve` / `.bin` files via Glaze.
 * Runs semantic validation through @ref ValidateConfig.
 * @param path  Filesystem path to the YAML or BEVE configuration file.
 * @return A validated DpdkConfig on success, or an error string.
 */
[[nodiscard]] std::expected<DpdkConfig, std::string> LoadConfig(const std::string& path) noexcept;

/**
 * @brief Save configuration in Glaze BEVE binary format for fast sub-millisecond reloads.
 *
 * @param config  The validated DpdkConfig struct.
 * @param path    Filesystem path to write binary configuration (e.g. "config.beve").
 * @return Void on success, or an error string.
 */
[[nodiscard]] std::expected<void, std::string> SaveConfigBinary(const DpdkConfig& config, const std::string& path) noexcept;

/**
 * @brief Save standalone rule store in Glaze BEVE binary format.
 *
 * @param rule_store The RuleStoreConfig struct containing filter_groups and dpi.
 * @param path       Filesystem path to write binary rule stream (e.g. "rules.beve").
 * @return Void on success, or an error string.
 */
[[nodiscard]] std::expected<void, std::string> SaveRuleStoreBinary(const RuleStoreConfig& rule_store, const std::string& path) noexcept;

}  // namespace dpdk
