#pragma once

#include <expected>
#include <string>

#include "dpdk_config.hpp"

// Validate all configuration sections (EAL, port, mempool, SPI rules).
[[nodiscard]] std::expected<void, std::string> ValidateConfig(
    const DpdkConfig& config) noexcept;

// Load and validate YAML configuration from the given file path.
[[nodiscard]] std::expected<DpdkConfig, std::string> LoadConfig(
    const std::string& path) noexcept;
