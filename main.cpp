#include <dpdk_environment.hpp>
#include <expected>
#include <glaze/yaml.hpp>
#include <iostream>
#include <print>
#include <string>

[[nodiscard]] std::expected<DpdkConfig, std::string> load_config(
    const std::string& path) noexcept {
  DpdkConfig config;
  if (const auto ec{glz::read_file_yaml(config, path)}; ec) {
    return std::unexpected(
        std::format("Failed to parse '{}': {}", path, glz::format_error(ec)));
  }
  return config;
}

int main() {
  auto config{load_config(CONFIG_PATH)};
  if (!config) {
    std::println(stderr, "Config error: {}", config.error());
    return 1;
  }

  auto env{dpdk::Environment{std::move(*config)}};
  auto result{env.init()};
  if (!result) {
    std::println(stderr, "DPDK init failed: {}", result.error().message);
    return 1;
  }
}