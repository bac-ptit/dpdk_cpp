#include <dpdk/config/dpdk_config_loader.hpp>
#include <print>
#include <iostream>

int main(int argc, char** argv) {
  if (argc < 3) {
    std::println("Usage: {} <input.yaml> <output.beve> [--rules-only]", argv[0]);
    return 1;
  }

  const std::string input_path = argv[1];
  const std::string output_path = argv[2];
  const bool rules_only = (argc >= 4 && std::string(argv[3]) == "--rules-only");

  std::println("[yaml2beve] Reading YAML config: {}", input_path);
  auto config = dpdk::LoadConfig(input_path);
  if (!config) {
    std::println(stderr, "[yaml2beve] Error loading YAML config: {}", config.error());
    return 1;
  }

  if (rules_only) {
    std::println("[yaml2beve] Writing RuleStore BEVE Stream: {}", output_path);
    dpdk::RuleStoreConfig store{
        .filter_groups = std::move(config->spi.filter_groups),
        .dpi = std::move(config->dpi)
    };
    auto result = dpdk::SaveRuleStoreBinary(store, output_path);
    if (!result) {
      std::println(stderr, "[yaml2beve] Error saving rule store binary: {}", result.error());
      return 1;
    }
  } else {
    std::println("[yaml2beve] Writing Binary BEVE Stream: {}", output_path);
    auto result = dpdk::SaveConfigBinary(*config, output_path);
    if (!result) {
      std::println(stderr, "[yaml2beve] Error saving binary BEVE: {}", result.error());
      return 1;
    }
  }

  std::println("[yaml2beve] Successfully converted {} -> {} (Glaze BEVE Binary Stream)", input_path, output_path);
  return 0;
}
