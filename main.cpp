#include <cstddef>
#include <cstdint>
#include <chrono>
#include <dpdk/dpdk.hpp>
#include <expected>
#include <memory>
#include <print>
#include <utility>

/**
 * @brief Compile DPI rules if enabled.
 * @param dpi_config  DPI configuration.
 * @param enabled     Whether DPI is enabled.
 * @return DPI rule table on success, or an error string.
 */
[[nodiscard]] auto CompileDpiRules(const dpdk::DpiConfig& dpi_config)
    -> std::expected<std::unique_ptr<dpdk::dpi::DpiRuleTable>, std::string> {
  if (!dpi_config.enabled) {
    return std::unique_ptr<dpdk::dpi::DpiRuleTable>{};
  }
  auto compiled{dpdk::dpi::CompileDpiRuleTable(dpi_config)};
  if (!compiled) {
    return std::unexpected{std::format("DPI compile error: {}", compiled.error())};
  }
  auto rules{std::make_unique<dpdk::dpi::DpiRuleTable>(std::move(*compiled))};
  std::println("Loaded {} DPI filters", rules->FilterCount());
  return rules;
}

/**
 * @brief Run pipeline, time it, and print final stats.
 * @param pipeline          Pipeline instance.
 * @param timer_period_sec  Seconds between periodic stats prints.
 * @return 0 on success, 1 on pipeline error.
 */
void PrintStat(dpdk::spi::Pipeline& pipeline, std::uint32_t timer_period_sec) {
  const auto start_time{std::chrono::steady_clock::now()};
  const auto stats{pipeline.RunUntilStopped(dpdk::ForceQuitFlag(), dpdk::ReloadFlag(), CONFIG_PATH, timer_period_sec)};
  const auto end_time{std::chrono::steady_clock::now()};
  if (!stats) {
    std::println(stderr, "Pipeline error: {}", stats.error());
    return;
  }

  const auto elapsed_sec{std::chrono::duration<double>(end_time - start_time).count()};
  const auto mpps{static_cast<double>(stats->received) / elapsed_sec / 1e6};
  const auto gbps{static_cast<double>(stats->received) * 64.0 * 8.0 / elapsed_sec / 1e9};

  std::println("Final stats: {}", *stats);
  std::println("Performance: {:.2f} Mpps, {:.2f} Gbps, {:.1f}s elapsed", mpps, gbps, elapsed_sec);
}

/**
 * @brief Application entry point.
 *
 * 1. Install signal handlers for Ctrl+C / SIGTERM / SIGUSR1.
 * 2. Load and validate YAML config from CONFIG_PATH.
 * 3. Extract config values needed by pipeline.
 * 4. Initialize the DPDK environment (EAL, mempool, ports).
 * 5. Compile SPI filter groups + DPI rules into hot-path tables.
 * 6. Run the packet-processing pipeline until interrupted.
 * 7. Print final statistics.
 *
 * Dynamic reload: send SIGUSR1 to reload SPI rules from config file
 * without restarting.  kill -USR1 $(pidof FastAPI)
 * @return 0 on success, 1 on error.
 */
int main() {
  if (!dpdk::InstallSignalHandlers()) {
    std::println(stderr, "Failed to install signal handlers");
    return 1;
  }

  auto config{dpdk::LoadConfig(CONFIG_PATH)};
  if (!config) {
    std::println(stderr, "Config error: {}", config.error());
    return 1;
  }

  // Stash the runtime fields Pipeline needs before *config is moved into
  // the Environment. Copy instead of move so *config is still valid
  // for the Pipeline constructor below.
  const auto timer_period_sec{config->app.timer_period_sec};
  const auto spi_config{config->spi};
  const auto dpi_config{config->dpi};
  const auto pcap_injector{config->pcap_injector};

  // Initialize DPDK EAL first — rte_acl_create() in CompileRuleTable requires it.
  auto env{dpdk::Environment{*config}};
  if (auto result{env.init()}; !result) {
    std::println(stderr, "DPDK init failed: {}", result.error());
    return 1;
  }

  // Now compile rules (requires EAL for rte_acl_create).
  auto rule_table{dpdk::spi::CompileRuleTable(spi_config)};
  if (!rule_table) {
    std::println(stderr, "SPI compile error: {}", rule_table.error());
    return 1;
  }
  std::println("Loaded {} SPI filter groups, {} filters", rule_table->GroupCount(), rule_table->FilterCount());

  auto dpi_rules{CompileDpiRules(dpi_config)};
  if (!dpi_rules) {
    std::println(stderr, "{}", dpi_rules.error());
    return 1;
  }

  dpdk::spi::Pipeline pipeline{env, std::move(*rule_table), std::move(*dpi_rules), *config};
  PrintStat(pipeline, timer_period_sec);
}
