#include <cstddef>
#include <cstdint>
#include <chrono>
#include <dpdk/dpdk.hpp>
#include <memory>
#include <print>
#include <utility>

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

  const auto burst_size{config->app.burst_size};
  const bool mac_updating{config->app.mac_updating};
  const auto l3_forward{config->l3_forward};
  const auto timer_period_sec{config->app.timer_period_sec};
  const auto worker_count{config->spi.worker_count};
  const bool drop_unmatched{config->spi.drop_unmatched};
  const auto packet_distribution{config->spi.packet_distribution};
  const auto dispatch_queue_size{config->spi.dispatch_queue_size};
  const auto flow_ttl_sec{config->spi.flow_ttl_sec};
  const bool dpi_enabled{config->dpi.enabled};
  auto dpi_config{std::move(config->dpi)};
  auto spi_config{std::move(config->spi)};

  // Initialize DPDK EAL first — rte_acl_create() in CompileRuleTable requires it.
  auto env{dpdk::Environment{std::move(*config)}};
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

  // Compile DPI rules if enabled.
  std::unique_ptr<dpdk::dpi::DpiRuleTable> dpi_rules;
  if (dpi_enabled) {
    auto compiled{dpdk::dpi::CompileDpiRuleTable(dpi_config)};
    if (!compiled) {
      std::println(stderr, "DPI compile error: {}", compiled.error());
      return 1;
    }
    dpi_rules = std::make_unique<dpdk::dpi::DpiRuleTable>(std::move(*compiled));
    std::println("Loaded {} DPI filters", dpi_rules->FilterCount());
  }

  dpdk::spi::Pipeline pipeline{
      env,        std::move(*rule_table), std::move(dpi_rules), burst_size,          worker_count, mac_updating,
      l3_forward, drop_unmatched,         packet_distribution,  dispatch_queue_size, flow_ttl_sec};
  const auto start_time{std::chrono::steady_clock::now()};
  const auto stats{pipeline.RunUntilStopped(dpdk::ForceQuitFlag(), dpdk::ReloadFlag(), CONFIG_PATH, timer_period_sec)};
  const auto end_time{std::chrono::steady_clock::now()};
  if (!stats) {
    std::println(stderr, "Pipeline error: {}", stats.error());
    return 1;
  }

  const auto elapsed_sec{std::chrono::duration<double>(end_time - start_time).count()};
  const auto mpps{static_cast<double>(stats->received) / elapsed_sec / 1e6};
  const auto gbps{static_cast<double>(stats->received) * 64.0 * 8.0 / elapsed_sec / 1e9};  // assume 64-byte packets

  std::println("Final stats: {}", *stats);
  std::println("Performance: {:.2f} Mpps, {:.2f} Gbps, {:.1f}s elapsed", mpps, gbps, elapsed_sec);
}
