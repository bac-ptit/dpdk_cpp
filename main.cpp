#include <cstddef>
#include <dpdk/dpdk.hpp>
#include <print>
#include <utility>

/**
 * @brief Application entry point.
 *
 * 1. Install signal handlers for Ctrl+C / SIGTERM.
 * 2. Load and validate YAML config from CONFIG_PATH.
 * 3. Compile SPI rules into a hot-path rule table.
 * 4. Initialize the DPDK environment (EAL, mempool, ports).
 * 5. Run the packet-processing pipeline until interrupted.
 * 6. Print final statistics and per-rule match counts.
 * @return 0 on success, 1 on error.
 */
int main() {
  // Ctrl+C and SIGTERM request a graceful stop of the packet loop.
  if (!dpdk::InstallSignalHandlers()) {
    std::println(stderr, "Failed to install signal handlers");
    return 1;
  }

  // Load and validate all startup configuration before touching DPDK.
  auto config{dpdk::LoadConfig(CONFIG_PATH)};
  if (!config) {
    std::println(stderr, "Config error: {}", config.error());
    return 1;
  }

  // Compile config rules once before the future packet-processing loop.
  auto rule_table{dpdk::spi::CompileRuleTable(config->spi)};
  if (!rule_table) {
    std::println(stderr, "Rule compile error: {}", rule_table.error());
    return 1;
  }
  std::println("Loaded {} SPI rules", rule_table->Size());

  // Preserve runtime settings before DpdkConfig is moved into Environment.
  const auto burst_size{config->l2_forward.burst_size};
  const bool mac_updating{config->l2_forward.mac_updating};
  const auto l3_forward{config->l3_forward};
  const auto timer_period_sec{config->l2_forward.timer_period_sec};
  const auto worker_count{config->spi.worker_count};
  const bool drop_unmatched{config->spi.drop_unmatched};
  const auto packet_distribution{config->spi.packet_distribution};
  const auto dispatch_queue_size{config->spi.dispatch_queue_size};

  // Environment owns EAL, mempool, ports, queues, and link startup.
  auto env{dpdk::Environment{std::move(*config)}};
  if (auto result{env.init()}; !result) {
    std::println(stderr, "DPDK init failed: {}", result.error().message);
    return 1;
  }

  // Pipeline receives packets, classifies them, and forwards the mbufs.
  dpdk::spi::Pipeline pipeline{env,
                               *rule_table,
                               burst_size,
                               worker_count,
                               mac_updating,
                               l3_forward,
                               drop_unmatched,
                               packet_distribution,
                               dispatch_queue_size};
  const auto stats{pipeline.RunUntilStopped(dpdk::ForceQuitFlag(), timer_period_sec)};
  if (!stats) {
    std::println(stderr, "Pipeline error: {}", stats.error());
    return 1;
  }

  std::println(
      "Final SPI stats: received={} transmitted={} parsed={} matched={} "
      "unknown={} malformed={} dropped={}",
      stats->received, stats->transmitted, stats->parsed, stats->matched, stats->unknown, stats->malformed,
      stats->dropped);

  // Rule counters show which configured SPI rules matched traffic.
  const auto& rule_counts{pipeline.GetRuleMatchCounts()};
  for (std::size_t i{0}; i < rule_counts.size(); ++i) {
    std::println("Rule {}: matches={}", i, rule_counts[i]);
  }
}
