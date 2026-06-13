#include <dpdk_config_loader.hpp>
#include <dpdk_environment.hpp>
#include <spi_pipeline.hpp>
#include <spi_rule_engine.hpp>

#include <csignal>
#include <cstddef>
#include <print>
#include <utility>

namespace {

// Signal handlers can only safely touch simple signal-safe state.
volatile std::sig_atomic_t& ForceQuitFlag() noexcept {
  static volatile std::sig_atomic_t flag{0};
  return flag;
}

void HandleSignal(int signal) noexcept {
  if (signal == SIGINT || signal == SIGTERM) {
    ForceQuitFlag() = 1;
  }
}

[[nodiscard]] bool InstallSignalHandlers() noexcept {
  return std::signal(SIGINT, HandleSignal) != SIG_ERR &&
         std::signal(SIGTERM, HandleSignal) != SIG_ERR;
}

}  // namespace

int main() {
  // Ctrl+C and SIGTERM request a graceful stop of the packet loop.
  if (!InstallSignalHandlers()) {
    std::println(stderr, "Failed to install signal handlers");
    return 1;
  }

  // Load and validate all startup configuration before touching DPDK.
  auto config{LoadConfig(CONFIG_PATH)};
  if (!config) {
    std::println(stderr, "Config error: {}", config.error());
    return 1;
  }

  // Compile config rules once before the future packet-processing loop.
  auto rule_table{spi::CompileRuleTable(config->spi)};
  if (!rule_table) {
    std::println(stderr, "Rule compile error: {}", rule_table.error());
    return 1;
  }
  std::println("Loaded {} SPI rules", rule_table->Size());

  // Preserve runtime settings before DpdkConfig is moved into Environment.
  const auto burst_size{config->l2fwd.burst_size};
  const auto timer_period_sec{config->l2fwd.timer_period_sec};
  const auto worker_count{config->spi.worker_count};

  // Environment owns EAL, mempool, ports, queues, and link startup.
  auto env{dpdk::Environment{std::move(*config)}};
  auto result{env.init()};
  if (!result) {
    std::println(stderr, "DPDK init failed: {}", result.error().message);
    return 1;
  }

  // Pipeline receives packets, classifies them, and dispatches matches.
  spi::Pipeline pipeline{env, *rule_table, burst_size, worker_count};
  const auto stats{pipeline.RunUntilStopped(ForceQuitFlag(), timer_period_sec)};
  if (!stats) {
    std::println(stderr, "Pipeline error: {}", stats.error());
    return 1;
  }

  std::println(
      "Final SPI stats: received={} transmitted={} parsed={} matched={} "
      "unknown={} malformed={} dropped={}",
      stats->received, stats->transmitted, stats->parsed, stats->matched,
      stats->unknown, stats->malformed, stats->dropped);

  // Rule counters show which configured SPI rules matched traffic.
  const auto& rule_counts{pipeline.GetRuleMatchCounts()};
  for (std::size_t i{0}; i < rule_counts.size(); ++i) {
    std::println("Rule {}: matches={}", i, rule_counts[i]);
  }
}
