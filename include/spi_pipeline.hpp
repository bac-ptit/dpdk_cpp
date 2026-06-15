#pragma once

#include <array>
#include <atomic>
#include <csignal>
#include <cstdint>
#include <expected>
#include <string>
#include <vector>

#include "dpdk_environment.hpp"
#include "spi_rule_engine.hpp"

struct rte_mbuf;

namespace spi {

struct PipelineStats {
  std::uint64_t received{};
  std::uint64_t transmitted{};
  std::uint64_t parsed{};
  std::uint64_t matched{};
  std::uint64_t unknown{};
  std::uint64_t malformed{};
  std::uint64_t dropped{};
};

struct alignas(64) AtomicCounters {
  std::atomic<std::uint64_t> received{};
  std::atomic<std::uint64_t> transmitted{};
  std::atomic<std::uint64_t> parsed{};
  std::atomic<std::uint64_t> matched{};
  std::atomic<std::uint64_t> unknown{};
  std::atomic<std::uint64_t> malformed{};
  std::atomic<std::uint64_t> dropped{};
};

struct WorkerContext {
  const dpdk::Environment* environment{};
  const RuleTable* rules{};
  AtomicCounters* counters{};
  std::vector<std::uint64_t> rule_match_counts;
  const volatile std::sig_atomic_t* force_quit{};
  std::uint16_t burst_size{};
  std::uint16_t worker_id{};
};

class Pipeline final {
public:
  Pipeline(const dpdk::Environment& environment, const RuleTable& rules,
           std::uint16_t burst_size, std::uint16_t worker_count);
  ~Pipeline();

  Pipeline(const Pipeline&) = delete;
  Pipeline& operator=(const Pipeline&) = delete;

  [[nodiscard]] std::expected<PipelineStats, std::string> RunUntilStopped(
      const volatile std::sig_atomic_t& force_quit,
      std::uint32_t timer_period_sec) noexcept;
  [[nodiscard]] const std::vector<std::uint64_t>& GetRuleMatchCounts()
      const noexcept {
    return rule_match_counts_;
  }

private:
  static constexpr std::uint16_t kTxPortBurstSize{64};

  [[nodiscard]] std::expected<void, std::string> StartWorkers() noexcept;
  void StopWorkers() noexcept;

  const dpdk::Environment& environment_;
  const RuleTable& rules_;
  AtomicCounters counters_;
  std::vector<std::uint64_t> rule_match_counts_;
  std::vector<WorkerContext> worker_contexts_;
  std::uint16_t burst_size_{};
  volatile std::sig_atomic_t worker_force_quit_{0};
  bool workers_started_{false};
};

}  // namespace spi
