#pragma once

#include <rte_ether.h>

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

namespace dpdk::spi {

/// Snapshot of pipeline counters collected at a point in time.
struct PipelineStats {
  std::uint64_t received{};
  std::uint64_t transmitted{};
  std::uint64_t parsed{};
  std::uint64_t matched{};
  std::uint64_t unknown{};
  std::uint64_t malformed{};
  std::uint64_t dropped{};
};

/// Cache-line-aligned atomic counters shared between workers and stats thread.
struct alignas(64) AtomicCounters {
  std::atomic<std::uint64_t> received{};
  std::atomic<std::uint64_t> transmitted{};
  std::atomic<std::uint64_t> parsed{};
  std::atomic<std::uint64_t> matched{};
  std::atomic<std::uint64_t> unknown{};
  std::atomic<std::uint64_t> malformed{};
  std::atomic<std::uint64_t> dropped{};
};

/// Startup-compiled IPv4 route used by the L3 forwarding path.
struct L3RouteEntry {
  /// Destination network in host byte order.
  std::uint32_t network_address{};
  /// Prefix mask in host byte order.
  std::uint32_t prefix_mask{};
  /// CIDR prefix length.
  std::uint16_t prefix_length{};
  /// Output DPDK port.
  std::uint16_t output_port{};
};

/// Startup-compiled destination MAC for an output port.
struct EthernetDestinationEntry {
  /// Output DPDK port.
  std::uint16_t port_id{};
  /// Destination MAC to use on that port.
  rte_ether_addr mac_address{};
};

/// Per-worker state passed to the worker loop function.
struct WorkerContext {
  const dpdk::Environment* environment{};
  const RuleTable* rules{};
  const std::vector<L3RouteEntry>* l3_routes{};
  const std::vector<EthernetDestinationEntry>* ethernet_destinations{};
  AtomicCounters* counters{};
  std::vector<std::uint64_t> rule_match_counts;
  const volatile std::sig_atomic_t* force_quit{};
  std::uint16_t burst_size{};
  std::uint16_t worker_id{};
  bool mac_updating{true};
  bool l3_forwarding{false};
  bool drop_unmatched{false};
};

/**
 * @brief DPDK-based SPI packet-processing pipeline with L2 forwarding.
 *
 * Receives packets via rte_eth_rx_burst, classifies each packet using the
 * compiled RuleTable, rewrites L2 headers, and transmits via rte_eth_tx_burst.
 * Supports single-worker (main-lcore) and multi-worker (remote-launch) modes.
 */
class Pipeline final {
 public:
  /**
   * @brief Construct without starting workers.
   * @param environment  Initialized DPDK environment (ports, mempool).
   * @param rules        Compiled rule table owned by caller.
   * @param burst_size   Packets per rte_eth_rx_burst call.
   * @param worker_count Number of worker lcores to launch.
   * @param mac_updating Whether to rewrite Ethernet source/destination MACs.
   * @param l3_forward   L3 forwarding configuration loaded from YAML.
   * @param drop_unmatched Whether to drop packets that match no SPI rule.
   */
  Pipeline(const dpdk::Environment& environment, const RuleTable& rules, std::uint16_t burst_size,
           std::uint16_t worker_count, bool mac_updating, L3ForwardConfig l3_forward, bool drop_unmatched);

  /// Stop all workers and release per-worker resources.
  ~Pipeline();

  Pipeline(const Pipeline&) = delete;
  Pipeline& operator=(const Pipeline&) = delete;

  /**
   * @brief Enter packet-processing loop until force_quit becomes non-zero.
   *
   * In single-worker mode (`worker_count == 1`) the calling thread runs the
   * hot path directly. In multi-worker mode it launches workers on remote
   * lcores and polls the force-quit flag on the main lcore.
   * @param force_quit       Signal flag; when non-zero the loop exits.
   * @param timer_period_sec Seconds between periodic stats prints (0=off).
   * @return Final pipeline statistics after the loop exits.
   */
  [[nodiscard]] std::expected<PipelineStats, std::string> RunUntilStopped(const volatile std::sig_atomic_t& force_quit,
                                                                          std::uint32_t timer_period_sec) noexcept;

  /// Return const reference to per-rule match counters.
  [[nodiscard]] const std::vector<std::uint64_t>& GetRuleMatchCounts() const noexcept { return rule_match_counts_; }

 private:
  /**
   * @brief Launch all workers on remote lcores.
   * @return Void on success, or an error string.
   */
  [[nodiscard]] std::expected<void, std::string> StartWorkers() noexcept;
  /**
   * @brief Launch a single worker on the specified lcore.
   * @param worker_id  Zero-based worker index.
   * @param lcore_id   Target lcore for rte_eal_remote_launch.
   * @return Void on success, or an error string.
   */
  [[nodiscard]] std::expected<void, std::string> LaunchWorker(std::size_t worker_id, unsigned lcore_id) noexcept;
  /**
   * @brief Run the hot path on the calling (main) lcore.
   * @return Final pipeline statistics.
   */
  [[nodiscard]] std::expected<PipelineStats, std::string> RunSingleWorker(const volatile std::sig_atomic_t& force_quit,
                                                                          std::uint32_t timer_period_sec) noexcept;
  /**
   * @brief Run workers on remote lcores, poll on main lcore.
   * @return Final pipeline statistics.
   */
  [[nodiscard]] std::expected<PipelineStats, std::string> RunMultiWorker(const volatile std::sig_atomic_t& force_quit,
                                                                         std::uint32_t timer_period_sec) noexcept;
  /**
   * @brief Fill a WorkerContext with pointers to shared state.
   * @param context    Worker context to populate.
   * @param force_quit Signal flag pointer for the worker.
   * @param worker_id  Zero-based worker index.
   */
  void PrepareWorkerContext(WorkerContext& context, const volatile std::sig_atomic_t& force_quit,
                            std::uint16_t worker_id) noexcept;
  /**
   * @brief Sum per-rule match counters across all workers.
   */
  void CollectWorkerRuleCounts() noexcept;
  /**
   * @brief Set force-quit flag and wait for all workers to finish.
   */
  void StopWorkers() noexcept;

  const dpdk::Environment& environment_;
  const RuleTable& rules_;
  AtomicCounters counters_;
  std::vector<std::uint64_t> rule_match_counts_;
  std::vector<WorkerContext> worker_contexts_;
  std::vector<L3RouteEntry> l3_routes_;
  std::vector<EthernetDestinationEntry> ethernet_destinations_;
  std::uint16_t burst_size_{};
  bool mac_updating_{true};
  bool l3_forwarding_{false};
  bool drop_unmatched_{false};
  volatile std::sig_atomic_t worker_force_quit_{0};
  bool workers_started_{false};
};

}  // namespace dpdk::spi
