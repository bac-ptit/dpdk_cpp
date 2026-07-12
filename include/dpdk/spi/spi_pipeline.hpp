#pragma once

#include <rte_ether.h>

#include <array>
#include <atomic>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <vector>

#include "dpdk/dpdk_environment.hpp"
#include "dpdk/config/dpdk_config.hpp"
#include "dpdk/dpi/dpi_rule_engine.hpp"
#include "dpdk/dpi/dpi_rule_table_manager.hpp"
#include "dpdk/dpi/hostname_cache.hpp"
#include "dpdk/spi/spi_flow_table.hpp"
#include "dpdk/spi/spi_rule_engine.hpp"
#include "dpdk/spi/spi_rule_table_manager.hpp"

struct rte_mbuf;
struct rte_ring;

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
  std::uint64_t dropped_by_rule{};
  std::uint64_t flow_cache_hits{};
  std::uint64_t dpi_cache_hits{};
  std::uint64_t dpi_cache_misses{};
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
  std::atomic<std::uint64_t> dropped_by_rule{};
  std::atomic<std::uint64_t> flow_cache_hits{};
  std::atomic<std::uint64_t> dpi_cache_hits{};
  std::atomic<std::uint64_t> dpi_cache_misses{};
};

/// Per-burst counters accumulated in a single worker iteration.
struct BurstCounters {
  std::uint64_t received{};
  std::uint64_t transmitted{};
  std::uint64_t parsed{};
  std::uint64_t matched{};
  std::uint64_t unknown{};
  std::uint64_t malformed{};
  std::uint64_t dropped{};
  std::uint64_t dropped_by_rule{};
  std::uint64_t flow_cache_hits{};
  std::uint64_t dpi_cache_hits{};
  std::uint64_t dpi_cache_misses{};
};

/// Flush pending BurstCounters into the shared AtomicCounters.
void FlushAtomicCounters(AtomicCounters& counters, const BurstCounters& pending) noexcept;

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
struct alignas(64) WorkerContext {
  const dpdk::Environment* environment{};
  const RuleTableManager* rule_manager{};
  /// Pointer to the DPI table manager (atomic-pointer swap for hot-reload).
  /// Workers call `dpi_rule_manager->Load()` once per packet to read the
  /// active DpiRuleTable pointer under a memory_order_acquire load.
  const dpi::DpiRuleTableManager* dpi_rule_manager{};
  FlowTable* flow_table{};
  const std::vector<L3RouteEntry>* l3_routes{};
  const std::vector<EthernetDestinationEntry>* ethernet_destinations{};
  AtomicCounters* counters{};
  PipelineStats stats{};
  /// Counters accumulated since the last atomic flush — drained every
  /// `kAtomicFlushBurstInterval` iterations to avoid hammering shared
  /// cache lines on every burst.
  BurstCounters pending_burst{};
  /// Iterations elapsed since the last atomic flush.
  std::uint32_t bursts_since_flush{};
  std::vector<std::uint64_t> rule_match_counts;
  rte_ring* dispatch_ring{};
  const volatile std::sig_atomic_t* force_quit{};
  std::uint16_t burst_size{};
  std::uint16_t worker_id{};
  bool mac_updating{true};
  bool l3_forwarding{false};
  bool drop_unmatched{false};

  /// Per-worker hostname → DPI result cache. Avoids re-running
  /// ExtractTlsSni/ExtractHttpHost + DpiRuleTable::Match for hostnames
  /// already classified. Sits on its own cache line so it doesn't share
  /// with the hot fields above.
  static constexpr std::size_t kWorkerCacheLineBytes{64};
  alignas(kWorkerCacheLineBytes) dpi::HostnameCache dpi_hostname_cache;
};

/**
 * @brief Aggregated runtime configuration for the SPI pipeline.
 *
 * Bundles the fields from AppConfig, SpiConfig, L3ForwardConfig, and
 * PcapInjectorConfig that the pipeline needs to start up. Decouples the
 * Pipeline constructor signature from the YAML config schema so adding
 * new config fields doesn't change the constructor.
 */
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
   * @param rules        Compiled SPI rule table owned by caller.
   * @param dpi_rules    Compiled DPI rule table (nullptr if DPI disabled).
   * @param config       Top-level config (Pipeline reads the fields it needs
   *                    from app, l3_forward, spi, and pcap_injector).
   */
  Pipeline(const dpdk::Environment& environment, RuleTable initial_rules, std::unique_ptr<dpi::DpiRuleTable> dpi_rules,
           const DpdkConfig& config);

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
                                                                          volatile std::sig_atomic_t& reload_flag,
                                                                          const std::string& config_path,
                                                                          std::uint32_t timer_period_sec) noexcept;

  /// Return const reference to per-rule match counters.
  [[nodiscard]] const std::vector<std::uint64_t>& GetRuleMatchCounts() const noexcept { return rule_match_counts_; }

  /// Access to the SPI rule table manager (used by MaybeReload to swap).
  [[nodiscard]] RuleTableManager& GetRuleTableManager() noexcept { return rule_manager_; }
  [[nodiscard]] const RuleTableManager& GetRuleTableManager() const noexcept { return rule_manager_; }

  /// Access to the DPI rule table manager (used by MaybeReload to swap).
  [[nodiscard]] dpi::DpiRuleTableManager& GetDpiRuleTableManager() noexcept { return dpi_rule_manager_; }
  [[nodiscard]] const dpi::DpiRuleTableManager& GetDpiRuleTableManager() const noexcept { return dpi_rule_manager_; }

 private:
  using WorkerEntryPoint = int (*)(void*);

  /**
   * @brief Launch all workers on remote lcores.
   * @param entry_point Worker loop function.
   * @return Void on success, or an error string.
   */
  [[nodiscard]] std::expected<void, std::string> StartWorkers(WorkerEntryPoint entry_point) noexcept;
  /**
   * @brief Launch a single worker on the specified lcore.
   * @param worker_id  Zero-based worker index.
   * @param lcore_id   Target lcore for rte_eal_remote_launch.
   * @param entry_point Worker loop function.
   * @return Void on success, or an error string.
   */
  [[nodiscard]] std::expected<void, std::string> LaunchWorker(std::size_t worker_id, unsigned lcore_id,
                                                              WorkerEntryPoint entry_point) noexcept;
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
   * @brief Run software flow-hash dispatch on main lcore plus remote workers.
   * @return Final pipeline statistics.
   */
  [[nodiscard]] std::expected<PipelineStats, std::string> RunFlowHashDispatch(
      const volatile std::sig_atomic_t& force_quit, std::uint32_t timer_period_sec) noexcept;
  /**
   * @brief Read packets from a pcap file and push them into the dispatcher
   *        rings instead of calling rte_eth_rx_burst. Used to integrate
   *        DPI verification into the production binary without depending
   *        on the net_pcap PMD (which truncates payloads in this lab).
   * @return Final pipeline statistics.
   */
  [[nodiscard]] std::expected<PipelineStats, std::string> RunPcapInjectDispatch(
      const volatile std::sig_atomic_t& force_quit, std::uint32_t timer_period_sec) noexcept;
  /**
   * @brief Allocate per-worker rte_rings for flow-hash dispatch mode.
   */
  [[nodiscard]] std::expected<void, std::string> CreateDispatchRings() noexcept;
  /**
   * @brief Free per-worker rte_rings.
   */
  void DestroyDispatchRings() noexcept;
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
  RuleTableManager rule_manager_;
  std::unique_ptr<dpi::DpiRuleTable> dpi_rules_;  ///< Pre-reload table (kept alive until manager Init).
  dpi::DpiRuleTableManager dpi_rule_manager_;    ///< Atomic-pointer DPI table for hot-reload.
  FlowTable flow_table_;
  AtomicCounters counters_;
  std::string config_path_;
  volatile std::sig_atomic_t* reload_flag_{nullptr};
  std::vector<std::uint64_t> rule_match_counts_;
  std::vector<WorkerContext> worker_contexts_;
  std::vector<rte_ring*> dispatch_rings_;
  std::vector<L3RouteEntry> l3_routes_;
  std::vector<EthernetDestinationEntry> ethernet_destinations_;
  std::string packet_distribution_;
  PcapInjectorConfig pcap_injector_;
  std::uint32_t dispatch_queue_size_{};
  std::uint16_t burst_size_{};
  bool mac_updating_{true};
  bool l3_forwarding_{false};
  bool drop_unmatched_{false};
  std::uint32_t flow_ttl_sec_{300};
  volatile std::sig_atomic_t worker_force_quit_{0};
  bool workers_started_{false};
};

}  // namespace dpdk::spi
