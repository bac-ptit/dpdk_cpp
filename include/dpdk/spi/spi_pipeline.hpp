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
  /// Packets that would have triggered DPI but were short-circuited by
  /// SPI gating (l7_required: false on the matched group, response-direction
  /// skip, or non-TCP / non-{80,443}). The delta between this and
  /// `parsed` shows how much DPI work the SPI rules are saving.
  std::uint64_t dpi_skipped_by_spi{};
  /// Packets that hit the SPI→DPI static-link fast path: SPI match
  /// already determined the DPI group via `dpi_filter_group` in the config,
  /// so ExtractHostname + MatchDpi were skipped. Flow cache takes the SPI
  /// action directly. Operators use this counter to verify the link is
  /// firing on real traffic.
  std::uint64_t dpi_skipped_by_link{};
  /// Flow-table `rte_hash_add_key` returned `-ENOSPC` (table full).
  /// Incremented for every Insert failure; visible via the periodic stats print.
  std::uint64_t flow_table_full{};
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
  std::atomic<std::uint64_t> dpi_skipped_by_spi{};
  std::atomic<std::uint64_t> dpi_skipped_by_link{};
  std::atomic<std::uint64_t> flow_table_full{};
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
  std::uint64_t dpi_skipped_by_spi{};
  std::uint64_t dpi_skipped_by_link{};
  std::uint64_t flow_table_full{};
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
  /// Force-quit flag polled by the worker loop. `std::atomic<int>` so
  /// the cross-lcore access (main lcore writes, worker reads) is
  /// well-defined per the C++ memory model. In multi-worker mode this
  /// points to `Pipeline::worker_force_quit_`; in single-worker mode
  /// it points to the global `dpdk::ForceQuitFlag()` set by the
  /// signal handler.
  const std::atomic<int>* force_quit{};
  std::uint16_t burst_size{};
  std::uint16_t worker_id{};
  bool mac_updating{true};
  bool l3_forwarding{false};
  bool drop_unmatched{false};
  /// When the flow cache is full, drop the packet (true) or forward it
  /// without caching (false). Mirrors `SpiConfig::flow_overflow_action`.
  bool flow_overflow_drop{true};
  /// Set to `true` by `MaybeReload` for the duration of an in-place rule
  /// rebuild; workers busy-wait while this is set. Combined with the
  /// `rte_eal_mp_wait_lcore` symmetric wait, this guarantees no worker
  /// is in the middle of `RuleTable::Match` when `RebuildInPlace` runs.
  const std::atomic<bool>* reload_barrier{nullptr};

  /// Per-worker hostname → DPI result cache. Avoids re-running
  /// ExtractTlsSni/ExtractHttpHost + DpiRuleTable::Match for hostnames
  /// already classified. Sits on its own cache line so it doesn't share
  /// with the hot fields above.
  static constexpr std::size_t kWorkerCacheLineBytes{64};
  alignas(kWorkerCacheLineBytes) dpi::HostnameCache dpi_hostname_cache;
  /// Cached `rte_rdtsc()` sampled once per burst (ProcessPortBurst,
  /// ProcessDispatchedWorkerIteration). Passed through to Lookup() so the
  /// per-packet hot path avoids one `rdtsc` (~24 cycles on Skylake-class)
  /// per cache hit. Refreshed at the top of every burst; lies on the
  /// same cache line as `dpi_hostname_cache` (aligned 64 B) to keep it
  /// out of the hot-fields cacheline.
  std::uint64_t current_burst_tsc{};
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
  [[nodiscard]] std::expected<PipelineStats, std::string> RunUntilStopped(const std::atomic<int>& force_quit,
                                                                          std::atomic<int>& reload_flag,
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
  [[nodiscard]] std::expected<PipelineStats, std::string> RunSingleWorker(const std::atomic<int>& force_quit,
                                                                          std::uint32_t timer_period_sec) noexcept;
  /**
   * @brief Run workers on remote lcores, poll on main lcore.
   * @return Final pipeline statistics.
   */
  [[nodiscard]] std::expected<PipelineStats, std::string> RunMultiWorker(const std::atomic<int>& force_quit,
                                                                         std::uint32_t timer_period_sec) noexcept;
  /**
   * @brief Run software flow-hash dispatch on main lcore plus remote workers.
   * @return Final pipeline statistics.
   */
  [[nodiscard]] std::expected<PipelineStats, std::string> RunFlowHashDispatch(
      const std::atomic<int>& force_quit, std::uint32_t timer_period_sec) noexcept;
  /**
   * @brief Read packets from a pcap file and push them into the dispatcher
   *        rings instead of calling rte_eth_rx_burst. Used to integrate
   *        DPI verification into the production binary without depending
   *        on the net_pcap PMD (which truncates payloads in this lab).
   * @return Final pipeline statistics.
   */
  [[nodiscard]] std::expected<PipelineStats, std::string> RunPcapInjectDispatch(
      const std::atomic<int>& force_quit, std::uint32_t timer_period_sec) noexcept;
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
  void PrepareWorkerContext(WorkerContext& context, const std::atomic<int>& force_quit,
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
  std::unique_ptr<FlowTable> flow_table_;
  AtomicCounters counters_;
  std::string config_path_;
  std::atomic<int>* reload_flag_{nullptr};
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
  /// Hard ceiling on concurrent flow cache entries. Sized once at startup;
  /// the rte_hash table never grows past this.
  std::uint32_t max_concurrent_flows_{1'000'000};
  /// Policy when flow table is full: "drop" (default, observable via
  /// `flow_table_full`) or "reclassify" (forward without caching).
  bool flow_overflow_drop_{true};
  /// Set by `MaybeReload` for the duration of an in-place rule rebuild;
  /// workers busy-wait while this is true. Reset by the main lcore once
  /// the rebuild completes.
  std::atomic<bool> reload_barrier_{false};
  /// Per-Pipeline worker quit flag. Main lcore sets it to 1 in
  /// `StopWorkers`; workers poll it every burst. `std::atomic<int>`
  /// rather than `volatile sig_atomic_t` so the cross-lcore access is
  /// well-defined per the C++ memory model (the POSIX `volatile
  /// sig_atomic_t` idiom is correct for signal-handler→main only,
  /// not main→worker). The signal-handler-driven global
  /// `force_quit` in `app_signal.cpp` keeps the POSIX idiom because
  /// it IS only touched by the signal handler + main lcore.
  std::atomic<int> worker_force_quit_{0};
  bool workers_started_{false};
};

}  // namespace dpdk::spi
