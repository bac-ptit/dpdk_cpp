#include "spi_pipeline.hpp"

#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <format>
#include <print>
#include <span>
#include <vector>

#include "spi_packet_parser.hpp"

namespace dpdk::spi {
namespace {

constexpr std::uint16_t kMaxBurstCapacity{64};
constexpr std::uint16_t kMinBurstCapacity{1};
constexpr std::size_t kLocalAdminMacByteIndex{0};
constexpr std::size_t kPortMacByteIndex{5};
constexpr std::uint8_t kLocalAdminMacPrefix{0x02};

/// Per-burst counters accumulated in a single worker iteration.
struct BurstCounters {
  std::uint64_t received{};
  std::uint64_t transmitted{};
  std::uint64_t parsed{};
  std::uint64_t matched{};
  std::uint64_t unknown{};
  std::uint64_t malformed{};
  std::uint64_t dropped{};
};

/**
 * @brief Determine the transmit port paired with the receive port.
 *
 * Adjacent ports in the active list are paired as 0<->1, 2<->3, etc.
 * If unpaired, the port transmits back to itself.
 * @param active_ports  List of active port IDs.
 * @param receive_port  The port where packets were received.
 * @return The port ID to transmit on.
 */
[[nodiscard]] std::uint16_t GetTransmitPort(const std::vector<std::uint16_t>& active_ports,
                                            std::uint16_t receive_port) noexcept {
  if (active_ports.size() <= 1) {
    return receive_port;
  }

  const auto port_it{std::ranges::find(active_ports, receive_port)};
  if (port_it == active_ports.end()) {
    return receive_port;
  }

  const auto port_index{static_cast<std::size_t>(std::distance(active_ports.begin(), port_it))};
  const bool is_even_index{(port_index & std::size_t{1}) == std::size_t{0}};
  if (is_even_index && port_index + std::size_t{1} < active_ports.size()) {
    return active_ports[port_index + std::size_t{1}];
  }
  if (!is_even_index) {
    return active_ports[port_index - std::size_t{1}];
  }
  return receive_port;
}

/**
 * @brief Rewrite Ethernet source/destination MACs for L2 forwarding.
 *
 * The destination MAC uses a locally-administered prefix with the transmit
 * port ID encoded in the last byte. The source MAC is the transmit port's
 * real address.
 * @param packet         The mbuf whose Ethernet header is modified.
 * @param src_addr       Source MAC (transmit port's real address).
 * @param transmit_port  Port ID embedded in the destination MAC.
 */
void UpdateL2ForwardMacs(const rte_mbuf& packet, const rte_ether_addr& src_addr,
                          std::uint16_t transmit_port) noexcept {
  auto* eth_hdr{rte_pktmbuf_mtod(&packet, rte_ether_hdr*)};
  rte_ether_addr dst_addr{};
  dst_addr.addr_bytes[kLocalAdminMacByteIndex] = kLocalAdminMacPrefix;
  dst_addr.addr_bytes[kPortMacByteIndex] = static_cast<std::uint8_t>(transmit_port);
  rte_ether_addr_copy(&dst_addr, &eth_hdr->dst_addr);
  rte_ether_addr_copy(&src_addr, &eth_hdr->src_addr);
}

/// Relaxed load from an atomic counter.
[[nodiscard]] std::uint64_t LoadCounter(const std::atomic<std::uint64_t>& counter) noexcept {
  return counter.load(std::memory_order_relaxed);
}

/**
 * @brief Collect a snapshot of all pipeline counters.
 * @param counters  Shared atomic counters.
 * @return PipelineStats with current counter values.
 */
[[nodiscard]] PipelineStats CollectStats(const AtomicCounters& counters) noexcept {
  return PipelineStats{
      .received = LoadCounter(counters.received),
      .transmitted = LoadCounter(counters.transmitted),
      .parsed = LoadCounter(counters.parsed),
      .matched = LoadCounter(counters.matched),
      .unknown = LoadCounter(counters.unknown),
      .malformed = LoadCounter(counters.malformed),
      .dropped = LoadCounter(counters.dropped),
  };
}

/**
 * @brief Add per-burst counters to the global atomic counters.
 * @param counters  Shared atomic counters.
 * @param burst     Per-burst counters to fold in.
 */
void AddBurstCounters(AtomicCounters& counters, const BurstCounters& burst) noexcept {
  counters.received.fetch_add(burst.received, std::memory_order_relaxed);
  counters.transmitted.fetch_add(burst.transmitted, std::memory_order_relaxed);
  counters.parsed.fetch_add(burst.parsed, std::memory_order_relaxed);
  counters.matched.fetch_add(burst.matched, std::memory_order_relaxed);
  counters.unknown.fetch_add(burst.unknown, std::memory_order_relaxed);
  counters.malformed.fetch_add(burst.malformed, std::memory_order_relaxed);
  counters.dropped.fetch_add(burst.dropped, std::memory_order_relaxed);
}

/// Print the current counter state to stdout.
void PrintStats(const AtomicCounters& counters) noexcept {
  std::println(
      "SPI stats: received={} transmitted={} parsed={} matched={} unknown={} "
      "malformed={} dropped={}",
      LoadCounter(counters.received), LoadCounter(counters.transmitted), LoadCounter(counters.parsed),
      LoadCounter(counters.matched), LoadCounter(counters.unknown), LoadCounter(counters.malformed),
      LoadCounter(counters.dropped));
}

/**
 * @brief Conditionally print stats if the timer period has elapsed.
 * @param counters          Shared atomic counters.
 * @param timer_period_sec  Print interval in seconds (0=disabled).
 * @param stats_period_tsc  Ticks between prints.
 * @param previous_tsc      Previous TSC value (updated in place).
 * @param timer_tsc         Accumulated ticks (updated in place).
 */
void MaybePrintStats(const AtomicCounters& counters, std::uint32_t timer_period_sec, std::uint64_t stats_period_tsc,
                     std::uint64_t& previous_tsc, std::uint64_t& timer_tsc) noexcept {
  if (timer_period_sec == 0) {
    return;
  }

  const auto current_tsc{rte_rdtsc()};
  const auto diff_tsc{current_tsc - previous_tsc};
  previous_tsc = current_tsc;
  timer_tsc += diff_tsc;

  if (timer_tsc >= stats_period_tsc) {
    PrintStats(counters);
    timer_tsc = 0;
  }
}

/// Print forward mapping from receive port to transmit port.
void PrintForwardMap(const std::vector<std::uint16_t>& active_ports) noexcept {
  for (const auto port_id : active_ports) {
    std::println("Forward map: receive port {} -> transmit port {}", port_id, GetTransmitPort(active_ports, port_id));
  }
}

/// Print queue assignment per worker.
void PrintQueueMap(std::size_t worker_count) noexcept {
  for (std::size_t worker_id{0}; worker_id < worker_count; ++worker_id) {
    std::println("Queue map: worker {} -> receive queue {} / transmit queue {}", worker_id, worker_id, worker_id);
  }
}

/**
 * @brief Collect available worker lcores up to the requested count.
 * @param worker_count  Number of lcores needed.
 * @return Vector of lcore IDs.
 */
[[nodiscard]] std::vector<unsigned> GetWorkerLcores(std::size_t worker_count) noexcept {
  std::vector<unsigned> worker_lcores;
  worker_lcores.reserve(worker_count);
  unsigned lcore_id{};
  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    if (worker_lcores.size() >= worker_count) {
      break;
    }
    worker_lcores.push_back(lcore_id);
  }
  return worker_lcores;
}

/// Print the list of assigned worker lcore IDs.
void PrintWorkerLcores(const std::vector<unsigned>& worker_lcores) noexcept {
  std::println("Worker lcores: {}", worker_lcores.size());
  for (const auto lcore_id : worker_lcores) {
    std::println("  worker lcore {}", lcore_id);
  }
}

/**
 * @brief Parse and classify a single packet, updating counters.
 * @param context  Worker context with rule table and counters.
 * @param counters  Per-burst counters (updated in place).
 * @param packet    The mbuf to classify.
 */
void ClassifyPacket(WorkerContext& context, BurstCounters& counters, const rte_mbuf& packet) noexcept {
  if (const auto metadata{ParsePacket(packet)}) {
    ++counters.parsed;
    if (const auto match{context.rules->Match(*metadata)}) {
      ++counters.matched;
      ++context.rule_match_counts[match->rule_index];
    } else {
      ++counters.unknown;
    }
  } else {
    ++counters.malformed;
  }
}

/// Prefetch each packet in the burst into the CPU cache.
void PrefetchPackets(std::span<rte_mbuf*> packets) noexcept {
  for (auto* packet : packets) {
    rte_prefetch0(rte_pktmbuf_mtod(packet, void*));
  }
}

/**
 * @brief Classify, rewrite MAC, and enqueue for TX.
 *
 * If the transmit port is out of range, the packet is dropped.
 * @param context           Worker context.
 * @param active_ports      List of active ports.
 * @param counters          Per-burst counters.
 * @param packet            The mbuf to forward.
 * @param receive_port      Port where packet was received.
 * @param transmit_buffers  Per-port TX buffers.
 * @param transmit_counts   Per-port TX counts.
 */
void ForwardPacket(WorkerContext& context, const std::vector<std::uint16_t>& active_ports, BurstCounters& counters,
                   rte_mbuf* packet, std::uint16_t receive_port,
                   std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
                   std::vector<std::uint16_t>& transmit_counts) noexcept {
  const auto transmit_port{GetTransmitPort(active_ports, receive_port)};
  const auto* transmit_mac{context.environment->GetPortMacAddress(transmit_port)};
  if (transmit_mac == nullptr || transmit_port >= transmit_buffers.size()) {
    ++counters.dropped;
    rte_pktmbuf_free(packet);
    return;
  }

  ClassifyPacket(context, counters, *packet);
  UpdateL2ForwardMacs(*packet, *transmit_mac, transmit_port);
  auto* tx_buffer{transmit_buffers[transmit_port].data()};
  tx_buffer[transmit_counts[transmit_port]++] = packet;
}

/**
 * @brief Flush all non-empty TX buffers via rte_eth_tx_burst.
 *
 * Freed unsent packets if TX burst could not send all.
 * @param context           Worker context.
 * @param transmit_buffers  Per-port TX buffers.
 * @param transmit_counts   Per-port TX counts (reset to 0).
 * @param counters          Per-burst counters.
 */
void FlushTransmitBuffers(WorkerContext const& context,
                          std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
                          std::vector<std::uint16_t>& transmit_counts, BurstCounters& counters) noexcept {
  for (const auto port_id : context.environment->GetActivePorts()) {
    const auto count{transmit_counts[port_id]};
    if (count == 0) {
      continue;
    }

    const auto sent{rte_eth_tx_burst(port_id, context.worker_id, transmit_buffers[port_id].data(), count)};
    counters.transmitted += sent;
    if (sent < count) {
      counters.dropped += static_cast<std::uint64_t>(count - sent);
    }
    for (auto i{sent}; i < count; ++i) {
      rte_pktmbuf_free(transmit_buffers[port_id][i]);
    }
    transmit_counts[port_id] = 0;
  }
}

/**
 * @brief Receive a burst on a port, prefetch, and forward each packet.
 * @param context           Worker context.
 * @param active_ports      List of active ports.
 * @param port_id           Port to receive from.
 * @param packets           Local packet array.
 * @param transmit_buffers  Per-port TX buffers.
 * @param transmit_counts   Per-port TX counts.
 * @param counters          Per-burst counters.
 */
void ProcessPortBurst(WorkerContext& context, const std::vector<std::uint16_t>& active_ports, std::uint16_t port_id,
                      std::array<rte_mbuf*, kMaxBurstCapacity>& packets,
                      std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
                      std::vector<std::uint16_t>& transmit_counts, BurstCounters& counters) noexcept {
  const auto received{rte_eth_rx_burst(port_id, context.worker_id, packets.data(), context.burst_size)};
  counters.received += received;

  const std::span received_packets{packets.data(), received};
  PrefetchPackets(received_packets);

  for (auto* packet : received_packets) {
    ForwardPacket(context, active_ports, counters, packet, port_id, transmit_buffers, transmit_counts);
  }
}

/**
 * @brief Run one full iteration of the worker loop.
 *
 * Receives on all ports, forwards to paired TX ports, flushes TX buffers,
 * and folds counters into the shared AtomicCounters.
 * @param context           Worker context.
 * @param packets           Local packet array.
 * @param transmit_buffers  Per-port TX buffers.
 * @param transmit_counts   Per-port TX counts.
 */
void ProcessWorkerIteration(WorkerContext& context, std::array<rte_mbuf*, kMaxBurstCapacity>& packets,
                            std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
                            std::vector<std::uint16_t>& transmit_counts) noexcept {
  const auto& active_ports{context.environment->GetActivePorts()};
  BurstCounters burst_counters;
  std::ranges::fill(transmit_counts, 0);

  for (const auto port_id : active_ports) {
    ProcessPortBurst(context, active_ports, port_id, packets, transmit_buffers, transmit_counts, burst_counters);
  }

  FlushTransmitBuffers(context, transmit_buffers, transmit_counts, burst_counters);
  AddBurstCounters(*context.counters, burst_counters);
}

/**
 * @brief Entry point for rte_eal_remote_launch workers.
 *
 * @param arg  Pointer to a WorkerContext.
 * @return 0 on exit.
 */
int WorkerLoop(void* arg) noexcept {
  auto* context{static_cast<WorkerContext*>(arg)};
  std::array<rte_mbuf*, kMaxBurstCapacity> packets{};
  std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>> transmit_buffers(context->environment->GetPortCount());
  std::vector<std::uint16_t> transmit_counts(context->environment->GetPortCount());

  while (*context->force_quit == 0) {
    ProcessWorkerIteration(*context, packets, transmit_buffers, transmit_counts);
  }
  return 0;
}

}  // namespace

Pipeline::Pipeline(const dpdk::Environment& environment, const RuleTable& rules, std::uint16_t burst_size,
                   std::uint16_t worker_count)
    : environment_{environment},
      rules_{rules},
      rule_match_counts_(rules.Size()),
      worker_contexts_(worker_count),
      burst_size_{std::clamp(burst_size, kMinBurstCapacity, kMaxBurstCapacity)} {}

Pipeline::~Pipeline() { StopWorkers(); }

std::expected<void, std::string> Pipeline::StartWorkers() noexcept {
  if (workers_started_) {
    return {};
  }

  const auto worker_lcores{GetWorkerLcores(worker_contexts_.size())};
  PrintWorkerLcores(worker_lcores);
  if (worker_lcores.size() != worker_contexts_.size()) {
    return std::unexpected(
        std::format("Need {} worker lcores, found {}", worker_contexts_.size(), worker_lcores.size()));
  }

  worker_force_quit_ = 0;
  for (std::size_t worker_id{0}; worker_id < worker_contexts_.size(); ++worker_id) {
    if (const auto launched{LaunchWorker(worker_id, worker_lcores[worker_id])}; !launched) {
      return std::unexpected(launched.error());
    }
  }

  workers_started_ = true;
  return {};
}

std::expected<void, std::string> Pipeline::LaunchWorker(std::size_t worker_id, unsigned lcore_id) noexcept {
  auto& context{worker_contexts_[worker_id]};
  PrepareWorkerContext(context, worker_force_quit_, static_cast<std::uint16_t>(worker_id));

  const int ret{rte_eal_remote_launch(WorkerLoop, &context, lcore_id)};
  if (ret == 0) {
    return {};
  }

  worker_force_quit_ = 1;
  rte_eal_mp_wait_lcore();
  return std::unexpected(
      std::format("rte_eal_remote_launch worker {} on lcore {} failed (ret={})", worker_id, lcore_id, ret));
}

void Pipeline::StopWorkers() noexcept {
  if (!workers_started_) {
    return;
  }

  worker_force_quit_ = 1;
  rte_eal_mp_wait_lcore();
  workers_started_ = false;
}

void Pipeline::PrepareWorkerContext(WorkerContext& context, const volatile std::sig_atomic_t& force_quit,
                                    std::uint16_t worker_id) noexcept {
  context.environment = &environment_;
  context.rules = &rules_;
  context.counters = &counters_;
  context.rule_match_counts.assign(rules_.Size(), 0);
  context.force_quit = &force_quit;
  context.burst_size = burst_size_;
  context.worker_id = worker_id;
}

std::expected<PipelineStats, std::string> Pipeline::RunSingleWorker(const volatile std::sig_atomic_t& force_quit,
                                                                     std::uint32_t timer_period_sec) noexcept {
  const auto& active_ports{environment_.GetActivePorts()};
  auto& context{worker_contexts_[0]};
  PrepareWorkerContext(context, force_quit, 0);

  std::println("Entering SPI packet-processing loop");
  std::println("Single-worker direct mode on main lcore");
  PrintForwardMap(active_ports);
  PrintQueueMap(1);

  std::array<rte_mbuf*, kMaxBurstCapacity> packets{};
  std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>> transmit_buffers(environment_.GetPortCount());
  std::vector<std::uint16_t> transmit_counts(environment_.GetPortCount());
  std::uint64_t previous_tsc{rte_rdtsc()};
  std::uint64_t timer_tsc{};
  const auto stats_period_tsc{rte_get_tsc_hz() * timer_period_sec};

  while (force_quit == 0) {
    ProcessWorkerIteration(context, packets, transmit_buffers, transmit_counts);
    MaybePrintStats(counters_, timer_period_sec, stats_period_tsc, previous_tsc, timer_tsc);
  }

  rule_match_counts_ = context.rule_match_counts;
  return CollectStats(counters_);
}

std::expected<PipelineStats, std::string> Pipeline::RunMultiWorker(const volatile std::sig_atomic_t& force_quit,
                                                                    std::uint32_t timer_period_sec) noexcept {
  if (const auto started{StartWorkers()}; !started) {
    return std::unexpected(started.error());
  }

  const auto& active_ports{environment_.GetActivePorts()};
  std::println("Entering SPI packet-processing loop");
  PrintForwardMap(active_ports);
  PrintQueueMap(worker_contexts_.size());

  std::uint64_t previous_tsc{rte_rdtsc()};
  std::uint64_t timer_tsc{};
  const auto stats_period_tsc{rte_get_tsc_hz() * timer_period_sec};
  while (force_quit == 0) {
    MaybePrintStats(counters_, timer_period_sec, stats_period_tsc, previous_tsc, timer_tsc);
    rte_pause();
  }

  StopWorkers();
  CollectWorkerRuleCounts();
  return CollectStats(counters_);
}

void Pipeline::CollectWorkerRuleCounts() noexcept {
  for (std::size_t rule_index{0}; rule_index < rule_match_counts_.size(); ++rule_index) {
    std::uint64_t count{};
    for (const auto& context : worker_contexts_) {
      count += context.rule_match_counts[rule_index];
    }
    rule_match_counts_[rule_index] = count;
  }
}

std::expected<PipelineStats, std::string> Pipeline::RunUntilStopped(const volatile std::sig_atomic_t& force_quit,
                                                                     std::uint32_t timer_period_sec) noexcept {
  if (worker_contexts_.size() == 1) {
    return RunSingleWorker(force_quit, timer_period_sec);
  }
  return RunMultiWorker(force_quit, timer_period_sec);
}

}  // namespace dpdk::spi
