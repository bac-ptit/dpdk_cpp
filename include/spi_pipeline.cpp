#include "spi_pipeline.hpp"

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_errno.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <format>
#include <print>
#include <ranges>
#include <span>

#include "spi_packet_parser.hpp"

namespace {

constexpr std::uint16_t kMaxBurstSize{64};
constexpr std::uint16_t kMinBurstSize{1};

struct BurstCounters {
  std::uint64_t received{};
  std::uint64_t transmitted{};
  std::uint64_t parsed{};
  std::uint64_t matched{};
  std::uint64_t unknown{};
  std::uint64_t malformed{};
  std::uint64_t dropped{};
};

[[nodiscard]] std::uint16_t GetForwardPort(
    const std::vector<std::uint16_t>& active_ports,
    std::uint16_t rx_port) noexcept {
  if (active_ports.size() <= 1) {
    return rx_port;
  }

  const auto port_it{std::ranges::find(active_ports, rx_port)};
  if (port_it == active_ports.end()) {
    return rx_port;
  }

  const auto port_index{
      static_cast<std::size_t>(std::distance(active_ports.begin(), port_it))};
  if ((port_index % 2U) == 0U && port_index + 1U < active_ports.size()) {
    return active_ports[port_index + 1U];
  }
  if ((port_index % 2U) == 1U) {
    return active_ports[port_index - 1U];
  }
  return rx_port;
}

void UpdateL2ForwardMacs(rte_mbuf& packet,
                         const rte_ether_addr& src_addr,
                         std::uint16_t tx_port) noexcept {
  auto* eth_hdr{rte_pktmbuf_mtod(&packet, rte_ether_hdr*)};
  rte_ether_addr dst_addr{};
  dst_addr.addr_bytes[0] = 0x02;
  dst_addr.addr_bytes[5] = static_cast<std::uint8_t>(tx_port);
  rte_ether_addr_copy(&dst_addr, &eth_hdr->dst_addr);
  rte_ether_addr_copy(&src_addr, &eth_hdr->src_addr);
}

[[nodiscard]] std::uint64_t LoadCounter(
    const std::atomic<std::uint64_t>& counter) noexcept {
  return counter.load(std::memory_order_relaxed);
}

void AddBurstCounters(spi::AtomicCounters& counters,
                      const BurstCounters& burst) noexcept {
  counters.received.fetch_add(burst.received, std::memory_order_relaxed);
  counters.transmitted.fetch_add(burst.transmitted, std::memory_order_relaxed);
  counters.parsed.fetch_add(burst.parsed, std::memory_order_relaxed);
  counters.matched.fetch_add(burst.matched, std::memory_order_relaxed);
  counters.unknown.fetch_add(burst.unknown, std::memory_order_relaxed);
  counters.malformed.fetch_add(burst.malformed, std::memory_order_relaxed);
  counters.dropped.fetch_add(burst.dropped, std::memory_order_relaxed);
}

void PrintStats(const spi::AtomicCounters& counters) noexcept {
  std::println(
      "SPI stats: received={} transmitted={} parsed={} matched={} unknown={} "
      "malformed={} dropped={}",
      LoadCounter(counters.received), LoadCounter(counters.transmitted),
      LoadCounter(counters.parsed), LoadCounter(counters.matched),
      LoadCounter(counters.unknown), LoadCounter(counters.malformed),
      LoadCounter(counters.dropped));
}

void ClassifyPacket(spi::WorkerContext& context, BurstCounters& counters,
                    const rte_mbuf& packet) noexcept {
  if (const auto metadata{spi::ParsePacket(packet)}) {
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

void FlushTxBuffers(spi::WorkerContext& context,
                    std::vector<std::array<rte_mbuf*, kMaxBurstSize>>& tx_bufs,
                    std::vector<std::uint16_t>& tx_counts,
                    BurstCounters& counters) noexcept {
  for (const auto port_id : context.environment->GetActivePorts()) {
    const auto count{tx_counts[port_id]};
    if (count == 0) {
      continue;
    }

    const auto sent{rte_eth_tx_burst(port_id, context.worker_id,
                                     tx_bufs[port_id].data(), count)};
    counters.transmitted += sent;
    if (sent < count) {
      counters.dropped += static_cast<std::uint64_t>(count - sent);
    }
    for (auto i{sent}; i < count; ++i) {
      rte_pktmbuf_free(tx_bufs[port_id][i]);
    }
    tx_counts[port_id] = 0;
  }
}

void ProcessWorkerIteration(
    spi::WorkerContext& context, std::array<rte_mbuf*, kMaxBurstSize>& packets,
    std::vector<std::array<rte_mbuf*, kMaxBurstSize>>& tx_bufs,
    std::vector<std::uint16_t>& tx_counts) noexcept {
  const auto& active_ports{context.environment->GetActivePorts()};
  BurstCounters burst_counters;
  std::ranges::fill(tx_counts, 0);

  for (const auto port_id : active_ports) {
    const auto received{rte_eth_rx_burst(
        port_id, context.worker_id, packets.data(), context.burst_size)};
    burst_counters.received += received;

    for (std::uint16_t i{0}; i < received; ++i) {
      rte_prefetch0(rte_pktmbuf_mtod(packets[i], void*));
    }

    for (std::uint16_t i{0}; i < received; ++i) {
      auto* packet{packets[i]};
      const auto tx_port{GetForwardPort(active_ports, port_id)};
      const auto* tx_mac{context.environment->GetPortMacAddress(tx_port)};
      if (tx_mac == nullptr || tx_port >= tx_bufs.size()) {
        ++burst_counters.dropped;
        rte_pktmbuf_free(packet);
        continue;
      }

      ClassifyPacket(context, burst_counters, *packet);
      UpdateL2ForwardMacs(*packet, *tx_mac, tx_port);
      tx_bufs[tx_port][tx_counts[tx_port]++] = packet;
    }
  }

  FlushTxBuffers(context, tx_bufs, tx_counts, burst_counters);
  AddBurstCounters(*context.counters, burst_counters);
}

int WorkerLoop(void* arg) noexcept {
  auto* context{static_cast<spi::WorkerContext*>(arg)};
  std::array<rte_mbuf*, kMaxBurstSize> packets;
  std::vector<std::array<rte_mbuf*, kMaxBurstSize>> tx_bufs(
      context->environment->GetPortCount());
  std::vector<std::uint16_t> tx_counts(context->environment->GetPortCount());

  while (*context->force_quit == 0) {
    ProcessWorkerIteration(*context, packets, tx_bufs, tx_counts);
  }
  return 0;
}

}  // namespace

namespace spi {

Pipeline::Pipeline(const dpdk::Environment& environment, const RuleTable& rules,
                   std::uint16_t burst_size, std::uint16_t worker_count)
    : environment_{environment},
      rules_{rules},
      rule_match_counts_(rules.Size()),
      worker_contexts_(worker_count),
      burst_size_{std::clamp(burst_size, kMinBurstSize, kMaxBurstSize)} {}

Pipeline::~Pipeline() {
  StopWorkers();
}

std::expected<void, std::string> Pipeline::StartWorkers() noexcept {
  if (workers_started_) {
    return {};
  }

  std::vector<unsigned> worker_lcores;
  worker_lcores.reserve(worker_contexts_.size());
  unsigned lcore_id{};
  RTE_LCORE_FOREACH_WORKER(lcore_id) {
    if (worker_lcores.size() >= worker_contexts_.size()) {
      break;
    }
    worker_lcores.push_back(lcore_id);
  }

  std::println("Worker lcores: {}", worker_lcores.size());
  for (const auto lc : worker_lcores) {
    std::println("  worker lcore {}", lc);
  }
  if (worker_lcores.size() != worker_contexts_.size()) {
    return std::unexpected(std::format(
        "Need {} worker lcores, found {}", worker_contexts_.size(),
        worker_lcores.size()));
  }

  worker_force_quit_ = 0;
  for (std::size_t worker_id{0}; worker_id < worker_contexts_.size();
       ++worker_id) {
    auto& context{worker_contexts_[worker_id]};
    context.environment = &environment_;
    context.rules = &rules_;
    context.counters = &counters_;
    context.rule_match_counts.assign(rules_.Size(), 0);
    context.force_quit = &worker_force_quit_;
    context.burst_size = burst_size_;
    context.worker_id = static_cast<std::uint16_t>(worker_id);

    const int ret{rte_eal_remote_launch(WorkerLoop, &context,
                                        worker_lcores[worker_id])};
    if (ret != 0) {
      worker_force_quit_ = 1;
      rte_eal_mp_wait_lcore();
      return std::unexpected(std::format(
          "rte_eal_remote_launch worker {} on lcore {} failed (ret={})",
          worker_id, worker_lcores[worker_id], ret));
    }
  }

  workers_started_ = true;
  return {};
}

void Pipeline::StopWorkers() noexcept {
  if (!workers_started_) {
    return;
  }

  worker_force_quit_ = 1;
  rte_eal_mp_wait_lcore();
  workers_started_ = false;
}

std::expected<PipelineStats, std::string> Pipeline::RunUntilStopped(
    const volatile std::sig_atomic_t& force_quit,
    std::uint32_t timer_period_sec) noexcept {
  const auto& active_ports{environment_.GetActivePorts()};
  if (worker_contexts_.size() == 1) {
    auto& context{worker_contexts_[0]};
    context.environment = &environment_;
    context.rules = &rules_;
    context.counters = &counters_;
    context.rule_match_counts.assign(rules_.Size(), 0);
    context.force_quit = &force_quit;
    context.burst_size = burst_size_;
    context.worker_id = 0;

    std::println("Entering SPI packet-processing loop");
    std::println("Single-worker direct mode on main lcore");
    for (const auto port_id : active_ports) {
      std::println("Forward map: RX port {} -> TX port {}", port_id,
                   GetForwardPort(active_ports, port_id));
    }
    std::println("Queue map: worker 0 -> RX queue 0 / TX queue 0");

    std::array<rte_mbuf*, kMaxBurstSize> packets;
    std::vector<std::array<rte_mbuf*, kMaxBurstSize>> tx_bufs(
        environment_.GetPortCount());
    std::vector<std::uint16_t> tx_counts(environment_.GetPortCount());
    std::uint64_t previous_tsc{rte_rdtsc()};
    std::uint64_t timer_tsc{};
    const auto stats_period_tsc{rte_get_tsc_hz() * timer_period_sec};

    while (force_quit == 0) {
      ProcessWorkerIteration(context, packets, tx_bufs, tx_counts);

      if (timer_period_sec == 0) {
        continue;
      }

      const auto current_tsc{rte_rdtsc()};
      const auto diff_tsc{current_tsc - previous_tsc};
      previous_tsc = current_tsc;
      timer_tsc += diff_tsc;

      if (timer_tsc >= stats_period_tsc) {
        PrintStats(counters_);
        timer_tsc = 0;
      }
    }

    rule_match_counts_ = context.rule_match_counts;
    return PipelineStats{
        .received = LoadCounter(counters_.received),
        .transmitted = LoadCounter(counters_.transmitted),
        .parsed = LoadCounter(counters_.parsed),
        .matched = LoadCounter(counters_.matched),
        .unknown = LoadCounter(counters_.unknown),
        .malformed = LoadCounter(counters_.malformed),
        .dropped = LoadCounter(counters_.dropped),
    };
  }

  if (const auto started{StartWorkers()}; !started) {
    return std::unexpected(started.error());
  }

  std::println("Entering SPI packet-processing loop");
  for (const auto port_id : active_ports) {
    std::println("Forward map: RX port {} -> TX port {}", port_id,
                 GetForwardPort(active_ports, port_id));
  }
  for (std::size_t worker_id{0}; worker_id < worker_contexts_.size();
       ++worker_id) {
    std::println("Queue map: worker {} -> RX queue {} / TX queue {}",
                 worker_id, worker_id, worker_id);
  }

  std::uint64_t previous_tsc{rte_rdtsc()};
  std::uint64_t timer_tsc{};
  const auto stats_period_tsc{rte_get_tsc_hz() * timer_period_sec};
  while (force_quit == 0) {
    if (timer_period_sec == 0) {
      rte_pause();
      continue;
    }

    const auto current_tsc{rte_rdtsc()};
    const auto diff_tsc{current_tsc - previous_tsc};
    previous_tsc = current_tsc;
    timer_tsc += diff_tsc;

    if (timer_tsc >= stats_period_tsc) {
      PrintStats(counters_);
      timer_tsc = 0;
    }
    rte_pause();
  }

  StopWorkers();

  for (std::size_t rule_index{0}; rule_index < rule_match_counts_.size();
       ++rule_index) {
    std::uint64_t count{};
    for (const auto& context : worker_contexts_) {
      count += context.rule_match_counts[rule_index];
    }
    rule_match_counts_[rule_index] = count;
  }

  return PipelineStats{
      .received = LoadCounter(counters_.received),
      .transmitted = LoadCounter(counters_.transmitted),
      .parsed = LoadCounter(counters_.parsed),
      .matched = LoadCounter(counters_.matched),
      .unknown = LoadCounter(counters_.unknown),
      .malformed = LoadCounter(counters_.malformed),
      .dropped = LoadCounter(counters_.dropped),
  };
}

}  // namespace spi
