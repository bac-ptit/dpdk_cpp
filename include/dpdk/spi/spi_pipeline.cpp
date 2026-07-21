#include "dpdk/spi/spi_pipeline.hpp"

#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <format>
#include <iostream>
#include <limits>
#include <iterator>
#include <memory>
#include <optional>
#include <print>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "dpdk/config/dpdk_config_loader.hpp"
#include "dpdk/spi/spi_ip_address.hpp"
#include "dpdk/spi/spi_packet_parser.hpp"
#include "helpers/format_helpers.hpp"

namespace dpdk::spi {
namespace {

constexpr std::uint16_t kMaxBurstCapacity{256};
constexpr std::uint16_t kMinBurstCapacity{1};
/// Drain worker-local counters into the shared atomic counters once per this
/// many iterations. Skipping the per-burst atomic fetch_add avoids cache-line
/// bouncing across all workers on every burst.
// Larger interval → fewer atomic cache-line bounces per second → less mem-pool
// ring + atomic-counter contention. Trade-off: stats lag behind more, but
// the stats are only sampled every `timer_period_sec`, so the user-visible
// delay is unchanged.
constexpr std::uint32_t kAtomicFlushBurstInterval{256};
constexpr std::size_t kBitsPerByte{8};
constexpr std::uint8_t kHexBase{10};
constexpr std::size_t kLocalAdminMacByteIndex{0};
constexpr std::size_t kPortMacByteIndex{5};
constexpr std::uint8_t kLocalAdminMacPrefix{0x02};
constexpr std::uint16_t kTlsPort{443};
constexpr std::uint16_t kHttpPort{80};

/// Per-burst counters accumulated in a single worker iteration.
// BurstCounters is defined in spi_pipeline.hpp so WorkerContext can hold one.

/// Runtime packet-distribution mode.
enum class PacketDistribution : std::uint8_t {
  kQueuePerWorker,
  kFlowHash,
};

/// Classification outcome for one packet.
struct PacketClassification {
  PacketMetadata metadata{};
  Action action{Action::kForward};
  bool parsed{false};
  bool matched{false};
};

/// Convert one hexadecimal character to its numeric value.
[[nodiscard]] constexpr std::uint8_t HexValue(char value) noexcept {
  if (value >= '0' && value <= '9') {
    return static_cast<std::uint8_t>(value - '0');
  }
  if (value >= 'a' && value <= 'f') {
    return static_cast<std::uint8_t>(value - 'a' + kHexBase);
  }
  return static_cast<std::uint8_t>(value - 'A' + kHexBase);
}

/// Mix one 32-bit word into a lightweight FNV-1a hash state.
[[nodiscard]] constexpr std::uint32_t MixHash(std::uint32_t hash, std::uint32_t value) noexcept {
  constexpr std::uint32_t kFnvPrime{16777619U};
  for (std::size_t shift{0}; shift < sizeof(value) * kBitsPerByte; shift += kBitsPerByte) {
    hash ^= static_cast<std::uint8_t>(value >> shift);
    hash *= kFnvPrime;
  }
  return hash;
}

/// Calculate a flow-stable hash used by software dispatcher mode.
[[nodiscard]] std::uint32_t HashPacketFlow(const rte_mbuf& packet, std::uint16_t receive_port) noexcept {
  constexpr std::uint32_t kFnvOffset{2166136261U};
  std::uint32_t hash{MixHash(kFnvOffset, receive_port)};
  hash = MixHash(hash, rte_pktmbuf_pkt_len(&packet));

  const auto data_len{rte_pktmbuf_data_len(&packet)};
  if (data_len < sizeof(rte_ether_hdr)) [[unlikely]] {
    return hash;
  }

  const auto* ether_hdr{rte_pktmbuf_mtod(&packet, const rte_ether_hdr*)};
  const auto ether_type{rte_be_to_cpu_16(ether_hdr->ether_type)};
  hash = MixHash(hash, ether_type);
  if (ether_type != RTE_ETHER_TYPE_IPV4 || data_len < sizeof(rte_ether_hdr) + sizeof(rte_ipv4_hdr)) {
    return hash;
  }

  const auto* ipv4_hdr{rte_pktmbuf_mtod_offset(&packet, const rte_ipv4_hdr*, sizeof(rte_ether_hdr))};
  const auto ipv4_header_len{rte_ipv4_hdr_len(ipv4_hdr)};
  if (ipv4_header_len < sizeof(rte_ipv4_hdr)) [[unlikely]] {
    return hash;
  }

  hash = MixHash(hash, rte_be_to_cpu_32(ipv4_hdr->src_addr));
  hash = MixHash(hash, rte_be_to_cpu_32(ipv4_hdr->dst_addr));
  hash = MixHash(hash, ipv4_hdr->next_proto_id);

  const auto l4_offset{static_cast<std::uint16_t>(sizeof(rte_ether_hdr) + ipv4_header_len)};
  if (data_len < l4_offset + sizeof(rte_udp_hdr)) {
    return hash;
  }

  if (ipv4_hdr->next_proto_id == IPPROTO_TCP) {
    if (data_len < l4_offset + sizeof(rte_tcp_hdr)) [[unlikely]] {
      return hash;
    }
    const auto* tcp_hdr{rte_pktmbuf_mtod_offset(&packet, const rte_tcp_hdr*, l4_offset)};
    hash = MixHash(hash, rte_be_to_cpu_16(tcp_hdr->src_port));
    hash = MixHash(hash, rte_be_to_cpu_16(tcp_hdr->dst_port));
  } else if (ipv4_hdr->next_proto_id == IPPROTO_UDP) {
    const auto* udp_hdr{rte_pktmbuf_mtod_offset(&packet, const rte_udp_hdr*, l4_offset)};
    hash = MixHash(hash, rte_be_to_cpu_16(udp_hdr->src_port));
    hash = MixHash(hash, rte_be_to_cpu_16(udp_hdr->dst_port));
  }

  return hash;
}

/// Parse a validated MM:MM:MM:MM:MM:MM MAC address.
[[nodiscard]] constexpr rte_ether_addr ParseMacAddress(std::string_view mac_address) noexcept {
  rte_ether_addr parsed{};
  for (std::size_t byte_index{0}; byte_index < RTE_ETHER_ADDR_LEN; ++byte_index) {
    const auto string_index{byte_index * 3U};
    const auto high_nibble{static_cast<unsigned>(HexValue(mac_address[string_index]))};
    const auto low_nibble{static_cast<unsigned>(HexValue(mac_address[string_index + 1U]))};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    parsed.addr_bytes[byte_index] = static_cast<std::uint8_t>((high_nibble << 4U) | low_nibble);
  }
  return parsed;
}

/// Build startup L3 route table from YAML config.
[[nodiscard]] std::vector<L3RouteEntry> BuildL3Routes(const L3ForwardConfig& config) noexcept {
  std::vector<L3RouteEntry> routes;
  routes.reserve(config.ipv4_routes.size());

  for (const auto& route : config.ipv4_routes) {
    const auto parsed_address{ParseIpv4Address(route.destination_ip_address)};
    if (!parsed_address) {
      continue;
    }

    const auto mask{PrefixMask(route.prefix_length)};
    routes.emplace_back(L3RouteEntry{
        .network_address = *parsed_address & mask,
        .prefix_mask = mask,
        .prefix_length = route.prefix_length,
        .output_port = route.output_port,
    });
  }

  std::ranges::sort(
      routes, [](const L3RouteEntry& lhs, const L3RouteEntry& rhs) { return lhs.prefix_length > rhs.prefix_length; });
  return routes;
}

/// Build startup destination-MAC table from YAML config.
[[nodiscard]] std::vector<EthernetDestinationEntry> BuildEthernetDestinations(const L3ForwardConfig& config) noexcept {
  std::vector<EthernetDestinationEntry> destinations;
  destinations.reserve(config.ethernet_destinations.size());

  for (const auto& destination : config.ethernet_destinations) {
    destinations.emplace_back(EthernetDestinationEntry{
        .port_id = destination.port_id,
        .mac_address = ParseMacAddress(destination.mac_address),
    });
  }

  return destinations;
}

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

/// Look up output port via longest-prefix IPv4 route match.
[[nodiscard]] std::optional<std::uint16_t> LookupL3TransmitPort(const std::vector<L3RouteEntry>& routes,
                                                                const PacketMetadata& metadata) noexcept {
  for (const auto& route : routes) {
    if ((metadata.destination_ip_address & route.prefix_mask) == route.network_address) {
      return route.output_port;
    }
  }
  return std::nullopt;
}

/// Look up configured destination MAC for an output port.
[[nodiscard]] const rte_ether_addr* GetEthernetDestination(const std::vector<EthernetDestinationEntry>& destinations,
                                                           std::uint16_t port_id) noexcept {
  for (const auto& destination : destinations) {
    if (destination.port_id == port_id) {
      return &destination.mac_address;
    }
  }
  return nullptr;
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
void UpdateL2ForwardMacs(const rte_mbuf& packet, const rte_ether_addr& src_addr, std::uint16_t transmit_port) noexcept {
  auto* eth_hdr{rte_pktmbuf_mtod(&packet, rte_ether_hdr*)};
  rte_ether_addr dst_addr{};
  dst_addr.addr_bytes[kLocalAdminMacByteIndex] = kLocalAdminMacPrefix;
  dst_addr.addr_bytes[kPortMacByteIndex] = static_cast<std::uint8_t>(transmit_port);
  rte_ether_addr_copy(&dst_addr, &eth_hdr->dst_addr);
  rte_ether_addr_copy(&src_addr, &eth_hdr->src_addr);
}

/// Recompute IPv4 TCP/UDP checksum after L3 header updates.
[[nodiscard]] bool RecomputeL4Checksum(rte_mbuf& packet, const rte_ipv4_hdr& ipv4_hdr) noexcept {
  const auto ipv4_header_len{rte_ipv4_hdr_len(&ipv4_hdr)};
  const auto l4_offset{static_cast<std::uint16_t>(sizeof(rte_ether_hdr) + ipv4_header_len)};

  packet.ol_flags &= ~RTE_MBUF_F_TX_OFFLOAD_MASK;

  if (ipv4_hdr.next_proto_id == IPPROTO_TCP) {
    if (rte_pktmbuf_data_len(&packet) < l4_offset + sizeof(rte_tcp_hdr)) [[unlikely]] {
      return false;
    }

    auto* tcp_hdr{rte_pktmbuf_mtod_offset(&packet, rte_tcp_hdr*, l4_offset)};
    tcp_hdr->cksum = 0;
    tcp_hdr->cksum = rte_ipv4_udptcp_cksum_mbuf(&packet, &ipv4_hdr, l4_offset);
    return true;
  }

  if (ipv4_hdr.next_proto_id == IPPROTO_UDP) {
    if (rte_pktmbuf_data_len(&packet) < l4_offset + sizeof(rte_udp_hdr)) [[unlikely]] {
      return false;
    }

    auto* udp_hdr{rte_pktmbuf_mtod_offset(&packet, rte_udp_hdr*, l4_offset)};
    udp_hdr->dgram_cksum = 0;
    udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum_mbuf(&packet, &ipv4_hdr, l4_offset);
  }

  return true;
}

/**
 * @brief Rewrite Ethernet MACs and decrement IPv4 TTL for L3 forwarding.
 * @param packet    The mbuf whose Ethernet/IPv4 headers are modified.
 * @param src_addr  Source MAC from the output DPDK port.
 * @param dst_addr  Destination MAC for the next hop/VM.
 * @return true on success, false if TTL expired.
 */
[[nodiscard]] bool UpdateL3ForwardHeaders(rte_mbuf& packet, const rte_ether_addr& src_addr,
                                          const rte_ether_addr& dst_addr) noexcept {
  auto* eth_hdr{rte_pktmbuf_mtod(&packet, rte_ether_hdr*)};
  rte_ether_addr_copy(&dst_addr, &eth_hdr->dst_addr);
  rte_ether_addr_copy(&src_addr, &eth_hdr->src_addr);

  auto* ipv4_hdr{rte_pktmbuf_mtod_offset(&packet, rte_ipv4_hdr*, sizeof(rte_ether_hdr))};
  if (ipv4_hdr->time_to_live <= 1U) {
    return false;
  }

  --ipv4_hdr->time_to_live;
  ipv4_hdr->hdr_checksum = 0;
  ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
  return RecomputeL4Checksum(packet, *ipv4_hdr);
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
      .dropped_by_rule = LoadCounter(counters.dropped_by_rule),
      .flow_cache_hits = LoadCounter(counters.flow_cache_hits),
      .dpi_cache_hits = LoadCounter(counters.dpi_cache_hits),
      .dpi_cache_misses = LoadCounter(counters.dpi_cache_misses),
      .dpi_skipped_by_spi = LoadCounter(counters.dpi_skipped_by_spi),
      .dpi_skipped_by_link = LoadCounter(counters.dpi_skipped_by_link),
      .flow_table_full = LoadCounter(counters.flow_table_full),
      .pressure_evictions = LoadCounter(counters.pressure_evictions),
      .flow_table_resizes = LoadCounter(counters.flow_table_resizes),
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
  counters.dropped_by_rule.fetch_add(burst.dropped_by_rule, std::memory_order_relaxed);
  counters.flow_cache_hits.fetch_add(burst.flow_cache_hits, std::memory_order_relaxed);
  counters.dpi_cache_hits.fetch_add(burst.dpi_cache_hits, std::memory_order_relaxed);
  counters.dpi_cache_misses.fetch_add(burst.dpi_cache_misses, std::memory_order_relaxed);
  counters.dpi_skipped_by_spi.fetch_add(burst.dpi_skipped_by_spi, std::memory_order_relaxed);
  counters.dpi_skipped_by_link.fetch_add(burst.dpi_skipped_by_link, std::memory_order_relaxed);
  counters.flow_table_full.fetch_add(burst.flow_table_full, std::memory_order_relaxed);
  counters.pressure_evictions.fetch_add(burst.pressure_evictions, std::memory_order_relaxed);
  counters.flow_table_resizes.fetch_add(burst.flow_table_resizes, std::memory_order_relaxed);
}

/// Fold worker-side counters in dispatcher mode without double-counting RX.
void AddDispatchedWorkerCounters(AtomicCounters& counters, const BurstCounters& burst) noexcept {
  counters.transmitted.fetch_add(burst.transmitted, std::memory_order_relaxed);
  counters.parsed.fetch_add(burst.parsed, std::memory_order_relaxed);
  counters.matched.fetch_add(burst.matched, std::memory_order_relaxed);
  counters.unknown.fetch_add(burst.unknown, std::memory_order_relaxed);
  counters.malformed.fetch_add(burst.malformed, std::memory_order_relaxed);
  counters.dropped.fetch_add(burst.dropped, std::memory_order_relaxed);
  counters.dropped_by_rule.fetch_add(burst.dropped_by_rule, std::memory_order_relaxed);
  counters.flow_cache_hits.fetch_add(burst.flow_cache_hits, std::memory_order_relaxed);
  counters.dpi_cache_hits.fetch_add(burst.dpi_cache_hits, std::memory_order_relaxed);
  counters.dpi_cache_misses.fetch_add(burst.dpi_cache_misses, std::memory_order_relaxed);
  counters.dpi_skipped_by_spi.fetch_add(burst.dpi_skipped_by_spi, std::memory_order_relaxed);
  counters.dpi_skipped_by_link.fetch_add(burst.dpi_skipped_by_link, std::memory_order_relaxed);
  counters.flow_table_full.fetch_add(burst.flow_table_full, std::memory_order_relaxed);
  counters.pressure_evictions.fetch_add(burst.pressure_evictions, std::memory_order_relaxed);
  counters.flow_table_resizes.fetch_add(burst.flow_table_resizes, std::memory_order_relaxed);
}

/// Add per-burst counters to a worker-local stats snapshot.
void AddBurstStats(PipelineStats& stats, const BurstCounters& burst) noexcept {
  stats.received += burst.received;
  stats.transmitted += burst.transmitted;
  stats.parsed += burst.parsed;
  stats.matched += burst.matched;
  stats.unknown += burst.unknown;
  stats.malformed += burst.malformed;
  stats.dropped += burst.dropped;
  stats.dropped_by_rule += burst.dropped_by_rule;
  stats.flow_cache_hits += burst.flow_cache_hits;
  stats.dpi_cache_hits += burst.dpi_cache_hits;
  stats.dpi_cache_misses += burst.dpi_cache_misses;
  stats.dpi_skipped_by_spi += burst.dpi_skipped_by_spi;
  stats.dpi_skipped_by_link += burst.dpi_skipped_by_link;
  stats.flow_table_full += burst.flow_table_full;
  stats.pressure_evictions += burst.pressure_evictions;
  stats.flow_table_resizes += burst.flow_table_resizes;
}

/// Fold per-burst counters into a worker-local pending accumulator. Used
/// between atomic flushes so that per-burst updates never touch shared
/// cache lines.
void AddBurstCounters(BurstCounters& accumulator, const BurstCounters& burst) noexcept {
  accumulator.received += burst.received;
  accumulator.transmitted += burst.transmitted;
  accumulator.parsed += burst.parsed;
  accumulator.matched += burst.matched;
  accumulator.unknown += burst.unknown;
  accumulator.malformed += burst.malformed;
  accumulator.dropped += burst.dropped;
  accumulator.dropped_by_rule += burst.dropped_by_rule;
  accumulator.flow_cache_hits += burst.flow_cache_hits;
  accumulator.dpi_cache_hits += burst.dpi_cache_hits;
  accumulator.dpi_cache_misses += burst.dpi_cache_misses;
  accumulator.dpi_skipped_by_spi += burst.dpi_skipped_by_spi;
  accumulator.dpi_skipped_by_link += burst.dpi_skipped_by_link;
  accumulator.flow_table_full += burst.flow_table_full;
  accumulator.pressure_evictions += burst.pressure_evictions;
  accumulator.flow_table_resizes += burst.flow_table_resizes;
}

/// Print the current counter state to stdout.
/**
 * @brief Conditionally print stats if the timer period has elapsed.
 * @param counters          Shared atomic counters.
 * @param timer_period_sec  Print interval in seconds (0=disabled).
 * @param stats_period_tsc  Ticks between prints.
 * @param previous_tsc      Previous TSC value (updated in place).
 * @param timer_tsc         Accumulated ticks (updated in place).
 * @param start_tsc
 */
void MaybePrintStats(const AtomicCounters& counters, std::uint32_t timer_period_sec, std::uint64_t stats_period_tsc,
                     std::uint64_t& previous_tsc, std::uint64_t& timer_tsc, std::uint64_t start_tsc) noexcept {
  if (timer_period_sec == 0) {
    return;
  }

  const auto current_tsc{rte_rdtsc()};
  const auto diff_tsc{current_tsc - previous_tsc};
  previous_tsc = current_tsc;
  timer_tsc += diff_tsc;

  if (timer_tsc >= stats_period_tsc) {
    const auto stats{CollectStats(counters)};
    const auto elapsed_sec{static_cast<double>(current_tsc - start_tsc) / static_cast<double>(rte_get_tsc_hz())};
    const auto mpps{static_cast<double>(stats.received) / elapsed_sec / 1e6};
    // Print to std::cerr (unbuffered by default, separate stream from workers'
    // stdout) so a stdout-mutex contention or pipe-buffer stall on the main
    // lcore can never appear as the dispatcher "hanging". std::cerr MUST come
    // FIRST — the (ostream, fmt, args...) overload of std::println picks it as
    // the destination; placing it after the format string makes the compiler
    // treat it as a format arg (no std::formatter<ostream> exists → build fail).
    std::println(
        std::cerr,
        "SPI stats: received={} matched={} flow_table_full={} pressure_evictions={} "
        "flow_table_resizes={} dpi_skipped_by_spi={} dpi_skipped_by_link={} "
        "elapsed={:.1f}s Mpps={:.2f}",
        stats.received, stats.matched, stats.flow_table_full, stats.pressure_evictions,
        stats.flow_table_resizes, stats.dpi_skipped_by_spi, stats.dpi_skipped_by_link,
        elapsed_sec, mpps);
    timer_tsc = 0;
  }
}

}  // namespace (anonymous) — close before Pipeline::MaybeReload so the
                               //  member-function body has access to `this`.

/// Check the reload flag and rebuild active SPI/DPI tables if requested.
///
/// The reload request is consumed with `exchange(0)`, so a second SIGUSR1
/// arriving during a reload remains pending for the next main-loop iteration.
/// Replacement tables are compiled while workers continue using the active
/// tables. The main lcore then sets `reload_barrier`, waits up to 100 ms for
/// every worker to acknowledge the pause, publishes the new tables, and
/// releases the workers. A timeout or shutdown request cancels the publish.
[[gnu::cold]] void dpdk::spi::Pipeline::MaybeReload(const std::atomic<int>& force_quit,
                                                    std::atomic<int>* reload_flag,
                                                    const std::string& config_path,
                                                    std::atomic<bool>& reload_barrier) noexcept {
  if (reload_flag == nullptr || reload_flag->exchange(0, std::memory_order_acq_rel) == 0 ||
      force_quit.load(std::memory_order_relaxed) != 0) {
    return;
  }

  // Compile replacement tables before pausing workers. They use independent
  // storage; only the in-place publish below needs a quiescent worker set.
  auto config{dpdk::LoadConfig(config_path)};
  if (!config) {
    std::println(stderr, "Reload failed: {}", config.error());
    return;
  }

  auto new_rules{CompileRuleTable(config->spi)};
  if (!new_rules) {
    std::println(stderr, "Reload failed: {}", new_rules.error());
    return;
  }

  std::unique_ptr<dpi::DpiRuleTable> new_dpi_rules;
  if (config->dpi.enabled) {
    auto compiled_dpi{dpi::CompileDpiRuleTable(config->dpi)};
    if (!compiled_dpi) {
      std::println(stderr, "DPI reload failed: {}", compiled_dpi.error());
      return;
    }
    new_dpi_rules = std::make_unique<dpi::DpiRuleTable>(std::move(*compiled_dpi));
    if (const auto resolve{new_rules->ResolveDpiLinks(*new_dpi_rules)}; !resolve) {
      std::println(stderr, "Reload failed: {}", resolve.error());
      return;
    }
  }

  if (force_quit.load(std::memory_order_relaxed) != 0) {
    return;
  }

  // Pause workers and wait for an explicit acknowledgement from every remote
  // lcore. The bounded wait prevents a failed worker from blocking SIGINT.
  reload_barrier.store(true, std::memory_order_release);
  constexpr std::uint64_t kMillisecondsPerSecond{1000};
  constexpr std::uint64_t kReloadQuiesceTimeoutMs{100};
  const auto timeout_tsc{rte_get_tsc_hz() * kReloadQuiesceTimeoutMs /
                         kMillisecondsPerSecond,};
  const auto wait_start_tsc{rte_rdtsc()};
  bool wait_timed_out{false};
  if (worker_contexts_.size() > 1) {
    while (workers_paused_.load(std::memory_order_acquire) < worker_contexts_.size()) {
      if (force_quit.load(std::memory_order_relaxed) != 0) {
        break;
      }
      if (rte_rdtsc() - wait_start_tsc >= timeout_tsc) {
        wait_timed_out = true;
        break;
      }
      rte_pause();
    }
  }

  if (force_quit.load(std::memory_order_relaxed) != 0 || wait_timed_out) {
    reload_barrier.store(false, std::memory_order_release);
    if (wait_timed_out) {
      std::println(stderr,
                   "Reload cancelled: only {}/{} workers reached the pause barrier",
                   workers_paused_.load(std::memory_order_relaxed),
                   worker_contexts_.size());
    }
    return;
  }

  const auto* active{rule_manager_.Load()};
  if (active == nullptr) {
    std::println(stderr, "Reload failed: no active RuleTable");
    reload_barrier.store(false, std::memory_order_release);
    return;
  }

  auto new_groups{std::move(*new_rules).MoveGroupsOut()};
  auto new_precedence{std::move(*new_rules).MovePrecedenceOrderOut()};
  if (const auto rebuild{const_cast<RuleTable*>(active)->RebuildInPlace(
          std::move(new_groups), std::move(new_precedence))};
      !rebuild) {
    std::println(stderr, "Reload failed: {}", rebuild.error());
    reload_barrier.store(false, std::memory_order_release);
    return;
  }

  dpi_rule_manager_.Swap(std::move(new_dpi_rules));
  MaybeReloadFlowTable(*config);

  std::println("Rules reloaded: {} groups, {} filters (in-place)",
               active->GroupCount(), active->FilterCount());
  reload_barrier.store(false, std::memory_order_release);
}

namespace {
// Reopen the anonymous namespace for the rest of the file's TU-local
// helpers (PrintWorkerStats, PrintForwardMap, …).

void PrintWorkerStats(const std::vector<WorkerContext>& contexts) noexcept {
  for (const auto& context : contexts) {
    std::println("Worker {} stats: {}", context.worker_id, context.stats);
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

/// Print dispatch ring assignment per worker for flow-hash mode.
void PrintDispatchMap(const dpdk::Environment& environment, std::size_t worker_count,
                      std::uint32_t dispatch_queue_size) noexcept {
  const auto& active_ports{environment.GetActivePorts()};
  std::println("Entering SPI packet-processing loop");
  std::println("Software flow-hash dispatcher mode on main lcore");
  PrintForwardMap(active_ports);
  std::println("Dispatch map: main lcore receives packets and flow-hashes into {} worker rings",
               worker_count);
  for (std::size_t worker_id{0}; worker_id < worker_count; ++worker_id) {
    std::println("Dispatch map: worker {} -> ring size {} / transmit queue {}",
                 worker_id, dispatch_queue_size, worker_id);
  }
}

/// Select queue-per-worker or software flow-hash packet distribution.
[[nodiscard]] PacketDistribution ResolvePacketDistribution(const dpdk::Environment& environment,
                                                           std::string_view configured_mode,
                                                           std::size_t worker_count) noexcept {
  if (configured_mode == "queue") {
    std::println("Packet distribution: queue (forced by config)");
    return PacketDistribution::kQueuePerWorker;
  }
  if (configured_mode == "flow_hash") {
    std::println("Packet distribution: flow_hash (forced by config)");
    return PacketDistribution::kFlowHash;
  }
  if (worker_count <= 1) {
    std::println("Packet distribution: queue (auto, single worker)");
    return PacketDistribution::kQueuePerWorker;
  }
  // No RSS offloads → all packets land on queue 0. Software dispatcher is the
  // only way to fan them out across workers. Checked FIRST so the per-port
  // branches below can safely assume queue-per-worker actually works.
  if (!environment.ActivePortsSupportRss()) {
    std::println("Packet distribution: flow_hash (auto, active ports report no RSS offloads)");
    return PacketDistribution::kFlowHash;
  }
  // net_pcap with multiple rx_pcap= shards binds each shard to its own RX queue
  // (only true when RSS is on; without it everything funnels to queue 0).
  if (environment.HasPcapPort()) {
    std::println("Packet distribution: queue (auto, net_pcap shards feed separate queues)");
    return PacketDistribution::kQueuePerWorker;
  }
  if (environment.HasSoftwareBackedPort()) {
    std::println("Packet distribution: flow_hash (auto, software/vNIC PMD detected)");
    return PacketDistribution::kFlowHash;
  }
  if (environment.GetReceiveQueueCount() < worker_count) {
    std::println("Packet distribution: flow_hash (auto, RX queues < worker count)");
    return PacketDistribution::kFlowHash;
  }

  std::println("Packet distribution: queue (auto, NIC RSS path)");
  return PacketDistribution::kQueuePerWorker;
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

/// Build a matched PacketClassification and insert into flow cache.
[[nodiscard, gnu::always_inline]] inline PacketClassification MakeMatched(
    const PacketMetadata& metadata, Action action, const FlowKey& key, const WorkerContext& context,
    BurstCounters& counters) noexcept {
  // `match_count = 1` marks the slot as populated (the lookup check is
  // `packed == 0`). New `action_and_count` value is published via the
  // release-store inside `Insert`.
  if (const auto ins{context.flow_table->Insert(key, /*match_count=*/1, action)};
      ins != FlowInsertResult::kOk) [[unlikely]] {
    // Flow table is full (-ENOSPC). Apply configured overflow policy.
    ++counters.flow_table_full;
    if (context.flow_overflow_drop) {
      // Tell the caller to drop this packet; DropPacket frees the mbuf and
      // increments `dropped_by_rule` + `dropped`. Bump `matched` so the
      // matched counter stays consistent with the dropped_by_rule counter
      // (every `dropped_by_rule++` must correspond to exactly one
      // `matched++`; otherwise the rule engine's credit is hidden in
      // the overflow path and stats look like SPI never matched anything).
      ++counters.matched;
      return {.metadata = metadata, .action = Action::kDrop, .parsed = true, .matched = true};
    }
    // reclassify: forward without caching. Decrement `matched` so the caller
    // doesn't double-count (the rule engine doesn't get credit for a flow it
    // couldn't cache).
    ++counters.unknown;
    return {.metadata = metadata, .action = Action::kForward, .parsed = true, .matched = false};
  }
  ++counters.matched;
  return {.metadata = metadata, .action = action, .parsed = true, .matched = true};
}

/// Extract L7 hostname from TLS SNI (port 443) or HTTP Host (port 80).
void ExtractHostname(const rte_mbuf& packet, PacketMetadata& metadata) noexcept {
  const auto* ip_hdr{rte_pktmbuf_mtod_offset(&packet, const rte_ipv4_hdr*, sizeof(rte_ether_hdr))};
  // Skip past IP header to TCP/UDP header. Then skip TCP header (data_offset
  // field) to reach the L7 payload. UDP has no header beyond l4_len.
  const auto l4_off{static_cast<std::uint32_t>(sizeof(rte_ether_hdr) + rte_ipv4_hdr_len(ip_hdr))};
  std::uint32_t payload_off{l4_off};
  if (metadata.protocol == Protocol::kTcp) {
    // rte_pktmbuf_read returns either `&tcp_hdr` (when it copied) or a
    // pointer into the mbuf (when data is contiguous). We need the bytes
    // regardless — copy from the returned pointer.
    rte_tcp_hdr tcp_hdr{};
    const void* tcp_data{rte_pktmbuf_read(&packet, l4_off, sizeof(tcp_hdr), &tcp_hdr)};
    if (tcp_data == nullptr) [[unlikely]] {
      return;
    }
    if (tcp_data != &tcp_hdr) {
      std::memcpy(&tcp_hdr, tcp_data, sizeof(tcp_hdr));
    }
    const auto tcp_hdr_len{static_cast<std::uint32_t>(tcp_hdr.data_off >> 4U) * 4U};
    if (tcp_hdr_len < sizeof(rte_tcp_hdr)) [[unlikely]] {
      return;
    }
    payload_off = l4_off + tcp_hdr_len;
  }

  if (metadata.destination_port == kTlsPort) {
    if (const auto sni{ExtractTlsSni(packet, payload_off)}) {
      metadata.hostname = sni->first;
      metadata.hostname_length = sni->second;
    }
  } else if (metadata.destination_port == kHttpPort) {
    if (const auto host{ExtractHttpHost(packet, payload_off)}) {
      metadata.hostname = host->first;
      metadata.hostname_length = host->second;
    }
  }
}

/// DPI match result with group info.
struct DpiMatch {
  std::string_view filter_group;
  std::string_view label;
  std::uint32_t priority{};
};

/// Run DPI hostname matching if hostname was extracted.
[[nodiscard, gnu::always_inline]] inline std::optional<DpiMatch> MatchDpi(
    WorkerContext& context, BurstCounters& counters, const PacketMetadata& metadata) noexcept {
  if (metadata.hostname == nullptr) [[unlikely]] {
    return std::nullopt;
  }
  const std::string_view hostname{metadata.hostname, metadata.hostname_length};

  // H1: hoist a single acquire-load of the DPI rule table so all reads
  // below come from the same table pointer. Without this, a Swap()
  // between two consecutive Load() calls could observe different
  // tables — the cached_idx from the OLD table might be >= FilterCount()
  // on the NEW table, causing ResultAt() OOB read.
  const auto* const dpi_rules{context.dpi_rule_manager->Load()};
  if (dpi_rules == nullptr) [[unlikely]] {
    return std::nullopt;
  }
  const auto filter_count{dpi_rules->FilterCount()};
  const auto current_generation{dpi_rules->Generation()};

  // Cache fast path — ~20 ns vs ~300 ns for full Match(). Per-worker
  // cache, no contention. False positives at 1K entries ≈ 0.001%.
  // M1: pass current_generation so cache entries from a previous DPI
  // reload are invalidated on their next Lookup.
  const auto cached_idx{context.dpi_hostname_cache.Lookup(hostname, current_generation)};
  if (cached_idx != dpi::HostnameCache::kNoMatchIdx) [[likely]] {
    ++counters.dpi_cache_hits;
    if (cached_idx < filter_count) [[likely]] {
      const auto result = dpi_rules->ResultAt(cached_idx);
      return DpiMatch{.filter_group = result.filter_group, .label = result.label,
                       .priority = result.priority};
    }
    // kNoMatchIdx — cache recorded a negative result, skip Match.
    return std::nullopt;
  }

  ++counters.dpi_cache_misses;

  // Cache miss — full Match() + insert into cache.
  const auto result{dpi_rules->Match(hostname)};
  if (result.matched) [[unlikely]] {
    // Look up the filter index for cache. For ≤30 entries this is O(N)
    // but each step is a string_view compare, fits in one cache line.
    std::uint16_t idx{0U};
    for (std::size_t i = 0; i < filter_count; ++i) {
      idx = static_cast<std::uint16_t>(i);
      const auto probe = dpi_rules->ResultAt(idx);
      if (probe.filter_group == result.filter_group && probe.label == result.label &&
          probe.priority == result.priority) {
        break;
      }
    }
    context.dpi_hostname_cache.Insert(hostname, idx, current_generation);
    return DpiMatch{.filter_group = result.filter_group, .label = result.label,
                     .priority = result.priority};
  }
  // Cache the negative result too so we don't redo the search.
  context.dpi_hostname_cache.Insert(hostname, dpi::HostnameCache::kNoMatchIdx, current_generation);
  return std::nullopt;
}

// Forward declaration — full definition lives below (after ProcessPortBurst helpers).
// Both `ClassifyPacket` (flow_hash dispatch path) and `ForwardPacket` only need the
// same SPI-gated DPI behaviour that the queue+bulk path already gets via
// `ResolvePacketAction` → `TryDpiClassify`. Routing both paths through this single
// function ensures the SPI gate short-circuits DPI work in *every* packet flow,
// matching the mentor's "spi -> link tới dpi" requirement.
[[gnu::hot, gnu::always_inline]] inline void TryDpiClassify(
    WorkerContext& context, BurstCounters& counters, const rte_mbuf& packet, PacketMetadata& metadata,
    const ClassificationResult& spi_match, const FlowKey& key, Action& action, bool& matched) noexcept;

/**
 * @brief Parse and classify a single packet, updating counters.
 * @param context  Worker context with rule table and counters.
 * @param counters  Per-burst counters (updated in place).
 * @param packet    The mbuf to classify.
 * @return Parsed metadata plus whether a SPI rule matched.
 */
[[nodiscard, gnu::hot]] PacketClassification ClassifyPacket(WorkerContext& context, BurstCounters& counters,
                                                            const rte_mbuf& packet) noexcept {
  if (auto parsed{ParsePacket(packet)}) {
    ++counters.parsed;
    auto metadata{*parsed};

    const FlowKey key{MakeCanonical(metadata.source_ip_address,
                                  metadata.destination_ip_address,
                                  metadata.source_port,
                                  metadata.destination_port,
                                  metadata.protocol)};

    // Cache hit — fast path. Returns std::optional<FlowEntryView>; on the
    // hot path the view is captured into a register and the action bit is
    // consumed directly without re-reading the atomic.
    if (auto cached{context.flow_table->Lookup(key, context.current_burst_tsc)}) [[likely]] {
      ++counters.flow_cache_hits;
      return {.metadata = metadata, .action = cached->action, .parsed = true, .matched = true};
    }

    // Cache miss — run SPI rules.
    const auto* rules = context.rule_manager->Load();

    // Tuple-Space Search pre-check (O(1) hash probe vs ACL multi-bit trie
    // walk). Fires only for SPI filters whose FULL 5-tuple is specified
    // (no CIDR, no "any source", no "any port"). For CIDR / port-only
    // filters, `ProbeTss` returns `kNoTssHit` and we fall through to the
    // regular ACL path unchanged. When TSS hits, we synthesize the same
    // `ClassificationResult` the ACL would have produced — including
    // `bound_dpi_filter_index` — so the static-link fast path below still
    // fires for linked groups. See docs_search/17 §2.
    ClassificationResult spi_match{};
    if (const auto tss_hit{rules->ProbeTss(key)}; tss_hit != RuleTable::kNoTssHit) [[likely]] {
      spi_match = rules->ResultForCategory(tss_hit);
    } else {
      spi_match = rules->Match(metadata);
    }

    // SPI→DPI static link fast path (MUST run BEFORE TryDpiClassify).
    // When the SPI group declared a `dpi_filter_group` in config, the SPI
    // match already determines the DPI group — skip ExtractHostname +
    // MatchDpi entirely, cache the SPI action, and return. Without this
    // branch sitting here, the matched path below would return BEFORE
    // TryDpiClassify is invoked, leaving the link unreachable on the
    // flow-hash dispatch path.
    if (spi_match.matched && spi_match.bound_dpi_filter_index != kNoDpiLink) [[likely]] {
      if (context.flow_table->Insert(key, /*match_count=*/1, spi_match.action) != FlowInsertResult::kOk) [[unlikely]] {
        ++counters.flow_table_full;
        if (context.flow_overflow_drop) {
          // Bump `matched` for counter consistency: the returned
          // PacketClassification has matched=true, so the caller will
          // increment `dropped_by_rule`; without this bump the matched
          // counter would under-count every overflow drop.
          ++counters.matched;
          return {.metadata = metadata, .action = Action::kDrop, .parsed = true, .matched = true};
        }
        // overflow policy == reclassify: don't cache, fall through. Bump
        // matched here too — the caller treats this packet as a successful
        // match (action=spi_match.action, matched=true) but we did NOT cache
        // the entry. Still count as matched because the rule engine did its
        // job; only the cache failed.
        ++counters.matched;
        return {.metadata = metadata, .action = spi_match.action, .parsed = true, .matched = true};
      }
      ++counters.dpi_skipped_by_link;
      ++counters.matched;
      return {.metadata = metadata, .action = spi_match.action, .parsed = true, .matched = true};
    }

    // SPI-only fast path: when DPI is fully disabled (`dpi.rules` empty →
    // `IsEnabled()` false), bypass `TryDpiClassify` entirely. Otherwise the
    // SPI path would pay ~8 cycles/cache-miss for the Load() + IsEnabled()
    // check + return — material on a 30 Mpps workload (a few % throughput).
    // The DPI engine's own `IsEnabled()` short-circuit at the top of
    // `TryDpiClassify` still handles partial cases (table loaded but
    // runtime disabled), so this is strictly an optimisation for the
    // "DPI off entirely" mode that the bench harness uses for `bench-spi`.
    //
    // Production: DPI is enabled by default → branch is `[[unlikely]]` so
    // the compiler lays out the fall-through (DPI on) path inline. The
    // `bench-spi` benchmark takes the early-out on every cache miss and
    // pays the mispredict cost (~15 cycles), but bench-spi is a benchmark
    // — production never hits this path with DPI enabled.
    const auto* const dpi_rules{context.dpi_rule_manager->Load()};
    if (dpi_rules == nullptr || !dpi_rules->IsEnabled()) [[unlikely]] {
      if (spi_match.matched) {
        return MakeMatched(metadata, spi_match.action, key, context, counters);
      }
      ++counters.unknown;
      return {.metadata = metadata, .action = Action::kForward, .parsed = true, .matched = false};
    }

    // Single SPI-gated DPI entry point (same logic as the queue-mode
    // `ResolvePacketAction`/`FinalizePackets` path). Encapsulates:
    //   1. Skip if DPI is disabled.
    //   2. Skip when SPI already decided a final action that does not need L7.
    //   3. Skip non-TCP / non-{80,443} traffic.
    //   4. Skip response-direction packets (canonical FlowKey means the request-side
    //      cache hit covers this packet; no need to redo ExtractHostname).
    //   5. Otherwise run ExtractHostname + MatchDpi; on match, Insert into flow cache
    //      and propagate the action via the out-params.
    Action action{Action::kForward};
    bool matched{false};
    TryDpiClassify(context, counters, packet, metadata, spi_match, key, action, matched);
    if (matched) {
      return {.metadata = metadata, .action = action, .parsed = true, .matched = true};
    }

    // Plain SPI match (no DPI on this packet — or DPI found nothing).
    if (spi_match.matched) {
      return MakeMatched(metadata, spi_match.action, key, context, counters);
    }

    ++counters.unknown;
    return {.metadata = metadata, .action = Action::kForward, .parsed = true, .matched = false};
  }

  ++counters.malformed;
  return {.metadata = {}, .action = Action::kForward, .parsed = false, .matched = false};
}

/// Increment dropped counter and free the mbuf.
[[gnu::cold]] void DropPacket(BurstCounters& counters, rte_mbuf* packet) noexcept {
  ++counters.dropped;
  rte_pktmbuf_free(packet);
}

/// Resolve output port via L2 pairing or L3 route lookup.
[[nodiscard]] std::optional<std::uint16_t> ResolveTransmitPort(const WorkerContext& context,
                                                               const PacketClassification& classification,
                                                               const std::vector<std::uint16_t>& active_ports,
                                                               std::uint16_t receive_port) noexcept {
  if (!context.l3_forwarding) {
    return GetTransmitPort(active_ports, receive_port);
  }

  if (!classification.parsed || context.l3_routes == nullptr || context.ethernet_destinations == nullptr) {
    return std::nullopt;
  }

  const auto l3_transmit_port{LookupL3TransmitPort(*context.l3_routes, classification.metadata)};
  if (!l3_transmit_port || *l3_transmit_port == receive_port) {
    return std::nullopt;
  }
  return l3_transmit_port;
}

/// Look up MACs and rewrite Ethernet/IPv4 headers.
[[nodiscard]] bool PrepareAndRewriteHeaders(const WorkerContext& context, std::uint16_t transmit_port,
                                            rte_mbuf& packet) noexcept {
  const auto* transmit_mac{context.environment->GetPortMacAddress(transmit_port)};
  if (transmit_mac == nullptr) [[unlikely]] {
    return false;
  }
  [[assume(transmit_mac != nullptr)]];

  if (context.l3_forwarding) {
    const auto* destination_mac{GetEthernetDestination(*context.ethernet_destinations, transmit_port)};
    if (destination_mac == nullptr || !UpdateL3ForwardHeaders(packet, *transmit_mac, *destination_mac)) [[unlikely]] {
      return false;
    }
  } else if (context.mac_updating) {
    UpdateL2ForwardMacs(packet, *transmit_mac, transmit_port);
  }
  return true;
}

/// Place packet into the per-port TX staging buffer.
[[gnu::always_inline]] inline void EnqueuePacket(
    rte_mbuf* packet, std::uint16_t transmit_port,
    std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
    std::vector<std::uint16_t>& transmit_counts) noexcept {
  const auto buf_size{transmit_buffers.size()};
  [[assume(transmit_port < buf_size)]];
  auto& count{transmit_counts[transmit_port]};
  *std::next(transmit_buffers[transmit_port].data(), static_cast<std::ptrdiff_t>(count)) = packet;
  ++count;
}

/**
 * @brief Classify, rewrite MAC, and enqueue one packet for TX.
 *
 * @param context           Worker context.
 * @param active_ports      List of active ports.
 * @param counters          Per-burst counters.
 * @param packet            The mbuf to forward.
 * @param receive_port      Port where packet was received.
 * @param transmit_buffers  Per-port TX buffers.
 * @param transmit_counts   Per-port TX counts.
 */
[[gnu::hot]] void ForwardPacket(WorkerContext& context, const std::vector<std::uint16_t>& active_ports,
                                BurstCounters& counters, rte_mbuf* packet, std::uint16_t receive_port,
                                std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
                                std::vector<std::uint16_t>& transmit_counts) noexcept {
  const auto classification{ClassifyPacket(context, counters, *packet)};
  // Drop by explicit SPI rule action.
  if (classification.matched && classification.action == Action::kDrop) [[unlikely]] {
    ++counters.dropped_by_rule;
    DropPacket(counters, packet);
    return;
  }
  // Drop unmatched packets when configured.
  if (context.drop_unmatched && !classification.matched) [[unlikely]] {
    DropPacket(counters, packet);
    return;
  }

  const auto transmit_port{ResolveTransmitPort(context, classification, active_ports, receive_port)};
  if (!transmit_port || *transmit_port >= transmit_buffers.size()) [[unlikely]] {
    DropPacket(counters, packet);
    return;
  }

  if (!PrepareAndRewriteHeaders(context, *transmit_port, *packet)) [[unlikely]] {
    DropPacket(counters, packet);
    return;
  }

  EnqueuePacket(packet, *transmit_port, transmit_buffers, transmit_counts);
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
[[gnu::hot]] void FlushTransmitBuffers(WorkerContext const& context,
                                       std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
                                       std::vector<std::uint16_t>& transmit_counts, BurstCounters& counters) noexcept {
  for (const auto port_id : context.environment->GetActivePorts()) {
    const auto count{transmit_counts[port_id]};
    if (count == 0) {
      continue;
    }

    const auto sent{rte_eth_tx_burst(port_id, context.worker_id, transmit_buffers[port_id].data(), count)};
    [[assume(sent <= count)]];
    counters.transmitted += sent;
    if (sent < count) [[unlikely]] {
      counters.dropped += static_cast<std::uint64_t>(count - sent);
    }
    for (const std::span<rte_mbuf*, kMaxBurstCapacity> buff{transmit_buffers[port_id]};
         auto*& pkt : buff.subspan(sent, count - sent)) {
      rte_pktmbuf_free(pkt);
    }
    transmit_counts[port_id] = 0;
  }
}

/**
 * @brief Receive a burst on a port and forward each packet.
 *
 * Refactored 2026-07-05 to use `rte_hash_lookup_bulk` for the per-burst
 * cache lookups. The 99.9% cache-hit case now pipelines all N hash
 * computations (vectorised CRC32) and bucket loads via a single DPDK call
 * before walking results. The miss path runs per-packet SPI/DPI just as
 * before.
 *
 * Three stages:
 *   A. Prefetch + parse every received packet; collect metadata + FlowKey.
 *      Drop malformed packets now and remember them via the `kUnmapped`
 *      sentinel in `packet_to_parsed`.
 *   B. Call `rte_hash_lookup_bulk` once per chunk (RTE_HASH_LOOKUP_BULK_MAX
 *      = 64 keys/call) on the contiguous keys[] array; `positions[]`
 *      holds the per-packet slot index (>= 0) or a negative value for
 *      misses.
 *   C. Per-packet finalize: extract the cached action if a hit, otherwise
 *      run SPI rules + DPI hostname extraction. Apply drop/forward
 *      decisions identical to `ForwardPacket`.
 *
 * @param context           Worker context.
 * @param active_ports      List of active ports.
 * @param port_id           Port to receive from.
 * @param packets           Local packet array.
 * @param transmit_buffers  Per-port TX buffers.
 * @param transmit_counts   Per-port TX counts.
 * @param counters          Per-burst counters.
 */

/// Run L7 DPI classification on a single flow-cache-miss packet.
///
/// Gated on (DPI enabled) ∧ (TCP) ∧ (dst port 443 | 80). On DPI match,
/// inserts the new flow entry, increments matched counter, sets
/// `action` and `matched` in place. Caller is responsible for the
/// drop/forward decision that follows.
///
/// Extracted from ProcessPortBurst to keep that function under
/// NIST's CC < 10 guideline for hot paths.
[[gnu::hot, gnu::always_inline]] inline void TryDpiClassify(
    WorkerContext& context, BurstCounters& counters, const rte_mbuf& packet, PacketMetadata& metadata,
    const ClassificationResult& spi_match, const FlowKey& key, Action& action, bool& matched) noexcept {
  const auto* const dpi_rules{context.dpi_rule_manager->Load()};
  if (dpi_rules == nullptr || !dpi_rules->IsEnabled()) [[likely]] {
    return;
  }
  // SPI-gated DPI: short-circuit when SPI already gave us a final answer
  // that does NOT require L7 inspection. With W4a's canonical tuple, the
  // response packet's FlowKey already points to the request-side cached
  // entry, so DPI work is unnecessary on the response path too.
  if (spi_match.matched && spi_match.action == Action::kDrop) [[unlikely]] {
    ++counters.dpi_skipped_by_spi;
    return;
  }
  if (spi_match.matched && spi_match.action == Action::kForward && !spi_match.l7_required) [[likely]] {
    ++counters.dpi_skipped_by_spi;
    return;
  }
  // SPI→DPI static link fast path: the SPI group declared a `dpi_filter_group`
  // in config, so the SPI match already determines the DPI group. Skip
  // ExtractHostname + MatchDpi entirely; cache the SPI action in the flow
  // table so subsequent packets on this 5-tuple skip DPI work too. This
  // is the dominant DPI throughput win when IP-range groups unambiguously
  // identify the application (e.g. Facebook IPs always serve `*.facebook.com`).
  if (spi_match.matched && spi_match.bound_dpi_filter_index != kNoDpiLink) [[likely]] {
    if (context.flow_table->Insert(key, /*match_count=*/1, spi_match.action) != FlowInsertResult::kOk) [[unlikely]] {
      ++counters.flow_table_full;
      if (context.flow_overflow_drop) {
        // Bump `matched` for counter consistency with the returned
        // PacketClassification (action=Drop, matched=true → caller will
        // increment dropped_by_rule). Without this bump, every overflow
        // drop under-counts the matched counter.
        ++counters.matched;
        action = Action::kDrop;
        matched = true;
      }
      // matched stays false → caller treats as unknown → forwards.
      // NOTE: reclassify path keeps matched=false intentionally — the
      // caller will increment `unknown`, not `dropped_by_rule`, so we
      // don't bump `matched` here.
    } else {
      ++counters.dpi_skipped_by_link;
      ++counters.matched;
      action = spi_match.action;
      matched = true;
    }
    return;
  }
  if (metadata.protocol != Protocol::kTcp) [[likely]] {
    ++counters.dpi_skipped_by_spi;
    return;
  }
  if (metadata.destination_port != kTlsPort && metadata.destination_port != kHttpPort) [[likely]] {
    ++counters.dpi_skipped_by_spi;
    return;
  }

  // Skip the response direction: src_port is a well-known web port (80/443)
  // and dst_port is ephemeral (>= 1024). The canonical FlowKey of this
  // packet was already inserted by the request side; the cached entry
  // applies via the lookup hit in ResolvePacketAction, so we don't need
  // to run hostname extraction or DPI matching here.
  constexpr std::uint16_t kWellKnownPortMax{1024};
  const bool is_response{(metadata.source_port == kHttpPort || metadata.source_port == kTlsPort) &&
                         metadata.destination_port >= kWellKnownPortMax};
  if (is_response) [[likely]] {
    ++counters.dpi_skipped_by_spi;
    return;
  }

  // ExtractHostname mutates metadata.hostname to point into the mbuf
  // (zero-copy via rte_pktmbuf_read). Safe because the mbuf outlives
  // the metadata reference (we still hold the packet in the burst).
  ExtractHostname(packet, metadata);
  if (auto dpi{MatchDpi(context, counters, metadata)}) {
    const auto final_action{spi_match.matched ? spi_match.action : Action::kForward};
    if (context.flow_table->Insert(key, /*match_count=*/1, final_action) != FlowInsertResult::kOk) [[unlikely]] {
      // Flow table is full (-ENOSPC). Apply configured overflow policy.
      ++counters.flow_table_full;
      if (context.flow_overflow_drop) {
        // Bump `matched` for counter consistency (returned PacketClassification
        // will have matched=true → caller increments dropped_by_rule).
        ++counters.matched;
        action = Action::kDrop;
        matched = true;
      }
      // reclassify: matched stays false; caller treats as unknown and forwards.
      // No `matched` bump here — caller increments `unknown`, not `dropped_by_rule`.
    } else {
      ++counters.matched;
      action = final_action;
      matched = true;
    }
  }
}

// ---------------------------------------------------------------------------
// ProcessPortBurst helpers — each ≤30 lines, cognitive complexity < 10
// ---------------------------------------------------------------------------

/// Parse all received packets, building metadata/keys arrays.
/// Returns the number of successfully parsed packets.
[[nodiscard]] std::uint32_t ParseReceivedPackets(
    std::span<rte_mbuf*> received_packets, BurstCounters& counters,
    std::span<PacketMetadata> metadata, std::span<FlowKey> keys,
    std::span<std::uint16_t> packet_to_parsed) noexcept {
  constexpr std::uint16_t kUnmapped{std::numeric_limits<std::uint16_t>::max()};
  constexpr auto kPrefetchDistance{4UZ};
  std::uint32_t n_parsed{0};

  for (auto i{0UZ}; i < received_packets.size(); ++i) {
    if (i + kPrefetchDistance < received_packets.size()) [[likely]] {
      rte_prefetch0(rte_pktmbuf_mtod(received_packets[i + kPrefetchDistance], void*));
    }
    auto* const packet{received_packets[i]};
    if (auto parsed{ParsePacket(*packet)}) {
      ++counters.parsed;
      metadata[n_parsed] = *parsed;
      keys[n_parsed] = MakeCanonical(parsed->source_ip_address,
                                     parsed->destination_ip_address,
                                     parsed->source_port,
                                     parsed->destination_port,
                                     parsed->protocol);
      packet_to_parsed[i] = static_cast<std::uint16_t>(n_parsed);
      ++n_parsed;
    } else {
      ++counters.malformed;
      packet_to_parsed[i] = kUnmapped;
    }
  }
  return n_parsed;
}

/// Bulk flow hash lookup in chunks of ≤64 keys.
void BulkFlowLookup(FlowTable& flow_table,
                    std::span<const FlowKey> keys, std::uint32_t n_parsed,
                    std::uint64_t now_tsc,
                    std::span<BulkResult> results) noexcept {
  constexpr std::uint32_t kBulkChunkMax{64};
  for (std::uint32_t chunk_start{0}; chunk_start < n_parsed;
       chunk_start += kBulkChunkMax) {
    const auto chunk_size{std::min(kBulkChunkMax, n_parsed - chunk_start)};
    flow_table.LookupBulk(keys.subspan(chunk_start, chunk_size).data(),
                          chunk_size,
                          now_tsc,
                          results.subspan(chunk_start, chunk_size));
  }
}

/// Resolve flow action: cache hit → fast path, miss → SPI + DPI.
[[gnu::hot, gnu::always_inline]] inline void ResolvePacketAction(
    WorkerContext& context, BurstCounters& counters,
    const rte_mbuf& packet, PacketMetadata& metadata,
    const FlowKey& key, const BulkResult& bulk_result,
    Action& action, bool& matched) noexcept {
  if (bulk_result.valid) [[likely]] {
    // Snapshot taken inside LookupBulk — no second acquire-load, no
    // position-lifetime window. See docs_search/13 §H4.
    ++counters.flow_cache_hits;
    action = bulk_result.view.action;
    matched = true;
    return;
  }

  const auto* rules{context.rule_manager->Load()};
  ClassificationResult spi_match{};
  if (const auto tss_hit{rules->ProbeTss(key)}; tss_hit != RuleTable::kNoTssHit) [[likely]] {
    spi_match = rules->ResultForCategory(tss_hit);
  } else {
    spi_match = rules->Match(metadata);
  }
  TryDpiClassify(context, counters, packet, metadata, spi_match, key,
                 action, matched);

  if (!matched) {
    if (spi_match.matched) {
      if (context.flow_table->Insert(key, /*match_count=*/1, spi_match.action) != FlowInsertResult::kOk) [[unlikely]] {
        // Flow table is full (-ENOSPC). Apply configured overflow policy.
        ++counters.flow_table_full;
        if (context.flow_overflow_drop) {
          // Bump `matched` for counter consistency with the returned
          // PacketClassification (matched=true → caller increments dropped_by_rule).
          ++counters.matched;
          action = Action::kDrop;
          matched = true;
        } else {
          ++counters.unknown;
        }
      } else {
        ++counters.matched;
        action = spi_match.action;
        matched = true;
      }
    } else {
      ++counters.unknown;
    }
  }
}

/// Apply drop/forward decision and enqueue or free the packet.
[[gnu::hot, gnu::always_inline]] inline void ApplyForwardDecision(
    WorkerContext& context, const std::vector<std::uint16_t>& active_ports,
    BurstCounters& counters, rte_mbuf* packet, std::uint16_t port_id,
    const PacketClassification& classification,
    std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
    std::vector<std::uint16_t>& transmit_counts) noexcept {
  if (classification.matched && classification.action == Action::kDrop) [[unlikely]] {
    ++counters.dropped_by_rule;
    DropPacket(counters, packet);
    return;
  }
  if (context.drop_unmatched && !classification.matched) [[unlikely]] {
    DropPacket(counters, packet);
    return;
  }
  const auto transmit_port{ResolveTransmitPort(context, classification, active_ports, port_id)};
  if (!transmit_port || *transmit_port >= transmit_buffers.size()) [[unlikely]] {
    DropPacket(counters, packet);
    return;
  }
  if (!PrepareAndRewriteHeaders(context, *transmit_port, *packet)) [[unlikely]] {
    DropPacket(counters, packet);
    return;
  }
  EnqueuePacket(packet, *transmit_port, transmit_buffers, transmit_counts);
}

/// Finalize classification and forward all packets in the burst.
void FinalizePackets(WorkerContext& context,
                     const std::vector<std::uint16_t>& active_ports,
                     std::uint16_t port_id,
                     std::span<rte_mbuf*> received_packets,
                     std::span<PacketMetadata> metadata,
                     std::span<FlowKey> keys,
                     std::span<const BulkResult> bulk_results,
                     std::span<const std::uint16_t> packet_to_parsed,
                     std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
                     std::vector<std::uint16_t>& transmit_counts,
                     BurstCounters& counters) noexcept {
  constexpr std::uint16_t kUnmapped{std::numeric_limits<std::uint16_t>::max()};
  for (auto i{0UZ}; i < received_packets.size(); ++i) {
    auto* const packet{received_packets[i]};
    const auto parsed_idx{packet_to_parsed[i]};
    if (parsed_idx == kUnmapped) [[unlikely]] {
      DropPacket(counters, packet);
      continue;
    }
    Action action{Action::kForward};
    bool matched{false};
    ResolvePacketAction(context, counters, *packet, metadata[parsed_idx],
                        keys[parsed_idx], bulk_results[parsed_idx],
                        action, matched);
    const PacketClassification classification{
        .metadata = metadata[parsed_idx], .action = action,
        .parsed = true, .matched = matched};
    ApplyForwardDecision(context, active_ports, counters, packet,
                         port_id, classification,
                         transmit_buffers, transmit_counts);
  }
}

[[gnu::hot, gnu::flatten]] void ProcessPortBurst(
    WorkerContext& context, const std::vector<std::uint16_t>& active_ports, std::uint16_t port_id,
    std::array<rte_mbuf*, kMaxBurstCapacity>& packets,
    std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
    std::vector<std::uint16_t>& transmit_counts, BurstCounters& counters) noexcept {
  // Sample rte_rdtsc() once per burst for any future GetEntry-side
  // last_seen_tsc touch. The bulk path's LookupBulk/GetEntry currently
  // doesn't read it, but having it ready costs ~1 cycle and lets us
  // add the touch without per-packet rdtsc later.
  context.current_burst_tsc = rte_rdtsc();
  const auto received{rte_eth_rx_burst(port_id, context.worker_id, packets.data(), context.burst_size)};
  [[assume(received <= kMaxBurstCapacity)]];
  [[assume(received <= context.burst_size)]];
  counters.received += received;
  if (received == 0) [[unlikely]] {
    return;
  }

  std::array<PacketMetadata, kMaxBurstCapacity> metadata{};
  std::array<FlowKey, kMaxBurstCapacity> keys{};
  std::array<BulkResult, kMaxBurstCapacity> bulk_results{};
  std::array<std::uint16_t, kMaxBurstCapacity> packet_to_parsed{};

  const std::span received_packets{packets.data(), received};
  const auto n_parsed{ParseReceivedPackets(received_packets, counters,
      metadata, keys, packet_to_parsed)};
  BulkFlowLookup(*context.flow_table, keys, n_parsed,
                 context.current_burst_tsc, bulk_results);
  FinalizePackets(context, active_ports, port_id, received_packets,
                  metadata, keys, bulk_results, packet_to_parsed,
                  transmit_buffers, transmit_counts, counters);
}

// NOTE: ProcessPortBurstBulk was explored as a future optimization
// (rte_hash_lookup_bulk to pipeline N hash lookups per call) but requires
// restructuring ClassifyPacket to expose the cached-action fast path
// without re-parsing. Estimated gain: ~1-3% over the current 120 Mpps.
// Defer until per-packet CPU cost becomes the dominant constraint again.

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
[[gnu::hot]] void ProcessWorkerIteration(WorkerContext& context, std::array<rte_mbuf*, kMaxBurstCapacity>& packets,
                                         std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
                                         std::vector<std::uint16_t>& transmit_counts) noexcept {
  const auto& active_ports{context.environment->GetActivePorts()};
  BurstCounters burst_counters;
  std::ranges::fill(transmit_counts, 0);

  for (const auto port_id : active_ports) {
    ProcessPortBurst(context, active_ports, port_id, packets, transmit_buffers, transmit_counts, burst_counters);
  }

  FlushTransmitBuffers(context, transmit_buffers, transmit_counts, burst_counters);
  AddBurstStats(context.stats, burst_counters);
  // Rate-limit the cross-core atomic flush: accumulate locally and drain
  // every kAtomicFlushBurstInterval iterations to keep shared cache lines
  // quiescent for the rest of the time.
  AddBurstCounters(context.pending_burst, burst_counters);
  if (++context.bursts_since_flush >= kAtomicFlushBurstInterval) {
    FlushAtomicCounters(*context.counters, context.pending_burst);
    context.pending_burst = {};
    context.bursts_since_flush = 0;
  }
}

/// Enqueue one received packet to the worker ring selected by flow hash.
void DispatchPacketToWorker(rte_mbuf* packet, std::uint16_t receive_port, std::span<rte_ring*> dispatch_rings,
                            BurstCounters& counters) noexcept {
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
  packet->port = receive_port;
  const auto worker_id{HashPacketFlow(*packet, receive_port) % dispatch_rings.size()};
  if (rte_ring_sp_enqueue(dispatch_rings[worker_id], packet) != 0) [[unlikely]] {
    DropPacket(counters, packet);
  }
}

/// Receive one burst from a selected RX queue and dispatch packets to workers.
void DispatchPortQueueBurst(std::uint16_t port_id, std::uint16_t queue_id, std::uint16_t burst_size,
                            std::array<rte_mbuf*, kMaxBurstCapacity>& packets, std::span<rte_ring*> dispatch_rings,
                            BurstCounters& counters) noexcept {
  const auto received{rte_eth_rx_burst(port_id, queue_id, packets.data(), burst_size)};
  [[assume(received <= kMaxBurstCapacity)]];
  [[assume(received <= burst_size)]];
  counters.received += received;

  constexpr auto kPrefetchDistance{4UZ};
  const std::span received_packets{packets.data(), received};
  for (auto i{0UZ}; i < received_packets.size(); ++i) {
    if (i + kPrefetchDistance < received_packets.size()) [[likely]] {
      rte_prefetch0(rte_pktmbuf_mtod(received_packets[i + kPrefetchDistance], void*));
    }
    DispatchPacketToWorker(received_packets[i], port_id, dispatch_rings, counters);
  }
}

/// Run one full dispatcher iteration on the main lcore.
[[gnu::hot]] void ProcessDispatchIteration(const dpdk::Environment& environment, std::uint16_t burst_size,
                                           std::array<rte_mbuf*, kMaxBurstCapacity>& packets,
                                           std::span<rte_ring*> dispatch_rings, AtomicCounters& counters) noexcept {
  BurstCounters burst_counters;
  for (const auto port_id : environment.GetActivePorts()) {
    for (std::uint16_t queue_id{0}; queue_id < environment.GetReceiveQueueCount(); ++queue_id) {
      DispatchPortQueueBurst(port_id, queue_id, burst_size, packets, dispatch_rings, burst_counters);
    }
  }
  AddBurstCounters(counters, burst_counters);
}

/// Run one worker iteration in software-dispatch mode.
void ProcessDispatchedWorkerIteration(WorkerContext& context, std::array<rte_mbuf*, kMaxBurstCapacity>& packets,
                                      std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
                                      std::vector<std::uint16_t>& transmit_counts) noexcept {
  BurstCounters burst_counters;
  std::ranges::fill(transmit_counts, 0);

  // Sample rte_rdtsc() once per burst — ForwardPacket → ClassifyPacket
  // → Lookup uses context.current_burst_tsc for the last_seen_tsc touch.
  // Single rdtsc amortized across all packets in the burst instead of
  // one per cache hit (~24 cycles each on Skylake-class).
  context.current_burst_tsc = rte_rdtsc();

  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  const auto received{rte_ring_sc_dequeue_burst(context.dispatch_ring, reinterpret_cast<void**>(packets.data()),
                                                 context.burst_size, nullptr)};
  [[assume(received <= kMaxBurstCapacity)]];
  [[assume(received <= context.burst_size)]];
  burst_counters.received += received;

  constexpr auto kPrefetchDistance{4UZ};
  const std::span received_packets{packets.data(), received};
  const auto& active_ports{context.environment->GetActivePorts()};
  for (auto i{0UZ}; i < received_packets.size(); ++i) {
    if (i + kPrefetchDistance < received_packets.size()) [[likely]] {
      rte_prefetch0(rte_pktmbuf_mtod(received_packets[i + kPrefetchDistance], void*));
    }
    auto* packet{received_packets[i]};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    ForwardPacket(context, active_ports, burst_counters, packet, packet->port, transmit_buffers, transmit_counts);
  }

  FlushTransmitBuffers(context, transmit_buffers, transmit_counts, burst_counters);
  AddBurstStats(context.stats, burst_counters);
  // Rate-limited atomic flush (see ProcessWorkerIteration for rationale).
  AddBurstCounters(context.pending_burst, burst_counters);
  if (++context.bursts_since_flush >= kAtomicFlushBurstInterval) {
    AddDispatchedWorkerCounters(*context.counters, context.pending_burst);
    context.pending_burst = {};
    context.bursts_since_flush = 0;
  }
}

/**
 * @brief Entry point for rte_eal_remote_launch workers.
 *
 * @param arg  Pointer to a WorkerContext.
 * @return 0 on exit.
 */
[[gnu::hot]] int WorkerLoop(void* arg) noexcept {
  auto* context{static_cast<WorkerContext*>(arg)};
  std::array<rte_mbuf*, kMaxBurstCapacity> packets{};
  std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>> transmit_buffers(context->environment->GetPortCount());
  std::vector<std::uint16_t> transmit_counts(context->environment->GetPortCount());

  while (context->force_quit->load(std::memory_order_relaxed) == 0) {
    ProcessWorkerIteration(*context, packets, transmit_buffers, transmit_counts);
    // Pause during in-place rule rebuilds. The main lcore sets
    // `reload_barrier` before doing the rebuild and clears it after;
    // we observe the flag at the end of each burst and spin
    // until the main lcore clears it. The acq_rel fetch_add AFTER
    // observing the barrier is what the main lcore's `workers_paused_`
    // spin-wait blocks on — without this hand-off, the main lcore
    // cannot prove every worker is quiescent before mutating
    // RuleTable / FlowTable.
    if (context->reload_barrier != nullptr && context->reload_barrier->load(std::memory_order_acquire) &&
        context->force_quit->load(std::memory_order_relaxed) == 0) {
      context->workers_paused->fetch_add(1, std::memory_order_acq_rel);
      while (context->reload_barrier->load(std::memory_order_acquire) &&
             context->force_quit->load(std::memory_order_relaxed) == 0) {
        rte_pause();
      }
      context->workers_paused->fetch_sub(1, std::memory_order_release);
    }
  }
  // Drain any unflushed counters so final stats are accurate.
  FlushAtomicCounters(*context->counters, context->pending_burst);
  context->pending_burst = {};
  return 0;
}

/// Entry point for workers that receive packets from software dispatch rings.
[[gnu::hot]] int DispatchWorkerLoop(void* arg) noexcept {
  auto* context{static_cast<WorkerContext*>(arg)};
  std::array<rte_mbuf*, kMaxBurstCapacity> packets{};
  std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>> transmit_buffers(context->environment->GetPortCount());
  std::vector<std::uint16_t> transmit_counts(context->environment->GetPortCount());

  while (context->force_quit->load(std::memory_order_relaxed) == 0) {
    ProcessDispatchedWorkerIteration(*context, packets, transmit_buffers, transmit_counts);
    // See WorkerLoop for the rationale on the acq_rel fetch_add +
    // release fetch_sub hand-off with the main lcore's
    // `workers_paused_` spin-wait.
    if (context->reload_barrier != nullptr && context->reload_barrier->load(std::memory_order_acquire) &&
        context->force_quit->load(std::memory_order_relaxed) == 0) {
      context->workers_paused->fetch_add(1, std::memory_order_acq_rel);
      while (context->reload_barrier->load(std::memory_order_acquire) &&
             context->force_quit->load(std::memory_order_relaxed) == 0) {
        rte_pause();
      }
      context->workers_paused->fetch_sub(1, std::memory_order_release);
    }
  }
  // Drain any unflushed counters so final stats are accurate.
  AddDispatchedWorkerCounters(*context->counters, context->pending_burst);
  context->pending_burst = {};
  return 0;
}

}  // namespace

/// Public: drain pending BurstCounters into the shared AtomicCounters.
/// Defined out-of-line in dpdk::spi (not in the anonymous namespace) so
/// the forward declaration in spi_pipeline.hpp matches this definition.
void FlushAtomicCounters(AtomicCounters& counters, const BurstCounters& pending) noexcept {
  counters.received.fetch_add(pending.received, std::memory_order_relaxed);
  counters.transmitted.fetch_add(pending.transmitted, std::memory_order_relaxed);
  counters.parsed.fetch_add(pending.parsed, std::memory_order_relaxed);
  counters.matched.fetch_add(pending.matched, std::memory_order_relaxed);
  counters.unknown.fetch_add(pending.unknown, std::memory_order_relaxed);
  counters.malformed.fetch_add(pending.malformed, std::memory_order_relaxed);
  counters.dropped.fetch_add(pending.dropped, std::memory_order_relaxed);
  counters.dropped_by_rule.fetch_add(pending.dropped_by_rule, std::memory_order_relaxed);
  counters.flow_cache_hits.fetch_add(pending.flow_cache_hits, std::memory_order_relaxed);
  counters.dpi_cache_hits.fetch_add(pending.dpi_cache_hits, std::memory_order_relaxed);
  counters.dpi_cache_misses.fetch_add(pending.dpi_cache_misses, std::memory_order_relaxed);
  counters.dpi_skipped_by_spi.fetch_add(pending.dpi_skipped_by_spi, std::memory_order_relaxed);
  counters.dpi_skipped_by_link.fetch_add(pending.dpi_skipped_by_link, std::memory_order_relaxed);
  counters.flow_table_full.fetch_add(pending.flow_table_full, std::memory_order_relaxed);
  counters.pressure_evictions.fetch_add(pending.pressure_evictions, std::memory_order_relaxed);
  counters.flow_table_resizes.fetch_add(pending.flow_table_resizes, std::memory_order_relaxed);
}

Pipeline::Pipeline(const dpdk::Environment& environment, RuleTable initial_rules,
                   std::unique_ptr<dpi::DpiRuleTable> dpi_rules, const DpdkConfig& config)
    : environment_{environment},
      dpi_rules_{std::move(dpi_rules)},
      rule_match_counts_(initial_rules.GroupCount()),
      worker_contexts_(static_cast<std::uint16_t>(config.spi.worker_count)),
      l3_routes_{BuildL3Routes(config.l3_forward)},
      ethernet_destinations_{BuildEthernetDestinations(config.l3_forward)},
      packet_distribution_{config.spi.packet_distribution},
      pcap_injector_{config.pcap_injector},
      dispatch_queue_size_{config.spi.dispatch_queue_size},
      burst_size_{std::clamp(config.app.burst_size, kMinBurstCapacity, kMaxBurstCapacity)},
      mac_updating_{config.app.mac_updating},
      l3_forwarding_{config.l3_forward.enabled},
      drop_unmatched_{config.spi.drop_unmatched},
      flow_ttl_sec_{config.spi.flow_ttl_sec},
      max_concurrent_flows_{config.spi.max_concurrent_flows},
      flow_overflow_drop_{config.spi.flow_overflow_action == "drop"} {
  // Allocate the flow cache with the configured hard ceiling. This is the
  // only place where flow_table_ is constructed — all hot-path lookups and
  // inserts go through the raw pointer stashed in WorkerContext.
  flow_table_ = std::make_unique<FlowTable>(max_concurrent_flows_);

  // Hand the dpi_rules unique_ptr to the manager FIRST so we can read the
  // DPI table pointer via `Load()` to resolve SPI→DPI static links below.
  if (dpi_rules_) {
    dpi_rule_manager_.Init(std::move(dpi_rules_));
  }
  // Resolve SPI→DPI static links against the active DPI table. Must run
  // before `rule_manager_.Init` because Init moves the table out of our
  // reach. `ResolveDpiLinks` mutates `initial_rules.groups_` in place to
  // populate `bound_dpi_filter_index` from each group's transient
  // `bound_dpi_name`. After resolution, the transient strings are freed.
  if (const auto* const dpi_table{dpi_rule_manager_.Load()}; dpi_table != nullptr) {
    if (const auto resolve_result{initial_rules.ResolveDpiLinks(*dpi_table)}; !resolve_result) {
      std::println(stderr, "Pipeline init failed: {}", resolve_result.error());
      std::abort();
    }
  }

  rule_manager_.Init(std::make_unique<RuleTable>(std::move(initial_rules)));
}

Pipeline::~Pipeline() {
  StopWorkers();
  DestroyDispatchRings();
}

void Pipeline::MaybeReloadFlowTable(const DpdkConfig& config) noexcept {
  const auto new_max{config.spi.max_concurrent_flows};
  if (new_max == max_concurrent_flows_) {
    return;
  }

  // Caller (the main-lcore run loop) already set reload_barrier_ and
  // slept 1 ms so workers are spinning in their pause loop. We are now
  // the only writer to `flow_table_` and to the `WorkerContext::flow_table`
  // raw pointer. Do the migration, swap, repoint.
  std::println("FlowTable resize: {} -> {} entries (migrating active flows)",
               max_concurrent_flows_, new_max);

  auto new_table{std::make_unique<FlowTable>(new_max)};
  if (!new_table->IsValid()) {
    std::println(stderr, "FlowTable resize failed: rte_hash_create({}) returned null — keeping {} entries",
                 new_max, max_concurrent_flows_);
    return;
  }

  // Best-effort migration: copy every occupied slot from the old table
  // to the new one. For a "grow" resize, all slots fit; for a "shrink"
  // resize, later slots are silently dropped (the operator shrunk the
  // table; we honour their intent and let those flows re-classify on
  // next packet). Workers are paused so no concurrent Insert / Purge
  // is in flight — no lock needed.
  std::size_t migrated{0};
  flow_table_->ForEachOccupied(
      [&new_table, &migrated](const FlowKey& key, std::uint64_t count, Action action) {
        if (new_table->InsertRaw(key, count, action) == FlowInsertResult::kOk) {
          ++migrated;
        }
      });

  // Publish: move the new table into `flow_table_` (frees the old on
  // scope exit of the local unique_ptr we're about to overwrite), then
  // repoint every worker's raw pointer. After `reload_barrier_` clears
  // (caller does this after we return), workers see the new pointer on
  // their next ProcessPortBurst.
  flow_table_ = std::move(new_table);
  for (auto& ctx : worker_contexts_) {
    ctx.flow_table = flow_table_.get();
  }
  max_concurrent_flows_ = new_max;
  counters_.flow_table_resizes.fetch_add(1, std::memory_order_relaxed);

  std::println("FlowTable resize complete: migrated={} flows, new capacity={}", migrated, new_max);
}

std::expected<void, std::string> Pipeline::StartWorkers(WorkerEntryPoint entry_point) noexcept {
  if (workers_started_) {
    return {};
  }

  const auto worker_lcores{GetWorkerLcores(worker_contexts_.size())};
  // Log assigned worker lcores.
  std::println("Worker lcores: {}", worker_lcores.size());
  for (const auto lcore_id : worker_lcores) {
    std::println("  worker lcore {}", lcore_id);
  }
  if (worker_lcores.size() != worker_contexts_.size()) {
    return std::unexpected(
        std::format("Need {} worker lcores, found {}", worker_contexts_.size(), worker_lcores.size()));
  }

  worker_force_quit_.store(0, std::memory_order_relaxed);
  for (std::size_t worker_id{0}; worker_id < worker_contexts_.size(); ++worker_id) {
    if (const auto launched{LaunchWorker(worker_id, worker_lcores[worker_id], entry_point)}; !launched) {
      return std::unexpected(launched.error());
    }
  }

  workers_started_ = true;
  return {};
}

std::expected<void, std::string> Pipeline::LaunchWorker(std::size_t worker_id, unsigned lcore_id,
                                                        WorkerEntryPoint entry_point) noexcept {
  auto& context{worker_contexts_[worker_id]};
  PrepareWorkerContext(context, worker_force_quit_, static_cast<std::uint16_t>(worker_id));

  const int ret{rte_eal_remote_launch(entry_point, &context, lcore_id)};
  if (ret == 0) {
    return {};
  }

  worker_force_quit_.store(1, std::memory_order_relaxed);
  rte_eal_mp_wait_lcore();
  return std::unexpected(
      std::format("rte_eal_remote_launch worker {} on lcore {} failed (ret={})", worker_id, lcore_id, ret));
}

void Pipeline::StopWorkers() noexcept {
  if (!workers_started_) {
    return;
  }

  worker_force_quit_.store(1, std::memory_order_relaxed);
  rte_eal_mp_wait_lcore();
  workers_started_ = false;
}

void Pipeline::PrepareWorkerContext(WorkerContext& context, const std::atomic<int>& force_quit,
                                    std::uint16_t worker_id) noexcept {
  context.environment = &environment_;
  context.rule_manager = &rule_manager_;
  context.dpi_rule_manager = &dpi_rule_manager_;
  context.flow_table = flow_table_.get();
  context.l3_routes = &l3_routes_;
  context.ethernet_destinations = &ethernet_destinations_;
  context.counters = &counters_;
  context.stats = {};
  context.pending_burst = {};
  context.bursts_since_flush = 0;
  context.rule_match_counts.assign(rule_manager_.Load()->GroupCount(), 0);
  context.dispatch_ring = worker_id < dispatch_rings_.size() ? dispatch_rings_[worker_id] : nullptr;
  context.force_quit = &force_quit;
  context.burst_size = burst_size_;
  context.worker_id = worker_id;
  context.mac_updating = mac_updating_;
  context.l3_forwarding = l3_forwarding_;
  context.drop_unmatched = drop_unmatched_;
  context.flow_overflow_drop = flow_overflow_drop_;
  context.reload_barrier = &reload_barrier_;
  context.workers_paused = &workers_paused_;
}

std::expected<void, std::string> Pipeline::CreateDispatchRings() noexcept {
  if (!dispatch_rings_.empty()) {
    return {};
  }

  dispatch_rings_.reserve(worker_contexts_.size());
  for (std::size_t worker_id{0}; worker_id < worker_contexts_.size(); ++worker_id) {
    const auto ring_name{std::format("spi_dispatch_{}", worker_id)};
    auto* const ring{rte_ring_create(
        ring_name.c_str(), static_cast<unsigned>(dispatch_queue_size_),
        static_cast<int>(rte_socket_id()), RING_F_SP_ENQ | RING_F_SC_DEQ)};
    if (ring == nullptr) {
      DestroyDispatchRings();
      return std::unexpected(
          std::format("rte_ring_create '{}' failed (rte_errno={}: {})", ring_name, rte_errno, rte_strerror(rte_errno)));
    }
    dispatch_rings_.push_back(ring);
  }
  return {};
}

void Pipeline::DestroyDispatchRings() noexcept {
  for (auto* ring : dispatch_rings_) {
    if (ring != nullptr) {
      rte_ring_free(ring);
    }
  }
  dispatch_rings_.clear();
}

std::expected<PipelineStats, std::string> Pipeline::RunMultiWorker(const std::atomic<int>& force_quit,
                                                                   std::uint32_t timer_period_sec) noexcept {
  if (environment_.GetReceiveQueueCount() < worker_contexts_.size()) {
    return std::unexpected(std::format("queue mode needs receive_queues >= worker_count ({} < {})",
                                       environment_.GetReceiveQueueCount(), worker_contexts_.size()));
  }
  if (environment_.GetTransmitQueueCount() < worker_contexts_.size()) {
    return std::unexpected(std::format("queue mode needs transmit_queues >= worker_count ({} < {})",
                                       environment_.GetTransmitQueueCount(), worker_contexts_.size()));
  }

  if (const auto started{StartWorkers(WorkerLoop)}; !started) {
    return std::unexpected(started.error());
  }

  const auto& active_ports{environment_.GetActivePorts()};
  std::println("Entering SPI packet-processing loop");
  PrintForwardMap(active_ports);
  PrintQueueMap(worker_contexts_.size());

  const auto start_tsc{rte_rdtsc()};
  std::uint64_t previous_tsc{start_tsc};
  std::uint64_t timer_tsc{};
  const auto stats_period_tsc{rte_get_tsc_hz() * timer_period_sec};
  while (force_quit.load(std::memory_order_relaxed) == 0) {
    MaybePrintStats(counters_, timer_period_sec, stats_period_tsc, previous_tsc, timer_tsc, start_tsc);
    MaybeReload(force_quit, reload_flag_, config_path_, reload_barrier_);
    if (flow_ttl_sec_ > 0 && timer_tsc == 0 && previous_tsc != 0) {
      flow_table_->PurgeExpired(rte_rdtsc(), static_cast<std::uint64_t>(flow_ttl_sec_) * rte_get_tsc_hz(), force_quit);
    }
    // Yield the main lcore when there's no work — keeps Ctrl+C latency at
    // ~100 µs while letting the scheduler put this core to sleep. `rte_pause`
    // is only a CPU PAUSE hint (~10 cycles), it spins forever at GHz and
    // makes the housekeeping loop look "stuck" in `top`.
    std::this_thread::sleep_for(std::chrono::microseconds(100));
  }

  StopWorkers();
  PrintWorkerStats(worker_contexts_);
  CollectWorkerRuleCounts();
  return CollectStats(counters_);
}

std::expected<PipelineStats, std::string> Pipeline::RunFlowHashDispatch(const std::atomic<int>& force_quit,
                                                                        std::uint32_t timer_period_sec) noexcept {
  if (environment_.GetTransmitQueueCount() < worker_contexts_.size()) {
    return std::unexpected(std::format("flow_hash mode needs transmit_queues >= worker_count ({} < {})",
                                       environment_.GetTransmitQueueCount(), worker_contexts_.size()));
  }

  if (const auto rings_created{CreateDispatchRings()}; !rings_created) {
    return std::unexpected(rings_created.error());
  }
  if (const auto started{StartWorkers(DispatchWorkerLoop)}; !started) {
    return std::unexpected(started.error());
  }

  PrintDispatchMap(environment_, worker_contexts_.size(), dispatch_queue_size_);

  std::array<rte_mbuf*, kMaxBurstCapacity> packets{};
  const auto start_tsc{rte_rdtsc()};
  std::uint64_t previous_tsc{start_tsc};
  std::uint64_t timer_tsc{};
  const auto stats_period_tsc{rte_get_tsc_hz() * timer_period_sec};
  const std::span dispatch_rings{dispatch_rings_.data(), dispatch_rings_.size()};
  while (force_quit.load(std::memory_order_relaxed) == 0) {
    static auto last_tick_tsc{std::uint64_t{rte_rdtsc()}};
    if (const auto now{rte_rdtsc()}; now - last_tick_tsc > rte_get_tsc_hz() * 5) {
      std::println(stderr, "[loop] main tick force_quit={}", force_quit.load(std::memory_order_relaxed));
      last_tick_tsc = now;
    }
    ProcessDispatchIteration(environment_, burst_size_, packets, dispatch_rings, counters_);
    MaybePrintStats(counters_, timer_period_sec, stats_period_tsc, previous_tsc, timer_tsc, start_tsc);
    MaybeReload(force_quit, reload_flag_, config_path_, reload_barrier_);
    if (flow_ttl_sec_ > 0 && timer_tsc == 0 && previous_tsc != 0) {
      flow_table_->PurgeExpired(rte_rdtsc(), static_cast<std::uint64_t>(flow_ttl_sec_) * rte_get_tsc_hz(), force_quit);
    }
  }

  StopWorkers();
  PrintWorkerStats(worker_contexts_);
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

std::expected<PipelineStats, std::string> Pipeline::RunUntilStopped(const std::atomic<int>& force_quit,
                                                                    std::atomic<int>& reload_flag,
                                                                    const std::string& config_path,
                                                                    std::uint32_t timer_period_sec) noexcept {
  config_path_ = config_path;
  reload_flag_ = &reload_flag;

  // M5: single-worker mode is removed. The pipeline now requires at least
  // two worker lcores — the main lcore alone is a serialisation point that
  // can't sustain line-rate packet processing, and it was the only path
  // that ran `ProcessWorkerIteration` on the main lcore (contending with
  // the stats/reload/purge work that RunMultiWorker keeps on the main
  // lcore for proper Ctrl+C responsiveness). Setting worker_count=1 used
  // to silently switch to a single-lcore hot path; we now refuse it so
  // the operator gets a clear error instead of a mysteriously-slow
  // pipeline.
  if (worker_contexts_.size() < 2) {
    return std::unexpected(std::format(
        "spi.worker_count must be >= 2 (got {}). Single-worker mode is "
        "no longer supported; the pipeline requires at least one main "
        "lcore plus one or more worker lcores for proper Ctrl+C "
        "responsiveness and to keep the signal-polling loop free of "
        "packet-processing work.",
        worker_contexts_.size()));
  }

  const auto packet_distribution{
      ResolvePacketDistribution(environment_, packet_distribution_, worker_contexts_.size())};
  if (packet_distribution == PacketDistribution::kFlowHash) {
    return RunFlowHashDispatch(force_quit, timer_period_sec);
  }
  return RunMultiWorker(force_quit, timer_period_sec);
}

}  // namespace dpdk::spi
