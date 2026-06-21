#include "spi_pipeline.hpp"

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

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <csignal>
#include <expected>
#include <format>
#include <iterator>
#include <optional>
#include <string>
#include <print>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "spi_ip_address.hpp"
#include "spi_packet_parser.hpp"

namespace dpdk::spi {
namespace {

constexpr std::uint16_t kMaxBurstCapacity{64};
constexpr std::uint16_t kMinBurstCapacity{1};
constexpr std::size_t kIpv4AddressBitCount{32};
constexpr std::uint8_t kHexBase{10};
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

/// Runtime packet-distribution mode.
enum class PacketDistribution {
  kQueuePerWorker,
  kFlowHash,
};

/// Classification outcome for one packet.
struct PacketClassification {
  PacketMetadata metadata{};
  bool parsed{false};
  bool matched{false};
};

/// Return a host-byte-order IPv4 prefix mask.
[[nodiscard]] constexpr std::uint32_t PrefixMask(std::uint16_t prefix_length) noexcept {
  if (prefix_length == 0) {
    return 0;
  }
  return UINT32_MAX << (kIpv4AddressBitCount - prefix_length);
}

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
  for (std::size_t shift{0}; shift < sizeof(value) * 8U; shift += 8U) {
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

/// Fold worker-side counters in dispatcher mode without double-counting RX.
void AddDispatchedWorkerCounters(AtomicCounters& counters, const BurstCounters& burst) noexcept {
  counters.transmitted.fetch_add(burst.transmitted, std::memory_order_relaxed);
  counters.parsed.fetch_add(burst.parsed, std::memory_order_relaxed);
  counters.matched.fetch_add(burst.matched, std::memory_order_relaxed);
  counters.unknown.fetch_add(burst.unknown, std::memory_order_relaxed);
  counters.malformed.fetch_add(burst.malformed, std::memory_order_relaxed);
  counters.dropped.fetch_add(burst.dropped, std::memory_order_relaxed);
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

/// Print final packet counters for each worker queue.
void PrintWorkerStats(const std::vector<WorkerContext>& contexts) noexcept {
  for (const auto& context : contexts) {
    const auto& stats{context.stats};
    std::println(
        "Worker {} stats: received={} transmitted={} parsed={} matched={} "
        "unknown={} malformed={} dropped={}",
        context.worker_id, stats.received, stats.transmitted, stats.parsed, stats.matched, stats.unknown,
        stats.malformed, stats.dropped);
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

/// Print software dispatcher assignment per worker.
void PrintDispatchMap(std::size_t worker_count, std::uint32_t queue_size) noexcept {
  std::println("Dispatch map: main lcore receives packets and flow-hashes into {} worker rings", worker_count);
  for (std::size_t worker_id{0}; worker_id < worker_count; ++worker_id) {
    std::println("Dispatch map: worker {} -> ring size {} / transmit queue {}", worker_id, queue_size, worker_id);
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
  if (environment.HasSoftwareBackedPort()) {
    std::println("Packet distribution: flow_hash (auto, software/vNIC PMD detected)");
    return PacketDistribution::kFlowHash;
  }
  if (!environment.ActivePortsSupportRss()) {
    std::println("Packet distribution: flow_hash (auto, active ports report no RSS offloads)");
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
 * @return Parsed metadata plus whether a SPI rule matched.
 */
[[nodiscard]] PacketClassification ClassifyPacket(WorkerContext& context, BurstCounters& counters,
                                                  const rte_mbuf& packet) noexcept {
  if (const auto metadata{ParsePacket(packet)}) {
    ++counters.parsed;
    if (const auto match{context.rules->Match(*metadata)}) {
      ++counters.matched;
      ++context.rule_match_counts[match->rule_index];
      PacketClassification result;
      result.metadata = *metadata;
      result.parsed = true;
      result.matched = true;
      return result;
    }

    ++counters.unknown;
    PacketClassification unknown_result;
    unknown_result.metadata = *metadata;
    unknown_result.parsed = true;
    return unknown_result;
  }

  ++counters.malformed;
  return {};
}

/// Increment dropped counter and free the mbuf.
void DropPacket(BurstCounters& counters, rte_mbuf* packet) noexcept {
  ++counters.dropped;
  rte_pktmbuf_free(packet);
}

/// Resolve output port via L2 pairing or L3 route lookup.
[[nodiscard]] std::optional<std::uint16_t> ResolveTransmitPort(
    const WorkerContext& context, const PacketClassification& classification,
    const std::vector<std::uint16_t>& active_ports, std::uint16_t receive_port) noexcept {
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
void EnqueuePacket(rte_mbuf* packet, std::uint16_t transmit_port,
                   std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
                   std::vector<std::uint16_t>& transmit_counts) noexcept {
  [[assume(transmit_port < transmit_buffers.size())]];
  auto& count{transmit_counts[transmit_port]};
  *std::next(transmit_buffers[transmit_port].data(), static_cast<std::ptrdiff_t>(count)) = packet;
  ++count;
}

/// Prefetch each packet in the burst into the CPU cache.
void PrefetchPackets(std::span<rte_mbuf*> packets) noexcept {
  for (auto* packet : packets) {
    rte_prefetch0(rte_pktmbuf_mtod(packet, void*));
  }
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
void ForwardPacket(WorkerContext& context, const std::vector<std::uint16_t>& active_ports, BurstCounters& counters,
                   rte_mbuf* packet, std::uint16_t receive_port,
                   std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>>& transmit_buffers,
                   std::vector<std::uint16_t>& transmit_counts) noexcept {
  const auto classification{ClassifyPacket(context, counters, *packet)};
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
void FlushTransmitBuffers(WorkerContext const& context,
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
  [[assume(received <= kMaxBurstCapacity)]];
  [[assume(received <= context.burst_size)]];
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
  AddBurstStats(context.stats, burst_counters);
  AddBurstCounters(*context.counters, burst_counters);
}

/// Enqueue one received packet to the worker ring selected by flow hash.
void DispatchPacketToWorker(rte_mbuf* packet, std::uint16_t receive_port, std::span<rte_ring*> dispatch_rings,
                            BurstCounters& counters) noexcept {
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

  const std::span received_packets{packets.data(), received};
  PrefetchPackets(received_packets);
  for (auto* packet : received_packets) {
    DispatchPacketToWorker(packet, port_id, dispatch_rings, counters);
  }
}

/// Run one full dispatcher iteration on the main lcore.
void ProcessDispatchIteration(const dpdk::Environment& environment, std::uint16_t burst_size,
                              std::array<rte_mbuf*, kMaxBurstCapacity>& packets, std::span<rte_ring*> dispatch_rings,
                              AtomicCounters& counters) noexcept {
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

  const auto received{rte_ring_sc_dequeue_burst(context.dispatch_ring, reinterpret_cast<void**>(packets.data()),
                                                context.burst_size, nullptr)};
  [[assume(received <= kMaxBurstCapacity)]];
  [[assume(received <= context.burst_size)]];
  burst_counters.received += received;

  const std::span received_packets{packets.data(), received};
  PrefetchPackets(received_packets);
  const auto& active_ports{context.environment->GetActivePorts()};
  for (auto* packet : received_packets) {
    ForwardPacket(context, active_ports, burst_counters, packet, packet->port, transmit_buffers, transmit_counts);
  }

  FlushTransmitBuffers(context, transmit_buffers, transmit_counts, burst_counters);
  AddBurstStats(context.stats, burst_counters);
  AddDispatchedWorkerCounters(*context.counters, burst_counters);
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

/// Entry point for workers that receive packets from software dispatch rings.
int DispatchWorkerLoop(void* arg) noexcept {
  auto* context{static_cast<WorkerContext*>(arg)};
  std::array<rte_mbuf*, kMaxBurstCapacity> packets{};
  std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>> transmit_buffers(context->environment->GetPortCount());
  std::vector<std::uint16_t> transmit_counts(context->environment->GetPortCount());

  while (*context->force_quit == 0) {
    ProcessDispatchedWorkerIteration(*context, packets, transmit_buffers, transmit_counts);
  }
  return 0;
}

}  // namespace

Pipeline::Pipeline(const dpdk::Environment& environment, const RuleTable& rules, std::uint16_t burst_size,
                   std::uint16_t worker_count, bool mac_updating, const L3ForwardConfig& l3_forward,
                   bool drop_unmatched, std::string packet_distribution, std::uint32_t dispatch_queue_size)
    : environment_{environment},
      rules_{rules},
      rule_match_counts_(rules.Size()),
      worker_contexts_(worker_count),
      l3_routes_{BuildL3Routes(l3_forward)},
      ethernet_destinations_{BuildEthernetDestinations(l3_forward)},
      packet_distribution_{std::move(packet_distribution)},
      dispatch_queue_size_{dispatch_queue_size},
      burst_size_{std::clamp(burst_size, kMinBurstCapacity, kMaxBurstCapacity)},
      mac_updating_{mac_updating},
      l3_forwarding_{l3_forward.enabled},
      drop_unmatched_{drop_unmatched} {}

Pipeline::~Pipeline() {
  StopWorkers();
  DestroyDispatchRings();
}

std::expected<void, std::string> Pipeline::StartWorkers(WorkerEntryPoint entry_point) noexcept {
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
  context.l3_routes = &l3_routes_;
  context.ethernet_destinations = &ethernet_destinations_;
  context.counters = &counters_;
  context.stats = {};
  context.rule_match_counts.assign(rules_.Size(), 0);
  context.dispatch_ring = worker_id < dispatch_rings_.size() ? dispatch_rings_[worker_id] : nullptr;
  context.force_quit = &force_quit;
  context.burst_size = burst_size_;
  context.worker_id = worker_id;
  context.mac_updating = mac_updating_;
  context.l3_forwarding = l3_forwarding_;
  context.drop_unmatched = drop_unmatched_;
}

std::expected<void, std::string> Pipeline::CreateDispatchRings() noexcept {
  if (!dispatch_rings_.empty()) {
    return {};
  }

  dispatch_rings_.reserve(worker_contexts_.size());
  for (std::size_t worker_id{0}; worker_id < worker_contexts_.size(); ++worker_id) {
    const auto ring_name{std::format("spi_dispatch_{}", worker_id)};
    rte_ring* ring{rte_ring_create(ring_name.c_str(), dispatch_queue_size_, rte_socket_id(),
                                   RING_F_SP_ENQ | RING_F_SC_DEQ)};
    if (ring == nullptr) {
      DestroyDispatchRings();
      return std::unexpected(std::format("rte_ring_create '{}' failed (rte_errno={}: {})", ring_name, rte_errno,
                                         rte_strerror(rte_errno)));
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

  rule_match_counts_ = std::move(context.rule_match_counts);
  PrintWorkerStats(worker_contexts_);
  return CollectStats(counters_);
}

std::expected<PipelineStats, std::string> Pipeline::RunMultiWorker(const volatile std::sig_atomic_t& force_quit,
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

  std::uint64_t previous_tsc{rte_rdtsc()};
  std::uint64_t timer_tsc{};
  const auto stats_period_tsc{rte_get_tsc_hz() * timer_period_sec};
  while (force_quit == 0) {
    MaybePrintStats(counters_, timer_period_sec, stats_period_tsc, previous_tsc, timer_tsc);
    rte_pause();
  }

  StopWorkers();
  PrintWorkerStats(worker_contexts_);
  CollectWorkerRuleCounts();
  return CollectStats(counters_);
}

std::expected<PipelineStats, std::string> Pipeline::RunFlowHashDispatch(
    const volatile std::sig_atomic_t& force_quit, std::uint32_t timer_period_sec) noexcept {
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

  const auto& active_ports{environment_.GetActivePorts()};
  std::println("Entering SPI packet-processing loop");
  std::println("Software flow-hash dispatcher mode on main lcore");
  PrintForwardMap(active_ports);
  PrintDispatchMap(worker_contexts_.size(), dispatch_queue_size_);

  std::array<rte_mbuf*, kMaxBurstCapacity> packets{};
  std::uint64_t previous_tsc{rte_rdtsc()};
  std::uint64_t timer_tsc{};
  const auto stats_period_tsc{rte_get_tsc_hz() * timer_period_sec};
  const std::span dispatch_rings{dispatch_rings_.data(), dispatch_rings_.size()};
  while (force_quit == 0) {
    ProcessDispatchIteration(environment_, burst_size_, packets, dispatch_rings, counters_);
    MaybePrintStats(counters_, timer_period_sec, stats_period_tsc, previous_tsc, timer_tsc);
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

std::expected<PipelineStats, std::string> Pipeline::RunUntilStopped(const volatile std::sig_atomic_t& force_quit,
                                                                    std::uint32_t timer_period_sec) noexcept {
  if (worker_contexts_.size() == 1) {
    return RunSingleWorker(force_quit, timer_period_sec);
  }

  const auto packet_distribution{
      ResolvePacketDistribution(environment_, packet_distribution_, worker_contexts_.size())};
  if (packet_distribution == PacketDistribution::kFlowHash) {
    return RunFlowHashDispatch(force_quit, timer_period_sec);
  }
  return RunMultiWorker(force_quit, timer_period_sec);
}

}  // namespace dpdk::spi
