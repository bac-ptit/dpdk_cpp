#include "spi_packet_parser.hpp"

#include <netinet/in.h>

#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <cstddef>
#include <cstdint>

namespace {

constexpr std::uint8_t kIpv4MinIhl{5};
constexpr std::uint8_t kIpv4IhlMask{0x0f};
constexpr std::uint8_t kIpv4WordBytes{4};

// Read a header struct from an mbuf at the given byte offset.
// rte_pktmbuf_read returns a direct pointer when data is contiguous; we
// copy into the output struct when the returned pointer differs from buf.
template <typename Header>
[[nodiscard]] bool ReadHeader(const rte_mbuf& packet, std::uint32_t offset,
                              Header& header) noexcept {
  const void* data{rte_pktmbuf_read(&packet, offset, sizeof(Header), &header)};
  if (data == nullptr) {
    return false;
  }
  if (data != &header) {
    header = *static_cast<const Header*>(data);
  }
  return true;
}

}  // namespace

namespace spi {

std::optional<PacketMetadata> ParsePacket(const rte_mbuf& packet) noexcept {
  // Ethernet header at offset 0 — only IPv4 is supported.
  rte_ether_hdr ether_hdr{};
  if (!ReadHeader(packet, 0, ether_hdr)) {
    return std::nullopt;
  }

  if (rte_be_to_cpu_16(ether_hdr.ether_type) != RTE_ETHER_TYPE_IPV4) {
    return std::nullopt;
  }

  // IPv4 header right after the ethernet header.
  constexpr std::uint32_t ipv4_offset{sizeof(rte_ether_hdr)};
  rte_ipv4_hdr ipv4_hdr{};
  if (!ReadHeader(packet, ipv4_offset, ipv4_hdr)) {
    return std::nullopt;
  }

  const auto ihl{static_cast<std::uint8_t>(
      ipv4_hdr.version_ihl & kIpv4IhlMask)};
  if (ihl < kIpv4MinIhl) {
    return std::nullopt;
  }

  const auto ipv4_header_len{static_cast<std::size_t>(ihl) * kIpv4WordBytes};
  const auto l4_offset{
      static_cast<std::uint32_t>(ipv4_offset + ipv4_header_len)};

  // TCP — extract source/destination port.
  if (ipv4_hdr.next_proto_id == IPPROTO_TCP) {
    rte_tcp_hdr tcp_hdr{};
    if (!ReadHeader(packet, l4_offset, tcp_hdr)) {
      return std::nullopt;
    }

    return PacketMetadata{
        .protocol = Protocol::kTcp,
        .src_port = rte_be_to_cpu_16(tcp_hdr.src_port),
        .dst_port = rte_be_to_cpu_16(tcp_hdr.dst_port),
    };
  }

  // UDP — extract source/destination port.
  if (ipv4_hdr.next_proto_id == IPPROTO_UDP) {
    rte_udp_hdr udp_hdr{};
    if (!ReadHeader(packet, l4_offset, udp_hdr)) {
      return std::nullopt;
    }

    return PacketMetadata{
        .protocol = Protocol::kUdp,
        .src_port = rte_be_to_cpu_16(udp_hdr.src_port),
        .dst_port = rte_be_to_cpu_16(udp_hdr.dst_port),
    };
  }

  // Unsupported L4 protocol (ICMP, SCTP, etc.).
  return std::nullopt;
}

}  // namespace spi
