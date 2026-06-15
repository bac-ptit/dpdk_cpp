#include "spi_packet_parser.hpp"

#include <netinet/in.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

namespace {

template <typename Header>
[[nodiscard]] bool ReadHeader(const rte_mbuf& packet, std::uint32_t offset, Header& header) noexcept {
  const void* data{rte_pktmbuf_read(&packet, offset, sizeof(Header), &header)};
  if (data == nullptr) {
    return false;
  }
  if (data != &header) {
    header = *static_cast<const Header*>(data);
  }
  return true;
}

template <typename L4Header>
[[nodiscard]] std::optional<dpdk::spi::PacketMetadata> ParseL4(const rte_mbuf& packet, std::uint32_t l4_offset,
                                                               const rte_ipv4_hdr& ipv4_hdr,
                                                               const dpdk::spi::Protocol proto) noexcept {
  L4Header hdr{};
  if (!ReadHeader(packet, l4_offset, hdr)) {
    return std::nullopt;
  }
  return dpdk::spi::PacketMetadata{
      .protocol = proto,
      .source_ip_address = rte_be_to_cpu_32(ipv4_hdr.src_addr),
      .destination_ip_address = rte_be_to_cpu_32(ipv4_hdr.dst_addr),
      .source_port = rte_be_to_cpu_16(hdr.src_port),
      .destination_port = rte_be_to_cpu_16(hdr.dst_port),
  };
}

}  // namespace

namespace dpdk::spi {

std::optional<PacketMetadata> ParsePacket(const rte_mbuf& packet) noexcept {
  rte_ether_hdr ether_hdr{};
  if (!ReadHeader(packet, 0, ether_hdr)) {
    return std::nullopt;
  }

  if (rte_be_to_cpu_16(ether_hdr.ether_type) != RTE_ETHER_TYPE_IPV4) {
    return std::nullopt;
  }

  constexpr std::uint32_t ipv4_offset{sizeof(rte_ether_hdr)};
  rte_ipv4_hdr ipv4_hdr{};
  if (!ReadHeader(packet, ipv4_offset, ipv4_hdr)) {
    return std::nullopt;
  }

  const auto ipv4_header_len{rte_ipv4_hdr_len(&ipv4_hdr)};
  if (ipv4_header_len < sizeof(rte_ipv4_hdr)) {
    return std::nullopt;
  }

  const auto l4_offset{static_cast<std::uint32_t>(ipv4_offset + ipv4_header_len)};

  if (ipv4_hdr.next_proto_id == IPPROTO_TCP) {
    return ParseL4<rte_tcp_hdr>(packet, l4_offset, ipv4_hdr, Protocol::kTcp);
  }

  if (ipv4_hdr.next_proto_id == IPPROTO_UDP) {
    return ParseL4<rte_udp_hdr>(packet, l4_offset, ipv4_hdr, Protocol::kUdp);
  }

  return std::nullopt;
}

}  // namespace dpdk::spi
