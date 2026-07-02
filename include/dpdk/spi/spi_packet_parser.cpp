#include "dpdk/spi/spi_packet_parser.hpp"

#include <netinet/in.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

namespace {

template <typename Header>
[[nodiscard, gnu::always_inline]] inline bool ReadHeader(const rte_mbuf& packet, std::uint32_t offset,
                                                         Header& header) noexcept {
  const void* data{rte_pktmbuf_read(&packet, offset, sizeof(Header), &header)};
  if (data == nullptr) [[unlikely]] {
    return false;
  }
  if (data != &header) {
    header = *static_cast<const Header*>(data);
  }
  return true;
}

template <typename L4Header>
[[nodiscard, gnu::always_inline]] inline std::optional<dpdk::spi::PacketMetadata> ParseL4(
    const rte_mbuf& packet, std::uint32_t l4_offset, const rte_ipv4_hdr& ipv4_hdr,
    const dpdk::spi::Protocol proto) noexcept {
  L4Header hdr{};
  if (!ReadHeader(packet, l4_offset, hdr)) [[unlikely]] {
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

[[nodiscard, gnu::hot]] std::optional<PacketMetadata> ParsePacket(const rte_mbuf& packet) noexcept {
  rte_ether_hdr ether_hdr{};
  if (!ReadHeader(packet, 0, ether_hdr)) [[unlikely]] {
    return std::nullopt;
  }

  // Most packets in a firewall are IPv4.
  if (rte_be_to_cpu_16(ether_hdr.ether_type) != RTE_ETHER_TYPE_IPV4) [[unlikely]] {
    return std::nullopt;
  }

  constexpr std::uint32_t ipv4_offset{sizeof(rte_ether_hdr)};
  rte_ipv4_hdr ipv4_hdr{};
  if (!ReadHeader(packet, ipv4_offset, ipv4_hdr)) [[unlikely]] {
    return std::nullopt;
  }

  const auto ipv4_header_len{rte_ipv4_hdr_len(&ipv4_hdr)};
  if (ipv4_header_len < sizeof(rte_ipv4_hdr)) [[unlikely]] {
    return std::nullopt;
  }

  const auto l4_offset{static_cast<std::uint32_t>(ipv4_offset + ipv4_header_len)};

  // TCP is the dominant protocol in most deployments.
  if (ipv4_hdr.next_proto_id == IPPROTO_TCP) [[likely]] {
    return ParseL4<rte_tcp_hdr>(packet, l4_offset, ipv4_hdr, Protocol::kTcp);
  }

  if (ipv4_hdr.next_proto_id == IPPROTO_UDP) {
    return ParseL4<rte_udp_hdr>(packet, l4_offset, ipv4_hdr, Protocol::kUdp);
  }

  return std::nullopt;
}

/// Read up to max_len bytes from mbuf into local buffer.
[[nodiscard]] std::uint32_t ReadPayload(const rte_mbuf& packet, std::uint32_t offset, void* buf,
                                        std::uint32_t max_len) noexcept {
  const void* data{rte_pktmbuf_read(&packet, offset, max_len, buf)};
  if (data == nullptr) [[unlikely]]
    return 0;
  if (data == buf) return max_len;
  return max_len;  // rte_pktmbuf_read copies to buf
}

/// Extract hostname from TLS ClientHello SNI extension.
[[nodiscard]] std::optional<std::pair<const char*, std::uint16_t>> ExtractTlsSni(
    const rte_mbuf& packet, std::uint32_t tcp_payload_offset) noexcept {
  constexpr std::uint32_t kMaxTlsInspect{512};
  alignas(1) unsigned char buf[kMaxTlsInspect]{};
  const auto available{rte_pktmbuf_data_len(&packet) - tcp_payload_offset};
  const auto len{std::min(available, kMaxTlsInspect)};
  if (len < 5) [[unlikely]]
    return std::nullopt;

  const auto copied{ReadPayload(packet, tcp_payload_offset, buf, len)};
  if (copied < 5) [[unlikely]]
    return std::nullopt;

  // TLS record header: content_type=0x16, version>=0x0301
  if (buf[0] != 0x16) [[unlikely]]
    return std::nullopt;
  if (buf[1] < 0x03 || (buf[1] == 0x03 && buf[2] < 0x01)) [[unlikely]]
    return std::nullopt;

  // Handshake type = 0x01 (ClientHello)
  if (buf[5] != 0x01) [[unlikely]]
    return std::nullopt;

  // Walk past ClientHello fixed fields: version(2) + random(32) + session_id
  std::uint32_t off{9 + 2 + 32};
  if (off >= len) return std::nullopt;

  const auto session_id_len{buf[off]};
  off += 1 + session_id_len;
  if (off + 2 > len) return std::nullopt;

  // Cipher suites
  const auto cipher_len{static_cast<std::uint16_t>((buf[off] << 8) | buf[off + 1])};
  off += 2 + cipher_len;
  if (off + 1 > len) return std::nullopt;

  // Compression methods
  const auto comp_len{buf[off]};
  off += 1 + comp_len;
  if (off + 2 > len) return std::nullopt;

  // Extensions
  const auto ext_len{static_cast<std::uint16_t>((buf[off] << 8) | buf[off + 1])};
  off += 2;
  const auto ext_end{std::min(off + ext_len, static_cast<std::uint32_t>(len))};

  while (off + 4 <= ext_end) {
    const auto ext_type{static_cast<std::uint16_t>((buf[off] << 8) | buf[off + 1])};
    const auto ext_data_len{static_cast<std::uint16_t>((buf[off + 2] << 8) | buf[off + 3])};
    if (ext_type == 0x0000 && off + 9 <= ext_end) {
      // SNI extension: list_len(2) + type(1) + name_len(2) + name
      const auto name_len{static_cast<std::uint16_t>((buf[off + 7] << 8) | buf[off + 8])};
      if (off + 9 + name_len <= ext_end && name_len > 0) [[likely]] {
        return std::make_pair(reinterpret_cast<const char*>(&buf[off + 9]), name_len);
      }
    }
    off += 4 + ext_data_len;
  }

  return std::nullopt;
}

/// Extract hostname from HTTP Host header.
[[nodiscard]] std::optional<std::pair<const char*, std::uint16_t>> ExtractHttpHost(
    const rte_mbuf& packet, std::uint32_t tcp_payload_offset) noexcept {
  constexpr std::uint32_t kMaxHttpInspect{256};
  alignas(1) unsigned char buf[kMaxHttpInspect]{};
  const auto available{rte_pktmbuf_data_len(&packet) - tcp_payload_offset};
  const auto len{std::min(available, kMaxHttpInspect)};
  if (len < 4) [[unlikely]]
    return std::nullopt;

  const auto copied{ReadPayload(packet, tcp_payload_offset, buf, len)};
  if (copied < 4) [[unlikely]]
    return std::nullopt;

  // Verify HTTP method prefix
  const bool is_http{buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' '};
  const bool is_post{buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T'};
  if (!is_http && !is_post) [[unlikely]]
    return std::nullopt;

  // Scan for "\r\nHost:" pattern
  for (std::uint32_t i{4}; i + 6 < len; ++i) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == 'H' && buf[i + 3] == 'o' && buf[i + 4] == 's' &&
        buf[i + 5] == 't' && buf[i + 6] == ':') {
      auto host_off{i + 7};
      // Skip optional whitespace after colon
      while (host_off < len && buf[host_off] == ' ') ++host_off;
      // Find end of header value (\r\n)
      auto host_start{host_off};
      while (host_off < len && buf[host_off] != '\r') ++host_off;
      if (host_off > host_start) [[likely]] {
        return std::make_pair(reinterpret_cast<const char*>(&buf[host_start]),
                              static_cast<std::uint16_t>(host_off - host_start));
      }
    }
  }

  return std::nullopt;
}

}  // namespace dpdk::spi
