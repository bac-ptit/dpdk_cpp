#include "dpdk/spi/spi_packet_parser.hpp"

#include <netinet/in.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_prefetch.h>
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
/// Returns pointer to the valid bytes — when the data is contiguous
/// in the mbuf, DPDK returns a pointer directly into the mbuf data
/// (not `buf`); otherwise it copies into `buf`. Caller must use the
/// returned pointer, not `buf`, to read the actual bytes.
[[nodiscard]] const void* ReadPayload(const rte_mbuf& packet, std::uint32_t offset, void* buf,
                                       std::uint32_t max_len) noexcept {
  const void* data{rte_pktmbuf_read(&packet, offset, max_len, buf)};
  return data;  // nullptr means insufficient data; else ptr to bytes
}

/// Extract hostname from TLS ClientHello SNI extension.
[[nodiscard]] std::optional<std::pair<const char*, std::uint16_t>> ExtractTlsSni(
    const rte_mbuf& packet, std::uint32_t tcp_payload_offset) noexcept {
  constexpr std::uint32_t kMaxTlsInspect{512};
  alignas(1) unsigned char local_buf[kMaxTlsInspect]{};
  const auto available{rte_pktmbuf_data_len(&packet) - tcp_payload_offset};
  const auto len{std::min(available, kMaxTlsInspect)};
  if (len < 5) [[unlikely]]
    return std::nullopt;

  // Prefetch the TLS payload region into L1. The extraction walks bytes
  // 0..~120 sequentially; pulling them in early hides the DRAM round-trip.
  if (packet.nb_segs == 1) [[likely]] {
    rte_prefetch0(rte_pktmbuf_mtod_offset(&packet, void*, tcp_payload_offset));
  }

  // rte_pktmbuf_read returns a pointer to the bytes — either in the mbuf
  // itself (contiguous, zero-copy) or in `local_buf` (multi-segment).
  // Always read through this pointer, never `local_buf` directly.
  const auto* data{static_cast<const unsigned char*>(ReadPayload(packet, tcp_payload_offset, local_buf, len))};
  if (data == nullptr) [[unlikely]]
    return std::nullopt;

  // TLS record header: content_type=0x16, version>=0x0301
  if (data[0] != 0x16) [[unlikely]]
    return std::nullopt;
  if (data[1] < 0x03 || (data[1] == 0x03 && data[2] < 0x01)) [[unlikely]]
    return std::nullopt;

  // Handshake type = 0x01 (ClientHello)
  if (data[5] != 0x01) [[unlikely]]
    return std::nullopt;

  // Walk past ClientHello fixed fields: version(2) + random(32) + session_id
  std::uint32_t off{9 + 2 + 32};
  if (off >= len) return std::nullopt;

  const auto session_id_len{data[off]};
  off += 1 + session_id_len;
  if (off + 2 > len) return std::nullopt;

  // Cipher suites
  const auto cipher_len{static_cast<std::uint16_t>((data[off] << 8) | data[off + 1])};
  off += 2 + cipher_len;
  if (off + 1 > len) return std::nullopt;

  // Compression methods
  const auto comp_len{data[off]};
  off += 1 + comp_len;
  if (off + 2 > len) return std::nullopt;

  // Extensions
  const auto ext_len{static_cast<std::uint16_t>((data[off] << 8) | data[off + 1])};
  off += 2;
  const auto ext_end{std::min(off + ext_len, len)};

  while (off + 4 <= ext_end) {
    const auto ext_type{static_cast<std::uint16_t>((data[off] << 8) | data[off + 1])};
    const auto ext_data_len{static_cast<std::uint16_t>((data[off + 2] << 8) | data[off + 3])};
    if (ext_type == 0x0000 && off + 9 <= ext_end) {
      // SNI extension: list_len(2) + type(1) + name_len(2) + name
      const auto name_len{static_cast<std::uint16_t>((data[off + 7] << 8) | data[off + 8])};
      if (off + 9 + name_len <= ext_end && name_len > 0) [[likely]] {
        return std::make_pair(reinterpret_cast<const char*>(&data[off + 9]), name_len);
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
  alignas(1) unsigned char local_buf[kMaxHttpInspect]{};
  const auto available{rte_pktmbuf_data_len(&packet) - tcp_payload_offset};
  const auto len{std::min(available, kMaxHttpInspect)};
  if (len < 4) [[unlikely]]
    return std::nullopt;

  // Prefetch the HTTP request region into L1.
  if (packet.nb_segs == 1) [[likely]] {
    rte_prefetch0(rte_pktmbuf_mtod_offset(&packet, void*, tcp_payload_offset));
  }

  // rte_pktmbuf_read returns a pointer to the bytes — either in the mbuf
  // itself (contiguous, zero-copy) or in `local_buf` (multi-segment).
  const auto* data{static_cast<const unsigned char*>(ReadPayload(packet, tcp_payload_offset, local_buf, len))};
  if (data == nullptr) [[unlikely]]
    return std::nullopt;

  // Verify HTTP method prefix
  const bool is_http{data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' '};
  const bool is_post{data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T'};
  if (!is_http && !is_post) [[unlikely]]
    return std::nullopt;

  // Scan for "\r\nHost:" pattern
  for (std::uint32_t i{4}; i + 6 < len; ++i) {
    if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == 'H' && data[i + 3] == 'o' && data[i + 4] == 's' &&
        data[i + 5] == 't' && data[i + 6] == ':') {
      auto host_off{i + 7};
      // Skip optional whitespace after colon
      while (host_off < len && data[host_off] == ' ') ++host_off;
      // Find end of header value (\r\n)
      auto host_start{host_off};
      while (host_off < len && data[host_off] != '\r') ++host_off;
      if (host_off > host_start) [[likely]] {
        return std::make_pair(reinterpret_cast<const char*>(&data[host_start]),
                              static_cast<std::uint16_t>(host_off - host_start));
      }
    }
  }

  return std::nullopt;
}

}  // namespace dpdk::spi
