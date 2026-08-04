#include "dpdk/spi/spi_packet_parser.hpp"

#include <netinet/in.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_ip6.h>
#include <rte_ip_frag.h>
#include <rte_prefetch.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <array>
#include <cstring>
#include <span>

namespace {

/// Slow-path header reader for multi-segment mbufs. Falls back to
/// `rte_pktmbuf_read`, which walks the segment chain and linearizes.
template <typename Header>
[[nodiscard, gnu::always_inline]] inline bool ReadHeader(const rte_mbuf& packet,
                                                         std::uint32_t offset,
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

/// Fast-path header reader for single-segment mbufs (the common case for
/// MTU ≤ 1500 with a 2176-byte mempool buffer).
///
/// `rte_pktmbuf_read()` is a function call that does:
///   1. Function prologue + parameter marshalling (~5-10 cycles).
///   2. `nb_segs == 1` branch (predictable, ~1 cycle).
///   3. `offset + len <= data_len` bounds check.
///   4. Pointer arithmetic.
/// Then the caller does another branch (was the read linear?) and a copy.
///
/// This helper inlines the same checks but:
///   - One branch (single-segment fast path).
///   - One bounds check.
///   - Direct cast + copy.
/// - Skip `rte_pktmbuf_read`'s call/return overhead (~10-20 cycles per
///   header). With 3 headers (eth + ipv4 + tcp/udp) per packet, ~30-60
///   cycles saved on the cache-hit hot path.
/// - Skips a redundant copy when `data != &header` in the slow path.
///
/// Mirrors the DPDK l3fwd sample's pattern of casting `rte_pktmbuf_mtod`
/// directly on single-segment mbufs.
template <typename Header>
[[nodiscard, gnu::always_inline]] inline bool ReadHeaderFast(const rte_mbuf& packet,
                                                             std::uint32_t offset,
                                                             Header& header) noexcept {
  if (packet.nb_segs != 1) [[unlikely]] {
    return ReadHeader(packet, offset, header);
  }
  if (offset + sizeof(Header) > packet.data_len) [[unlikely]] {
    return false;
  }
  const void* data{rte_pktmbuf_mtod_offset(&packet, void*, offset)};
  header = *static_cast<const Header*>(data);
  return true;
}

[[nodiscard, gnu::always_inline]] inline bool IsIpv4Fragmented(const rte_ipv4_hdr& ipv4_hdr) noexcept {
  return rte_ipv4_frag_pkt_is_fragmented(&ipv4_hdr) != 0;
}

[[nodiscard, gnu::always_inline]] inline bool IsValidFragment(const rte_ipv4_hdr& ipv4_hdr) noexcept {
  const std::uint16_t flag_offset{rte_be_to_cpu_16(ipv4_hdr.fragment_offset)};
  const std::uint16_t offset{static_cast<std::uint16_t>((flag_offset & RTE_IPV4_HDR_OFFSET_MASK) * 8)};
  const std::uint16_t mf{static_cast<std::uint16_t>(flag_offset & RTE_IPV4_HDR_MF_FLAG)};

  if (offset == 0 && mf != 0) {
    const std::uint16_t total_len{rte_be_to_cpu_16(ipv4_hdr.total_length)};
    const std::uint32_t header_len{rte_ipv4_hdr_len(&ipv4_hdr)};
    if (total_len < header_len + 8) {
      return false; // OWASP: Drop tiny fragment attack
    }
  }
  return true;
}

[[nodiscard, gnu::always_inline]] inline std::uint16_t ReadUint16Be(
    std::span<const unsigned char> data, std::uint32_t offset) noexcept {
  constexpr std::uint32_t kByteShift{8U};
  return static_cast<std::uint16_t>(
      (static_cast<std::uint32_t>(data[offset]) << kByteShift) |
       static_cast<std::uint32_t>(data[offset + 1U]));
}

template <typename L4Header>
[[nodiscard, gnu::always_inline]] inline std::optional<dpdk::spi::PacketMetadata>
ParseL4(const rte_mbuf& packet, std::uint32_t l4_offset,
        const rte_ipv4_hdr& ipv4_hdr,
        const dpdk::spi::Protocol proto) noexcept {
  L4Header hdr{};
  if (!ReadHeaderFast(packet, l4_offset, hdr)) [[unlikely]] {
    return std::nullopt;
  }
  return dpdk::spi::PacketMetadata{
      .source_ip_be = ipv4_hdr.src_addr,
      .destination_ip_be = ipv4_hdr.dst_addr,
      .source_port_be = hdr.src_port,
      .destination_port_be = hdr.dst_port,
      .protocol = proto,
      .ip_version = dpdk::spi::IpVersion::kIpv4,
  };
}

template <typename L4Header>
[[nodiscard, gnu::always_inline]] inline std::optional<dpdk::spi::PacketMetadata>
ParseL4Ipv6(const rte_mbuf& packet, std::uint32_t l4_offset,
            const rte_ipv6_hdr& ipv6_hdr,
            const dpdk::spi::Protocol proto) noexcept {
  L4Header hdr{};
  if (!ReadHeaderFast(packet, l4_offset, hdr)) [[unlikely]] {
    return std::nullopt;
  }
  dpdk::spi::PacketMetadata meta{
      .source_port_be = hdr.src_port,
      .destination_port_be = hdr.dst_port,
      .protocol = proto,
      .ip_version = dpdk::spi::IpVersion::kIpv6,
  };
  std::memcpy(meta.source_ip6_address.data(), &ipv6_hdr.src_addr, 16);
  std::memcpy(meta.destination_ip6_address.data(), &ipv6_hdr.dst_addr, 16);
  return meta;
}

[[nodiscard]] const void* ReadPayload(const rte_mbuf& packet,
                                      std::uint32_t offset, void* buf,
                                      std::uint32_t max_len) noexcept {
  return rte_pktmbuf_read(&packet, offset, max_len, buf);
}

// ---------------------------------------------------------------------------
// TLS ClientHello helpers
// ---------------------------------------------------------------------------

/// Validate TLS record header: content_type=0x16, version>=0x0301,
/// handshake type=ClientHello (0x01).
[[nodiscard]] bool ValidateTlsRecordHeader(
    std::span<const unsigned char> data) noexcept {
  constexpr std::uint8_t kTlsContentTypeHandshake{0x16U};
  constexpr std::uint8_t kTlsVersionMajor{0x03U};
  constexpr std::uint8_t kTlsVersionMinorMin{0x01U};
  constexpr std::uint8_t kHandshakeClientHello{0x01U};
  constexpr std::uint32_t kHandshakeTypeOffset{5U};

  if (data[0] != kTlsContentTypeHandshake) [[unlikely]] {
    return false;
  }
  if (data[1] < kTlsVersionMajor ||
      (data[1] == kTlsVersionMajor &&
       data[2] < kTlsVersionMinorMin)) [[unlikely]] {
    return false;
  }
  return data[kHandshakeTypeOffset] == kHandshakeClientHello;
}

/// Walk past ClientHello fixed fields and variable-length sections
/// (session_id, cipher_suites, compression_methods).  Returns the
/// byte offset to the start of the extensions block.
[[nodiscard]] std::optional<std::uint32_t> WalkClientHelloPreamble(
    std::span<const unsigned char> data) noexcept {
  // version(2) + random(32) + session_id_len(1)
  constexpr std::uint32_t kClientHelloFixedLen{9U + 2U + 32U};

  std::uint32_t off{kClientHelloFixedLen};
  if (off >= data.size()) {
    return std::nullopt;
  }

  const auto session_id_len{data[off]};
  off += 1U + session_id_len;
  if (off + 2U > data.size()) {
    return std::nullopt;
  }

  const auto cipher_len{ReadUint16Be(data, off)};
  off += 2U + cipher_len;
  if (off + 1U > data.size()) {
    return std::nullopt;
  }

  const auto comp_len{data[off]};
  off += 1U + comp_len;
  if (off + 2U > data.size()) {
    return std::nullopt;
  }

  return off;
}

/// Walk TLS extensions starting at `ext_offset` and extract the
/// SNI hostname.  `ext_end` is the upper bound (min of declared
/// extension length and data size).
[[nodiscard]] std::optional<std::pair<const char*, std::uint16_t>>
FindSniExtension(std::span<const unsigned char> data,
                 std::uint32_t ext_offset) noexcept {
  constexpr std::uint16_t kSniExtensionType{0x0000U};
  constexpr std::uint32_t kSniHeaderLen{9U};

  const auto ext_len{ReadUint16Be(data, ext_offset)};
  ext_offset += 2U;
  const auto ext_end{
      std::min(ext_offset + ext_len,
               static_cast<std::uint32_t>(data.size()))};

  while (ext_offset + 4U <= ext_end) {
    const auto ext_type{ReadUint16Be(data, ext_offset)};
    const auto ext_data_len{ReadUint16Be(data, ext_offset + 2U)};
    if (ext_type == kSniExtensionType &&
        ext_offset + kSniHeaderLen <= ext_end) {
      if (const auto name_len{ReadUint16Be(data, ext_offset + 7U)};
          ext_offset + kSniHeaderLen + name_len <= ext_end &&
          name_len > 0) [[likely]] {

        return std::make_pair(    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            reinterpret_cast<const char*>(
                &data[ext_offset + kSniHeaderLen]),
            name_len);
      }
    }
    ext_offset += 4U + ext_data_len;
  }

  return std::nullopt;
}

// ---------------------------------------------------------------------------
// HTTP Host header helpers
// ---------------------------------------------------------------------------

/// Verify that the TCP payload starts with a known HTTP request-method
/// prefix. Covers the seven standard RFC 7231 / RFC 5789 methods plus the
/// historical "PATCH " (third-party API tooling). Anything that fails
/// this check is not a request (could be an HTTP response starting with
/// "HTTP/1.1", a CONNECT tunnel handshake, garbage, etc.) and `ExtractHttpHost`
/// will return nullopt without scanning for a `Host:` header.
[[nodiscard]] constexpr bool IsHttpMethodValid(const std::span<const unsigned char> data) noexcept {
  return (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ')
      || (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T')
      || (data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D')
      || (data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ')
      || (data[0] == 'D' && data[1] == 'E' && data[2] == 'L' && data[3] == 'E')
      || (data[0] == 'P' && data[1] == 'A' && data[2] == 'T' && data[3] == 'C')
      || (data[0] == 'O' && data[1] == 'P' && data[2] == 'T' && data[3] == 'I');
}

/// Scan for the "\r\nHost": header line and return a pointer to the
/// hostname value (after optional whitespace, before \r).
[[nodiscard]] std::optional<std::pair<const char*, std::uint16_t>>
FindHostHeaderValue(
    const std::span<const unsigned char> data) noexcept {
  constexpr std::uint32_t kMinScanStart{4U};
  constexpr std::uint32_t kHostPatternLen{7U};  // "\r\nHost:" = 7 chars

  for (std::uint32_t i{kMinScanStart}; i + kHostPatternLen < data.size();
       ++i) {
    constexpr std::uint32_t kHostCharT{5U};
    if (constexpr std::uint32_t kHostColon{6U}; data[i] != '\r' || data[i + 1U] != '\n' ||
        data[i + 2U] != 'H' || data[i + 3U] != 'o' ||
        data[i + 4U] != 's' || data[i + kHostCharT] != 't' ||
        data[i + kHostColon] != ':') {
      continue;
    }

    constexpr std::uint32_t kHeaderValueStart{7U};
    auto host_off{i + kHeaderValueStart};
    while (host_off < data.size() && data[host_off] == ' ') {
      ++host_off;
    }

    const auto host_start{host_off};
    while (host_off < data.size() && data[host_off] != '\r') {
      ++host_off;
    }
    if (host_off > host_start) [[likely]] {
      return std::make_pair(   // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
          reinterpret_cast<const char*>(&data[host_start]),
          static_cast<std::uint16_t>(host_off - host_start));
    }
  }

  return std::nullopt;
}

}  // namespace

namespace dpdk::spi {

[[nodiscard, gnu::hot]] std::optional<PacketMetadata> ParsePacket(
    const rte_mbuf& packet,
    struct ::rte_ip_frag_tbl* frag_tbl,
    std::uint64_t tsc_timestamp) noexcept {
  const rte_mbuf* current_packet{&packet};
  rte_ether_hdr ether_hdr{};
  if (!ReadHeaderFast(*current_packet, 0, ether_hdr)) [[unlikely]] {
    return std::nullopt;
  }

  const auto ether_type{rte_be_to_cpu_16(ether_hdr.ether_type)};

  if (ether_type == RTE_ETHER_TYPE_IPV4) [[likely]] {
    constexpr std::uint32_t ipv4_offset{sizeof(rte_ether_hdr)};
    rte_ipv4_hdr ipv4_hdr{};
    if (!ReadHeaderFast(*current_packet, ipv4_offset, ipv4_hdr)) [[unlikely]] {
      return std::nullopt;
    }

    if (IsIpv4Fragmented(ipv4_hdr)) {
      if (!IsValidFragment(ipv4_hdr)) [[unlikely]] {
        return std::nullopt; // OWASP: Drop malformed / tiny fragment attack
      }
      if (frag_tbl != nullptr) {
        struct rte_ip_frag_death_row death_row{};
        rte_mbuf* reassembled = rte_ipv4_frag_reassemble_packet(
            frag_tbl, &death_row, const_cast<rte_mbuf*>(current_packet),
            tsc_timestamp, &ipv4_hdr);
        rte_ip_frag_free_death_row(&death_row, 0);
        if (reassembled == nullptr) {
          // Waiting for remaining fragments of this packet
          return std::nullopt;
        }
        current_packet = reassembled;
        if (!ReadHeaderFast(*current_packet, ipv4_offset, ipv4_hdr)) [[unlikely]] {
          return std::nullopt;
        }
      }
    }

    const auto ipv4_header_len{rte_ipv4_hdr_len(&ipv4_hdr)};
    if (ipv4_header_len < sizeof(rte_ipv4_hdr)) [[unlikely]] {
      return std::nullopt;
    }

    const auto l4_offset{
        static_cast<std::uint32_t>(ipv4_offset + ipv4_header_len)};

    if (ipv4_hdr.next_proto_id == IPPROTO_TCP) [[likely]] {
      return ParseL4<rte_tcp_hdr>(*current_packet, l4_offset, ipv4_hdr,
                                  Protocol::kTcp);
    }
    if (ipv4_hdr.next_proto_id == IPPROTO_UDP) {
      return ParseL4<rte_udp_hdr>(*current_packet, l4_offset, ipv4_hdr,
                                  Protocol::kUdp);
    }
    return std::nullopt;
  }

  if (ether_type == RTE_ETHER_TYPE_IPV6) {
    constexpr std::uint32_t ipv6_offset{sizeof(rte_ether_hdr)};
    rte_ipv6_hdr ipv6_hdr{};
    if (!ReadHeaderFast(packet, ipv6_offset, ipv6_hdr)) [[unlikely]] {
      return std::nullopt;
    }

    constexpr std::uint32_t l4_offset{ipv6_offset + sizeof(rte_ipv6_hdr)};

    if (ipv6_hdr.proto == IPPROTO_TCP) [[likely]] {
      return ParseL4Ipv6<rte_tcp_hdr>(packet, l4_offset, ipv6_hdr,
                                      Protocol::kTcp);
    }
    if (ipv6_hdr.proto == IPPROTO_UDP) {
      return ParseL4Ipv6<rte_udp_hdr>(packet, l4_offset, ipv6_hdr,
                                      Protocol::kUdp);
    }
    return std::nullopt;
  }

  return std::nullopt;
}

[[nodiscard]] std::optional<std::pair<const char*, std::uint16_t>>
ExtractTlsSni(const rte_mbuf& packet,
              std::uint32_t tcp_payload_offset) noexcept {
  constexpr std::uint32_t kMaxTlsInspect{512U};
  constexpr std::uint32_t kMinTlsRecord{5U};

  std::array<unsigned char, kMaxTlsInspect> local_buf{};
  const auto available{
      rte_pktmbuf_data_len(&packet) - tcp_payload_offset};
  const auto len{std::min(available, kMaxTlsInspect)};
  if (len < kMinTlsRecord) [[unlikely]] {
    return std::nullopt;
  }

  if (packet.nb_segs == 1) [[likely]] {  // NOLINT(cppcoreguidelines-pro-type-union-access)
    rte_prefetch0(rte_pktmbuf_mtod_offset(&packet, void*,
                                          tcp_payload_offset));
  }

  const auto* raw{static_cast<const unsigned char*>(ReadPayload(
      packet, tcp_payload_offset, local_buf.data(), len))};
  if (raw == nullptr) [[unlikely]] {
    return std::nullopt;
  }
  const std::span<const unsigned char> data{raw, len};

  if (!ValidateTlsRecordHeader(data)) [[unlikely]] {
    return std::nullopt;
  }

  const auto ext_offset{WalkClientHelloPreamble(data)};
  if (!ext_offset) [[unlikely]] {
    return std::nullopt;
  }

  return FindSniExtension(data, *ext_offset);
}

[[nodiscard]] std::optional<std::pair<const char*, std::uint16_t>>
ExtractHttpHost(const rte_mbuf& packet,
                std::uint32_t tcp_payload_offset) noexcept {
  constexpr std::uint32_t kMaxHttpInspect{256U};
  constexpr std::uint32_t kMinHttpLen{4U};

  std::array<unsigned char, kMaxHttpInspect> local_buf{};
  const auto available{
      rte_pktmbuf_data_len(&packet) - tcp_payload_offset};
  const auto len{std::min(available, kMaxHttpInspect)};
  if (len < kMinHttpLen) [[unlikely]] {
    return std::nullopt;
  }

  if (packet.nb_segs == 1) [[likely]] {  // NOLINT(cppcoreguidelines-pro-type-union-access)
    rte_prefetch0(rte_pktmbuf_mtod_offset(&packet, void*,
                                          tcp_payload_offset));
  }

  const auto* raw{static_cast<const unsigned char*>(ReadPayload(
      packet, tcp_payload_offset, local_buf.data(), len))};
  if (raw == nullptr) [[unlikely]] {
    return std::nullopt;
  }
  const std::span<const unsigned char> data{raw, len};

  if (!IsHttpMethodValid(data)) [[unlikely]] {
    return std::nullopt;
  }

  return FindHostHeaderValue(data);
}

}  // namespace dpdk::spi
