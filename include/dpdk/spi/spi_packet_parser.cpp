#include "dpdk/spi/spi_packet_parser.hpp"

#include <netinet/in.h>
#include <rte_byteorder.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_prefetch.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include <array>
#include <span>

namespace {

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

/// Verify that the TCP payload starts with a known HTTP method
/// prefix: "GET " or "POST".
[[nodiscard]] bool IsHttpMethodValid(const std::span<const unsigned char> data) noexcept {
  const bool is_get{
      data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' '};
  const bool is_post{data[0] == 'P' && data[1] == 'O' && data[2] == 'S' &&
                     data[3] == 'T'};
  return is_get || is_post;
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
    const rte_mbuf& packet) noexcept {
  rte_ether_hdr ether_hdr{};
  if (!ReadHeader(packet, 0, ether_hdr)) [[unlikely]] {
    return std::nullopt;
  }

  if (rte_be_to_cpu_16(ether_hdr.ether_type) !=
      RTE_ETHER_TYPE_IPV4) [[unlikely]] {
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

  const auto l4_offset{
      static_cast<std::uint32_t>(ipv4_offset + ipv4_header_len)};

  if (ipv4_hdr.next_proto_id == IPPROTO_TCP) [[likely]] {
    return ParseL4<rte_tcp_hdr>(packet, l4_offset, ipv4_hdr,
                                Protocol::kTcp);
  }
  if (ipv4_hdr.next_proto_id == IPPROTO_UDP) {
    return ParseL4<rte_udp_hdr>(packet, l4_offset, ipv4_hdr,
                                Protocol::kUdp);
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
