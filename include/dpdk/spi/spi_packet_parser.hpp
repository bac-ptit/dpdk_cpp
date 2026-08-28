#pragma once

#include <rte_mbuf.h>

#include <cstdint>
#include <optional>
#include <span>

#include "dpdk/spi/spi_rule_engine.hpp"

struct rte_ip_frag_tbl;

namespace dpdk::spi {

/// Outcome of parsing one packet, including the non-error fragment wait state.
enum class PacketParseStatus : std::uint8_t {
  kComplete,
  kWaitingForFragments,
  kMalformed,
};

/**
 * @brief Parse Ethernet/IPv4/IPv6/TCP/UDP headers from a raw mbuf into metadata.
 *
 * Walks the mbuf chain: Ethernet, IPv4/IPv6, (TCP | UDP).
 * If `frag_tbl` is provided and the packet is fragmented, performs IP reassembly
 * using DPDK librte_ip_frag and enforces OWASP fragment normalization rules.
 *
 * `packet` is updated to the reassembled mbuf when the final fragment arrives.
 * When reassembly is still in progress, ownership has moved to `frag_tbl` and
 * `packet` is set to nullptr so the caller must not forward or free it.
 *
 * @param packet  The received mbuf; updated on reassembly or cleared while waiting.
 * @param frag_tbl Optional IP fragment table for reassembly.
 * @param tsc_timestamp Current TSC timestamp.
 * @param status Detailed parse/reassembly outcome.
 * @return PacketMetadata on success, or nullopt for unsupported/malformed/in-progress fragment packets.
 */
[[nodiscard]] std::optional<PacketMetadata> ParsePacketOwned(
    rte_mbuf*& packet,
    struct ::rte_ip_frag_tbl* frag_tbl = nullptr,
    std::uint64_t tsc_timestamp = 0,
    PacketParseStatus* status = nullptr,
    bool* was_reassembled = nullptr) noexcept;

/// Compatibility parser used by the existing software flow-hash path.
[[nodiscard]] std::optional<PacketMetadata> ParsePacket(
    const rte_mbuf& packet,
    struct ::rte_ip_frag_tbl* frag_tbl = nullptr,
    std::uint64_t tsc_timestamp = 0) noexcept;

/**
 * @brief Extract hostname from TLS ClientHello SNI extension.
 *
 * Inspects first 512 bytes of TCP payload for TLS handshake.
 * @param packet             The received mbuf.
 * @param tcp_payload_offset Offset to TCP payload start.
 * @return Pointer + length of SNI hostname, or nullopt.
 */
[[nodiscard]] std::optional<std::pair<const char*, std::uint16_t>> ExtractTlsSni(
    const rte_mbuf& packet, std::uint32_t tcp_payload_offset) noexcept;

/// Extract TLS SNI from a contiguous, reassembled TCP byte stream.
[[nodiscard]] std::optional<std::pair<const char*, std::uint16_t>> ExtractTlsSni(
    std::span<const unsigned char> payload) noexcept;

/**
 * @brief Extract hostname from HTTP Host header.
 *
 * Inspects first 256 bytes of TCP payload for HTTP request.
 * @param packet             The received mbuf.
 * @param tcp_payload_offset Offset to TCP payload start.
 * @return Pointer + length of Host header value, or nullopt.
 */
[[nodiscard]] std::optional<std::pair<const char*, std::uint16_t>> ExtractHttpHost(
    const rte_mbuf& packet, std::uint32_t tcp_payload_offset) noexcept;

/// Extract HTTP Host from a contiguous, reassembled TCP byte stream.
[[nodiscard]] std::optional<std::pair<const char*, std::uint16_t>> ExtractHttpHost(
    std::span<const unsigned char> payload) noexcept;

}  // namespace dpdk::spi
