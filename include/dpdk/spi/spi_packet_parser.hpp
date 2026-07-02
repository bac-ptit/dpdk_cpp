#pragma once

#include <rte_mbuf.h>

#include <cstdint>
#include <optional>

#include "dpdk/spi/spi_rule_engine.hpp"

namespace dpdk::spi {

/**
 * @brief Parse Ethernet/IPv4/TCP/UDP headers from a raw mbuf into metadata.
 *
 * Walks the mbuf chain at offset 0: Ethernet, IPv4, (TCP | UDP). Only
 * IPv4 packets with known L4 protocols are parsed; all others return nullopt.
 * @param packet  The received mbuf to parse.
 * @return PacketMetadata on success, or nullopt for unsupported/malformed
 *         packets.
 */
[[nodiscard]] std::optional<PacketMetadata> ParsePacket(const rte_mbuf& packet) noexcept;

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

}  // namespace dpdk::spi
