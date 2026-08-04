#pragma once

#include <rte_mbuf.h>

#include <cstdint>
#include <optional>

#include "dpdk/spi/spi_rule_engine.hpp"

struct rte_ip_frag_tbl;

namespace dpdk::spi {

/**
 * @brief Parse Ethernet/IPv4/IPv6/TCP/UDP headers from a raw mbuf into metadata.
 *
 * Walks the mbuf chain: Ethernet, IPv4/IPv6, (TCP | UDP).
 * If `frag_tbl` is provided and the packet is fragmented, performs IP reassembly
 * using DPDK librte_ip_frag and enforces OWASP fragment normalization rules.
 *
 * @param packet  The received mbuf to parse.
 * @param frag_tbl Optional IP fragment table for reassembly.
 * @param tsc_timestamp Current TSC timestamp.
 * @return PacketMetadata on success, or nullopt for unsupported/malformed/in-progress fragment packets.
 */
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
