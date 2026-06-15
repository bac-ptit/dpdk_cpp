#pragma once

#include <rte_mbuf.h>

#include <optional>

#include "spi_rule_engine.hpp"

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

}  // namespace dpdk::spi
