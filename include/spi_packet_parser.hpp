#pragma once

#include <rte_mbuf.h>

#include <optional>

#include "spi_rule_engine.hpp"

namespace spi {

// Parse Ethernet/IPv4/TCP/UDP headers from a raw mbuf into compact metadata.
// Returns nullopt for non-IPv4, unsupported L4, malformed, or truncated packets.
[[nodiscard]] std::optional<PacketMetadata> ParsePacket(
    const rte_mbuf& packet) noexcept;

}  // namespace spi
