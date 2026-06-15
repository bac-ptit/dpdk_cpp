#pragma once

#include <cstdint>
#include <expected>
#include <string>

namespace dpdk::spi {

/**
 * @brief Parse dotted IPv4 text into host-byte-order integer.
 *
 * Converts a string like "192.0.2.1" to its numeric representation for
 * fast hot-path integer matching against @ref PacketMetadata.
 * @param address  The IPv4 address string (e.g. "10.17.50.1").
 * @return The address in host byte order on success, or an error string.
 */
[[nodiscard]] std::expected<std::uint32_t, std::string> ParseIpv4Address(const std::string& address) noexcept;

}  // namespace dpdk::spi
