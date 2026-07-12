#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <utility>

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

/// Compute a prefix mask from CIDR length (e.g. 18 → 0xFFFFC000).
[[nodiscard]] constexpr std::uint32_t PrefixMask(std::uint16_t prefix_length) noexcept {
  constexpr std::uint32_t kIpv4Bits{32U};
  if (prefix_length == 0U) {
    return 0U;
  }
  if (prefix_length >= kIpv4Bits) {
    constexpr std::uint32_t kIpv4Mask{0xFFFFFFFFU};
    return kIpv4Mask;
  }
  return ~((std::uint32_t{1U} << (kIpv4Bits - prefix_length)) - 1U);
}

/**
 * @brief Parse CIDR notation into network address and prefix mask.
 *
 * Parses "31.13.64.0/18" into (network_address & mask, mask).
 * @param cidr  The CIDR string (e.g. "31.13.64.0/18").
 * @return Pair of (network_address, prefix_mask) in host byte order,
 *         or an error string.
 */
[[nodiscard]] std::expected<std::pair<std::uint32_t, std::uint32_t>, std::string> ParseCidr(
    const std::string& cidr) noexcept;

}  // namespace dpdk::spi
