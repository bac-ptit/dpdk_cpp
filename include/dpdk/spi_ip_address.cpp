#include "spi_ip_address.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <rte_byteorder.h>

#include <format>

namespace dpdk::spi {

/**
 * @brief Parse dotted IPv4 text into host-byte-order integer.
 *
 * Uses inet_pton for address-family validation, then converts from network
 * to host byte order via rte_be_to_cpu_32.
 * @param address  The IPv4 address string (e.g. "192.0.2.1").
 * @return Address in host byte order on success, or an error string.
 */
std::expected<std::uint32_t, std::string> ParseIpv4Address(const std::string& address) noexcept {
  in_addr parsed{};
  if (inet_pton(AF_INET, address.c_str(), &parsed) != 1) {
    return std::unexpected(std::format("invalid IPv4 address '{}'", address));
  }

  return rte_be_to_cpu_32(parsed.s_addr);
}

}  // namespace dpdk::spi
