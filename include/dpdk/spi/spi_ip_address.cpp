#include "dpdk/spi/spi_ip_address.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <rte_byteorder.h>

#include <charconv>
#include <cstring>
#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace dpdk::spi {

std::expected<std::uint32_t, std::string> ParseIpv4Address(const std::string& address) noexcept {
  in_addr parsed{};
  if (inet_pton(AF_INET, address.c_str(), &parsed) != 1) {
    return std::unexpected("invalid IPv4 address '" + address + "'");
  }

  return rte_be_to_cpu_32(parsed.s_addr);
}

std::expected<std::pair<std::uint32_t, std::uint32_t>, std::string> ParseCidr(
    const std::string& cidr) noexcept {
  constexpr std::uint16_t kMaxPrefixLength{32};

  const auto slash{cidr.find('/')};
  if (slash == std::string::npos) {
    return std::unexpected("invalid CIDR '" + cidr + "': missing '/'");
  }

  const auto ip_part{cidr.substr(0, slash)};
  const auto prefix_part{cidr.substr(slash + 1)};

  const auto parsed_address{ParseIpv4Address(ip_part)};
  if (!parsed_address) {
    return std::unexpected("invalid CIDR '" + cidr + "': " + parsed_address.error());
  }

  std::uint16_t prefix_length{};
  const std::string_view prefix_view{prefix_part};
  if (const auto [ptr, ec]{std::from_chars(prefix_view.begin(), prefix_view.end(), prefix_length)};
      ec != std::errc{} || ptr != prefix_view.end() || prefix_length > kMaxPrefixLength) {
    return std::unexpected("invalid CIDR '" + cidr + "': bad prefix length");
  }

  const auto mask{PrefixMask(prefix_length)};
  return std::make_pair(*parsed_address & mask, mask);
}

std::expected<std::array<std::uint8_t, 16>, std::string> ParseIpv6Address(const std::string& address) noexcept {
  in6_addr parsed{};
  if (inet_pton(AF_INET6, address.c_str(), &parsed) != 1) {
    return std::unexpected("invalid IPv6 address '" + address + "'");
  }

  std::array<std::uint8_t, 16> result{};
  std::memcpy(result.data(), &parsed.s6_addr, 16);
  return result;
}

std::expected<std::pair<std::array<std::uint8_t, 16>, std::uint16_t>, std::string> ParseIpv6Cidr(
    const std::string& cidr) noexcept {
  constexpr std::uint16_t kMaxIpv6PrefixLength{128};

  const auto slash{cidr.find('/')};
  if (slash == std::string::npos) {
    const auto parsed_address{ParseIpv6Address(cidr)};
    if (!parsed_address) {
      return std::unexpected("invalid IPv6 CIDR '" + cidr + "': " + parsed_address.error());
    }
    return std::make_pair(*parsed_address, kMaxIpv6PrefixLength);
  }

  const auto ip_part{cidr.substr(0, slash)};
  const auto prefix_part{cidr.substr(slash + 1)};

  const auto parsed_address{ParseIpv6Address(ip_part)};
  if (!parsed_address) {
    return std::unexpected("invalid IPv6 CIDR '" + cidr + "': " + parsed_address.error());
  }

  std::uint16_t prefix_length{};
  const std::string_view prefix_view{prefix_part};
  if (const auto [ptr, ec]{std::from_chars(prefix_view.begin(), prefix_view.end(), prefix_length)};
      ec != std::errc{} || ptr != prefix_view.end() || prefix_length > kMaxIpv6PrefixLength) {
    return std::unexpected("invalid IPv6 CIDR '" + cidr + "': bad prefix length");
  }

  return std::make_pair(*parsed_address, prefix_length);
}

}  // namespace dpdk::spi
