#include "dpdk_config_loader.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <format>
#include <glaze/yaml.hpp>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

#include "spi_ip_address.hpp"

namespace dpdk {
namespace {

constexpr std::uint16_t kMaxL3BurstSize{64};
constexpr std::uint32_t kMinL3PacketLength{64};
constexpr std::uint32_t kMaxL3PacketLength{9600};
constexpr std::size_t kMacAddressLength{17};
constexpr std::size_t kMacAddressSeparatorPeriod{3};
constexpr std::size_t kIpv6AddressBytes{16};

/**
 * @brief Validate a semantic condition and return an error string on failure.
 *
 * Used to check SPI rule constraints before / after YAML loading.
 * @param condition  The boolean condition to assert.
 * @param ...        Format string and arguments for the error message.
 */
#define CONFIG_VALIDATE(invalid_condition, ...)         \
  do {                                                  \
    if (invalid_condition) {                            \
      return std::unexpected(std::format(__VA_ARGS__)); \
    }                                                   \
  } while (0)

#define CONFIG_PROPAGATE(expr)               \
  do {                                       \
    if (const auto valid{(expr)}; !valid) {  \
      return std::unexpected(valid.error()); \
    }                                        \
  } while (0)

/// Whether the protocol string is "tcp" or "udp".
[[nodiscard]] constexpr bool IsSupportedProtocol(std::string_view protocol) noexcept {
  return protocol == "tcp" || protocol == "udp";
}

/// Whether the L3 lookup method matches DPDK l3fwd's supported modes.
[[nodiscard]] constexpr bool IsSupportedL3LookupMethod(std::string_view method) noexcept {
  return method == "em" || method == "lpm" || method == "fib" || method == "acl";
}

/// Whether the L3 packet I/O mode is supported by the DPDK l3fwd sample.
[[nodiscard]] constexpr bool IsSupportedL3Mode(std::string_view mode) noexcept {
  return mode == "poll" || mode == "eventdev";
}

/// Whether the eventdev scheduling mode is accepted by DPDK l3fwd.
[[nodiscard]] constexpr bool IsSupportedEventQueueSchedule(std::string_view schedule) noexcept {
  return schedule == "ordered" || schedule == "atomic" || schedule == "parallel";
}

/// Whether the ACL classify algorithm is accepted by DPDK l3fwd.
[[nodiscard]] constexpr bool IsSupportedAclClassifyAlgorithm(std::string_view algorithm) noexcept {
  return algorithm == "default" || algorithm == "scalar" || algorithm == "sse" || algorithm == "avx2" ||
         algorithm == "neon" || algorithm == "altivec" || algorithm == "avx512x16" || algorithm == "avx512x32";
}

/// Whether a character is a hexadecimal digit.
[[nodiscard]] constexpr bool IsHexDigit(char value) noexcept {
  return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F');
}

/// Whether an optional port value is present but zero (invalid).
[[nodiscard]] constexpr bool HasInvalidPort(const std::optional<std::uint16_t>& port) noexcept {
  return port.has_value() && *port == 0;
}

/// Whether the rule has at least one match field configured.
[[nodiscard]] constexpr bool HasMatchField(const SpiRuleConfig& rule) noexcept {
  return rule.source_ip_address || rule.destination_ip_address || rule.source_port || rule.destination_port;
}

/// Whether an optional IP field is absent or a valid IPv4 address.
[[nodiscard]] bool HasValidIp(const std::optional<std::string>& address) noexcept {
  return !address || spi::ParseIpv4Address(*address).has_value();
}

/// Whether a string is a valid IPv4 address.
[[nodiscard]] bool HasValidIpv4Address(const std::string& address) noexcept {
  return !address.empty() && spi::ParseIpv4Address(address).has_value();
}

/// Whether a string is a valid IPv6 address.
[[nodiscard]] bool HasValidIpv6Address(const std::string& address) noexcept {
  std::array<unsigned char, kIpv6AddressBytes> parsed{};
  return !address.empty() && inet_pton(AF_INET6, address.c_str(), parsed.data()) == 1;
}

/// Whether an optional hash-entry string is a valid hex uint32 value.
[[nodiscard]] bool HasValidOptionalHexUint32(const std::string& value) noexcept {
  if (value.empty()) {
    return true;
  }

  errno = 0;
  char* end{nullptr};
  const auto parsed{std::strtoul(value.c_str(), &end, 16)};
  return errno == 0 && end != value.c_str() && *end == '\0' && parsed <= std::numeric_limits<std::uint32_t>::max();
}

/// Whether a MAC address uses MM:MM:MM:MM:MM:MM format.
[[nodiscard]] constexpr bool HasValidMacAddress(std::string_view address) noexcept {
  if (address.size() != kMacAddressLength) {
    return false;
  }

  for (std::size_t i{0}; i < address.size(); ++i) {
    if ((i + 1U) % kMacAddressSeparatorPeriod == 0U) {
      if (address[i] != ':') {
        return false;
      }
    } else if (!IsHexDigit(address[i])) {
      return false;
    }
  }

  return true;
}

/**
 * @brief Validate a single SPI rule entry.
 * @param rule   The rule config to validate.
 * @param index  Index of the rule for error messages.
 * @return Void on success, or an error string.
 */
[[nodiscard]] std::expected<void, std::string> ValidateRuleConfig(const SpiRuleConfig& rule,
                                                                  std::size_t index) noexcept {
  CONFIG_VALIDATE(IsSupportedProtocol(rule.protocol), "spi.rules[{}].protocol must be 'tcp' or 'udp'", index);
  CONFIG_VALIDATE(HasMatchField(rule),
                  "spi.rules[{}] must set source_ip_address, destination_ip_address, source_port, "
                  "or dst_port",
                  index);
  CONFIG_VALIDATE(HasValidIp(rule.source_ip_address), "spi.rules[{}].source_ip_address must be a valid IPv4 address",
                  index);
  CONFIG_VALIDATE(HasValidIp(rule.destination_ip_address),
                  "spi.rules[{}].destination_ip_address must be a valid IPv4 address", index);
  CONFIG_VALIDATE(!HasInvalidPort(rule.source_port), "spi.rules[{}].source_port must be greater than 0", index);
  CONFIG_VALIDATE(!HasInvalidPort(rule.destination_port), "spi.rules[{}].destination_port must be greater than 0",
                  index);
  CONFIG_VALIDATE(!rule.label.empty(), "spi.rules[{}].label must not be empty", index);

  return {};
}

/// Validate an inline IPv4 L3 forwarding route.
[[nodiscard]] std::expected<void, std::string> ValidateL3Ipv4Route(const L3ForwardConfig::Ipv4Route& route,
                                                                   std::size_t index) noexcept {
  CONFIG_VALIDATE(HasValidIpv4Address(route.destination_ip_address),
                  "l3_forward.ipv4_routes[{}].destination_ip_address must be a valid IPv4 address", index);
  CONFIG_VALIDATE(route.prefix_length <= kDefaultIpv4PrefixLength,
                  "l3_forward.ipv4_routes[{}].prefix_length must be between 0 and 32", index);
  return {};
}

/// Validate an inline IPv6 L3 forwarding route.
[[nodiscard]] std::expected<void, std::string> ValidateL3Ipv6Route(const L3ForwardConfig::Ipv6Route& route,
                                                                   std::size_t index) noexcept {
  CONFIG_VALIDATE(HasValidIpv6Address(route.destination_ip_address),
                  "l3_forward.ipv6_routes[{}].destination_ip_address must be a valid IPv6 address", index);
  CONFIG_VALIDATE(route.prefix_length <= kDefaultIpv6PrefixLength,
                  "l3_forward.ipv6_routes[{}].prefix_length must be between 0 and 128", index);
  return {};
}

/// Validate one optional L3 destination MAC override.
[[nodiscard]] std::expected<void, std::string> ValidateL3EthernetDestination(
    const L3ForwardConfig::EthernetDestination& destination, std::size_t index) noexcept {
  CONFIG_VALIDATE(HasValidMacAddress(destination.mac_address),
                  "l3_forward.ethernet_destinations[{}].mac_address must use MM:MM:MM:MM:MM:MM format", index);
  return {};
}

/// Whether a destination MAC has been configured for an output port.
[[nodiscard]] bool HasEthernetDestination(const L3ForwardConfig& config, std::uint16_t port_id) noexcept {
  return std::ranges::any_of(
      config.ethernet_destinations,
      [port_id](const L3ForwardConfig::EthernetDestination& destination) { return destination.port_id == port_id; });
}

/// Whether L3 config provides a file-backed or inline route source.
[[nodiscard]] bool HasL3RouteSource(const L3ForwardConfig& config) noexcept {
  return !config.ipv4_rule_file.empty() || !config.ipv6_rule_file.empty() || !config.ipv4_routes.empty() ||
         !config.ipv6_routes.empty();
}

/// Validate L3 lookup and packet I/O mode options.
[[nodiscard]] std::expected<void, std::string> ValidateL3ModeOptions(const L3ForwardConfig& config) noexcept {
  CONFIG_VALIDATE(IsSupportedL3LookupMethod(config.lookup_method),
                  "l3_forward.lookup_method must be 'em', 'lpm', 'fib', or 'acl'");
  CONFIG_VALIDATE(IsSupportedL3Mode(config.mode), "l3_forward.mode must be 'poll' or 'eventdev'");
  return {};
}

/// Validate L3 eventdev-related options.
[[nodiscard]] std::expected<void, std::string> ValidateL3EventOptions(const L3ForwardConfig& config) noexcept {
  CONFIG_VALIDATE(IsSupportedEventQueueSchedule(config.event_queue_schedule),
                  "l3_forward.event_queue_schedule must be 'ordered', 'atomic', or 'parallel'");
  CONFIG_VALIDATE(config.event_eth_rx_queues > 0, "l3_forward.event_eth_rx_queues must be greater than 0");
  return {};
}

/// Validate L3 ACL-related options.
[[nodiscard]] std::expected<void, std::string> ValidateL3AclOptions(const L3ForwardConfig& config) noexcept {
  CONFIG_VALIDATE(IsSupportedAclClassifyAlgorithm(config.acl_classify_algorithm),
                  "l3_forward.acl_classify_algorithm must be a DPDK ACL classify algorithm or 'default'");
  return {};
}

/// Validate L3 RX/TX burst sizes.
[[nodiscard]] std::expected<void, std::string> ValidateL3BurstSizes(const L3ForwardConfig& config) noexcept {
  CONFIG_VALIDATE(config.receive_burst_size <= 0 || config.receive_burst_size > kMaxL3BurstSize,
                  "l3_forward.receive_burst_size must be between 1 and {}", kMaxL3BurstSize);
  CONFIG_VALIDATE(config.transmit_burst_size <= 0 || config.transmit_burst_size > kMaxL3BurstSize,
                  "l3_forward.transmit_burst_size must be between 1 and {}", kMaxL3BurstSize);
  return {};
}

/// Validate the optional L3 maximum packet length override.
[[nodiscard]] std::expected<void, std::string> ValidateL3MaxPacketLength(const L3ForwardConfig& config) noexcept {
  CONFIG_VALIDATE(
      config.max_packet_length != 0 &&
          (config.max_packet_length < kMinL3PacketLength || config.max_packet_length > kMaxL3PacketLength),
      "l3_forward.max_packet_length must be 0 or between {} and {}", kMinL3PacketLength, kMaxL3PacketLength);
  return {};
}

/// Validate the optional L3 exact-match hash entry count.
[[nodiscard]] std::expected<void, std::string> ValidateL3HashEntryNum(const L3ForwardConfig& config) noexcept {
  CONFIG_VALIDATE(HasValidOptionalHexUint32(config.hash_entry_num),
                  "l3_forward.hash_entry_num must be a hexadecimal uint32 string");
  return {};
}

/// Validate scalar L3 options shared by enabled and disabled configurations.
[[nodiscard]] std::expected<void, std::string> ValidateL3ScalarOptions(const L3ForwardConfig& config) noexcept {
  CONFIG_PROPAGATE(ValidateL3ModeOptions(config));
  CONFIG_PROPAGATE(ValidateL3EventOptions(config));
  CONFIG_PROPAGATE(ValidateL3AclOptions(config));
  CONFIG_PROPAGATE(ValidateL3BurstSizes(config));
  CONFIG_PROPAGATE(ValidateL3MaxPacketLength(config));
  CONFIG_PROPAGATE(ValidateL3HashEntryNum(config));

  return {};
}

/// Validate all inline IPv4 routes in an L3 config.
[[nodiscard]] std::expected<void, std::string> ValidateL3Ipv4Routes(const L3ForwardConfig& config) noexcept {
  for (std::size_t i{0}; i < config.ipv4_routes.size(); ++i) {
    CONFIG_PROPAGATE(ValidateL3Ipv4Route(config.ipv4_routes[i], i));
  }
  return {};
}

/// Validate all inline IPv6 routes in an L3 config.
[[nodiscard]] std::expected<void, std::string> ValidateL3Ipv6Routes(const L3ForwardConfig& config) noexcept {
  for (std::size_t i{0}; i < config.ipv6_routes.size(); ++i) {
    CONFIG_PROPAGATE(ValidateL3Ipv6Route(config.ipv6_routes[i], i));
  }
  return {};
}

/// Validate all per-port L3 Ethernet destination overrides.
[[nodiscard]] std::expected<void, std::string> ValidateL3EthernetDestinations(const L3ForwardConfig& config) noexcept {
  for (std::size_t i{0}; i < config.ethernet_destinations.size(); ++i) {
    CONFIG_PROPAGATE(ValidateL3EthernetDestination(config.ethernet_destinations[i], i));
  }
  return {};
}

/// Validate L3 requirements that only apply when forwarding is enabled.
[[nodiscard]] std::expected<void, std::string> ValidateEnabledL3RouteSource(const L3ForwardConfig& config) noexcept {
  CONFIG_VALIDATE(HasL3RouteSource(config),
                  "l3_forward requires ipv4_rule_file, ipv6_rule_file, ipv4_routes, or ipv6_routes when enabled");
  return {};
}

/// Validate poll-mode L3 requirements.
[[nodiscard]] std::expected<void, std::string> ValidateL3PollModeRequirements(const L3ForwardConfig& config) noexcept {
  if (config.mode == "poll") {
    CONFIG_VALIDATE(!config.queue_mappings.empty(),
                    "l3_forward.queue_mappings must contain at least one entry when enabled in poll mode");
  }
  return {};
}

/// Validate every inline IPv4 route has a destination MAC for its output port.
[[nodiscard]] std::expected<void, std::string> ValidateL3Ipv4RouteDestinations(const L3ForwardConfig& config) noexcept {
  for (std::size_t i{0}; i < config.ipv4_routes.size(); ++i) {
    CONFIG_VALIDATE(HasEthernetDestination(config, config.ipv4_routes[i].output_port),
                    "l3_forward.ipv4_routes[{}].output_port={} has no matching ethernet_destinations entry", i,
                    config.ipv4_routes[i].output_port);
  }

  return {};
}

/// Validate L3 requirements that only matter when L3 forwarding is enabled.
[[nodiscard]] std::expected<void, std::string> ValidateEnabledL3ForwardConfig(const L3ForwardConfig& config) noexcept {
  if (!config.enabled) {
    return {};
  }

  CONFIG_PROPAGATE(ValidateEnabledL3RouteSource(config));
  CONFIG_PROPAGATE(ValidateL3PollModeRequirements(config));
  CONFIG_PROPAGATE(ValidateL3Ipv4RouteDestinations(config));

  return {};
}

/**
 * @brief Validate L3 forwarding config section.
 * @param config  L3 forwarding config loaded from YAML.
 * @return Void on success, or an error string.
 */
[[nodiscard]] std::expected<void, std::string> ValidateL3ForwardConfig(const L3ForwardConfig& config) noexcept {
  CONFIG_PROPAGATE(ValidateL3ScalarOptions(config));
  CONFIG_PROPAGATE(ValidateL3Ipv4Routes(config));
  CONFIG_PROPAGATE(ValidateL3Ipv6Routes(config));
  CONFIG_PROPAGATE(ValidateL3EthernetDestinations(config));
  CONFIG_PROPAGATE(ValidateEnabledL3ForwardConfig(config));

  return {};
}

}  // namespace

/**
 * @brief Validate all configuration sections.
 *
 * Checks worker_count, rule list non-empty, and per-rule semantic
 * constraints.
 * @param config  The fully-loaded configuration struct.
 * @return Void on success, or an error string.
 */
std::expected<void, std::string> ValidateConfig(const DpdkConfig& config) noexcept {
  const auto& spi_config{config.spi};
  CONFIG_PROPAGATE(ValidateL3ForwardConfig(config.l3_forward));

  CONFIG_VALIDATE(spi_config.worker_count > 0, "spi.worker_count must be greater than 0");
  CONFIG_VALIDATE(!spi_config.rules.empty(), "spi.rules must contain at least one rule");

  for (std::size_t i{0}; i < spi_config.rules.size(); ++i) {
    CONFIG_PROPAGATE(ValidateRuleConfig(spi_config.rules[i], i));
  }

  return {};
}

/**
 * @brief Load and validate YAML configuration from file.
 *
 * Uses Glaze (glz::read_file_yaml) to parse into the auto-reflected
 * DpdkConfig struct, then runs ValidateConfig.
 * @param path  Filesystem path to the YAML configuration file.
 * @return A validated DpdkConfig on success, or an error string.
 */
std::expected<DpdkConfig, std::string> LoadConfig(const std::string& path) noexcept {
  // Parse YAML into the auto-reflected DpdkConfig struct.
  DpdkConfig config;
  if (const auto parse_error{glz::read_file_yaml(config, path)}; parse_error) {
    return std::unexpected(std::format("Failed to parse '{}': {}", path, glz::format_error(parse_error)));
  }

  // Validate semantic constraints before use.
  if (const auto valid{ValidateConfig(config)}; !valid) {
    return std::unexpected(valid.error());
  }

  return config;
}

}  // namespace dpdk
