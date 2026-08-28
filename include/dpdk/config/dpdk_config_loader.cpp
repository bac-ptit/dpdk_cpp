#include "dpdk/config/dpdk_config_loader.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <format>
#include <fstream>
#include <glaze/glaze.hpp>
#include <glaze/yaml.hpp>
#include <limits>
#include <optional>
#include <print>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_set>

#include "dpdk/spi/spi_ip_address.hpp"

namespace dpdk {
namespace {

constexpr std::uint16_t kMaxL3BurstSize{64};
constexpr std::uint32_t kMinL3PacketLength{64};
constexpr std::uint32_t kMaxL3PacketLength{9600};
constexpr std::size_t kMacAddressLength{17};
constexpr std::size_t kMacAddressSeparatorPeriod{3};
constexpr std::size_t kIpv6AddressBytes{16};
constexpr std::size_t kBytesPerMiB{1024U * 1024U};

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

/// Whether the SPI packet distribution mode is supported.
[[nodiscard]] constexpr bool IsSupportedPacketDistribution(std::string_view mode) noexcept {
  return mode == "auto" || mode == "queue" || mode == "flow_hash";
}

/// Whether the configured flow-cache overflow action is supported.
[[nodiscard]] constexpr bool IsSupportedFlowOverflowAction(std::string_view action) noexcept {
  return action == "drop" || action == "reclassify";
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

/// Whether a positive integer is a power of two.
[[nodiscard]] constexpr bool IsPowerOfTwo(std::uint32_t value) noexcept {
  return value != 0U && (value & (value - 1U)) == 0U;
}

/// Whether the filter has at least one match field configured.
[[nodiscard]] constexpr bool HasMatchField(const SpiFilterConfig& filter) noexcept {
  return filter.source_ip_address || filter.destination_ip_address || filter.source_port || filter.destination_port;
}

/// Whether an optional IP field is absent, a valid IPv4 address, or a valid CIDR.
[[nodiscard]] bool HasValidIp(const std::optional<std::string>& address) noexcept {
  if (!address) {
    return true;
  }
  if (address->contains('/')) {
    return spi::ParseCidr(*address).has_value();
  }
  return spi::ParseIpv4Address(*address).has_value();
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
 * @brief Validate a single SPI filter entry.
 * @param filter  The filter config to validate.
 * @param gi      Group index for error messages.
 * @param fi      Filter index within the group.
 * @return Void on success, or an error string.
 */
[[nodiscard]] std::expected<void, std::string> ValidateFilterConfig(const SpiFilterConfig& filter, std::size_t gi,
                                                                    std::size_t fi) noexcept {
  CONFIG_VALIDATE(!IsSupportedProtocol(filter.protocol),
                  "spi.filter_groups[{}].filters[{}].protocol must be 'tcp' or 'udp'", gi, fi);
  CONFIG_VALIDATE(!HasMatchField(filter), "spi.filter_groups[{}].filters[{}] must set at least one match field", gi,
                  fi);
  CONFIG_VALIDATE(!HasValidIp(filter.source_ip_address), "spi.filter_groups[{}].filters[{}].source_ip_address invalid",
                  gi, fi);
  CONFIG_VALIDATE(!HasValidIp(filter.destination_ip_address),
                  "spi.filter_groups[{}].filters[{}].destination_ip_address invalid", gi, fi);
  CONFIG_VALIDATE(HasInvalidPort(filter.source_port), "spi.filter_groups[{}].filters[{}].source_port must be > 0", gi,
                  fi);
  CONFIG_VALIDATE(HasInvalidPort(filter.destination_port),
                  "spi.filter_groups[{}].filters[{}].destination_port must be > 0", gi, fi);
  return {};
}

/**
 * @brief Validate a single SPI filter group entry.
 * @param group  The filter group config to validate.
 * @param index  Group index for error messages.
 * @return Void on success, or an error string.
 */
[[nodiscard]] std::expected<void, std::string> ValidateFilterGroupConfig(const SpiFilterGroupConfig& group,
                                                                         std::size_t index) noexcept {
  CONFIG_VALIDATE(group.name.empty(), "spi.filter_groups[{}].name must not be empty", index);
  CONFIG_VALIDATE(group.filters.empty(), "spi.filter_groups[{}].filters must not be empty", index);
  CONFIG_VALIDATE(!IsSupportedProtocol(group.action) && group.action != "forward" && group.action != "drop",
                  "spi.filter_groups[{}].action must be 'forward' or 'drop'", index);

  for (std::size_t fi{0}; fi < group.filters.size(); ++fi) {
    CONFIG_PROPAGATE(ValidateFilterConfig(group.filters[fi], index, fi));
  }
  return {};
}

/// Validate an inline IPv4 L3 forwarding route.
[[nodiscard]] std::expected<void, std::string> ValidateL3Ipv4Route(const L3ForwardConfig::Ipv4Route& route,
                                                                   std::size_t index) noexcept {
  CONFIG_VALIDATE(!HasValidIpv4Address(route.destination_ip_address),
                  "l3_forward.ipv4_routes[{}].destination_ip_address must be a valid IPv4 address", index);
  CONFIG_VALIDATE(route.prefix_length > kDefaultIpv4PrefixLength,
                  "l3_forward.ipv4_routes[{}].prefix_length must be between 0 and 32", index);
  return {};
}

/// Validate an inline IPv6 L3 forwarding route.
[[nodiscard]] std::expected<void, std::string> ValidateL3Ipv6Route(const L3ForwardConfig::Ipv6Route& route,
                                                                   std::size_t index) noexcept {
  CONFIG_VALIDATE(!HasValidIpv6Address(route.destination_ip_address),
                  "l3_forward.ipv6_routes[{}].destination_ip_address must be a valid IPv6 address", index);
  CONFIG_VALIDATE(route.prefix_length > kDefaultIpv6PrefixLength,
                  "l3_forward.ipv6_routes[{}].prefix_length must be between 0 and 128", index);
  return {};
}

/// Validate one optional L3 destination MAC override.
[[nodiscard]] std::expected<void, std::string> ValidateL3EthernetDestination(
    const L3ForwardConfig::EthernetDestination& destination, std::size_t index) noexcept {
  CONFIG_VALIDATE(!HasValidMacAddress(destination.mac_address),
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
  CONFIG_VALIDATE(!IsSupportedL3LookupMethod(config.lookup_method),
                  "l3_forward.lookup_method must be 'em', 'lpm', 'fib', or 'acl'");
  CONFIG_VALIDATE(!IsSupportedL3Mode(config.mode), "l3_forward.mode must be 'poll' or 'eventdev'");
  return {};
}

/// Validate L3 eventdev-related options.
[[nodiscard]] std::expected<void, std::string> ValidateL3EventOptions(const L3ForwardConfig& config) noexcept {
  CONFIG_VALIDATE(!IsSupportedEventQueueSchedule(config.event_queue_schedule),
                  "l3_forward.event_queue_schedule must be 'ordered', 'atomic', or 'parallel'");
  CONFIG_VALIDATE(config.event_eth_rx_queues <= 0, "l3_forward.event_eth_rx_queues must be greater than 0");
  return {};
}

/// Validate L3 ACL-related options.
[[nodiscard]] std::expected<void, std::string> ValidateL3AclOptions(const L3ForwardConfig& config) noexcept {
  CONFIG_VALIDATE(!IsSupportedAclClassifyAlgorithm(config.acl_classify_algorithm),
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
  CONFIG_VALIDATE(config.max_packet_length != 0 &&
                      (config.max_packet_length < kMinL3PacketLength || config.max_packet_length > kMaxL3PacketLength),
                  "l3_forward.max_packet_length must be 0 or between {} and {}", kMinL3PacketLength,
                  kMaxL3PacketLength);
  return {};
}

/// Validate the optional L3 exact-match hash entry count.
[[nodiscard]] std::expected<void, std::string> ValidateL3HashEntryNum(const L3ForwardConfig& config) noexcept {
  CONFIG_VALIDATE(!HasValidOptionalHexUint32(config.hash_entry_num),
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
  CONFIG_VALIDATE(!HasL3RouteSource(config),
                  "l3_forward requires ipv4_rule_file, ipv6_rule_file, ipv4_routes, or ipv6_routes when enabled");
  return {};
}

/// Validate poll-mode L3 requirements.
[[nodiscard]] std::expected<void, std::string> ValidateL3PollModeRequirements(const L3ForwardConfig& config) noexcept {
  if (config.mode == "poll") {
    CONFIG_VALIDATE(config.queue_mappings.empty(),
                    "l3_forward.queue_mappings must contain at least one entry when enabled in poll mode");
  }
  return {};
}

/// Validate every inline IPv4 route has a destination MAC for its output port.
[[nodiscard]] std::expected<void, std::string> ValidateL3Ipv4RouteDestinations(const L3ForwardConfig& config) noexcept {
  for (std::size_t i{0}; i < config.ipv4_routes.size(); ++i) {
    CONFIG_VALIDATE(!HasEthernetDestination(config, config.ipv4_routes[i].output_port),
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

/// Validate that every configured worker has a matching RX/TX queue.
[[nodiscard]] std::expected<void, std::string> ValidateWorkerQueueConfig(const DpdkConfig& config) noexcept {
  const auto& port_config{config.port};
  const auto& spi_config{config.spi};
  const bool injector_mode{config.pcap_injector.enabled};

  CONFIG_VALIDATE(!injector_mode && port_config.receive_queues == 0,
                  "port.receive_queues must be greater than 0");
  CONFIG_VALIDATE(!injector_mode && port_config.transmit_queues == 0,
                  "port.transmit_queues must be greater than 0");
  CONFIG_VALIDATE(spi_config.worker_count == 0, "spi.worker_count must be greater than 0");
  CONFIG_VALIDATE(!IsSupportedPacketDistribution(spi_config.packet_distribution),
                  "spi.packet_distribution must be 'auto', 'queue', or 'flow_hash'");
  CONFIG_VALIDATE(!IsPowerOfTwo(spi_config.dispatch_queue_size),
                  "spi.dispatch_queue_size must be a power of two greater than 0");
  CONFIG_VALIDATE(spi_config.worker_count > spi_config.dispatch_queue_size,
                  "spi.worker_count={} exceeds spi.dispatch_queue_size={}", spi_config.worker_count,
                  spi_config.dispatch_queue_size);
  CONFIG_VALIDATE(!injector_mode && spi_config.packet_distribution == "queue"
                      && spi_config.worker_count > port_config.receive_queues,
                  "spi.worker_count={} exceeds port.receive_queues={}", spi_config.worker_count,
                  port_config.receive_queues);
  CONFIG_VALIDATE(!injector_mode && spi_config.worker_count > port_config.transmit_queues,
                  "spi.worker_count={} exceeds port.transmit_queues={}", spi_config.worker_count,
                  port_config.transmit_queues);

  return {};
}

/// Validate the pcap injector block. Caller is responsible for ensuring
/// `dpi.enabled` matches the user's intent; we only guard injector config
/// semantic constraints.
[[nodiscard]] std::expected<void, std::string> ValidatePcapInjectorConfig(
    const PcapInjectorConfig& cfg) noexcept {
  CONFIG_VALIDATE(cfg.enabled && cfg.pcap_file.empty(),
                  "pcap_injector.pcap_file must be non-empty when enabled");
  CONFIG_VALIDATE(cfg.inject_burst_size == 0 || cfg.inject_burst_size > 256,
                  "pcap_injector.inject_burst_size must be between 1 and 256 (got {})", cfg.inject_burst_size);
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
  CONFIG_PROPAGATE(ValidateWorkerQueueConfig(config));
  CONFIG_PROPAGATE(ValidatePcapInjectorConfig(config.pcap_injector));

  CONFIG_VALIDATE(spi_config.filter_groups.empty(), "spi.filter_groups must contain at least one group");
  CONFIG_VALIDATE(spi_config.max_concurrent_flows == 0,
                  "spi.max_concurrent_flows must be greater than 0 (got {})", spi_config.max_concurrent_flows);
  CONFIG_VALIDATE(spi_config.fragment_timeout_sec == 0,
                  "spi.fragment_timeout_sec must be greater than 0 for IPv4/IPv6 fragments (got {})",
                  spi_config.fragment_timeout_sec);
  const auto& tcp_reassembly{spi_config.tcp_reassembly};
  CONFIG_VALIDATE(tcp_reassembly.enabled && tcp_reassembly.idle_timeout_sec == 0,
                  "spi.tcp_reassembly.idle_timeout_sec must be greater than 0 when enabled");
  CONFIG_VALIDATE(tcp_reassembly.enabled && tcp_reassembly.max_concurrent_streams == 0,
                  "spi.tcp_reassembly.max_concurrent_streams must be greater than 0 when enabled");
  CONFIG_VALIDATE(tcp_reassembly.enabled && tcp_reassembly.max_buffered_bytes_per_direction == 0,
                  "spi.tcp_reassembly.max_buffered_bytes_per_direction must be greater than 0 when enabled");
  CONFIG_VALIDATE(tcp_reassembly.enabled && tcp_reassembly.max_out_of_order_segments == 0,
                  "spi.tcp_reassembly.max_out_of_order_segments must be greater than 0 when enabled");
  CONFIG_VALIDATE(tcp_reassembly.enabled && tcp_reassembly.memory_budget_mb == 0,
                  "spi.tcp_reassembly.memory_budget_mb must be greater than 0 when enabled");
  CONFIG_VALIDATE(!IsSupportedFlowOverflowAction(spi_config.flow_overflow_action),
                  "spi.flow_overflow_action must be 'drop' or 'reclassify' (got '{}')",
                  spi_config.flow_overflow_action);

  const std::size_t sys_cpus{std::max<std::size_t>(1, std::thread::hardware_concurrency())};
  CONFIG_VALIDATE(spi_config.max_compilation_threads == 0 || spi_config.max_compilation_threads > sys_cpus,
                  "spi.max_compilation_threads={} must be greater than 0 and cannot exceed available system CPU cores ({})",
                  spi_config.max_compilation_threads, sys_cpus);
  CONFIG_VALIDATE(spi_config.max_acl_build_threads == 0 || spi_config.max_acl_build_threads > sys_cpus,
                  "spi.max_acl_build_threads={} must be greater than 0 and cannot exceed available system CPU cores ({})",
                  spi_config.max_acl_build_threads, sys_cpus);
  CONFIG_VALIDATE(!IsSupportedAclClassifyAlgorithm(spi_config.acl_classify_algorithm),
                  "spi.acl_classify_algorithm must be 'default', 'scalar', 'sse', 'avx2', 'neon', 'altivec', "
                  "'avx512x16', or 'avx512x32'");
  CONFIG_VALIDATE(spi_config.acl_build_max_size_mb > std::numeric_limits<std::size_t>::max() / kBytesPerMiB,
                  "spi.acl_build_max_size_mb is too large");

  for (std::size_t i{0}; i < spi_config.filter_groups.size(); ++i) {
    CONFIG_PROPAGATE(ValidateFilterGroupConfig(spi_config.filter_groups[i], i));
  }

  // Cross-reference SPI→DPI link targets. Build the set of DPI filter
  // group names once, then reject any SPI group whose `dpi_filter_group`
  // does not resolve. Empty `dpi_filter_group` (the default) is always
  // valid — it means "no static link, run full hostname DPI".
  std::unordered_set<std::string_view> dpi_group_names;
  dpi_group_names.reserve(config.dpi.filters.size());
  for (const auto& f : config.dpi.filters) {
    dpi_group_names.insert(f.filter_group);
  }
  for (std::size_t i{0}; i < spi_config.filter_groups.size(); ++i) {
    const auto& g = spi_config.filter_groups[i];
    if (g.dpi_filter_group.empty()) {
      continue;
    }
    CONFIG_VALIDATE(!dpi_group_names.contains(g.dpi_filter_group),
                    "spi.filter_groups[{}] ('{}') dpi_filter_group='{}' has no matching "
                    "entry in dpi.filters (must equal one of dpi.filters[*].filter_group)",
                    i, g.name, g.dpi_filter_group);
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
  DpdkConfig config;
  if (path.ends_with(".beve") || path.ends_with(".bin")) {
    std::string buffer;
    if (const auto parse_error{glz::read_file_beve(config, path, buffer)}; parse_error) {
      return std::unexpected(std::format("Failed to parse binary BEVE '{}': {}", path, glz::format_error(parse_error)));
    }
  } else {
    if (const auto parse_error{glz::read_file_yaml(config, path)}; parse_error) {
      return std::unexpected(std::format("Failed to parse YAML '{}': {}", path, glz::format_error(parse_error)));
    }
  }

  // If spi.rule_path is specified, prioritize loading rules from that stream file
  if (!config.spi.rule_path.empty()) {
    const std::string& rule_path{config.spi.rule_path};
    std::println("[Config] Reading binary rule stream from '{}'...", rule_path);
    RuleStoreConfig rule_store;
    bool loaded{false};

    if (rule_path.ends_with(".beve") || rule_path.ends_with(".bin")) {
      std::string buffer;
      if (const auto err{glz::read_file_beve(rule_store, rule_path, buffer)}; !err) {
        loaded = true;
      } else {
        DpdkConfig full_cfg;
        std::string buf2;
        if (const auto err2{glz::read_file_beve(full_cfg, rule_path, buf2)}; !err2) {
          rule_store.filter_groups = std::move(full_cfg.spi.filter_groups);
          rule_store.dpi = std::move(full_cfg.dpi);
          loaded = true;
        }
      }
    } else {
      if (const auto err{glz::read_file_yaml(rule_store, rule_path)}; !err) {
        loaded = true;
      } else {
        DpdkConfig full_cfg;
        if (const auto err2{glz::read_file_yaml(full_cfg, rule_path)}; !err2) {
          rule_store.filter_groups = std::move(full_cfg.spi.filter_groups);
          rule_store.dpi = std::move(full_cfg.dpi);
          loaded = true;
        }
      }
    }

    if (!loaded) {
      return std::unexpected(std::format("Failed to load rule_path stream file: '{}'", rule_path));
    }

    if (!rule_store.filter_groups.empty()) {
      config.spi.filter_groups = std::move(rule_store.filter_groups);
    }
    if (rule_store.dpi.enabled || !rule_store.dpi.filters.empty()) {
      config.dpi = std::move(rule_store.dpi);
    }
  }

  if (const auto valid{ValidateConfig(config)}; !valid) {
    return std::unexpected(valid.error());
  }

  return config;
}

std::expected<void, std::string> SaveConfigBinary(const DpdkConfig& config, const std::string& path) noexcept {
  if (const auto write_error{glz::write_file_beve(config, path, std::string{})}; write_error) {
    return std::unexpected(std::format("Failed to save binary BEVE '{}': {}", path, glz::format_error(write_error)));
  }
  return {};
}

std::expected<void, std::string> SaveRuleStoreBinary(const RuleStoreConfig& rule_store, const std::string& path) noexcept {
  if (const auto write_error{glz::write_file_beve(rule_store, path, std::string{})}; write_error) {
    return std::unexpected(std::format("Failed to save rule store binary BEVE '{}': {}", path, glz::format_error(write_error)));
  }
  return {};
}

}  // namespace dpdk
