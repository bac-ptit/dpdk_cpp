#pragma once
#include <rte_ethdev.h>
#include <rte_mempool.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dpdk {

// Named constants to avoid magic-number warnings
constexpr std::size_t kDefaultMemoryBufferCount{65536};
constexpr std::size_t kDefaultCacheSize{256};
constexpr std::uint16_t kDefaultReceiveDescriptors{1024};
constexpr std::uint16_t kDefaultTransmitDescriptors{1024};
constexpr int kDefaultLinkCheckIntervalMs{100};
constexpr int kDefaultLinkCheckMaxCount{90};
constexpr std::uint16_t kDefaultBurstSize{32};
constexpr std::uint32_t kDefaultTimerPeriodSec{10};
constexpr std::uint16_t kDefaultIpv4PrefixLength{32};
constexpr std::uint16_t kDefaultIpv6PrefixLength{128};
constexpr std::uint16_t kDefaultEventEthRxQueues{1};

/// EAL configuration — translated directly to DPDK EAL command-line args.
struct EalConfig {
  /// CPU core list for `-l` (e.g. "0-4").
  std::string cpu_core_list{"0-4"};
  /// Number of memory channels for `-n`.
  int memory_channels{4};
  /// Skip hugepage allocation via `--no-huge`.
  bool disable_hugepages{false};
  /// Preallocate memory in legacy mode via `-m` (megabytes).
  std::string memory_size;
  /// Enable legacy memory mode via `--legacy-mem`.
  bool legacy_memory{false};
  /// Disable PCI bus scan via `--no-pci`.
  bool disable_pci{false};
  /// Process type for `--proc-type` (primary/secondary).
  std::string process_type{"primary"};
  /// File prefix for `--file-prefix` (shared memory name).
  std::string file_prefix;
  /// Log level for `--log-level` (0-8).
  std::string log_level{"7"};
  /// Virtual device declarations for `--vdev`.
  std::vector<std::string> virtual_devices;
};

/// Ethernet port configuration — masks, queues, descriptors, link polling.
struct PortConfig {
  /// Static port-pair override: forward from receive_port to transmit_port.
  struct PortPair {
    std::uint16_t receive_port{};
    std::uint16_t transmit_port{};
  };
  /// Hex bitmask of enabled ports (e.g. "0x1" for port 0).
  std::string port_bitmask{"0x1"};
  /// Enable promiscuous mode after port start.
  bool promiscuous{false};
  /// Number of receive queues per port.
  uint16_t receive_queues{1};
  /// Number of transmit queues per port.
  uint16_t transmit_queues{1};
  /// Descriptors per receive queue.
  uint16_t receive_descriptors{kDefaultReceiveDescriptors};
  /// Descriptors per transmit queue.
  uint16_t transmit_descriptors{kDefaultTransmitDescriptors};
  /// Link speed in Mbps (0 = auto-negotiate).
  uint32_t link_speed{0};
  /// Static port pair overrides for non-default mapping.
  std::vector<PortPair> port_pairs;
  /// Milliseconds between link-status polls.
  int link_check_interval_ms{kDefaultLinkCheckIntervalMs};
  /// Maximum number of link-status polls.
  int link_check_max_count{kDefaultLinkCheckMaxCount};
};

/// Mempool configuration — mbuf pool name, size, cache, and buffer size.
struct MempoolConfig {
  /// Name of the mbuf pool.
  std::string name{"mbuf_pool"};
  /// Number of mbufs in the pool.
  std::size_t memory_buffer_count{kDefaultMemoryBufferCount};
  /// Per-core cache size for mbuf allocation.
  std::size_t cache_size{kDefaultCacheSize};
  /// Size of each mbuf's data buffer.
  std::size_t memory_buffer_size{RTE_MBUF_DEFAULT_BUF_SIZE};
};

/// L2 forwarding configuration — burst size, MAC update, timer.
struct L2ForwardConfig {
  /// Enable MAC address rewriting on forwarded packets.
  bool mac_updating{true};
  /// Maximum packets per rx_burst.
  uint16_t burst_size{kDefaultBurstSize};
  /// Number of receive queues assigned to each worker lcore.
  uint16_t receive_queue_per_lcore{1};
  /// Seconds between periodic stats print (0 = disable).
  uint32_t timer_period_sec{kDefaultTimerPeriodSec};
};

/// L3 forwarding configuration based on the DPDK l3fwd sample options.
struct L3ForwardConfig {
  /// Queue-to-lcore mapping equivalent to --config(port,queue,lcore).
  struct QueueMapping {
    /// DPDK Ethernet port ID.
    std::uint16_t port_id{};
    /// RX queue ID on the port.
    std::uint16_t queue_id{};
    /// EAL lcore ID that handles the queue.
    std::uint32_t lcore_id{};
  };

  /// Per-port destination Ethernet address equivalent to --eth-dest.
  struct EthernetDestination {
    /// DPDK Ethernet port ID.
    std::uint16_t port_id{};
    /// Destination MAC address in MM:MM:MM:MM:MM:MM format.
    std::string mac_address;
  };

  /// Inline IPv4 route equivalent to an LPM/FIB route rule.
  struct Ipv4Route {
    /// Destination IPv4 address without prefix length.
    std::string destination_ip_address;
    /// CIDR prefix length.
    std::uint16_t prefix_length{kDefaultIpv4PrefixLength};
    /// Output port for matching packets.
    std::uint16_t output_port{};
  };

  /// Inline IPv6 route equivalent to an LPM/FIB route rule.
  struct Ipv6Route {
    /// Destination IPv6 address without prefix length.
    std::string destination_ip_address;
    /// CIDR prefix length.
    std::uint16_t prefix_length{kDefaultIpv6PrefixLength};
    /// Output port for matching packets.
    std::uint16_t output_port{};
  };

  /// Enable the L3 forwarding runtime path when implemented.
  bool enabled{false};
  /// Lookup method: "lpm", "fib", "em", or "acl".
  std::string lookup_method{"lpm"};
  /// IPv4 route-rule file path, equivalent to --rule_ipv4.
  std::string ipv4_rule_file;
  /// IPv6 route-rule file path, equivalent to --rule_ipv6.
  std::string ipv6_rule_file;
  /// Inline IPv4 route rules for YAML-only configuration.
  std::vector<Ipv4Route> ipv4_routes;
  /// Inline IPv6 route rules for YAML-only configuration.
  std::vector<Ipv6Route> ipv6_routes;
  /// Poll-mode queue mappings.
  std::vector<QueueMapping> queue_mappings;
  /// Optional destination MAC overrides per output port.
  std::vector<EthernetDestination> ethernet_destinations;
  /// Maximum packets per RX burst.
  std::uint16_t receive_burst_size{kDefaultBurstSize};
  /// Maximum packets per TX burst.
  std::uint16_t transmit_burst_size{kDefaultBurstSize};
  /// Maximum packet length; 0 keeps the PMD/default setting.
  std::uint32_t max_packet_length{};
  /// Keep NUMA-aware allocation enabled.
  bool numa_aware{true};
  /// Hash-entry count for EM lookup; empty keeps the DPDK sample default.
  std::string hash_entry_num;
  /// Parse IPv6 packets/routes.
  bool ipv6{false};
  /// Use software packet-type parsing.
  bool parse_packet_type{false};
  /// Use independent buffer pools per port.
  bool per_port_pool{false};
  /// Packet I/O mode: "poll" or "eventdev".
  std::string mode{"poll"};
  /// Event queue schedule: "ordered", "atomic", or "parallel".
  std::string event_queue_schedule{"atomic"};
  /// Ethernet RX queues per device in eventdev mode.
  std::uint16_t event_eth_rx_queues{kDefaultEventEthRxQueues};
  /// Enable event vectorization.
  bool event_vector{false};
  /// Event vector size; 0 keeps the DPDK sample default.
  std::uint16_t event_vector_size{};
  /// Event vector timeout in nanoseconds; 0 keeps the DPDK sample default.
  std::uint64_t event_vector_timeout_ns{};
  /// ACL classify algorithm, or "default".
  std::string acl_classify_algorithm{"default"};
};

/// Single SPI classification rule — protocol, optional L3/L4 match fields, and label.
struct SpiRuleConfig {
  /// L4 transport protocol ("tcp" or "udp").
  std::string protocol;
  /// Optional source IPv4 address.
  std::optional<std::string> source_ip_address;
  /// Optional destination IPv4 address.
  std::optional<std::string> destination_ip_address;
  /// Optional L4 source port.
  std::optional<std::uint16_t> source_port;
  /// Optional L4 destination port.
  std::optional<std::uint16_t> destination_port;
  /// Human-readable classification label.
  std::string label;
};

/// SPI configuration — ordered rule list and packet-processing worker count.
struct SpiConfig {
  /// Number of worker lcores processing packets.
  std::uint16_t worker_count{1};
  /// Drop packets that do not match any SPI rule.
  bool drop_unmatched{false};
  /// Ordered list of classification rules.
  std::vector<SpiRuleConfig> rules;
};

/// Top-level application configuration — all config sections.
struct DpdkConfig {
  EalConfig eal;
  PortConfig port;
  MempoolConfig mempool;
  L2ForwardConfig l2_forward;
  L3ForwardConfig l3_forward;
  SpiConfig spi;
};

}  // namespace dpdk
