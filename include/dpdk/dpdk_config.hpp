#pragma once
#include <rte_ethdev.h>
#include <rte_mempool.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#include <vector>

namespace dpdk {

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
  uint16_t receive_descriptors{1024};
  /// Descriptors per transmit queue.
  uint16_t transmit_descriptors{1024};
  /// Link speed in Mbps (0 = auto-negotiate).
  uint32_t link_speed{0};
  /// Static port pair overrides for non-default mapping.
  std::vector<PortPair> port_pairs;
  /// Milliseconds between link-status polls.
  int link_check_interval_ms{100};
  /// Maximum number of link-status polls.
  int link_check_max_count{90};
};

/// Mempool configuration — mbuf pool name, size, cache, and buffer size.
struct MempoolConfig {
  /// Name of the mbuf pool.
  std::string name{"mbuf_pool"};
  /// Number of mbufs in the pool.
  std::size_t memory_buffer_count{65536};
  /// Per-core cache size for mbuf allocation.
  std::size_t cache_size{256};
  /// Size of each mbuf's data buffer.
  std::size_t memory_buffer_size{RTE_MBUF_DEFAULT_BUF_SIZE};
};

/// L2 forwarding configuration — burst size, MAC update, timer.
struct L2ForwardConfig {
  /// Enable MAC address rewriting on forwarded packets.
  bool mac_updating{true};
  /// Maximum packets per rx_burst.
  uint16_t burst_size{32};
  /// Number of receive queues assigned to each worker lcore.
  uint16_t receive_queue_per_lcore{1};
  /// Seconds between periodic stats print (0 = disable).
  uint32_t timer_period_sec{10};
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
  /// Ordered list of classification rules.
  std::vector<SpiRuleConfig> rules;
};

/// Top-level application configuration — all config sections.
struct DpdkConfig {
  EalConfig eal;
  PortConfig port;
  MempoolConfig mempool;
  L2ForwardConfig l2_forward;
  SpiConfig spi;
};

}  // namespace dpdk
