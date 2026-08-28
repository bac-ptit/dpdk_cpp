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
constexpr std::uint32_t kDefaultDispatchQueueSize{8192};

/// Bounded TCP byte-stream reassembly used only for L7 inspection.
struct TcpReassemblyConfig {
  /// Enable TCP payload reassembly before HTTP/TLS DPI.
  bool enabled{false};
  /// Remove a stream with no new segment after this many seconds.
  std::uint32_t idle_timeout_sec{60};
  /// Hard cap on streams that are still awaiting an L7 decision per worker.
  std::uint32_t max_concurrent_streams{16384};
  /// Maximum contiguous payload retained for one direction of one stream.
  std::uint32_t max_buffered_bytes_per_direction{16384};
  /// Maximum out-of-order segments retained for one direction.
  std::uint16_t max_out_of_order_segments{32};
  /// Hard aggregate payload budget per worker, in MiB.
  std::uint32_t memory_budget_mb{256};
  /// Reject a flow when overlapping TCP bytes disagree.
  bool drop_conflicting_overlap{true};
};

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

/// Application-level settings — burst size, MAC update, stats interval.
struct AppConfig {
  /// Maximum packets per rx_burst.
  uint16_t burst_size{kDefaultBurstSize};
  /// Enable MAC address rewriting on forwarded packets.
  bool mac_updating{true};
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

/// Single filter within a filter group — protocol, optional L3/L4 match fields.
struct SpiFilterConfig {
  /// L4 transport protocol ("tcp" or "udp").
  std::string protocol;
  /// Optional source IPv4 address.
  std::optional<std::string> source_ip_address;
  /// Optional destination IPv4 address or CIDR (e.g. "31.13.64.0/18").
  std::optional<std::string> destination_ip_address;
  /// Optional L4 source port.
  std::optional<std::uint16_t> source_port;
  /// Optional L4 destination port.
  std::optional<std::uint16_t> destination_port;
  /// Human-readable label for this filter.
  std::string label;
};

/// Filter group — ACL context with precedence, action, and a list of filters.
struct SpiFilterGroupConfig {
  /// Group name (e.g. "fg_l34_facebook").
  std::string name;
  /// Precedence — lower value = higher priority.
  std::uint32_t precedence{100};
  /// Action on match: "forward" or "drop".
  std::string action{"forward"};
  /// Filters in this group — any filter match means the group matches.
  std::vector<SpiFilterConfig> filters;
  /// When true, packets matching this group are STILL sent through DPI
  /// (hostname extraction + DpiRuleTable::Match). When false (default),
  /// DPI is skipped for packets that match this group. Use this to cap
  /// DPI work to a small opt-in set of groups (e.g. port-based groups
  /// that need to know the L7 hostname to forward correctly).
  bool l7_required{false};
  /// Optional static link to a DPI filter group (matched by
  /// `dpi.filters[*].filter_group`). When non-empty AND `l7_required`
  /// is true, a packet that matches this SPI group is treated as
  /// DPI-classified to the named DPI group without running
  /// ExtractHostname / MatchDpi. The SPI action is cached in the flow
  /// table; subsequent packets on the same 5-tuple skip DPI work
  /// entirely. Empty string = no link (legacy behaviour, full hostname
  /// DPI path runs as before).
  ///
  /// Use case: an SPI group whose IP ranges unambiguously identify an
  /// application (e.g. Facebook IP blocks always serve `*.facebook.com`)
  /// should declare the link so the per-packet TLS-SNI parse is skipped.
  /// Port-only catch-alls (port 80, port 443) should NOT declare a link
  /// — they can serve any application.
  std::string dpi_filter_group;
};

/// SPI configuration — hierarchical filter groups and worker settings.
struct SpiConfig {
  /// Number of worker lcores processing packets.
  std::uint16_t worker_count{1};
  /// Packet distribution mode: "auto", "queue", or "flow_hash".
  std::string packet_distribution{"auto"};
  /// Per-worker rte_ring size for flow_hash dispatcher mode.
  std::uint32_t dispatch_queue_size{kDefaultDispatchQueueSize};
  /// Drop packets that do not match any filter group.
  bool drop_unmatched{false};
  /// Flow cache TTL in seconds (0 = disable flow caching).
  std::uint32_t flow_ttl_sec{300};
  /// Maximum time to retain an incomplete IPv4 or IPv6 fragment set.
  std::uint32_t fragment_timeout_sec{60};
  /// TCP stream state used to make L7 DPI independent of TCP segmentation.
  TcpReassemblyConfig tcp_reassembly;
  /// Hard ceiling on concurrent flow cache entries (pre-allocated at startup).
  /// When exceeded, the action configured in `flow_overflow_action` is taken.
  std::uint32_t max_concurrent_flows{1'000'000};
  /// Action when the flow cache is full and a new connection arrives.
  /// "drop" — drop the packet (predictable, observable via `flow_table_full`).
  /// "reclassify" — forward without caching; the next packet re-runs SPI/DPI.
  std::string flow_overflow_action{"drop"};
  /// Maximum threads used to parse raw rules into compiled numeric filters.
  std::size_t max_compilation_threads{2};
  /// Maximum concurrent rte_acl_build operations. Keep this lower than the
  /// parsing thread count because every build needs a large temporary trie.
  std::size_t max_acl_build_threads{2};
  /// ACL classify implementation for SPI contexts: default, scalar, sse,
  /// avx2, neon, altivec, avx512x16, or avx512x32.
  std::string acl_classify_algorithm{"default"};
  /// Optional upper bound for each ACL context's runtime trie, in MiB.
  /// Zero preserves DPDK's normal memory-minimizing build behavior.
  std::size_t acl_build_max_size_mb{0};
  /// Path to binary BEVE or YAML rule stream file (e.g. "rules.beve").
  /// When specified, rules are loaded directly from this binary stream file.
  std::string rule_path;
  /// Hierarchical filter groups — sorted by precedence (ascending).
  std::vector<SpiFilterGroupConfig> filter_groups;
};

/// Single DPI filter rule — hostname pattern + filter group.
struct DpiFilterConfig {
  /// Hostname pattern ("*.facebook.com", "dns.google", "*" for catch-all).
  std::string hostname_pattern;
  /// Optional URI pattern (e.g. "http://*", "NA" for none).
  std::optional<std::string> uri_pattern;
  /// Filter group name (e.g. "fg_l7_facebook").
  std::string filter_group;
  /// Priority — lower value = higher priority.
  std::uint32_t priority{100};
  /// Human-readable label for this filter.
  std::string label;
};

/// DPI configuration — L7 hostname classification.
struct DpiConfig {
  /// Enable/disable DPI processing.
  bool enabled{false};
  /// Ordered list of DPI filters (sorted by priority after compilation).
  std::vector<DpiFilterConfig> filters;
};

/// Standalone rule store container for binary stream files.
struct RuleStoreConfig {
  std::vector<SpiFilterGroupConfig> filter_groups;
  DpiConfig dpi;
};

/// Pcap injector — bypass net_pcap PMD's payload truncation by reading a
/// pcap file from disk and feeding full L2-L7 mbufs into the dispatcher
/// rings. Used for end-to-end DPI verification without a real NIC.
struct PcapInjectorConfig {
  /// Enable the injector (defaults to `false` — no behaviour change when off).
  bool enabled{false};
  /// Path to the pcap file to read. Required when `enabled = true`.
  std::string pcap_file;
  /// How many times to replay the file. `0` means infinite loop.
  std::uint32_t loop_count{1};
  /// Rate limit; `0` = unlimited.
  std::uint64_t packets_per_second{0};
  /// Hard cap on packets emitted across all loops. `0` = no cap.
  std::uint64_t max_packets{0};
  /// Synthetic receive port id stored on `mbuf->port` so L2-pair lookup
  /// resolves to a valid (synthetic) port. Defaults to `0`.
  std::uint16_t receive_port_id{0};
  /// Maximum mbufs read per read-burst (capped at the pipeline max).
  std::uint32_t inject_burst_size{64};
};

/// Top-level application configuration — all config sections.
struct DpdkConfig {
  EalConfig eal;
  PortConfig port;
  MempoolConfig mempool;
  AppConfig app;
  L3ForwardConfig l3_forward;
  SpiConfig spi;
  DpiConfig dpi;
  /// Optional: only present when the user adds a `pcap_injector:` block.
  /// Glaze reflects std::optional<>'s monostate absence as "field omitted
  /// from YAML." Default-constructed when missing — equivalent to
  /// enabled=false with empty pcap_file.
  PcapInjectorConfig pcap_injector{};
};

}  // namespace dpdk
