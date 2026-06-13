//
// Created by bac on 6/9/26.
//

#pragma once
#include <rte_ethdev.h>
#include <rte_mempool.h>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// EAL configuration — translated directly to DPDK EAL command-line args.
struct EalConfig {
  std::string core_list{"0-4"};        // -l
  int memory_channels{4};              // -n
  bool no_huge{false};                 // --no-huge
  std::string memory_size;         // -m (megabytes), preallocate in legacy mode
  bool legacy_mem{false};          // --legacy-mem
  bool no_pci{false};                  // --no-pci
  std::string proc_type{"primary"};    // --proc-type
  std::string file_prefix;         // --file-prefix
  std::string log_level{"7"};          // --log-level
  std::vector<std::string> vdevs;      // --vdev
};

// Ethernet port configuration — masks, queues, descriptors, link polling.
struct PortConfig {
  using PortPair = std::pair<std::uint16_t, std::uint16_t>;
  std::string port_mask{"0x1"};
  bool promiscuous{false};
  uint16_t rx_queues{1};
  uint16_t tx_queues{1};
  uint16_t rx_desc{1024};
  uint16_t tx_desc{1024};
  uint32_t link_speed{0};              // 0 = auto
  std::vector<PortPair> port_pairs;
  int link_check_interval_ms{100};     // poll interval for link status
  int link_check_max_count{90};        // max polls (interval * count = total timeout)
};

// Mempool configuration — mbuf pool name, size, cache, and buffer size.
struct MempoolConfig {
  std::string name{"mbuf_pool"};
  std::size_t num_mbufs{65536};
  std::size_t cache_size{256};
  std::size_t mbuf_size{RTE_MBUF_DEFAULT_BUF_SIZE};
};

// L2 forwarding configuration — burst size, MAC update, timer.
struct L2fwdConfig {
  bool mac_updating{true};
  uint16_t burst_size{32};
  uint16_t rx_queue_per_lcore{1};
  uint32_t timer_period_sec{10};
};

// Single SPI classification rule — protocol, ports, and label.
struct SpiRuleConfig {
  std::string protocol;
  std::optional<std::uint16_t> src_port;
  std::optional<std::uint16_t> dst_port;
  std::string label;
  // Optional legacy field; forwarding no longer dispatches packets to workers.
  std::vector<std::uint16_t> workers;
};

// SPI configuration — ordered rule list. worker_count is retained for legacy
// configs that still set per-rule workers.
struct SpiConfig {
  std::uint16_t worker_count{1};
  std::vector<SpiRuleConfig> rules;
};

// Top-level application configuration — all config sections.
struct DpdkConfig {
  EalConfig eal;
  PortConfig port;
  MempoolConfig mempool;
  L2fwdConfig l2fwd;
  SpiConfig spi;
};
