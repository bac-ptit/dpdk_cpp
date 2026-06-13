//
// Created by bac on 6/9/26.
//

#pragma once
#include <rte_ethdev.h>
#include <rte_mempool.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

struct EalConfig {
  std::string core_mask{"0x3"};        // -c or -l
  int memory_channels{4};              // -n
  std::string socket_mem;          // --socket-mem
  bool no_huge{false};                 // --no-huge
  bool no_pci{false};                  // --no-pci
  std::string proc_type{"primary"};    // --proc-type
  std::string file_prefix;         // --file-prefix
  std::string log_level{"7"};          // --log-level
};

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

struct MempoolConfig {
  std::string name{"mbuf_pool"};
  std::size_t num_mbufs{65536};
  std::size_t cache_size{256};
  std::size_t mbuf_size{RTE_MBUF_DEFAULT_BUF_SIZE};
};

struct L2fwdConfig {
  bool mac_updating{true};
  uint16_t burst_size{32};
  uint16_t rx_queue_per_lcore{1};
  uint32_t timer_period_sec{10};
};

struct DpdkConfig {
  EalConfig eal;
  PortConfig port;
  MempoolConfig mempool;
  L2fwdConfig l2fwd;
};