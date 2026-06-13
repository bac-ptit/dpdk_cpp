//
// Created by bac on 6/9/26.
//

// NOLINTBEGIN(misc-include-cleaner)
#include "dpdk_environment.hpp"

#include "dpdk_config.hpp"

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <expected>
#include <format>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

constexpr std::size_t kEalArgReserve{16};
constexpr std::uint64_t kDefaultRssHash{
    RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_TCP |
    RTE_ETH_RSS_NONFRAG_IPV4_UDP};

// Container for EAL argv that keeps string storage alive.
struct EalArgs {
  std::vector<std::string> args;
  std::vector<char*> argv;
  int argc{};
};

// Check DPDK function returning < 0 on failure.
[[nodiscard]] std::expected<void, dpdk::DpdkError> CheckNegativeResult(
    int dpdk_result, std::string_view function_name) noexcept {
  if (dpdk_result < 0) {
    return std::unexpected(dpdk::DpdkError{
        .message = std::format("{} failed (ret={})", function_name,
                               dpdk_result),
        .dpdk_errno = errno});
  }
  return {};
}

// Check DPDK function returning != 0 on failure.
[[nodiscard]] std::expected<void, dpdk::DpdkError> CheckNonZeroResult(
    int dpdk_result, std::string_view function_name) noexcept {
  if (dpdk_result != 0) {
    return std::unexpected(dpdk::DpdkError{
        .message = std::format("{} failed (ret={})", function_name,
                               dpdk_result),
        .dpdk_errno = errno});
  }
  return {};
}

// Build EAL argv from config struct — no terminal args, everything from YAML.
[[nodiscard]] std::vector<std::string> build_eal_args(const EalConfig& eal) {
  std::vector<std::string> args;
  args.reserve(kEalArgReserve);

  args.emplace_back("dpdk_app");

  args.emplace_back("-l");
  args.emplace_back(eal.core_list);

  args.emplace_back("-n");
  args.emplace_back(std::to_string(eal.memory_channels));

  if (eal.no_huge) {
    args.emplace_back("--no-huge");
  }
  if (!eal.memory_size.empty()) {
    args.emplace_back("-m");
    args.emplace_back(eal.memory_size);
  }
  if (eal.legacy_mem) {
    args.emplace_back("--legacy-mem");
  }
  if (eal.no_pci) {
    args.emplace_back("--no-pci");
  }
  for (const auto& vdev : eal.vdevs) {
    args.emplace_back("--vdev");
    args.emplace_back(vdev);
  }
  if (eal.proc_type != "primary") {
    args.emplace_back("--proc-type");
    args.emplace_back(eal.proc_type);
  }
  if (!eal.file_prefix.empty()) {
    args.emplace_back("--file-prefix");
    args.emplace_back(eal.file_prefix);
  }
  if (eal.log_level != "7") {
    args.emplace_back("--log-level");
    args.emplace_back(eal.log_level);
  }

  return args;
}

// Convert string vector to C-style argv for rte_eal_init.
[[nodiscard]] std::vector<char*> to_c_argv(std::vector<std::string>& args) {
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (auto& argument : args) {
    argv.push_back(argument.data());
  }
  return argv;
}

[[nodiscard]] EalArgs BuildEalArgv(const EalConfig& eal) {
  auto args{build_eal_args(eal)};
  auto argv{to_c_argv(args)};
  const int argc{static_cast<int>(argv.size())};
  return {
      .args = std::move(args),
      .argv = std::move(argv),
      .argc = argc,
  };
}

// Parse hex port mask like "0x3" into a bitmask.
[[nodiscard]] std::optional<std::uint32_t> parse_port_mask(
    const std::string& mask) {
  if (mask.empty()) {
    return std::nullopt;
  }
  char* end{nullptr};
  const auto val{std::strtoul(mask.c_str(), &end, 16)};
  if (end == mask.c_str() || *end != '\0') {
    return std::nullopt;
  }
  return static_cast<std::uint32_t>(val);
}

[[nodiscard]] std::pair<std::uint16_t, std::uint16_t> GetDescriptorCounts(
    const PortConfig& port_config) noexcept {
  return {port_config.rx_desc, port_config.tx_desc};
}

}  // namespace

namespace dpdk {

Environment::Environment(DpdkConfig config) noexcept : config_{std::move(config)} {}

Environment::~Environment() {
  if (initialized_) {
    Cleanup();
  }
}

// EAL → mempool → ports → link check — stops at first failure.
std::expected<void, DpdkError> Environment::init() noexcept {
  if (initialized_) {
    return {};
  }

  if (const auto init_result{InitEal()}; !init_result) {
    return std::unexpected(init_result.error());
  }
  if (const auto mempool_result{CreateMempool()}; !mempool_result) {
    return std::unexpected(mempool_result.error());
  }
  if (const auto ports_result{SetupPorts()}; !ports_result) {
    return std::unexpected(ports_result.error());
  }
  if (const auto link_result{CheckLinkStatus()}; !link_result) {
    return std::unexpected(link_result.error());
  }
  initialized_ = true;

  return {};
}

// Initialise EAL with args built from config.yaml.
std::expected<void, DpdkError> Environment::InitEal() noexcept {
  auto [args, argv, argc]{BuildEalArgv(config_.eal)};

  if (const auto eal_result{
          CheckNegativeResult(rte_eal_init(argc, argv.data()),
                              "rte_eal_init")};
      !eal_result) {
    return std::unexpected(eal_result.error());
  }

  port_count_ = rte_eth_dev_count_avail();
  if (port_count_ == 0) {
    return std::unexpected(DpdkError{
      .message = "No Ethernet ports available after EAL init",
      .dpdk_errno = 0
    });
  }
  port_mac_addrs_.resize(port_count_);

  return {};
}

// Create the mbuf pool used by all RX/TX queues.
std::expected<void, DpdkError> Environment::CreateMempool() noexcept {
  const auto& mempool_config{config_.mempool};
  const auto num_mbufs{static_cast<unsigned>(
      std::max(mempool_config.num_mbufs,
               static_cast<std::size_t>(port_count_) * 1024U))};

  mbuf_pool_ = rte_pktmbuf_pool_create(
    mempool_config.name.c_str(),
    num_mbufs,
    static_cast<unsigned>(mempool_config.cache_size),
    0,
    static_cast<unsigned>(mempool_config.mbuf_size),
    static_cast<int>(rte_socket_id())
  );

  if (mbuf_pool_ == nullptr) {
    return std::unexpected(DpdkError{
      .message = std::format("rte_pktmbuf_pool_create '{}' failed (rte_errno={}: {})",
                             mempool_config.name, rte_errno,
                             rte_strerror(rte_errno)),
      .dpdk_errno = rte_errno
    });
  }

  return {};
}

// Configure and start all ports matching the port mask.
std::expected<void, DpdkError> Environment::SetupPorts() noexcept {
  const auto port_mask{ValidatePortMask()};
  if (!port_mask) {
    return std::unexpected(port_mask.error());
  }

  std::uint16_t nb_ports_available{0};
  for (std::uint16_t port_id{0}; port_id < port_count_; ++port_id) {
    if (((*port_mask) & (1U << port_id)) == 0U) {
      std::println("Skipping disabled port {}", port_id);
      continue;
    }

    if (const auto port_result{SetupPort(port_id)}; !port_result) {
      return std::unexpected(port_result.error());
    }
    ++nb_ports_available;
  }

  if (nb_ports_available == 0) {
    return std::unexpected(DpdkError{
      .message = "No ports available after mask filtering",
      .dpdk_errno = 0
    });
  }

  return {};
}

std::expected<std::uint32_t, DpdkError> Environment::ValidatePortMask()
    const noexcept {
  const auto& port_config{config_.port};

  const auto mask{parse_port_mask(port_config.port_mask)};
  if (!mask) {
    return std::unexpected(DpdkError{
      .message = std::format("Invalid port mask '{}'",
                             port_config.port_mask),
      .dpdk_errno = 0
    });
  }
  const auto port_mask{*mask};

  if ((port_mask & ~((1U << port_count_) - 1U)) != 0U) {
    return std::unexpected(DpdkError{
      .message = std::format(
          "Port mask 0x{:x} exceeds available ports (0x{:x})",
          port_mask, (1U << port_count_) - 1U),
      .dpdk_errno = 0
    });
  }

  return port_mask;
}

// Full per-port setup: configure, queues, start, promiscuous.
std::expected<void, DpdkError> Environment::SetupPort(
    std::uint16_t port_id) noexcept {
  const auto& port_config{config_.port};
  auto dev_info{ConfigurePort(port_id, port_config)};
  if (!dev_info) {
    return std::unexpected(dev_info.error());
  }

  auto [nb_rxd, nb_txd]{GetDescriptorCounts(port_config)};

  if (const auto rx_result{SetupRxQueues(port_id, *dev_info,
                                           default_port_conf_, nb_rxd)};
      !rx_result) {
    return std::unexpected(rx_result.error());
  }
  if (const auto tx_result{SetupTxQueues(port_id, *dev_info,
                                           default_port_conf_, nb_txd)};
      !tx_result) {
    return std::unexpected(tx_result.error());
  }

  if (const auto start_result{
          CheckNegativeResult(rte_eth_dev_start(port_id),
                              "rte_eth_dev_start")};
      !start_result) {
    return std::unexpected(start_result.error());
  }

  if (port_config.promiscuous) {
    if (const auto promiscuous_result{CheckNonZeroResult(
            rte_eth_promiscuous_enable(port_id),
            "rte_eth_promiscuous_enable")};
        !promiscuous_result) {
      return std::unexpected(promiscuous_result.error());
    }
  }

  active_ports_.push_back(port_id);
  return {};
}

// Get device info, configure port, read MAC address.
std::expected<rte_eth_dev_info, DpdkError> Environment::ConfigurePort(
    std::uint16_t port_id, const PortConfig& port_config) noexcept {

  rte_eth_dev_info dev_info{};
  if (const auto info_result{CheckNonZeroResult(
          rte_eth_dev_info_get(port_id, &dev_info),
          "rte_eth_dev_info_get")};
      !info_result) {
    return std::unexpected(info_result.error());
  }
  if (port_config.rx_queues > dev_info.max_rx_queues) {
    return std::unexpected(DpdkError{
        .message = std::format(
            "port {} rx_queues={} exceeds PMD max_rx_queues={}", port_id,
            port_config.rx_queues, dev_info.max_rx_queues),
        .dpdk_errno = 0});
  }
  if (port_config.tx_queues > dev_info.max_tx_queues) {
    return std::unexpected(DpdkError{
        .message = std::format(
            "port {} tx_queues={} exceeds PMD max_tx_queues={}", port_id,
            port_config.tx_queues, dev_info.max_tx_queues),
        .dpdk_errno = 0});
  }

  auto local_port_conf{default_port_conf_};
  if ((dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) != 0UL) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
  }
  if (port_config.rx_queues > 1) {
    const auto rss_hf{kDefaultRssHash & dev_info.flow_type_rss_offloads};
    if (rss_hf != 0U) {
      local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
      local_port_conf.rx_adv_conf.rss_conf.rss_hf = rss_hf;
    } else {
      std::println(stderr,
                   "Warning: port {} has {} RX queues but PMD reports no "
                   "compatible RSS offloads; traffic may stay on queue 0",
                   port_id, port_config.rx_queues);
    }
  }

  if (const auto configure_result{CheckNegativeResult(
          rte_eth_dev_configure(port_id, port_config.rx_queues,
                                port_config.tx_queues, &local_port_conf),
          "rte_eth_dev_configure")};
      !configure_result) {
    return std::unexpected(configure_result.error());
  }

  auto [nb_rxd, nb_txd]{GetDescriptorCounts(port_config)};
  if (const auto adjust_result{CheckNegativeResult(
          rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd),
          "rte_eth_dev_adjust_nb_rx_tx_desc")};
      !adjust_result) {
    return std::unexpected(adjust_result.error());
  }

  rte_ether_addr mac_addr{};
  if (const auto mac_result{CheckNegativeResult(
          rte_eth_macaddr_get(port_id, &mac_addr), "rte_eth_macaddr_get")};
      !mac_result) {
    return std::unexpected(mac_result.error());
  }
  port_mac_addrs_[port_id] = mac_addr;

  return dev_info;
}

// Setup RX queue for each configured queue on the port.
std::expected<void, DpdkError> Environment::SetupRxQueues(
    std::uint16_t port_id, const rte_eth_dev_info& dev_info,
    const rte_eth_conf& port_conf, std::uint16_t nb_rxd) const noexcept {

  for (std::uint16_t queue_id{0}; queue_id < config_.port.rx_queues;
       ++queue_id) {
    rte_eth_rxconf rxq_conf{dev_info.default_rxconf};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    rxq_conf.offloads = port_conf.rxmode.offloads;

    if (const auto rx_setup_result{CheckNegativeResult(
            rte_eth_rx_queue_setup(port_id, queue_id, nb_rxd,
                                   rte_eth_dev_socket_id(port_id), &rxq_conf,
                                   mbuf_pool_),
            "rte_eth_rx_queue_setup")};
        !rx_setup_result) {
      return std::unexpected(rx_setup_result.error());
    }
  }

  return {};
}

// Setup TX queue for each configured queue on the port.
std::expected<void, DpdkError> Environment::SetupTxQueues(
    std::uint16_t port_id, const rte_eth_dev_info& dev_info,
    const rte_eth_conf& port_conf, std::uint16_t nb_txd) const noexcept {

  for (std::uint16_t queue_id{0}; queue_id < config_.port.tx_queues;
       ++queue_id) {
    rte_eth_txconf txq_conf{dev_info.default_txconf};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    txq_conf.offloads = port_conf.txmode.offloads;

    if (const auto tx_setup_result{CheckNegativeResult(
            rte_eth_tx_queue_setup(port_id, queue_id, nb_txd,
                                   rte_eth_dev_socket_id(port_id), &txq_conf),
            "rte_eth_tx_queue_setup")};
        !tx_setup_result) {
      return std::unexpected(tx_setup_result.error());
    }
  }

  return {};
}

// Poll links until all enabled ports report UP, with configurable timeout.
std::expected<void, DpdkError> Environment::CheckLinkStatus() const noexcept {
  const auto& port_config{config_.port};

  std::print("Checking link status");

  for (auto count{0}; count <= port_config.link_check_max_count; ++count) {
    bool all_ports_up{true};

    for (const auto port_id : active_ports_) {
      rte_eth_link link{};
      const int dpdk_result{rte_eth_link_get_nowait(port_id, &link)};
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      if (dpdk_result < 0 || link.link_status == RTE_ETH_LINK_DOWN) {
        all_ports_up = false;
        break;
      }
    }

    if (all_ports_up) {
      std::println(" done");
      return {};
    }

    std::print(".");
    rte_delay_ms(port_config.link_check_interval_ms);
  }

  std::println(" timeout (some links may still be down)");
  return {};
}

// Release all DPDK resources in reverse init order.
void Environment::Cleanup() noexcept {
  for (const auto port_id : active_ports_) {
    std::print("Closing port {}...", port_id);
    if (const int dpdk_result{rte_eth_dev_stop(port_id)}; dpdk_result != 0) {
      std::print(" rte_eth_dev_stop err={}", dpdk_result);
    }
    rte_eth_dev_close(port_id);
    std::println(" Done");
  }

  rte_eal_cleanup();
  std::println("DPDK environment cleaned up");
  initialized_ = false;
}

}  // namespace dpdk
// NOLINTEND(misc-include-cleaner)
