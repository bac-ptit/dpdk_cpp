//
// Created by bac on 6/9/26.
//
#include "dpdk_environment.hpp"

#include <format>
#include <optional>
#include <print>

namespace {

// ---------------------------------------------------------------------------
// Error-checking macros for DPDK API calls
// ---------------------------------------------------------------------------

// Check ret < 0 — used by most rte_eth_* API calls
#define DPDK_CHECK_RET(expr, func) \
  do {                             \
    if (const auto ret{(expr)}; ret < 0) { \
      return std::unexpected(DpdkError{ \
        std::format("{} failed (ret={})", func, ret), errno \
      }); \
    } \
  } while (0)

// Check ret != 0 — used by rte_eth_promiscuous_enable, rte_eth_dev_info_get, etc.
#define DPDK_CHECK_RET_NEQ(expr, func) \
  do {                                  \
    if (const auto ret{(expr)}; ret != 0) { \
      return std::unexpected(DpdkError{ \
        std::format("{} failed (ret={})", func, ret), errno \
      }); \
    } \
  } while (0)

// Propagate std::expected error
#define DPDK_PROPAGATE(expr) \
  do { if (const auto r{expr}; !r) return std::unexpected(r.error()); } while (0)

// Build EAL argv array from EalConfig (parsed from config.yaml).
// rte_eal_init() requires C-style argv, so we construct it from the struct.
// No terminal args involved — everything comes from config.
[[nodiscard]] std::vector<std::string> build_eal_args(const EalConfig& eal) {
  std::vector<std::string> args;
  args.reserve(16);

  // argv[0] is required by EAL as program name
  args.emplace_back("dpdk_app");

  args.emplace_back("-c");
  args.emplace_back(eal.core_mask);

  args.emplace_back("-n");
  args.emplace_back(std::to_string(eal.memory_channels));

  if (!eal.socket_mem.empty()) {
    args.emplace_back("--socket-mem");
    args.emplace_back(eal.socket_mem);
  }
  if (eal.no_huge) {
    args.emplace_back("--no-huge");
  }
  if (eal.no_pci) {
    args.emplace_back("--no-pci");
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

[[nodiscard]] std::vector<char*> to_c_argv(const std::vector<std::string>& args) {
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (const auto& s : args) {
    argv.push_back(const_cast<char*>(s.c_str()));
  }
  return argv;
}

// Parse hex port mask string (e.g. "0x3") to uint32_t.
[[nodiscard]] std::optional<std::uint32_t> parse_port_mask(const std::string& mask) {
  if (mask.empty()) return std::nullopt;
  char* end{nullptr};
  const auto val{std::strtoul(mask.c_str(), &end, 16)};
  if (end == mask.c_str() || *end != '\0') return std::nullopt;
  return static_cast<std::uint32_t>(val);
}
}  // namespace

namespace dpdk {

Environment::Environment(DpdkConfig config) noexcept : config_{std::move(config)} {}

Environment::~Environment() {
  if (initialized_) {
    cleanup();
  }
}

std::expected<void, DpdkError> Environment::init() noexcept {
  if (initialized_) return {};  // already initialized, skip

  DPDK_PROPAGATE(init_eal());
  DPDK_PROPAGATE(create_mempool());
  DPDK_PROPAGATE(setup_ports());
  DPDK_PROPAGATE(check_link_status());
  initialized_ = true;

  return {};
}

std::expected<void, DpdkError> Environment::init_eal() noexcept {
  const auto args{build_eal_args(config_.eal)};
  auto argv{to_c_argv(args)};
  const int argc{static_cast<int>(argv.size())};

  // rte_eal_init consumes EAL args, returns number of args consumed
  DPDK_CHECK_RET(rte_eal_init(argc, argv.data()), "rte_eal_init");

  // Count available ports after EAL init
  port_count_ = rte_eth_dev_count_avail();
  if (port_count_ == 0) {
    return std::unexpected(DpdkError{
      "No Ethernet ports available after EAL init",
      0
    });
  }

  return {};
}

std::expected<void, DpdkError> Environment::create_mempool() noexcept {
  const auto& mc{config_.mempool};

  const auto num_mbufs{static_cast<unsigned>(
    std::max(mc.num_mbufs, static_cast<std::size_t>(port_count_) * 1024U)
  )};

  mbuf_pool_ = rte_pktmbuf_pool_create(
    mc.name.c_str(),
    num_mbufs,
    static_cast<unsigned>(mc.cache_size),
    0,  // private data size
    static_cast<unsigned>(mc.mbuf_size),
    rte_socket_id()
  );

  if (mbuf_pool_ == nullptr) {
    return std::unexpected(DpdkError{
      std::format("rte_pktmbuf_pool_create '{}' failed", mc.name),
      errno
    });
  }

  return {};
}

std::expected<void, DpdkError> Environment::setup_ports() noexcept {
  const auto& pc{config_.port};

  const auto mask{parse_port_mask(pc.port_mask)};
  if (!mask) {
    return std::unexpected(DpdkError{
      std::format("Invalid port mask '{}'", pc.port_mask), 0
    });
  }
  const auto port_mask{*mask};

  if (port_mask & ~((1U << port_count_) - 1U)) {
    return std::unexpected(DpdkError{
      std::format("Port mask 0x{:x} exceeds available ports (0x{:x})",
                   port_mask, (1U << port_count_) - 1U), 0
    });
  }

  std::uint16_t nb_ports_available{0};

  for (std::uint16_t port_id{0}; port_id < port_count_; ++port_id) {
    if ((port_mask & (1U << port_id)) == 0) {
      std::println("Skipping disabled port {}", port_id);
      continue;
    }

    auto dev_info{configure_port(port_id, pc)};
    DPDK_PROPAGATE(dev_info);

    auto nb_rxd{pc.rx_desc};
    auto nb_txd{pc.tx_desc};

    DPDK_PROPAGATE(setup_rx_queues(port_id, *dev_info, default_port_conf_, nb_rxd));
    DPDK_PROPAGATE(setup_tx_queues(port_id, *dev_info, default_port_conf_, nb_txd));

    DPDK_CHECK_RET(rte_eth_dev_start(port_id), "rte_eth_dev_start");

    if (pc.promiscuous) {
      DPDK_CHECK_RET_NEQ(rte_eth_promiscuous_enable(port_id), "rte_eth_promiscuous_enable");
    }

    active_ports_.push_back(port_id);
    ++nb_ports_available;
  }

  if (nb_ports_available == 0) {
    return std::unexpected(DpdkError{"No ports available after mask filtering", 0});
  }

  return {};
}

std::expected<rte_eth_dev_info, DpdkError> Environment::configure_port(
    std::uint16_t port_id, const PortConfig& pc) noexcept {

  rte_eth_dev_info dev_info{};
  DPDK_CHECK_RET_NEQ(rte_eth_dev_info_get(port_id, &dev_info), "rte_eth_dev_info_get");

  auto local_port_conf{default_port_conf_};
  if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
    local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
  }

  DPDK_CHECK_RET(rte_eth_dev_configure(port_id, pc.rx_queues, pc.tx_queues, &local_port_conf),
                 "rte_eth_dev_configure");

  auto nb_rxd{pc.rx_desc};
  auto nb_txd{pc.tx_desc};
  DPDK_CHECK_RET(rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd, &nb_txd),
                 "rte_eth_dev_adjust_nb_rx_tx_desc");

  rte_ether_addr mac_addr{};
  DPDK_CHECK_RET(rte_eth_macaddr_get(port_id, &mac_addr), "rte_eth_macaddr_get");
  port_mac_addrs_.push_back(mac_addr);

  return dev_info;
}

std::expected<void, DpdkError> Environment::setup_rx_queues(
    std::uint16_t port_id, const rte_eth_dev_info& dev_info,
    const rte_eth_conf& port_conf, std::uint16_t nb_rxd) noexcept {

  for (std::uint16_t q{0}; q < config_.port.rx_queues; ++q) {
    rte_eth_rxconf rxq_conf{dev_info.default_rxconf};
    rxq_conf.offloads = port_conf.rxmode.offloads;

    DPDK_CHECK_RET(rte_eth_rx_queue_setup(port_id, q, nb_rxd,
      rte_eth_dev_socket_id(port_id), &rxq_conf, mbuf_pool_),
      "rte_eth_rx_queue_setup");
  }

  return {};
}

std::expected<void, DpdkError> Environment::setup_tx_queues(
    std::uint16_t port_id, const rte_eth_dev_info& dev_info,
    const rte_eth_conf& port_conf, std::uint16_t nb_txd) const noexcept {

  for (std::uint16_t q{0}; q < config_.port.tx_queues; ++q) {
    rte_eth_txconf txq_conf{dev_info.default_txconf};
    txq_conf.offloads = port_conf.txmode.offloads;

    DPDK_CHECK_RET(rte_eth_tx_queue_setup(port_id, q, nb_txd,
      rte_eth_dev_socket_id(port_id), &txq_conf),
      "rte_eth_tx_queue_setup");
  }

  return {};
}

std::expected<void, DpdkError> Environment::check_link_status() noexcept {
  const auto& pc{config_.port};

  std::print("Checking link status");

  for (int count{0}; count <= pc.link_check_max_count; ++count) {
    bool all_ports_up{true};

    for (const auto port_id : active_ports_) {
      rte_eth_link link{};
      const int ret{rte_eth_link_get_nowait(port_id, &link)};
      if (ret < 0 || link.link_status == RTE_ETH_LINK_DOWN) {
        all_ports_up = false;
        break;
      }
    }

    if (all_ports_up) {
      std::println(" done");
      return {};
    }

    std::print(".");
    rte_delay_ms(pc.link_check_interval_ms);
  }

  // Timeout — not fatal, warn and continue
  std::println(" timeout (some links may still be down)");
  return {};
}

void Environment::cleanup() noexcept {
  for (const auto port_id : active_ports_) {
    std::print("Closing port {}...", port_id);
    const int ret{rte_eth_dev_stop(port_id)};
    if (ret != 0) {
      std::print(" rte_eth_dev_stop err={}", ret);
    }
    rte_eth_dev_close(port_id);
    std::println(" Done");
  }

  rte_eal_cleanup();
  std::println("DPDK environment cleaned up");
  initialized_ = false;
}

}  // namespace dpdk
