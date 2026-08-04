// NOLINTBEGIN(misc-include-cleaner)
#include "dpdk/dpdk_environment.hpp"

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_hash_crc.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <algorithm>
#include <array>
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

#include "dpdk/config/dpdk_config.hpp"
#include <rte_vect.h>

namespace {

constexpr std::size_t kEalArgReserve{16};
constexpr std::uint64_t kDefaultRssHash{
    RTE_ETH_RSS_IPV4 | RTE_ETH_RSS_FRAG_IPV4 | RTE_ETH_RSS_NONFRAG_IPV4_TCP | RTE_ETH_RSS_NONFRAG_IPV4_UDP |
    RTE_ETH_RSS_IPV6 | RTE_ETH_RSS_FRAG_IPV6 | RTE_ETH_RSS_NONFRAG_IPV6_TCP | RTE_ETH_RSS_NONFRAG_IPV6_UDP};
constexpr std::array<std::string_view, 11> kSoftwareBackedDriverPrefixes{
    "net_af_packet", "net_pcap",    "net_tap",  "net_ring",    "net_memif",  "net_vhost",
    "net_virtio",    "net_vmxnet3", "net_null", "net_softnic", "net_af_xdp",
};

/// Container for EAL argv that keeps string storage alive.
struct EalArgs {
  std::vector<std::string> args;
  std::vector<char*> argv;
  int argc{};
};

/**
 * @brief Check a DPDK function that returns < 0 on failure.
 * @param dpdk_result    The return value to check.
 * @param function_name  Human-readable name for error messages.
 * @return Void on success, or a DpdkError describing the failure.
 */
[[nodiscard]] std::expected<void, dpdk::DpdkError> CheckNegativeResult(int dpdk_result,
                                                                       std::string_view function_name) noexcept {
  if (dpdk_result < 0) {
    return std::unexpected(
        dpdk::DpdkError{.message = std::format("{} failed (ret={})", function_name, dpdk_result), .dpdk_errno = errno});
  }
  return {};
}

/**
 * @brief Check a DPDK function that returns != 0 on failure.
 * @param dpdk_result    The return value to check.
 * @param function_name  Human-readable name for error messages.
 * @return Void on success, or a DpdkError describing the failure.
 */
[[nodiscard]] std::expected<void, dpdk::DpdkError> CheckNonZeroResult(int dpdk_result,
                                                                      std::string_view function_name) noexcept {
  if (dpdk_result != 0) {
    return std::unexpected(
        dpdk::DpdkError{.message = std::format("{} failed (ret={})", function_name, dpdk_result), .dpdk_errno = errno});
  }
  return {};
}

/**
 * @brief Build EAL argv strings from config struct — no terminal args.
 *
 * Translates the YAML-derived EalConfig into DPDK command-line arguments
 * suitable for rte_eal_init. Every option is derived from config.
 * @param eal  The EAL configuration struct.
 * @return Vector of argument strings (not yet null-terminated).
 */
[[nodiscard]] std::vector<std::string> BuildEalArgs(const dpdk::EalConfig& eal) noexcept {
  std::vector<std::string> args;
  args.reserve(kEalArgReserve);

  args.emplace_back("dpdk_app");

  args.emplace_back("-l");
  args.emplace_back(eal.cpu_core_list);

  args.emplace_back("-n");
  args.emplace_back(std::to_string(eal.memory_channels));

  if (eal.disable_hugepages) {
    args.emplace_back("--no-huge");
  }
  if (!eal.memory_size.empty()) {
    args.emplace_back("-m");
    args.emplace_back(eal.memory_size);
  }
  if (eal.legacy_memory) {
    args.emplace_back("--legacy-mem");
  }
  if (eal.disable_pci) {
    args.emplace_back("--no-pci");
  }
  for (const auto& vdev : eal.virtual_devices) {
    args.emplace_back("--vdev");
    args.emplace_back(vdev);
  }
  if (eal.process_type != "primary") {
    args.emplace_back("--proc-type");
    args.emplace_back(eal.process_type);
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

/**
 * @brief Convert string vector to C-style argv for rte_eal_init.
 * @param args  Mutable string storage (data pointers are taken).
 * @return Vector of C-string pointers suitable for rte_eal_init.
 */
[[nodiscard]] std::vector<char*> ToCArgv(std::vector<std::string>& args) noexcept {
  std::vector<char*> argv;
  argv.reserve(args.size());
  for (auto& argument : args) {
    argv.push_back(argument.data());
  }
  return argv;
}

/**
 * @brief Build the complete (argv, argc) pair for rte_eal_init from config.
 * @param eal  The EAL configuration struct.
 * @return An EalArgs with stable string storage and C-style pointers.
 */
[[nodiscard]] EalArgs BuildEalArgv(const dpdk::EalConfig& eal) noexcept {
  auto args{BuildEalArgs(eal)};
  auto argv{ToCArgv(args)};
  const int argc{static_cast<int>(argv.size())};
  return {
      .args = std::move(args),
      .argv = std::move(argv),
      .argc = argc,
  };
}

/**
 * @brief Parse a hex port mask string (e.g. "0x3") into a bitmask.
 * @param mask  The hex string with optional "0x" prefix.
 * @return The parsed bitmask, or nullopt on parse failure.
 */
[[nodiscard]] std::optional<std::uint32_t> ParsePortMask(const std::string& mask) noexcept {
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

/// Whether a PMD driver is software-backed or virtualized.
[[nodiscard]] bool IsSoftwareBackedDriver(std::string_view driver_name) noexcept {
  return std::ranges::any_of(kSoftwareBackedDriverPrefixes,
                             [driver_name](const std::string_view prefix) { return driver_name.starts_with(prefix); });
}

}  // namespace

namespace dpdk {

Environment::Environment(DpdkConfig config) noexcept : config_{std::move(config)} {}

Environment::~Environment() {
  if (initialized_) {
    Cleanup();
  }
}

std::expected<void, DpdkError> Environment::init() noexcept {
  if (initialized_) {
    return {};
  }

  // Pcap-injector mode runs without any NIC port; the pipeline injects
  // packets from a disk file directly into the dispatcher rings. Skip
  // the InitEal port-count precondition and the SetupPorts/CheckLink
  // phases so the binary stays usable on hosts with zero NIC devices.
  skip_ports_ = config_.pcap_injector.enabled;

  if (const auto init_result{InitEal()}; !init_result) {
    return std::unexpected(init_result.error());
  }
  if (const auto mempool_result{CreateMempool()}; !mempool_result) {
    return std::unexpected(mempool_result.error());
  }
  if (skip_ports_) {
    initialized_ = true;
    return {};
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

/**
 * @brief Initialize EAL with config-derived arguments.
 *
 * Builds argv from EalConfig, calls rte_eal_init, and records the available
 * port count and allocates MAC-address storage.
 * @return Void on success, or a DpdkError.
 */
std::expected<void, DpdkError> Environment::InitEal() noexcept {
  auto [args, argv, argc]{BuildEalArgv(config_.eal)};

  if (const auto eal_result{CheckNegativeResult(rte_eal_init(argc, argv.data()), "rte_eal_init")}; !eal_result) {
    return std::unexpected(eal_result.error());
  }

  // Pin the CRC32 algorithm used by `rte_hash_crc` (FlowTable's hash func).
  // DPDK's runtime auto-detection picks the best implementation per call;
  // hard-pinning at init removes the per-call dispatch branch and makes the
  // choice deterministic across hosts. The SSE4.2 path is universally
  // available on our bench host; `rte_hash_crc_set_alg` returns void, so
  // there is no error to propagate. If SSE4.2 is unavailable, the function
  // is a no-op and the auto-detect fallback remains in effect.
  rte_hash_crc_set_alg(CRC32_SSE42_x64);

  // Pin the widest SIMD bitwidth DPDK should vectorize at runtime. On
  // AVX-512 capable CPUs (Xeon Skylake-X / Sapphire Rapids) this unlocks
  // the AVX-512 path in `rte_acl_classify` — Intel's AVX-512 brief
  // reports up to 3× faster ACL flow searches vs scalar. On this WSL2
  // host (no AVX-512) it is a no-op; DPDK remains on AVX2. The call
  // returns -ENOTSUP on hosts that have no wider-than-default bitwidth to
  // offer — we ignore that case. See
  // docs_search/17_os_skip_optimizations.md §3.
  (void)rte_vect_set_max_simd_bitwidth(/*RTE_VECT_SIMD_MAX=*/512);

  port_count_ = rte_eth_dev_count_avail();
  if (port_count_ == 0 && !skip_ports_) {
    return std::unexpected(DpdkError{.message = "No Ethernet ports available after EAL init", .dpdk_errno = 0});
  }
  if (skip_ports_) {
    // Pcap-injector mode has no real NIC. Synthesize a single sentinel
    // port id so worker `transmit_buffers[GetPortCount()]` indexing
    // (and the flush buffer-size loop) stays in range. Staging
    // buffers are still drained by the guard in FlushTransmitBuffers.
    port_count_ = 1;
    active_ports_.push_back(0);
  }
  port_mac_addrs_.resize(port_count_);
  port_runtime_infos_.resize(port_count_);

  return {};
}

/**
 * @brief Create the shared mbuf pool.
 *
 * Uses mempool config from DpdkConfig. Ensures at least
 * `port_count_ * 1024` mbufs are available.
 * @return Void on success, or a DpdkError.
 */
std::expected<void, DpdkError> Environment::CreateMempool() noexcept {
  const auto& [name, memory_buffer_count, cache_size, memory_buffer_size]{config_.mempool};
  const auto num_mbufs{static_cast<unsigned>(
      std::max(memory_buffer_count, static_cast<std::size_t>(port_count_) * 1024U))};

  memory_buffer_pool_ = rte_pktmbuf_pool_create(
      name.c_str(), num_mbufs, static_cast<unsigned>(cache_size), 0,
      static_cast<unsigned>(memory_buffer_size), static_cast<int>(rte_socket_id()));

  if (memory_buffer_pool_ == nullptr) {
    return std::unexpected(DpdkError{.message = std::format("rte_pktmbuf_pool_create '{}' failed (rte_errno={}: {})",
                                                            name, rte_errno, rte_strerror(rte_errno)),
                                     .dpdk_errno = rte_errno});
  }

  return {};
}

/**
 * @brief Validate port mask and set up all matching ports.
 *
 * Iterates all available ports, skips those not in the mask,
 * and configures/starts those that match.
 * @return Void on success, or a DpdkError.
 */
std::expected<void, DpdkError> Environment::SetupPorts() noexcept {
  const auto port_mask{ValidatePortMask()};
  if (!port_mask) {
    return std::unexpected(port_mask.error());
  }

  std::uint16_t nb_ports_available{0};
  for (std::uint16_t port_id{0}; port_id < port_count_; ++port_id) {
    if ((*port_mask & 1U << port_id) == 0U) {
      std::println("Skipping disabled port {}", port_id);
      continue;
    }

    if (const auto port_result{SetupPort(port_id)}; !port_result) {
      return std::unexpected(port_result.error());
    }
    ++nb_ports_available;
  }

  if (nb_ports_available == 0) {
    return std::unexpected(DpdkError{.message = "No ports available after mask filtering", .dpdk_errno = 0});
  }

  return {};
}

/**
 * @brief Parse and validate hex port mask.
 * @return Bitmask on success, or a DpdkError.
 */
std::expected<std::uint32_t, DpdkError> Environment::ValidatePortMask() const noexcept {
  const auto& port_config{config_.port};

  const auto mask{ParsePortMask(port_config.port_bitmask)};
  if (!mask) {
    return std::unexpected(
        DpdkError{.message = std::format("Invalid port mask '{}'", port_config.port_bitmask), .dpdk_errno = 0});
  }
  const auto port_mask{*mask};

  if ((port_mask & ~((1U << port_count_) - 1U)) != 0U) {
    return std::unexpected(DpdkError{.message = std::format("Port mask 0x{:x} exceeds available ports (0x{:x})",
                                                            port_mask, (1U << port_count_) - 1U),
                                     .dpdk_errno = 0});
  }

  return port_mask;
}

/**
 * @brief Configure queues, start device, enable promiscuous if requested.
 * @param port_id  DPDK port identifier.
 * @return Void on success, or a DpdkError.
 */
std::expected<void, DpdkError> Environment::SetupPort(std::uint16_t port_id) noexcept {
  const auto& port_config{config_.port};
  auto setup_info{ConfigurePort(port_id, port_config)};
  if (!setup_info) {
    return std::unexpected(setup_info.error());
  }

  if (const auto receive_result{
          SetupReceiveQueues(port_id, setup_info->dev_info, setup_info->port_conf, setup_info->receive_descriptors)};
      !receive_result) {
    return std::unexpected(receive_result.error());
  }
  if (const auto transmit_result{
          SetupTransmitQueues(port_id, setup_info->dev_info, setup_info->port_conf, setup_info->transmit_descriptors)};
      !transmit_result) {
    return std::unexpected(transmit_result.error());
  }

  if (const auto start_result{CheckNegativeResult(rte_eth_dev_start(port_id), "rte_eth_dev_start")}; !start_result) {
    return std::unexpected(start_result.error());
  }

  if (port_config.promiscuous) {
    if (const auto promiscuous_result{
            CheckNonZeroResult(rte_eth_promiscuous_enable(port_id), "rte_eth_promiscuous_enable")};
        !promiscuous_result) {
      return std::unexpected(promiscuous_result.error());
    }
  }

  active_ports_.push_back(port_id);
  return {};
}

/**
 * @brief Query device info, validate queues, configure port, get MAC.
 *
 * Orchestrates six focused steps: query → store → validate → build conf →
 * apply → retrieve MAC. Each step is a separate helper for readability.
 */
std::expected<Environment::PortSetupInfo, DpdkError> Environment::ConfigurePort(
    std::uint16_t port_id, const PortConfig& port_config) noexcept {
  auto dev_info{QueryDeviceInfo(port_id)};
  if (!dev_info) {
    return std::unexpected(dev_info.error());
  }

  StoreRuntimeInfo(port_id, *dev_info);

  if (const auto queue_result{ValidateQueueCounts(port_id, port_config, *dev_info)}; !queue_result) {
    return std::unexpected(queue_result.error());
  }

  auto local_port_conf{BuildPortConf(port_config, *dev_info, port_id)};

  auto descriptors{ApplyConfiguration(port_id, port_config, local_port_conf)};
  if (!descriptors) {
    return std::unexpected(descriptors.error());
  }

  if (const auto mac_result{RetrieveMacAddress(port_id)}; !mac_result) {
    return std::unexpected(mac_result.error());
  }

  return PortSetupInfo{
      .dev_info = *dev_info,
      .port_conf = local_port_conf,
      .receive_descriptors = descriptors->receive_descriptors,
      .transmit_descriptors = descriptors->transmit_descriptors,
  };
}

std::expected<rte_eth_dev_info, DpdkError> Environment::QueryDeviceInfo(std::uint16_t port_id) const noexcept {
  rte_eth_dev_info dev_info{};
  if (const auto info_result{CheckNonZeroResult(rte_eth_dev_info_get(port_id, &dev_info), "rte_eth_dev_info_get")};
      !info_result) {
    return std::unexpected(info_result.error());
  }
  return dev_info;
}

void Environment::StoreRuntimeInfo(std::uint16_t port_id, const rte_eth_dev_info& dev_info) noexcept {
  const std::string_view driver_name{dev_info.driver_name == nullptr ? "" : dev_info.driver_name};
  port_runtime_infos_[port_id] = PortRuntimeInfo{
      .driver_name = std::string{driver_name},
      .rss_offloads = dev_info.flow_type_rss_offloads,
      .software_backed = IsSoftwareBackedDriver(driver_name),
  };
  std::println("Port {} driver={} rss_offloads=0x{:x}", port_id, driver_name, dev_info.flow_type_rss_offloads);
}

std::expected<void, DpdkError> Environment::ValidateQueueCounts(std::uint16_t port_id,
                                                                const PortConfig& port_config,
                                                                const rte_eth_dev_info& dev_info) const noexcept {
  if (port_config.receive_queues > dev_info.max_rx_queues) {
    return std::unexpected(
        DpdkError{.message = std::format("port {} receive_queues={} exceeds PMD max_rx_queues={}", port_id,
                                         port_config.receive_queues, dev_info.max_rx_queues),
                  .dpdk_errno = 0});
  }
  if (port_config.transmit_queues > dev_info.max_tx_queues) {
    return std::unexpected(
        DpdkError{.message = std::format("port {} transmit_queues={} exceeds PMD max_tx_queues={}", port_id,
                                         port_config.transmit_queues, dev_info.max_tx_queues),
                  .dpdk_errno = 0});
  }
  return {};
}

rte_eth_conf Environment::BuildPortConf(const PortConfig& port_config,
                                        const rte_eth_dev_info& dev_info,
                                        std::uint16_t port_id) const noexcept {
  auto port_conf{default_port_conf_};

  if ((dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) != 0UL) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
  }

  if (port_config.receive_queues > 1) {
    const auto rss_hf{kDefaultRssHash & dev_info.flow_type_rss_offloads};
    if (rss_hf != 0U) {
      port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
      port_conf.rx_adv_conf.rss_conf.rss_hf = rss_hf;
    } else {
      std::println(stderr,
                   "Warning: port {} has {} RX queues but PMD reports no "
                   "compatible RSS offloads; traffic may stay on queue 0",
                   port_id, port_config.receive_queues);
    }
  }

  return port_conf;
}

std::expected<Environment::DescriptorCounts, DpdkError> Environment::ApplyConfiguration(
    std::uint16_t port_id, const PortConfig& port_config, const rte_eth_conf& port_conf) noexcept {
  if (const auto configure_result{CheckNegativeResult(
          rte_eth_dev_configure(port_id, port_config.receive_queues, port_config.transmit_queues, &port_conf),
          "rte_eth_dev_configure")};
      !configure_result) {
    return std::unexpected(configure_result.error());
  }

  auto receive_descriptors{port_config.receive_descriptors};
  auto transmit_descriptors{port_config.transmit_descriptors};
  if (const auto adjust_result{
          CheckNegativeResult(rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &receive_descriptors, &transmit_descriptors),
                              "rte_eth_dev_adjust_nb_rx_tx_desc")};
      !adjust_result) {
    return std::unexpected(adjust_result.error());
  }

  return DescriptorCounts{
      .receive_descriptors = receive_descriptors,
      .transmit_descriptors = transmit_descriptors,
  };
}

std::expected<void, DpdkError> Environment::RetrieveMacAddress(std::uint16_t port_id) noexcept {
  rte_ether_addr mac_addr{};
  if (const auto mac_result{CheckNegativeResult(rte_eth_macaddr_get(port_id, &mac_addr), "rte_eth_macaddr_get")};
      !mac_result) {
    return std::unexpected(mac_result.error());
  }
  port_mac_addrs_[port_id] = mac_addr;
  return {};
}

/**
 * @brief Set up all receiver queues for a port.
 * @param port_id              DPDK port identifier.
 * @param dev_info             Device info for default rxconf.
 * @param port_conf            Port config for RX offloads.
 * @param receive_descriptors  Descriptors per RX queue.
 * @return Void on success, or a DpdkError.
 */
std::expected<void, DpdkError> Environment::SetupReceiveQueues(std::uint16_t port_id, const rte_eth_dev_info& dev_info,
                                                               const rte_eth_conf& port_conf,
                                                               std::uint16_t receive_descriptors) const noexcept {
  for (std::uint16_t queue_id{0}; queue_id < config_.port.receive_queues; ++queue_id) {
    rte_eth_rxconf receive_queue_conf{dev_info.default_rxconf};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    receive_queue_conf.offloads = port_conf.rxmode.offloads;

    if (const auto receive_setup_result{CheckNegativeResult(
            rte_eth_rx_queue_setup(port_id, queue_id, receive_descriptors, rte_eth_dev_socket_id(port_id),
                                   &receive_queue_conf, memory_buffer_pool_),
            "rte_eth_rx_queue_setup")};
        !receive_setup_result) {
      return std::unexpected(receive_setup_result.error());
    }
  }

  return {};
}

/**
 * @brief Set up all transmitted queues for a port.
 * @param port_id               DPDK port identifier.
 * @param dev_info              Device info for default txconf.
 * @param port_conf             Port config for TX offloads.
 * @param transmit_descriptors  Descriptors per TX queue.
 * @return Void on success, or a DpdkError.
 */
std::expected<void, DpdkError> Environment::SetupTransmitQueues(std::uint16_t port_id, const rte_eth_dev_info& dev_info,
                                                                const rte_eth_conf& port_conf,
                                                                std::uint16_t transmit_descriptors) const noexcept {
  for (std::uint16_t queue_id{0}; queue_id < config_.port.transmit_queues; ++queue_id) {
    rte_eth_txconf transmit_queue_conf{dev_info.default_txconf};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
    transmit_queue_conf.offloads = port_conf.txmode.offloads;

    if (const auto transmit_setup_result{
            CheckNegativeResult(rte_eth_tx_queue_setup(port_id, queue_id, transmit_descriptors,
                                                       rte_eth_dev_socket_id(port_id), &transmit_queue_conf),
                                "rte_eth_tx_queue_setup")};
        !transmit_setup_result) {
      return std::unexpected(transmit_setup_result.error());
    }
  }

  return {};
}

/**
 * @brief Poll link status for all active ports until up or timeout.
 *
 * Prints a dot per poll iteration. Times out after
 * `link_check_max_count` polls at `link_check_interval_ms` intervals.
 * @return Void on success (all links up), or a DpdkError on timeout.
 */
std::expected<void, DpdkError> Environment::CheckLinkStatus() const noexcept {
  const auto& port_config{config_.port};

  std::print("Checking link status");

  for (auto count{0}; count <= port_config.link_check_max_count; ++count) {
    bool all_ports_up{true};

    for (const auto port_id : active_ports_) {
      rte_eth_link link{};
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-union-access)
      if (const int dpdk_result{rte_eth_link_get_nowait(port_id, &link)};
          dpdk_result < 0 || link.link_status == RTE_ETH_LINK_DOWN) {
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

/**
 * @brief Best-effort cleanup: stop ports, close devices, clean up EAL.
 *
 * Called by the destructor or explicitly. Prints status for each port.
 */
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

bool Environment::HasSoftwareBackedPort() const noexcept {
  return std::ranges::any_of(active_ports_, [this](std::uint16_t port_id) {
    return port_id < port_runtime_infos_.size() && port_runtime_infos_[port_id].software_backed;
  });
}

bool Environment::ActivePortsSupportRss() const noexcept {
  return std::ranges::all_of(active_ports_, [this](std::uint16_t port_id) {
    return port_id < port_runtime_infos_.size() && port_runtime_infos_[port_id].rss_offloads != 0U;
  });
}

bool Environment::HasPcapPort() const noexcept {
  return std::ranges::any_of(active_ports_, [this](std::uint16_t port_id) {
    return port_id < port_runtime_infos_.size() &&
           port_runtime_infos_[port_id].driver_name.starts_with("net_pcap");
  });
}

std::string_view Environment::GetPortDriverName(std::uint16_t port_id) const noexcept {
  if (port_id >= port_runtime_infos_.size()) {
    return {};
  }
  return port_runtime_infos_[port_id].driver_name;
}

}  // namespace dpdk
// NOLINTEND(misc-include-cleaner)
