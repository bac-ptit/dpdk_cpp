#pragma once
#include <rte_ether.h>
#include <rte_mempool.h>

#include <expected>
#include <string>
#include <vector>

#include "dpdk_config.hpp"

namespace dpdk {

/// Error information returned by fallible DPDK operations.
struct DpdkError {
  /// Human-readable error description.
  std::string message;
  /// DPDK errno value, 0 if not applicable.
  int dpdk_errno{0};
};

/**
 * @brief RAII wrapper around DPDK EAL, mempool, ports, and queues.
 *
 * Owns all DPDK resources for the lifetime of the application. Follows a
 * strict init-teardown lifecycle: @ref init() must be called once and only
 * once after construction; the destructor or @ref Cleanup() releases all
 * resources in reverse order. The class is non-copyable and non-movable.
 */
class Environment final {
 public:
  /**
   * @brief Store config for deferred initialization.
   * @param config  Application configuration loaded from config.yaml.
   */
  explicit Environment(DpdkConfig config) noexcept;

  /// Release all DPDK resources if @ref init() completed successfully.
  ~Environment();

  Environment(const Environment&) = delete;
  Environment& operator=(const Environment&) = delete;

  /**
   * @brief Run all initialization steps: EAL, mempool, ports, link check.
   *
   * Each step stops on the first failure and returns an error. Must be
   * called exactly once after construction.
   * @return Void on success, or a DpdkError describing the failure.
   */
  [[nodiscard]] std::expected<void, DpdkError> init() noexcept;

  // ── Accessors — safe only after init() succeeds ──────────────────────

  /// Whether @ref init() completed successfully.
  [[nodiscard]] bool IsInitialized() const noexcept { return initialized_; }

  /// The shared mbuf pool used by all RX queues.
  [[nodiscard]] rte_mempool* GetMemPool() const noexcept { return memory_buffer_pool_; }

  /// Port IDs matched by the port mask and successfully started.
  [[nodiscard]] const std::vector<std::uint16_t>& GetActivePorts() const noexcept { return active_ports_; }

  /// Total Ethernet ports available after EAL init.
  [[nodiscard]] std::uint16_t GetPortCount() const noexcept { return port_count_; }

  /**
   * @brief Look up the MAC address for a given port.
   * @param port_id  The DPDK port identifier.
   * @return Pointer to the MAC address, or nullptr if out of range.
   */
  [[nodiscard]] const rte_ether_addr* GetPortMacAddress(std::uint16_t port_id) const noexcept {
    if (port_id >= port_mac_addrs_.size()) {
      return nullptr;
    }
    return &port_mac_addrs_[port_id];
  }

 private:
  /// Per-port configuration and device info collected during ConfigurePort.
  struct PortSetupInfo {
    rte_eth_dev_info dev_info{};
    rte_eth_conf port_conf{};
    std::uint16_t receive_descriptors{};
    std::uint16_t transmit_descriptors{};
  };

  // ── Lifecycle steps — called in order by init() ──────────────────────

  /**
   * @brief Initialize DPDK EAL with config-derived command-line arguments.
   * @return Void on success, or a DpdkError describing the failure.
   */
  [[nodiscard]] std::expected<void, DpdkError> InitEal() noexcept;
  /**
   * @brief Create the shared mbuf pool for all RX/TX operations.
   * @return Void on success, or a DpdkError describing the failure.
   */
  [[nodiscard]] std::expected<void, DpdkError> CreateMempool() noexcept;
  /**
   * @brief Validate port mask and set up all matching ports.
   * @return Void on success, or a DpdkError describing the failure.
   */
  [[nodiscard]] std::expected<void, DpdkError> SetupPorts() noexcept;
  /**
   * @brief Validate that the port mask hex string is within range.
   * @return Bitmask on success, or a DpdkError if parsing fails.
   */
  [[nodiscard]] std::expected<std::uint32_t, DpdkError> ValidatePortMask() const noexcept;
  /**
   * @brief Configure queues, start the device, and optionally enable promiscuous mode.
   * @param port_id  DPDK port identifier.
   * @return Void on success, or a DpdkError describing the failure.
   */
  [[nodiscard]] std::expected<void, DpdkError> SetupPort(std::uint16_t port_id) noexcept;
  /**
   * @brief Poll link status for all active ports until up or timeout.
   * @return Void on success, or a DpdkError if link polling fails.
   */
  [[nodiscard]] std::expected<void, DpdkError> CheckLinkStatus() const noexcept;

  // ── SetupPort helpers ────────────────────────────────────────────────

  /**
   * @brief Gather device info, validate queue counts, configure port.
   * @param port_id      DPDK port identifier.
   * @param port_config  Port configuration from config.
   * @return PortSetupInfo on success, or a DpdkError.
   */
  [[nodiscard]] std::expected<PortSetupInfo, DpdkError> ConfigurePort(std::uint16_t port_id,
                                                                      const PortConfig& port_config) noexcept;
  /**
   * @brief Set up all receiver queues for the given port.
   * @param port_id              DPDK port identifier.
   * @param dev_info             Device info from rte_eth_dev_info_get.
   * @param port_conf            Port configuration after RSS setup.
   * @param receive_descriptors  Number of RX descriptors per queue.
   * @return Void on success, or a DpdkError.
   */
  [[nodiscard]] std::expected<void, DpdkError> SetupReceiveQueues(std::uint16_t port_id,
                                                                  const rte_eth_dev_info& dev_info,
                                                                  const rte_eth_conf& port_conf,
                                                                  std::uint16_t receive_descriptors) const noexcept;
  /**
   * @brief Set up all transmit queues for the given port.
   * @param port_id               DPDK port identifier.
   * @param dev_info              Device info from rte_eth_dev_info_get.
   * @param port_conf             Port configuration after RSS setup.
   * @param transmit_descriptors  Number of TX descriptors per queue.
   * @return Void on success, or a DpdkError.
   */
  [[nodiscard]] std::expected<void, DpdkError> SetupTransmitQueues(std::uint16_t port_id,
                                                                   const rte_eth_dev_info& dev_info,
                                                                   const rte_eth_conf& port_conf,
                                                                   std::uint16_t transmit_descriptors) const noexcept;

  /// Best-effort cleanup — cannot fail.
  void Cleanup() noexcept;

  DpdkConfig config_;
  bool initialized_{false};
  rte_mempool* memory_buffer_pool_{nullptr};
  std::uint16_t port_count_{};
  std::vector<std::uint16_t> active_ports_;
  std::vector<rte_ether_addr> port_mac_addrs_;

  static constexpr rte_eth_conf default_port_conf_{};
};

}  // namespace dpdk
