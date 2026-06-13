#pragma once
#include <rte_ether.h>
#include <rte_mempool.h>

#include <expected>
#include <string>
#include <vector>

#include "dpdk_config.hpp"

struct DpdkConfig;

namespace dpdk {

// Error information returned by fallible DPDK operations.
struct DpdkError {
  std::string message;
  int dpdk_errno{0};  // DPDK errno, 0 if not applicable
};

// RAII wrapper around DPDK EAL, mempool, ports, and queues.
// Owns all DPDK resources for the lifetime of the application.
class Environment final {
public:
  explicit Environment(DpdkConfig config) noexcept;
  ~Environment();

  Environment(const Environment&) = delete;
  Environment& operator=(const Environment&) = delete;

  // Run all init steps in order: EAL → mempool → ports → link check.
  [[nodiscard]] std::expected<void, DpdkError> init() noexcept;

  // Accessors — safe only after init() succeeds.
  [[nodiscard]] bool IsInitialized() const noexcept { return initialized_; }
  [[nodiscard]] rte_mempool* GetMemPool() const noexcept { return mbuf_pool_; }
  [[nodiscard]] const std::vector<std::uint16_t>& GetActivePorts() const noexcept {
    return active_ports_;
  }
  [[nodiscard]] std::uint16_t GetPortCount() const noexcept { return port_count_; }
  [[nodiscard]] const rte_ether_addr* GetPortMacAddress(
      std::uint16_t port_id) const noexcept {
    if (port_id >= port_mac_addrs_.size()) {
      return nullptr;
    }
    return &port_mac_addrs_[port_id];
  }

private:
  // Lifecycle steps — called in order by init().
  [[nodiscard]] std::expected<void, DpdkError> InitEal() noexcept;
  [[nodiscard]] std::expected<void, DpdkError> CreateMempool() noexcept;
  [[nodiscard]] std::expected<void, DpdkError> SetupPorts() noexcept;
  [[nodiscard]] std::expected<std::uint32_t, DpdkError> ValidatePortMask()
      const noexcept;
  [[nodiscard]] std::expected<void, DpdkError> SetupPort(
      std::uint16_t port_id) noexcept;
  [[nodiscard]] std::expected<void, DpdkError> CheckLinkStatus() const noexcept;

  // SetupPort helpers.
  [[nodiscard]] std::expected<rte_eth_dev_info, DpdkError> ConfigurePort(
    std::uint16_t port_id, const PortConfig& port_config) noexcept;
  [[nodiscard]] std::expected<void, DpdkError> SetupRxQueues(
    std::uint16_t port_id, const rte_eth_dev_info& dev_info,
    const rte_eth_conf& port_conf, std::uint16_t nb_rxd) const noexcept;
  [[nodiscard]] std::expected<void, DpdkError> SetupTxQueues(
    std::uint16_t port_id, const rte_eth_dev_info& dev_info,
    const rte_eth_conf& port_conf, std::uint16_t nb_txd) const noexcept;
  // Best-effort cleanup — cannot fail.
  void Cleanup() noexcept;

  DpdkConfig config_;
  bool initialized_{false};
  rte_mempool* mbuf_pool_{nullptr};
  std::uint16_t port_count_{};
  std::vector<std::uint16_t> active_ports_;
  std::vector<rte_ether_addr> port_mac_addrs_;

  static constexpr rte_eth_conf default_port_conf_{};
};

}  // namespace dpdk
