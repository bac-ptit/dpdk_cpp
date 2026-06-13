//
// Created by bac on 6/9/26.
//

#pragma once
#include <rte_mempool.h>

#include <expected>
#include <string>

#include "dpdk_config.hpp"

struct DpdkConfig;
namespace dpdk {
struct DpdkError {
  std::string message;
  int dpdk_errno{0};  // DPDK errno, 0 if not applicable
};

class Environment final {
public:
  explicit Environment(DpdkConfig config) noexcept;
  ~Environment();

  // Non-copyable — DPDK resources are tied to global state
  Environment(const Environment&) = delete;
  Environment& operator=(const Environment&) = delete;

  // Orchestrator — calls all init steps in order
  [[nodiscard]] std::expected<void, DpdkError> init() noexcept;

  // Accessors — safe to use only after init() succeeds
  [[nodiscard]] bool is_initialized() const noexcept { return initialized_; }
  [[nodiscard]] rte_mempool* GetMemPool() const noexcept { return mbuf_pool_; }
  [[nodiscard]] const std::vector<std::uint16_t>& GetActivePorts() const noexcept {
    return active_ports_;
  }
  [[nodiscard]] std::uint16_t GetPortCount() const noexcept { return port_count_; }

private:
  // Lifecycle steps — private, must be called in order
  [[nodiscard]] std::expected<void, DpdkError> init_eal() noexcept;
  [[nodiscard]] std::expected<void, DpdkError> create_mempool() noexcept;
  [[nodiscard]] std::expected<void, DpdkError> setup_ports() noexcept;
  [[nodiscard]] std::expected<void, DpdkError> check_link_status() noexcept;

  // setup_ports helpers
  [[nodiscard]] std::expected<rte_eth_dev_info, DpdkError> configure_port(
    std::uint16_t port_id, const PortConfig& pc) noexcept;
  [[nodiscard]] std::expected<void, DpdkError> setup_rx_queues(
    std::uint16_t port_id, const rte_eth_dev_info& dev_info,
    const rte_eth_conf& port_conf, std::uint16_t nb_rxd) noexcept;
  [[nodiscard]] std::expected<void, DpdkError> setup_tx_queues(
    std::uint16_t port_id, const rte_eth_dev_info& dev_info,
    const rte_eth_conf& port_conf, std::uint16_t nb_txd) const noexcept;
  void cleanup() noexcept;  // best-effort, cannot fail

  // Config & state
  DpdkConfig config_;
  bool initialized_{false};
  rte_mempool* mbuf_pool_{nullptr};
  std::uint16_t port_count_{};
  std::vector<std::uint16_t> active_ports_;
  std::vector<rte_ether_addr> port_mac_addrs_;

  static constexpr rte_eth_conf default_port_conf_{};
};

}  // namespace dpdk
