#pragma once  // NOLINT(portability-avoid-pragma-once)

#include <atomic>
#include <memory>
#include <utility>

#include "dpdk/dpi/dpi_rule_engine.hpp"

namespace dpdk::dpi {

/**
 * @brief Double-buffer DPI rule table manager for lock-free hot-reload.
 *
 * Mirrors @ref dpdk::spi::RuleTableManager but holds DpiRuleTable
 * pointers. Workers read the active table via atomic load; the main
 * lcore atomically swaps in a new DpiRuleTable on SIGUSR1.
 *
 * DPI rule tables are small (~30 entries) and reset is cheap (no
 * rte_acl-style heap fragmentation), so we can simply swap rather than
 * reusing the previous table in-place like SPI does.
 */
class DpiRuleTableManager final {
 public:
  DpiRuleTableManager() noexcept = default;

  DpiRuleTableManager(const DpiRuleTableManager&) = delete;
  DpiRuleTableManager& operator=(const DpiRuleTableManager&) = delete;
  DpiRuleTableManager(DpiRuleTableManager&&) = delete;
  DpiRuleTableManager& operator=(DpiRuleTableManager&&) = delete;
  ~DpiRuleTableManager() = default;

  /// Lock-free read of the active DPI rule table. Workers call this.
  [[nodiscard]] const DpiRuleTable* Load() const noexcept {
    return active_.load(std::memory_order_acquire);
  }

  /// Atomically swap in a new DPI rule table. Main lcore only.
  void Swap(std::unique_ptr<DpiRuleTable> new_table) noexcept {
    auto* old = active_.exchange(new_table.release(), std::memory_order_acq_rel);
    prev_retired_ = std::move(retired_);
    retired_.reset(old);
  }

  /// Initialize with the first DPI rule table (called from Pipeline ctor).
  void Init(std::unique_ptr<DpiRuleTable> table) noexcept {
    active_.store(table.release(), std::memory_order_release);
  }

 private:
  std::atomic<DpiRuleTable*> active_{nullptr};
  std::unique_ptr<DpiRuleTable> retired_;
  std::unique_ptr<DpiRuleTable> prev_retired_;
};

}  // namespace dpdk::dpi
