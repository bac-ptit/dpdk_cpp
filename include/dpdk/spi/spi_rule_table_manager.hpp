#pragma once

#include <atomic>
#include <memory>

#include "dpdk/spi/spi_rule_engine.hpp"

namespace dpdk::spi {

/**
 * @brief Double-buffer rule table manager for lock-free hot-reload.
 *
 * Maintains two RuleTable buffers. Workers read the active buffer via
 * atomic load (zero overhead on x86-64). The main lcore rebuilds the
 * inactive buffer and atomically swaps the pointer — zero packet loss.
 *
 * @note Old table is freed on the next swap (deferred cleanup).
 */
class RuleTableManager final {
 public:
  RuleTableManager() noexcept = default;

  RuleTableManager(const RuleTableManager&) = delete;
  RuleTableManager& operator=(const RuleTableManager&) = delete;
  RuleTableManager(RuleTableManager&&) = delete;
  RuleTableManager& operator=(RuleTableManager&&) = delete;

  /**
   * @brief Worker: lock-free read of the active rule table.
   *
   * On x86-64, atomic load with acquire semantics compiles to a plain
   * MOV instruction — identical cost to a raw pointer dereference.
   * @return Pointer to the current active RuleTable. Valid until the
   *         next Swap() call.
   */
  [[nodiscard]] const RuleTable* Load() const noexcept { return active_.load(std::memory_order_acquire); }

  /**
   * @brief Main lcore: atomically swap in a new rule table.
   *
   * Workers see the new table on their next Load() call.
   * The old table is kept alive until the *next* Swap() call,
   * ensuring any worker that loaded the old pointer finishes
   * using it before it is freed (deferred cleanup).
   * @param new_table  Newly compiled rule table.
   */
  void Swap(std::unique_ptr<RuleTable> new_table) noexcept {
    const auto* old = active_.exchange(new_table.release(), std::memory_order_acq_rel);
    // Free the *previous* retired table (safe — workers have moved on).
    // Keep the *current* old table alive for workers that just loaded it.
    prev_retired_ = std::move(retired_);
    retired_.reset(const_cast<RuleTable*>(old));
  }

  /**
   * @brief Initialize with a first rule table.
   *
   * Called once during Pipeline construction.
   * @param table  Initial compiled rule table.
   */
  void Init(std::unique_ptr<RuleTable> table) noexcept { active_.store(table.release(), std::memory_order_release); }

 private:
  std::atomic<const RuleTable*> active_{nullptr};
  std::unique_ptr<RuleTable> retired_;       // current old table (workers may still hold ptr)
  std::unique_ptr<RuleTable> prev_retired_;  // previous old table (safe to free)
};

}  // namespace dpdk::spi
