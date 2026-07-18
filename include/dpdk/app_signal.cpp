#include "dpdk/app_signal.hpp"

namespace {

/// Global force-quit flag set by the signal handler.
/// `std::atomic<int>` is async-signal-safe for `store()` on x86-64
/// (`is_lock_free()` is true), and lets workers poll it with
/// `.load(std::memory_order_relaxed)` cross-lcore safely.
std::atomic<int> force_quit{0};

/// Global reload-request flag set by SIGUSR1. Same rationale.
std::atomic<int> reload_requested{0};

/**
 * @brief Signal handler for SIGINT, SIGTERM, and SIGUSR1.
 *
 * SIGINT/SIGTERM → set force_quit for graceful shutdown.
 * SIGUSR1 → set reload_requested for config hot-reload.
 *
 * Only writes `std::atomic<int>` flags (lock-free for int on every
 * supported architecture), so the handler body is async-signal-safe.
 * @param signal  The received signal number.
 */
void HandleSignal(int signal) noexcept {
  if (signal == SIGINT || signal == SIGTERM) {
    force_quit.store(1, std::memory_order_relaxed);
  } else if (signal == SIGUSR1) {
    reload_requested.store(1, std::memory_order_relaxed);
  }
}

}  // namespace

namespace dpdk {

std::atomic<int>& ForceQuitFlag() noexcept { return force_quit; }

std::atomic<int>& ReloadFlag() noexcept { return reload_requested; }

/**
 * @brief Install signal handlers for SIGINT, SIGTERM, and SIGUSR1.
 * @return true on success, false if any handler could not be registered.
 */
bool InstallSignalHandlers() noexcept {
  return std::signal(SIGINT, HandleSignal) != SIG_ERR && std::signal(SIGTERM, HandleSignal) != SIG_ERR &&
         std::signal(SIGUSR1, HandleSignal) != SIG_ERR;
}

}  // namespace dpdk
