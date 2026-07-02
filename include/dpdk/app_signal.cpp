#include "dpdk/app_signal.hpp"

namespace {

/// Global force-quit flag set by the signal handler.
volatile std::sig_atomic_t force_quit{0};

/// Global reload-request flag set by SIGUSR1.
volatile std::sig_atomic_t reload_requested{0};

/**
 * @brief Signal handler for SIGINT, SIGTERM, and SIGUSR1.
 *
 * SIGINT/SIGTERM → set force_quit for graceful shutdown.
 * SIGUSR1 → set reload_requested for config hot-reload.
 * @param signal  The received signal number.
 */
void HandleSignal(int signal) noexcept {
  if (signal == SIGINT || signal == SIGTERM) {
    force_quit = 1;
  } else if (signal == SIGUSR1) {
    reload_requested = 1;
  }
}

}  // namespace

namespace dpdk {

volatile std::sig_atomic_t& ForceQuitFlag() noexcept { return force_quit; }

volatile std::sig_atomic_t& ReloadFlag() noexcept { return reload_requested; }

/**
 * @brief Install signal handlers for SIGINT, SIGTERM, and SIGUSR1.
 * @return true on success, false if any handler could not be registered.
 */
bool InstallSignalHandlers() noexcept {
  return std::signal(SIGINT, HandleSignal) != SIG_ERR && std::signal(SIGTERM, HandleSignal) != SIG_ERR &&
         std::signal(SIGUSR1, HandleSignal) != SIG_ERR;
}

}  // namespace dpdk
