#include "app_signal.hpp"

namespace {

/// Global force-quit flag set by the signal handler.
volatile std::sig_atomic_t force_quit{0};

/**
 * @brief Signal handler for SIGINT and SIGTERM.
 *
 * Sets the global force_quit flag to 1, which packet-processing loops
 * poll to trigger a graceful shutdown.
 * @param signal  The received signal number.
 */
void HandleSignal(int signal) noexcept {
  if (signal == SIGINT || signal == SIGTERM) {
    force_quit = 1;
  }
}

}  // namespace

namespace dpdk {

volatile std::sig_atomic_t& ForceQuitFlag() noexcept { return force_quit; }

/**
 * @brief Install SIGINT and SIGTERM handlers for graceful shutdown.
 * @return true on success, false if either handler could not be registered.
 */
bool InstallSignalHandlers() noexcept {
  return std::signal(SIGINT, HandleSignal) != SIG_ERR && std::signal(SIGTERM, HandleSignal) != SIG_ERR;
}

}  // namespace dpdk
