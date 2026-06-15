#pragma once

#include <csignal>

namespace dpdk {

/**
 * @brief Return the global force-quit flag used to signal graceful shutdown.
 *
 * The flag is set to 1 by @ref InstallSignalHandlers when SIGINT or
 * SIGTERM is received. Packet-processing loops poll this flag and
 * exit when it becomes non-zero.
 * @return Mutable reference to the global `volatile sig_atomic_t` flag.
 */
[[nodiscard]] volatile std::sig_atomic_t& ForceQuitFlag() noexcept;

/**
 * @brief Install signal handlers for graceful Ctrl+C / SIGTERM shutdown.
 *
 * Registers a handler that sets the force-quit flag (see @ref ForceQuitFlag)
 * on SIGINT and SIGTERM, allowing the packet loop to exit cleanly.
 * @return true on success, false if either handler could not be registered.
 */
[[nodiscard]] bool InstallSignalHandlers() noexcept;

}  // namespace dpdk
