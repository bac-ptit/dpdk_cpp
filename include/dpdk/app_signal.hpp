#pragma once

#include <atomic>
#include <csignal>

namespace dpdk {

/**
 * @brief Return the global force-quit flag used to signal graceful shutdown.
 *
 * The flag is set to 1 by @ref InstallSignalHandlers when SIGINT or
 * SIGTERM is received. Packet-processing loops poll this flag and
 * exit when it becomes non-zero.
 *
 * Stored as `std::atomic<int>` rather than `volatile sig_atomic_t` so
 * the same flag type is used by both the signal-handler-driven path
 * (single-worker mode) and the cross-lcore worker force-quit flag
 * (multi-worker mode). `std::atomic<int>::is_lock_free()` is always
 * true on x86-64, so signal-handler `store()` is async-signal-safe
 * per cppreference ([atomics.types.operations]/p11).
 * @return Mutable reference to the global `std::atomic<int>` flag.
 */
[[nodiscard]] std::atomic<int>& ForceQuitFlag() noexcept;

/**
 * @brief Return the global reload-request flag.
 *
 * Set to 1 by the SIGUSR1 handler. The main lcore polls this flag
 * and triggers a config reload when non-zero. Same `std::atomic<int>`
 * type as @ref ForceQuitFlag for the same signal-safety reasons.
 * @return Mutable reference to the global `std::atomic<int>` flag.
 */
[[nodiscard]] std::atomic<int>& ReloadFlag() noexcept;

/**
 * @brief Install signal handlers for graceful Ctrl+C / SIGTERM shutdown
 * and SIGUSR1 config reload.
 *
 * Registers a handler that sets the force-quit flag (see @ref ForceQuitFlag)
 * on SIGINT and SIGTERM, allowing the packet loop to exit cleanly.
 *
 * MUST be called AFTER `Environment::init()` because `rte_eal_init`
 * installs its own SIGUSR1/SIGINT/SIGTERM handlers internally and
 * would silently overwrite any pre-existing handlers.
 * @return true on success, false if either handler could not be registered.
 */
[[nodiscard]] bool InstallSignalHandlers() noexcept;

}  // namespace dpdk
