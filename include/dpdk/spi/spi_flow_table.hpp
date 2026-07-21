#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <tuple>
#include <utility>
#include <vector>

#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_spinlock.h>

#include "dpdk/spi/spi_rule_engine.hpp"

struct rte_hash;

namespace dpdk::spi {

/// Number of bytes in a FlowKey (5-tuple + padding).
inline constexpr std::size_t kFlowKeySize{16};

/// 5-tuple flow key for cache lookup. Padded to kFlowKeySize bytes.
/// Layout: [src_ip:4][dst_ip:4][src_port:2][dst_port:2][proto:1][pad:3]
/// The 3-byte pad MUST remain zero — garbage in pad breaks rte_hash_crc.
struct FlowKey {
  std::uint32_t src_ip{};
  std::uint32_t dst_ip{};
  std::uint16_t src_port{};
  std::uint16_t dst_port{};
  Protocol protocol{};
  std::array<std::uint8_t, 3> pad{};
};
static_assert(sizeof(FlowKey) == kFlowKeySize);

/// Build a canonical 5-tuple flow key so that request and response
/// directions of the same connection hash to the SAME entry.
///
/// Without canonicalisation, `(client_ip:client_port -> server_ip:server_port)`
/// and `(server_ip:server_port -> client_ip:client_port)` produce two distinct
/// `FlowKey` values, doubling flow-cache occupancy and forcing the response
/// side to redo the work the request side already cached. By ordering the
/// endpoints so `(src_ip, src_port) <= (dst_ip, dst_port)` (lexicographic),
/// both directions collapse to one entry — the standard stateful-firewall
/// pattern (Suricata, VPP, nDPI all do this).
[[gnu::hot, gnu::always_inline]] static constexpr FlowKey MakeCanonical(
    std::uint32_t sip, std::uint32_t dip, std::uint16_t sp, std::uint16_t dp, Protocol proto) noexcept {
  if (std::tie(sip, sp) > std::tie(dip, dp)) {
    std::swap(sip, dip);
    std::swap(sp, dp);
  }
  return FlowKey{.src_ip = sip, .dst_ip = dip, .src_port = sp, .dst_port = dp,
                 .protocol = proto, .pad = {}};
}

// ============================================================================
// Per-entry storage layout (v4 — pointer-based data)
// ============================================================================
//
// Each cached flow lives in a `FlowData` allocation that is registered as the
// `data` payload of the corresponding `rte_hash` key via
// `rte_hash_add_key_data`. Lookups retrieve the data pointer with
// `rte_hash_lookup_data`; bulk lookups use the bitmask API
// `rte_hash_lookup_bulk_data`. The numeric slot position returned by DPDK is
// intentionally ignored on the hot path — we go straight to the data pointer.
//
// `FlowData` keeps the v3 hot/cold split on separate cache lines so the
// per-packet TSC touch on the cold side does not invalidate neighbouring
// entries. With MULTI_WRITER_ADD enabled, the freed-slot allocator is owned
// by DPDK; we own `FlowData` allocations explicitly via a freelist.

/// Bit layout of FlowData::action_and_count.
///
///   bits  0..(kFlowActionBits-1) = Action (currently 1 bit used; 4 reserved)
///   bits  kFlowActionBits..63    = match_count (60 bits, never overflows at
///                                  any plausible packet rate)
inline constexpr std::uint64_t kFlowActionMask{0xFU};
inline constexpr std::uint32_t kFlowActionShift{0U};
inline constexpr std::uint32_t kFlowMatchCountShift{4U};

/// Compile-time guard: any future Action enum addition must fit in 4 bits
/// or this fails to compile. Prevents silent cache corruption.
static_assert(static_cast<std::uint64_t>(Action::kForward) <= kFlowActionMask,
              "Action must fit in kFlowActionMask bits");
static_assert(static_cast<std::uint64_t>(Action::kDrop) <= kFlowActionMask,
              "Action must fit in kFlowActionMask bits");

/// One cached flow entry.
///
/// Two cache lines: the hot action/count field is read on every cache hit;
/// the cold TSC field is written on every hit but read only by PurgeExpired.
/// Keeping them on separate lines preserves the v3 false-sharing invariant
/// (neighbour entries never share a cache line).
struct alignas(64) FlowData {
  /// Lower 4 bits = Action; upper 60 = match_count. Zero = "empty slot".
  /// Published with memory_order_release in Insert / PurgeExpired;
  /// observed with memory_order_acquire in Lookup / GetEntry / LookupBulk.
  std::atomic<std::uint64_t> action_and_count{};
  // Pad to a 64-byte boundary so `last_seen_tsc` lives on a separate cache
  // line from `action_and_count`. alignas(64) on the next member achieves
  // the same split as two separate allocations without doubling memory.
  std::array<std::uint8_t, 56> _pad{};
  /// Last-seen TSC, written on every cache hit (cold side). Read by
  /// PurgeExpired on the main lcore. The atomic store is `relaxed` because
  /// no other thread needs to observe it immediately.
  std::atomic<std::uint64_t> last_seen_tsc{};
};
static_assert(sizeof(FlowData) == 128,
              "FlowData must occupy exactly two cache lines (128 B)");

/// Snapshot returned to callers on a hit. Holds the (atomic-extracted)
/// action at the moment of the acquire-load. Moved/copied by value so the
/// caller doesn't have to re-load.
struct FlowEntryView {
  Action action;
};

/// Bulk-path snapshot returned by `LookupBulk`. Same fields as
/// `FlowEntryView` plus a `valid` flag so callers can tell hits from
/// misses without re-reading the hash result.
struct BulkResult {
  FlowEntryView view{};
  bool valid{false};
};

/// Helper: decode an action_and_count packed value into a snapshot view.
[[gnu::always_inline]] static constexpr FlowEntryView DecodePacked(
    std::uint64_t packed) noexcept {
  return FlowEntryView{
      .action = static_cast<Action>(packed & kFlowActionMask),
  };
}

namespace {

/// Bitmask layout of `BulkResult::view.action` matches the lower 4 bits of
/// the packed atomic word; we keep the canonical constants here so callers
/// that need to translate the bitmask-style result into the cache-miss
/// decision can do it without re-deriving them.

}  // namespace

/// Outcome of an Insert attempt. `kFull` means `rte_hash_add_key_data` returned
/// `-ENOSPC` — the table is at `max_concurrent_flows` capacity and no slot
/// was available. Callers apply their configured `flow_overflow_action`
/// (drop the packet or reclassify without caching) and increment the
/// `flow_table_full` counter so the overflow is observable in stats.
enum class FlowInsertResult : std::uint8_t {
  kOk,
  kFull,
};

/**
 * @brief Per-flow classification cache backed by rte_hash with data pointer.
 *
 * Stores the SPI match result for each 5-tuple. Subsequent packets
 * in the same flow skip rule evaluation (cache hit).
 *
 * Concurrency model (v4, see docs_search/22_*.md and the v4 plan):
 *   - Hot data (action_and_count) is read by every cache-hit packet.
 *   - Cold data (last_seen_tsc) is written on every cache-hit packet AND
 *     read by PurgeExpired on the main lcore. Both atomics live in the same
 *     FlowData allocation on separate cache lines.
 *   - Insert / PurgeExpired publish via `memory_order_release`.
 *   - Lookup / GetEntry / LookupBulk observe via `memory_order_acquire`.
 *   - `RW_CONCURRENCY_LF` makes lookups lock-free from N workers.
 *   - `MULTI_WRITER_ADD` lets `rte_hash_add_key_data` run concurrently from
 *     multiple lcores — DPDK uses a per-lcore free-slot cache and an
 *     internal rwlock. Our external `insert_lock_` is gone.
 *   - `NO_FREE_ON_DEL` keeps deleted entries alive until the next purge,
 *     which `PurgeExpired` uses to honour the reader-quiescence contract
 *     required by `rte_hash_free_key_with_position`.
 */
class FlowTable final {
 public:
  /// Construct a flow cache sized to `max_concurrent_flows` slots.
/// Backed by `rte_hash` with `RW_CONCURRENCY_LF` (lock-free Lookup) +
/// `MULTI_WRITER_ADD` (per-lcore free-slot cache, multi-writer safe) +
/// `NO_FREE_ON_DEL` (deferred-free semantics). Insert uses a find-then-
/// update pattern: LookupData first to reuse the existing FlowData on a
/// hit (no freelist churn); only on miss does it pop a free slot and call
/// add_key_data. See `spi_flow_table.cpp` for the rationale on flag
/// combination.
  explicit FlowTable(std::uint32_t max_concurrent_flows) noexcept;
  ~FlowTable();

  FlowTable(const FlowTable&) = delete;
  FlowTable& operator=(const FlowTable&) = delete;
  FlowTable(FlowTable&&) = delete;
  FlowTable& operator=(FlowTable&&) = delete;

  /**
   * @brief Lookup a flow in the cache, touching last_seen_tsc with a
   *        burst-shared TSC.
   * @param key      5-tuple flow key.
   * @param now_tsc  Caller-provided timestamp for `last_seen_tsc`.
   * @return View on hit, std::nullopt on miss / empty slot.
   *
   * Defined inline in the header so the hot path is inlined into the
   * caller's TU without relying on LTO. With 99%+ cache hit rate, this
   * function is on the per-packet critical path.
   *
   * The `now_tsc` parameter lets the caller amortize a single `rte_rdtsc()`
   * (24 cycles on Skylake-class) across a whole burst of Lookup calls.
   *
   * Memory ordering: the acquire-load on `action_and_count` synchronises
   * with the release-store in Insert / PurgeExpired. After this returns,
   * the caller's view of `last_seen_tsc` (read AFTER the acquire) is the
   * last published value — which may be the previous entry's TSC if a
   * concurrent writer just re-inserted. That's fine: PurgeExpired only
   * cares that TSC moves forward.
   */
  [[gnu::hot, gnu::always_inline]] [[nodiscard]] std::optional<FlowEntryView>
  Lookup(const FlowKey& key, std::uint64_t now_tsc) noexcept {
    if (hash_ == nullptr) [[unlikely]] {
      return std::nullopt;
    }
    void* data_ptr{nullptr};
    const auto result{rte_hash_lookup_data(hash_, &key, &data_ptr)};
    if (result < 0) [[unlikely]] {
      return std::nullopt;
    }
    auto* const data{static_cast<FlowData*>(data_ptr)};
    const auto packed{data->action_and_count.load(std::memory_order_acquire)};
    if (packed == 0) [[unlikely]] {
      return std::nullopt;  // empty slot
    }
    // Cold-side update — written to a separate cache line within the same
    // allocation, does not invalidate neighbour entries on other cores.
    // `relaxed` is sufficient: no other code on other cores needs to observe
    // this immediately.
    data->last_seen_tsc.store(now_tsc, std::memory_order_relaxed);
    return DecodePacked(packed);
  }

  /// Backward-compatible 1-arg Lookup — calls `rte_rdtsc()` itself.
  /// Less efficient on hot paths; kept for callers that have no burst TSC.
  [[gnu::hot, gnu::always_inline]] [[nodiscard]] std::optional<FlowEntryView>
  Lookup(const FlowKey& key) noexcept {
    return Lookup(key, rte_rdtsc());
  }

  /**
   * @brief Bulk lookup for a contiguous batch of keys. Returns snapshots
   *        in `results`, eliminating the position-lifetime window where
   *        `PurgeExpired` could delete/recycle a slot between the hash
   *        position lookup and the caller's later `GetEntry` call.
   *
   * Pipelined version of `Lookup` for the per-burst hot path. With
   * Clang's SSE4.2 CRC32 pin (from `Environment::InitEal`) the bulk
   * API computes all N CRC32 hashes in vectorised form and pipelines
   * bucket loads.
   *
   * Each result's `valid` is set iff the corresponding key resolved
   * to a non-empty slot; the `view` field holds the acquire-loaded
   * `action_and_count`. The burst-shared `now_tsc` refreshes
   * `last_seen_tsc` on hit slots via the same acquire-load pair.
   *
   * @param keys       Pointer to N FlowKey entries.
   * @param num_keys   Number of keys (>= 0). Clamped to
   *                   `RTE_HASH_LOOKUP_BULK_MAX` (= 64).
   * @param now_tsc    Burst-shared timestamp; refreshes `last_seen_tsc`
   *                   on hit slots.
   * @param results    Output span of at least `num_keys` `BulkResult`s.
   */
  [[gnu::hot]] void LookupBulk(const FlowKey* keys, std::uint32_t num_keys,
                                std::uint64_t now_tsc,
                                std::span<BulkResult> results) noexcept;

  /**
   * @brief Insert or update a flow entry.
   * @param key    5-tuple flow key.
   * @param match_count  Initial match count (typically 1).
   * @param action  Action for this flow (kForward/kDrop).
   * @return `kOk` on success, `kFull` when `rte_hash_add_key_data` returned
   *         `-ENOSPC` (the table is at `max_concurrent_flows` capacity) or
   *         the freelist was empty. Caller decides what to do on `kFull`
   *         (drop the packet or reclassify without caching) and increments
   *         the `flow_table_full` counter.
   *
   * Defined inline in the header to avoid a function call on the miss path.
   * Publishes via `memory_order_release` so concurrent Lookup calls see
   * either the pre-Insert state (empty) or the post-Insert state (full).
   *
   * `MULTI_WRITER_ADD` makes the underlying `rte_hash_add_key_data` safe for
   * concurrent writers across lcores — no external spinlock is needed.
   */
  [[gnu::always_inline]] [[nodiscard]] FlowInsertResult Insert(const FlowKey& key,
                                                               std::uint64_t match_count,
                                                               Action action) noexcept {
    if (hash_ == nullptr) [[unlikely]] {
      overflow_count_.fetch_add(1, std::memory_order_relaxed);
      return FlowInsertResult::kFull;
    }
    // Find-then-update pattern: lookup the existing data pointer BEFORE
    // popping the freelist. On hit, reuse the existing FlowData and just
    // update action_and_count in place — no allocation, no freelist churn.
    // On miss, pop a free slot and add_key_data. This pattern is the
    // critical correctness fix: `rte_hash_add_key_data` always overwrites
    // the data pointer on existing keys, so popping-then-add_key_data would
    // leak one freelist entry per duplicate Insert. With ~15K cache-miss
    // packets per second and 15 workers racing the same canonical 5-tuples,
    // the freelist would drain in seconds.
    void* existing_data{nullptr};
    if (rte_hash_lookup_data(hash_, &key, &existing_data) >= 0
        && existing_data != nullptr) [[likely]] {
      auto* const data{static_cast<FlowData*>(existing_data)};
      // ❗ Always use the NEW action. The slot may have been recycled from a
      //    previous entry whose `action` bit held a different value.
      //    Reading the existing cell and OR-ing the action bit would
      //    resurrect the old decision (a real correctness bug caught in
      //    the v2 audit).
      data->last_seen_tsc.store(rte_rdtsc(), std::memory_order_relaxed);
      const auto packed{(match_count << kFlowMatchCountShift)
                        | (static_cast<std::uint64_t>(action) & kFlowActionMask)};
      data->action_and_count.store(packed, std::memory_order_release);
      return FlowInsertResult::kOk;
    }
    // Cache miss — pop a free FlowData slot and insert.
    FlowData* data{nullptr};
    {
      rte_spinlock_lock(&freelist_lock_);
      if (free_list_.empty()) [[unlikely]] {
        rte_spinlock_unlock(&freelist_lock_);
        overflow_count_.fetch_add(1, std::memory_order_relaxed);
        return FlowInsertResult::kFull;
      }
      data = free_list_.back();
      free_list_.pop_back();
      rte_spinlock_unlock(&freelist_lock_);
    }
    // Initialise the slot before publishing — a concurrent Lookup must
    // observe either the pre-Insert empty state (action_and_count == 0) or
    // the post-Insert populated state. Writing last_seen_tsc first then the
    // packed word with release ordering is the published-then-visible
    // pattern.
    data->last_seen_tsc.store(rte_rdtsc(), std::memory_order_relaxed);
    const auto packed{(match_count << kFlowMatchCountShift)
                      | (static_cast<std::uint64_t>(action) & kFlowActionMask)};
    data->action_and_count.store(packed, std::memory_order_release);
    if (rte_hash_add_key_data(hash_, &key, data) != 0) [[unlikely]] {
      // Insert failed (table full). Push the new FlowData back to the
      // freelist so it isn't leaked.
      rte_spinlock_lock(&freelist_lock_);
      free_list_.push_back(data);
      rte_spinlock_unlock(&freelist_lock_);
      overflow_count_.fetch_add(1, std::memory_order_relaxed);
      return FlowInsertResult::kFull;
    }
    return FlowInsertResult::kOk;
  }

  /// Single-writer variant of `Insert` for resize-time migration. The caller
  /// MUST have paused worker writes (typically via `reload_barrier`). The
  /// MULTI_WRITER_ADD path is safe to call here too, but `InsertRaw` skips
  /// the freelist lock acquisition since only the main lcore runs it.
  [[gnu::always_inline]] [[nodiscard]] FlowInsertResult InsertRaw(
      const FlowKey& key, std::uint64_t match_count, Action action) noexcept {
    if (hash_ == nullptr) [[unlikely]] {
      return FlowInsertResult::kFull;
    }
    FlowData* data{nullptr};
    {
      rte_spinlock_lock(&freelist_lock_);
      if (free_list_.empty()) [[unlikely]] {
        rte_spinlock_unlock(&freelist_lock_);
        return FlowInsertResult::kFull;
      }
      data = free_list_.back();
      free_list_.pop_back();
      rte_spinlock_unlock(&freelist_lock_);
    }
    data->last_seen_tsc.store(rte_rdtsc(), std::memory_order_relaxed);
    const auto packed{(match_count << kFlowMatchCountShift)
                      | (static_cast<std::uint64_t>(action) & kFlowActionMask)};
    data->action_and_count.store(packed, std::memory_order_release);
    if (rte_hash_add_key_data(hash_, &key, data) != 0) [[unlikely]] {
      rte_spinlock_lock(&freelist_lock_);
      free_list_.push_back(data);
      rte_spinlock_unlock(&freelist_lock_);
      return FlowInsertResult::kFull;
    }
    return FlowInsertResult::kOk;
  }

  /// Iterate every occupied slot, calling `visitor(key, match_count, action)`
  /// for each. Used by `Pipeline::MaybeReloadFlowTable` to migrate entries
  /// from the old `FlowTable` to a freshly-allocated one on resize.
  ///
  /// Thread-safety: caller MUST have paused all writers (via the
  /// `reload_barrier`) — no concurrent `Insert`/`PurgeExpired` may run while
  /// this is executing.
  template <typename Visitor>
  void ForEachOccupied(Visitor&& visitor) const noexcept {
    if (hash_ == nullptr) [[unlikely]] {
      return;
    }
    for (std::uint32_t idx{0U}; idx < max_concurrent_flows_; ++idx) {
      const auto& slot{data_[idx]};
      const auto packed{slot.action_and_count.load(std::memory_order_relaxed)};
      if (packed == 0U) [[likely]] {
        continue;  // empty slot — most slots are empty at any given moment
      }
      void* key_ptr{nullptr};
      if (rte_hash_get_key_with_position(hash_, static_cast<std::int32_t>(idx), &key_ptr) < 0) [[unlikely]] {
        continue;
      }
      const auto& key{*static_cast<const FlowKey*>(key_ptr)};
      const auto match_count{packed >> kFlowMatchCountShift};
      const auto action{static_cast<Action>(packed & kFlowActionMask)};
      visitor(key, match_count, action);
    }
  }

  /// True iff `rte_hash_create` succeeded in the constructor. A `false`
  /// `FlowTable` rejects every operation (Lookup returns nullopt, Insert
  /// returns kFull, etc.) and lets the pipeline continue without flow
  /// caching — workers will re-classify every packet but the system stays
  /// up.
  [[nodiscard]] bool IsValid() const noexcept { return hash_ != nullptr; }

  /// Configured capacity. Equals `max_concurrent_flows` passed to the
  /// constructor. Used by resize logic to detect no-op reloads.
  [[nodiscard]] std::uint32_t Capacity() const noexcept { return max_concurrent_flows_; }

  /**
   * @brief Remove entries not seen since the given TSC threshold.
   * @param now_tsc     Current TSC value.
   * @param ttl_cycles  Entries older than (now_tsc - ttl_cycles) are purged.
   * @param force_quit  Signal flag; if non-zero the scan returns early so
   *                    Ctrl+C is observed within microseconds even on a
   *                    saturated million-slot table. Without this the main
   *                    lcore could spend many ms (or seconds if many
   *                    entries are expired and `rte_hash_del_key` takes
   *                    microseconds each) inside this scan and miss the
   *                    `while (force_quit == 0)` poll in `RunMultiWorker`.
   *                    The lock is released before returning, so no
   *                    readers are blocked on shutdown.
   *
   * Honouring `NO_FREE_ON_DEL`: `rte_hash_del_key` returns the position but
   * defers the actual free. The contract requires
   * `rte_hash_free_key_with_position` to run only after readers have stopped
   * referencing that entry. We use a one-cycle deferred-free queue — the
   * entries freed in the *previous* PurgeExpired run are released at the
   * start of this run, giving in-flight `LookupData` callers on other lcores
   * a full purge-cycle window to release their reference. The reload-barrier
   * resize path bypasses this queue and frees synchronously because it runs
   * after a full worker pause.
   */
  void PurgeExpired(std::uint64_t now_tsc, std::uint64_t ttl_cycles, const std::atomic<int>& force_quit) noexcept;

  /// Drain the deferred-free queue without scanning for TTL-expired entries.
  /// Called by the reload-barrier resize path so that any pending free
  /// positions are released before the old FlowTable is destroyed.
  void DrainPendingFrees() noexcept;

  /// Number of `Insert` calls that returned `kFull` since the last reset.
  /// Read by the main lcore to decide when to trigger proactive eviction.
  /// Lock-free (relaxed atomic load).
  [[gnu::hot]] [[nodiscard]] std::uint64_t OverflowCount() const noexcept {
    return overflow_count_.load(std::memory_order_relaxed);
  }

  /// Reset the overflow counter. Called by the main lcore after a
  /// proactive purge so the next eviction window starts fresh.
  [[gnu::hot]] void ResetOverflowCount() noexcept {
    overflow_count_.store(0U, std::memory_order_relaxed);
  }

  /// Threshold (in overflow events) that triggers a proactive purge.
  /// Sized at construction to ~1% of `max_concurrent_flows_` (min 1).
  /// With a 1 M-slot table this is 10 K events; with 4 M slots, 40 K.
  /// One purge per `~1% / sustained_overflow_rate` seconds at peak.
  [[gnu::hot]] [[nodiscard]] std::uint64_t EvictionThreshold() const noexcept {
    return eviction_threshold_;
  }

  /// True iff accumulated overflow events have crossed the eviction
  /// threshold. The main lcore polls this each idle iteration; on
  /// `true`, it calls `PurgeExpired` and `ResetOverflowCount` to start
  /// the next window. ~1 ns (relaxed atomic load).
  [[gnu::hot]] [[nodiscard]] bool ShouldEvictOnPressure() const noexcept {
    return overflow_count_.load(std::memory_order_relaxed) >= eviction_threshold_;
  }

 private:
  rte_hash* hash_{nullptr};
  /// Per-entry storage: one FlowData per cache slot, allocated once at
  /// construction. Pointers into this array are handed to
  /// `rte_hash_add_key_data` and reclaimed via `free_list_`. The addresses
  /// never change for the lifetime of the FlowTable (no resize-in-place
  /// growth), so the pointers handed to DPDK remain valid.
  ///
  /// Hot/cold split is preserved: `FlowData` is `alignas(64)` with the TSC
  /// member on a separate cache line from `action_and_count`.
  std::unique_ptr<FlowData[]> data_;
  /// Capacity cached at construction so `ForEachOccupied` / `PurgeExpired`
  /// can iterate `data_` without `unique_ptr<T[]>::size()` (which is
  /// unavailable in C++26).
  std::uint32_t max_concurrent_flows_{0U};
  /// LIFO freelist of unused FlowData pointers. Initialised at construction
  /// with every slot. Insert pops a slot; PurgeExpired pushes expired
  /// slots back. Guarded by `freelist_lock_`; contention is bounded by the
  /// <100 K/s insert rate so the lock is never hot.
  std::vector<FlowData*> free_list_;
  /// Serialises freelist pop/push operations across lcores. Acquired
  /// briefly per Insert; not held during the rte_hash_add_key_data call.
  rte_spinlock_t freelist_lock_{};
  /// One-purge-cycle deferred-free queue. v4 no longer needs this: the
/// FlowData pointer is owned by us and remains valid until the next
/// Insert pops it from the freelist. The slot index returned by
/// `rte_hash_del_key` is recycled immediately via
/// `rte_hash_free_key_with_position`; any in-flight reader holding the
/// stale data pointer is reading only `action_and_count` which is a
/// single acquire-load — once it returns, the reader no longer holds
/// the pointer, so the position can be reassigned.
  /// (kept as members for layout compatibility; the deferred vectors
  ///  are unused and never populated)
  /// Count of `Insert` calls that returned `kFull`. Workers relax-store
  /// into this atomic from the kFull branch of `Insert`; the main lcore
  /// reads it once per idle iteration and triggers `PurgeExpired` when
  /// the count crosses `eviction_threshold_`. This is the eviction-on-
  /// pressure path: when the table saturates, expired entries are
  /// reclaimed BEFORE the next miss has to be dropped, so short-lived
  /// flows age out naturally without the operator having to size the
  /// table to peak concurrent-active.
  ///
  /// Static-allocation discipline: this counter lives on one cache line
  /// inside the FlowTable object (allocated once at startup). No
  /// resizable container, no per-event allocation, no fragmentation.
  std::atomic<std::uint64_t> overflow_count_{0U};
  /// Threshold of overflow events that triggers a proactive purge.
  /// Sized at construction to ~1% of `max_concurrent_flows_` (min 1).
  /// Read by the main lcore on every idle iteration; cheap relaxed load.
  std::uint64_t eviction_threshold_{0U};
};

}  // namespace dpdk::spi