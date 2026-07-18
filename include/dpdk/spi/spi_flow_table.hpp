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
// Atomic publish protocol layout
// ============================================================================
//
// Each cached flow entry is split across two storage locations to keep the
// hot-side read (Action + count) on its own cache line and the cold-side
// update (last_seen_tsc, written on every hit but read only by PurgeExpired)
// on a separate cold array. This was the v2 fix in docs_search/12 §3.2:
//
//   cells_[i]              ← AtomicFlowCell{action_and_count}, 64 B
//   last_seen_tsc_[i]      ← uint64_t,                     8 B (separate array)
//
// Without the split, `cells_[i].last_seen_tsc = tsc` would invalidate 3
// neighbour cells on 7 other cores (false sharing) — measurable across
// all-burst traffic at 100 Mpps. With the split, only the cold line is
// invalidated; the hot line stays read-only on the workers' side.

/// Bit layout of AtomicFlowCell::action_and_count.
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

/// One hot-data cell per flow cache slot.
///
/// 64 B = exactly one cache line. Read by every cache-hit packet (hot path).
/// Written only by Insert and PurgeExpired — never on Lookup hits. This is
/// the key invariant that lets the hot line sit idle (read-only) on the
/// workers' cores while the cold-side TSC array takes the MESI invalidations.
struct alignas(64) AtomicFlowCell {
  /// Lower 4 bits = Action; upper 60 = match_count. Zero = "empty slot".
  /// Published with memory_order_release in Insert / PurgeExpired;
  /// observed with memory_order_acquire in Lookup / GetEntry.
  std::atomic<std::uint64_t> action_and_count{};
};
static_assert(sizeof(AtomicFlowCell) == 64,
              "AtomicFlowCell must be exactly one cache line — false-sharing guard");

/// Snapshot returned to callers on a hit. Holds the (atomic-extracted)
/// field values at the moment of the acquire-load. Moved/copied by value
/// so the caller doesn't have to re-load.
struct FlowEntryView {
  Action action;
  std::uint64_t match_count;
  std::uint64_t last_seen_tsc;
};

/// Bulk-path snapshot returned by `LookupBulk`. Same fields as
/// `FlowEntryView` plus a `valid` flag so callers can tell hits from
/// misses without checking for negative positions.
struct BulkResult {
  FlowEntryView view{};
  bool valid{false};
};

/// Helper: decode an action_and_count packed value into a snapshot view.
[[gnu::always_inline]] static constexpr FlowEntryView DecodePacked(
    std::uint64_t packed, std::uint64_t last_seen_tsc) noexcept {
  return FlowEntryView{
      .action = static_cast<Action>(packed & kFlowActionMask),
      .match_count = packed >> kFlowMatchCountShift,
      .last_seen_tsc = last_seen_tsc,
  };
}

/// Outcome of an Insert attempt. `kFull` means `rte_hash_add_key` returned
/// `-ENOSPC` — the table is at `max_concurrent_flows` capacity and no slot
/// was available. Callers apply their configured `flow_overflow_action`
/// (drop the packet or reclassify without caching) and increment the
/// `flow_table_full` counter so the overflow is observable in stats.
enum class FlowInsertResult : std::uint8_t {
  kOk,
  kFull,
};

/**
 * @brief Per-flow classification cache backed by rte_hash.
 *
 * Stores the SPI match result for each 5-tuple. Subsequent packets
 * in the same flow skip rule evaluation (cache hit).
 *
 * Concurrency model (v3, see docs_search/12_data_race_fix.md and
 * docs_search/13_data_race_audit.md):
 *   - Hot data (action_and_count) is read by every cache-hit packet.
 *   - Cold data (last_seen_tsc) is written on every cache-hit packet
 *     AND read by GetEntry on the hot path; written and read by
 *     PurgeExpired on the main lcore. Both arrays are atomic with
 *     `alignas(64)` per element to prevent false sharing.
 *   - Insert / PurgeExpired publish via `memory_order_release`.
 *   - Lookup / GetEntry observe via `memory_order_acquire`.
 *   - `RW_CONCURRENCY_LF` makes lookups lock-free from N workers.
 *   - `MULTI_WRITER_ADD` is INTENTIONALLY OMITTED (see v3 lesson in
 *     doc 12 §10.1: the flag's slot migration breaks our slot-indexed
 *     backing store). Insert is single-writer, serialised by an
 *     external `rte_spinlock_t`. PurgeExpired also holds this lock
 *     so it never races worker Inserts.
 */
class FlowTable final {
 public:
  /// Construct a flow cache sized to `max_concurrent_flows` slots.
  /// Backed by `rte_hash` with `RW_CONCURRENCY_LF` (lock-free Lookup) +
  /// external spinlock for Insert serialization.
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
    const auto result{rte_hash_lookup(hash_, &key)};
    if (result < 0) [[unlikely]] {
      return std::nullopt;
    }
    const auto idx{static_cast<std::size_t>(result)};
    const auto packed{cells_[idx].action_and_count.load(std::memory_order_acquire)};
    if (packed == 0) [[unlikely]] {
      return std::nullopt;  // empty slot
    }
    // Cold-side update — written to a separate line, does not invalidate
    // the hot line on other cores. `relaxed` is sufficient: no other code
    // on other cores needs to observe this immediately. The element is
    // `alignas(64)`-wrapped atomic so this write does not ping-pong cold
    // lines between workers (8 TSCs/line would otherwise).
    last_seen_tsc_[idx].value.store(now_tsc, std::memory_order_relaxed);
    return DecodePacked(packed, now_tsc);
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
   *        position lookup and the caller's later `GetEntry` call. See
   *        docs_search/13 §H4.
   *
   * Pipelined version of `Lookup` for the per-burst hot path. With
   * Clang's SSE4.2 CRC32 pin (from `Environment::InitEal`) the bulk
   * API computes all N CRC32 hashes in vectorised form and pipelines
   * bucket loads.
   *
   * Each result's `valid` is set iff the corresponding key resolved
   * to a non-empty slot; the `view` field holds the acquire-loaded
   * `action_and_count` and the burst-shared `now_tsc` (so the TTL
   * touch is folded into the same acquire-load).
   *
   * @param keys       Pointer to N FlowKey entries.
   * @param num_keys   Number of keys (>= 0). Clamped to
   *                   `RTE_HASH_LOOKUP_BULK_MAX` (= 64).
   * @param now_tsc    Burst-shared timestamp; refreshes `last_seen_tsc_`
   *                   on hit slots.
   * @param results    Output span of at least `num_keys` `BulkResult`s.
   */
  [[gnu::hot]] void LookupBulk(const FlowKey* keys, std::uint32_t num_keys,
                                std::uint64_t now_tsc,
                                std::span<BulkResult> results) noexcept;

  /**
   * @brief Get a FlowEntryView by slot index (output of LookupBulk).
   *
   * Single acquire-load on the hot cell. Returns std::nullopt on
   * negative position or empty slot. Refreshes `last_seen_tsc_` on
   * the matched slot so that long-running bulk-path flows survive
   * the TTL window — the same TTL-touch that `Lookup` performs for
   * the single-packet path. See docs_search/13 §H7.
   *
   * @param position  Slot index returned by `LookupBulk` (>= 0 on hit).
   * @param now_tsc   Burst-shared timestamp; the caller amortises one
   *                  `rte_rdtsc()` across the whole burst.
   */
  [[gnu::hot, gnu::always_inline]] [[nodiscard]] std::optional<FlowEntryView>
  GetEntry(std::int32_t position, std::uint64_t now_tsc) noexcept {
    if (position < 0) [[unlikely]] {
      return std::nullopt;
    }
    [[assume(position >= 0)]];
    const auto idx{static_cast<std::size_t>(position)};
    const auto packed{cells_[idx].action_and_count.load(std::memory_order_acquire)};
    if (packed == 0) [[unlikely]] {
      return std::nullopt;
    }
    // Cold-side touch — same atomic store as Lookup() above.
    // `relaxed` is sufficient: no other core needs to observe it
    // immediately, and the element is `alignas(64)` so this write
    // does not ping-pong cold lines.
    last_seen_tsc_[idx].value.store(now_tsc, std::memory_order_relaxed);
    return DecodePacked(packed, now_tsc);
  }

  /**
   * @brief Insert or update a flow entry.
   * @param key    5-tuple flow key.
   * @param action  Action for this flow (kForward/kDrop).
   * @param match_count  Initial match count (typically 1).
   * @return `kOk` on success, `kFull` when `rte_hash_add_key` returned `-ENOSPC`
   *         (the table is at `max_concurrent_flows` capacity). Caller decides
   *         what to do on `kFull` (drop the packet or reclassify without
   *         caching) and increments the `flow_table_full` counter.
   *
   * Defined inline in the header to avoid a function call on the miss path.
   * Publishes via `memory_order_release` so concurrent Lookup calls see
   * either the pre-Insert state (empty) or the post-Insert state (full).
   *
   * Serialised with `insert_lock_` because `RW_CONCURRENCY_LF` alone does
   * NOT make `rte_hash_add_key` multi-thread safe — that would require
   * `MULTI_WRITER_ADD`, which migrates keys between slots internally and
   * breaks our slot-indexed backing store. Holding an explicit spinlock
   * here is preferable because:
   *   (a) Insert rate at 99.9% cache hit is <100 K/sec across all workers,
   *       so spinlock contention is negligible compared to per-packet work.
   *   (b) Slot indices stay stable, so `cells_[idx]` writes land in slots
   *       the next Lookup will find via the hash.
   */
  [[gnu::always_inline]] [[nodiscard]] FlowInsertResult Insert(const FlowKey& key,
                                                               std::uint64_t match_count,
                                                               Action action) noexcept {
    if (hash_ == nullptr) [[unlikely]] {
      return FlowInsertResult::kFull;
    }
    rte_spinlock_lock(&insert_lock_);
    const auto result{rte_hash_add_key(hash_, &key)};
    if (result < 0) [[likely]] {
      rte_spinlock_unlock(&insert_lock_);
      return FlowInsertResult::kFull;
    }
    const auto idx{static_cast<std::size_t>(result)};
    // ❗ Always use the NEW action. The slot may have been recycled from a
    //    previous entry whose `action` bit held a different value. Reading
    //    the existing cell and OR-ing the action bit would resurrect the old
    //    decision (a real correctness bug caught in the v2 audit).
    last_seen_tsc_[idx].value.store(rte_rdtsc(), std::memory_order_relaxed);
    const auto packed{(match_count << kFlowMatchCountShift)
                      | (static_cast<std::uint64_t>(action) & kFlowActionMask)};
    cells_[idx].action_and_count.store(packed, std::memory_order_release);
    rte_spinlock_unlock(&insert_lock_);
    return FlowInsertResult::kOk;
  }

  /**
   * @brief Remove entries not seen since the given TSC threshold.
   * @param now_tsc     Current TSC value.
   * @param ttl_cycles  Entries older than (now_tsc - ttl_cycles) are purged.
   */
  void PurgeExpired(std::uint64_t now_tsc, std::uint64_t ttl_cycles) noexcept;

 private:
  rte_hash* hash_{nullptr};
  /// Hot side: 64 B per slot, one full cache line. Read by every cache hit,
  /// written only on Insert / PurgeExpired. False-sharing bounded to one
  /// entry per line. Sized once at startup.
  ///
  /// Stored as `std::unique_ptr<AtomicFlowCell[]>` because
  /// `std::atomic<uint64_t>` is neither copyable nor movable, which makes
  /// `std::vector<AtomicFlowCell>::resize()` unusable on it. The pointer
  /// wrapper yields a stable indexed-access view (`cells_[idx]`) just like
  /// a vector, with zero indirection on the hot path.
  std::unique_ptr<AtomicFlowCell[]> cells_;
  /// Cold-side TSC storage. Wrapper struct is `alignas(64)` so each
  /// element occupies a full cache line — without the padding, eight
  /// TSCs share one line and worker writes ping-pong with each other
  /// (~87% probability at 7 workers with uniform slot distribution).
  /// The `std::atomic<uint64_t>` member makes cross-lcore reads/writes
  /// well-defined per the C++ memory model (without it the writes
  /// race with `PurgeExpired`'s reads on the main lcore — see
  /// docs_search/13 §H2).
  struct alignas(64) ColdTsc {
    std::atomic<std::uint64_t> value{};
  };
  /// Cold side: separate allocation from the hot cells. Written on
  /// every Lookup / GetEntry hit and on Insert / PurgeExpired. Read on
  /// every GetEntry hit (hot path) and by PurgeExpired on the main
  /// lcore. Decoupling from the hot cells means the hot line is never
  /// invalidated by the per-packet TSC update.
  ///
  /// Stored as `std::unique_ptr<ColdTsc[]>` because `std::atomic<>` is
  /// neither copyable nor movable, which makes `std::vector` resize /
  /// emplace_back unusable on it. The pointer wrapper yields a stable
  /// indexed-access view (`last_seen_tsc_[idx]`) just like a vector,
  /// with zero indirection on the hot path.
  std::unique_ptr<ColdTsc[]> last_seen_tsc_;
  /// Serialises Insert calls across cores. Insert is rare (<100 K/sec at
  /// 99.9% hit rate, well below 1% of per-packet cost on the cache-miss
  /// path), so spinlock contention is negligible. The alternative —
  /// `RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD` — would force our
  /// slot-indexed backing store to be ephemeral because the hash migrates
  /// keys between slots internally for CAS retries. See docs_search/12
  /// §10 audit log.
  rte_spinlock_t insert_lock_{};
  /// Capacity cached at construction so `PurgeExpired` can iterate the
  /// `last_seen_tsc_` array without `unique_ptr<T[]>::size()` (which
  /// is unavailable in C++26).
  std::uint32_t max_concurrent_flows_{0U};
};

}  // namespace dpdk::spi
