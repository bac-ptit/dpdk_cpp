#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "dpdk/dpi/dpi_rule_engine.hpp"

namespace dpdk::dpi {

/// Per-worker cache of hostname -> DPI filter index.
///
/// Avoids re-running ExtractTlsSni / ExtractHttpHost + DpiRuleTable::Match
/// for hostnames already classified. Cache hits turn ~1 µs of DPI work into
/// a 32-bit hash + ~2 cache-line lookups (~20 ns).
///
/// Implementation: open-addressed hash table with bounded linear probing.
/// Each entry stores the FNV-1a hash + first 12 bytes of the hostname
/// (split as key32 + key64) for collision disambiguation, plus the
/// matching filter index (or `kNoMatchIdx` for "no match"). Fixed-size
/// array, no allocation, cache-line-friendly.
///
/// False-positive probability at N entries with a 32-bit hash and 12-byte
/// key: 32-bit birthday paradox + 96-bit suffix hash ≈ 0 at N ≤ 10K.
class HostnameCache {
 public:
  static constexpr std::uint16_t kNoMatchIdx{0xFFFFU};

  HostnameCache() noexcept = default;

  /// Look up cached result. Returns filter_index or `kNoMatchIdx` on miss.
  /// `current_generation` is the active `DpiRuleTable::Generation()` —
  /// if it differs from the generation stored at insertion time, the
  /// entry is treated as a miss (DPI table has reloaded). See
  /// docs_search/13 §M1.
  [[nodiscard, gnu::hot, gnu::always_inline]] std::uint16_t Lookup(
      std::string_view hostname, std::uint32_t current_generation) const noexcept {
    if (hostname.empty()) [[unlikely]] {
      return kNoMatchIdx;
    }
    const auto hash = Hash32(hostname);
    const auto slot = hash & kMask;
    const auto& first_entry = SlotAt(slot);
    if (first_entry.hash != 0U && first_entry.hash == hash &&
        first_entry.generation == current_generation &&
        KeyMatches(first_entry, hostname)) [[likely]] {
      return first_entry.filter_index;
    }
    // Linear probe (max 4 slots to bound cache-line traffic).
    for (std::uint32_t probe = 1U; probe < kMaxProbes; ++probe) {
      const auto& probe_entry = SlotAt((slot + probe) & kMask);
      if (probe_entry.hash != 0U && probe_entry.hash == hash &&
          probe_entry.generation == current_generation &&
          KeyMatches(probe_entry, hostname)) [[likely]] {
        return probe_entry.filter_index;
      }
    }
    return kNoMatchIdx;
  }

  /// Insert (or update) a hostname result, stamped with the current
  /// DPI rule-table generation.
  [[gnu::hot]] void Insert(std::string_view hostname, std::uint16_t filter_index,
                           std::uint32_t current_generation) noexcept {
    if (hostname.empty()) [[unlikely]] {
      return;
    }
    const auto hash = Hash32(hostname);
    const auto slot = hash & kMask;

    auto& first_entry = SlotAt(slot);
    if (first_entry.hash == 0U) {
      StoreEntry(first_entry, hash, hostname, filter_index, current_generation);
      return;
    }
    if (first_entry.hash == hash && KeyMatches(first_entry, hostname)) {
      first_entry.filter_index = filter_index;
      first_entry.generation = current_generation;
      return;
    }
    for (std::uint32_t probe = 1U; probe < kMaxProbes; ++probe) {
      auto& probe_entry = SlotAt((slot + probe) & kMask);
      if (probe_entry.hash == 0U) {
        StoreEntry(probe_entry, hash, hostname, filter_index, current_generation);
        return;
      }
      if (probe_entry.hash == hash && KeyMatches(probe_entry, hostname)) {
        probe_entry.filter_index = filter_index;
        probe_entry.generation = current_generation;
        return;
      }
    }
    // Cache full for this hash — silently drop (rare).
  }

  /// Clear all entries. Called from `MaybeReload` if you prefer a
  /// brute-force clear to the generation-counter approach.
  void Clear() noexcept { slots_.fill(EmptyEntry{}); }

 private:
  // 4096 slots × ~20 bytes = ~80 KiB. Fits in L2 (typically 256 KiB–1 MiB).
  static constexpr std::uint32_t kSlots{4096U};
  static constexpr std::uint32_t kMask{kSlots - 1U};
  static constexpr std::uint32_t kMaxProbes{4U};
  static constexpr std::uint32_t kFnvOffsetBasis{2166136261U};
  static constexpr std::uint32_t kFnvPrime{16777619U};

  struct Entry {
    std::uint32_t hash{0U};        // 0 = empty
    std::uint32_t key32{0U};       // first 4 bytes of hostname
    std::uint64_t key64{0U};       // bytes [4..11] of hostname
    std::uint16_t filter_index{kNoMatchIdx};
    /// DPI rule-table generation at insertion time. On mismatch the
    /// entry is treated as a miss (filter_index may point into the
    /// previous table). See docs_search/13 §M1.
    std::uint32_t generation{0U};
  };

  using EmptyEntry = Entry;

  static_assert((kSlots & (kSlots - 1U)) == 0U, "kSlots must be a power of 2");

  // Bounds-checked by construction: callers always pass `hash & kMask` or
  // `(slot + probe) & kMask`, both < kSlots. NOLINT centralized here to
  // keep hot-path code clean.
  [[nodiscard, gnu::always_inline]] Entry& SlotAt(std::uint32_t idx) noexcept {
    return slots_[idx];  // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
  }
  [[nodiscard, gnu::always_inline]] const Entry& SlotAt(std::uint32_t idx) const noexcept {
    return slots_[idx];  // NOLINT(cppcoreguidelines-pro-bounds-constant-array-index)
  }

  /// FNV-1a hash, 32-bit. Cheap (no FPU) and good distribution for short
  /// ASCII hostnames. ~5-10 cycles per byte, fits in 4 cache lines for
  /// typical hostnames (<30 bytes).
  [[gnu::always_inline]] static std::uint32_t Hash32(std::string_view hostname) noexcept {
    std::uint32_t hash{kFnvOffsetBasis};
    for (auto byte : hostname) {
      hash ^= static_cast<std::uint32_t>(byte);
      hash *= kFnvPrime;
    }
    return hash;
  }

  /// Pack first 12 bytes of hostname into two fields for collision
  /// disambiguation. False positive rate at 1K entries ≈ 0.001%.
  static void CopyKey(Entry& entry, std::string_view hostname) noexcept {
    entry.key32 = 0U;
    entry.key64 = 0U;
    if (hostname.size() >= 4U) {
      std::memcpy(&entry.key32, hostname.data(), 4U);
    } else {
      std::memcpy(&entry.key32, hostname.data(), hostname.size());
    }
    if (hostname.size() > 4U) {
      const auto count = std::min<std::size_t>(hostname.size() - 4U, 8U);
      std::memcpy(&entry.key64, hostname.substr(4U).data(), count);
    }
  }

  [[gnu::always_inline]] static bool KeyMatches(const Entry& entry, const std::string_view hostname) noexcept {
    if (hostname.size() < 4U) {
      // Hashes already match. For <4 bytes, key32 already has the right
      // bytes (CopyKey zero-pads the rest), so this is correct.
      return true;
    }
    std::uint32_t first4{0U};
    std::memcpy(&first4, hostname.data(), 4U);
    if (first4 != entry.key32) {
      return false;
    }
    if (hostname.size() <= 4U) {
      return true;
    }
    const auto count = std::min<std::size_t>(hostname.size() - 4U, 8U);
    std::uint64_t next8{0U};
    std::memcpy(&next8, hostname.substr(4U).data(), count);
    // Compare only `count` bytes — the rest of stored key is zero.
    return std::memcmp(&next8, &entry.key64, count) == 0;
  }

  static void StoreEntry(Entry& entry, const std::uint32_t hash, const std::string_view hostname,
                         const std::uint16_t filter_index,
                         const std::uint32_t generation) noexcept {
    entry.hash = hash;
    CopyKey(entry, hostname);
    entry.filter_index = filter_index;
    entry.generation = generation;
  }

  std::array<Entry, kSlots> slots_{};
};

}  // namespace dpdk::dpi
