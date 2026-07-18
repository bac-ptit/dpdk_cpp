#pragma once

#include <rte_acl.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "dpdk/config/dpdk_config.hpp"

namespace dpdk::spi {
struct FlowKey;  // Defined in spi_flow_table.hpp (forward decl to avoid
                 //  circular include — TSS needs FlowKey shape only).
}  // namespace dpdk::spi

namespace dpdk::dpi {
class DpiRuleTable;
}  // namespace dpdk::dpi

namespace dpdk::spi {

/// Number of fields for ACL matching.
constexpr uint32_t kAclNumFields{5};

/// Maximum number of categories (filter groups) in a single rte_acl_ctx.
/// Matches `RTE_ACL_MAX_CATEGORIES` in DPDK 24.11 — beyond this many groups,
/// config validation must reject the input rather than silently dropping groups.
inline constexpr std::size_t kMaxCategories{64};

/// Default filter group precedence (lower = higher priority).
constexpr std::uint32_t kDefaultPrecedence{100};

/// Sentinel for `CompiledFilterGroup::bound_dpi_filter_index` and
/// `ClassificationResult::bound_dpi_filter_index` meaning "no static SPI→DPI
/// link; the full hostname DPI path must run on `l7_required: true` groups".
/// Sentinel chosen as `uint32_t::max()` so it is impossible to confuse with
/// a real DpiRuleTable filter index (typical filter count is ≤30, and
/// validation rejects DPI tables with >1M filters).
inline constexpr std::uint32_t kNoDpiLink{std::numeric_limits<std::uint32_t>::max()};

/// ACL field indices in the 5-tuple.
enum class AclFieldIndex : uint8_t {
  kSrcIp = 0,
  kDstIp,
  kSrcPort,
  kDstPort,
  kProtocol,
};

/// 5-tuple input for rte_acl_classify (all fields in network byte order).
struct AclInputData {
  uint32_t src_ip_be;
  uint32_t dst_ip_be;
  uint16_t src_port_be;
  uint16_t dst_port_be;
  uint8_t protocol;
};

/// L4 protocols supported by the SPI classifier.
enum class Protocol : std::uint8_t {
  /// Transmission Control Protocol.
  kTcp,
  /// User Datagram Protocol.
  kUdp,
};

/// Action to take when a filter group matches.
enum class Action : std::uint8_t {
  kForward,
  kDrop,
};

/// Minimal parsed packet fields needed by the classifier.
struct PacketMetadata {
  /// Parsed L4 protocol.
  Protocol protocol{};
  /// IPv4 source address in host byte order.
  std::uint32_t source_ip_address{};
  /// IPv4 destination address in host byte order.
  std::uint32_t destination_ip_address{};
  /// TCP/UDP source port in host byte order.
  std::uint16_t source_port{};
  /// TCP/UDP destination port in host byte order.
  std::uint16_t destination_port{};
  /// L7 hostname extracted from TLS SNI or HTTP Host header (nullptr if not extracted).
  const char* hostname{nullptr};
  /// Length of hostname string (not null-terminated in mbuf).
  std::uint16_t hostname_length{};
};

/// Compiled filter — hot-path representation of a single SpiFilterConfig.
struct CompiledFilter {
  Protocol protocol;
  std::uint32_t source_ip_address{};
  std::uint32_t destination_ip_address{};
  std::uint32_t destination_network{};
  std::uint32_t destination_prefix_mask{};
  std::uint32_t destination_prefix_length{};
  std::uint16_t source_port{};
  std::uint16_t destination_port{};
  bool match_source_ip{false};
  bool match_destination_ip{false};
  bool match_destination_cidr{false};
  bool match_source_port{false};
  bool match_destination_port{false};
  std::string label;
};

/// Compiled filter group — hot-path representation of a SpiFilterGroupConfig.
///
/// One filter group = one `rte_acl` category. After PR4, all groups share a
/// single combined `rte_acl_ctx` (held by `RuleTable`), so this struct no
/// longer owns its own ctx — it only carries its position in the category
/// space.
struct CompiledFilterGroup {
  std::string name;
  std::uint32_t precedence{kDefaultPrecedence};
  Action action{Action::kForward};
  std::vector<CompiledFilter> filters;
  /// Bit index in the combined rte_acl category_mask; equals the position
  /// in the sorted `groups_` vector. Used to look up `results[cat]` and
  /// `category_to_group_index_[cat]` on every Match().
  std::uint32_t category_index{};
  /// Mirror of SpiFilterGroupConfig::l7_required — copied at compile time
  /// so the hot-path Match() can decide whether DPI should still run.
  bool l7_required{false};
  /// Index into the active DpiRuleTable's filter array, OR `kNoDpiLink` if
  /// the config did not declare a static SPI→DPI link on this group. Set
  /// by `ResolveDpiLinks` after BOTH the SPI rule table and the DPI rule
  /// table have been compiled. Carried through `RuleTable::Match` into
  /// `ClassificationResult::bound_dpi_filter_index` so the SPI pipeline
  /// can skip `ExtractHostname` + `MatchDpi` when the link is set.
  ///
  /// **Hot-path invariant**: read once per `Match()` call (one cache line
  /// load), never dereferenced as a `std::string_view` on the data path.
  /// The companion `bound_dpi_name` field is a TRANSIENT string used only
  /// by `ResolveDpiLinks`; it is cleared after the resolution pass to
  /// keep `CompiledFilterGroup` cache-line-friendly.
  std::uint32_t bound_dpi_filter_index{kNoDpiLink};
  /// Transient — populated by `CompileRuleTable` from the YAML config,
  /// consumed and cleared by `ResolveDpiLinks`. NOT read at runtime.
  /// Marked mutable so `ResolveDpiLinks` can clear it without `const`-cast.
  mutable std::string bound_dpi_name;

  // ─────────────────────────────────────────────────────────────────────
  // Tuple-Space Search (TSS) pre-check support
  //
  // For SPI filters that specify the FULL 5-tuple (source_ip +
  // destination_ip + a port + protocol — no CIDR, no "any" wildcards) we
  // can build an O(1) hash table keyed on the filter's 5-tuple → group
  // index. At runtime, on cache miss, the SPI engine probes this table
  // FIRST and returns the group index without walking the ACL trie.
  //
  // For CIDR ranges / port-only rules, the corresponding entry is NOT
  // added and the call falls through to `rte_acl_classify` unchanged.
  //
  // See docs_search/17_os_skip_optimizations.md §2 for the design.
  // ─────────────────────────────────────────────────────────────────────

  CompiledFilterGroup() = default;
  CompiledFilterGroup(CompiledFilterGroup&&) noexcept;
  CompiledFilterGroup& operator=(CompiledFilterGroup&&) noexcept;
  CompiledFilterGroup(const CompiledFilterGroup&) = delete;
  CompiledFilterGroup& operator=(const CompiledFilterGroup&) = delete;
  ~CompiledFilterGroup() = default;
};

/// Shared ACL field definitions — MASK type with bitmask values.
inline constexpr std::array<rte_acl_field_def, kAclNumFields> kAclFieldDefs{{
    {.type = RTE_ACL_FIELD_TYPE_MASK, .size = sizeof(uint32_t), .field_index = static_cast<uint32_t>(AclFieldIndex::kSrcIp), .input_index = 0,
     .offset = offsetof(AclInputData, src_ip_be)},
    {.type = RTE_ACL_FIELD_TYPE_MASK, .size = sizeof(uint32_t), .field_index = static_cast<uint32_t>(AclFieldIndex::kDstIp), .input_index = 0,
     .offset = offsetof(AclInputData, dst_ip_be)},
    {.type = RTE_ACL_FIELD_TYPE_MASK, .size = sizeof(uint16_t), .field_index = static_cast<uint32_t>(AclFieldIndex::kSrcPort), .input_index = 0,
     .offset = offsetof(AclInputData, src_port_be)},
    {.type = RTE_ACL_FIELD_TYPE_MASK, .size = sizeof(uint16_t), .field_index = static_cast<uint32_t>(AclFieldIndex::kDstPort), .input_index = 0,
     .offset = offsetof(AclInputData, dst_port_be)},
    {.type = RTE_ACL_FIELD_TYPE_MASK, .size = sizeof(uint8_t), .field_index = static_cast<uint32_t>(AclFieldIndex::kProtocol), .input_index = 0,
     .offset = offsetof(AclInputData, protocol)},
}};

/// Classification result returned by RuleTable::Match.
struct ClassificationResult {
  std::string_view group_name;
  std::string_view label;
  Action action{Action::kForward};
  std::uint32_t group_precedence{0};
  bool matched{false};
  /// Mirror of the matched group's l7_required. False on miss.
  bool l7_required{false};
  /// Mirror of the matched group's `bound_dpi_filter_index` (== `kNoDpiLink`
  /// on miss). Carried through `Match()` so `TryDpiClassify` can take the
  /// static-link fast path without an extra config lookup.
  std::uint32_t bound_dpi_filter_index{kNoDpiLink};
};

/**
 * @brief Immutable table of compiled filter groups.
 *
 * Groups are sorted by precedence (ascending). Matching iterates groups
 * in order; first group with any matching filter wins.
 */
class RuleTable final {
 public:
  /// Build a RuleTable from a sorted list of filter groups, the combined
  /// rte_acl_ctx, and the precedence-ordered category walk. All three must
  /// come from the same `CompileRuleTable` call — never construct ad hoc.
  RuleTable(std::vector<CompiledFilterGroup> groups, rte_acl_ctx* acl_ctx,
            std::vector<std::uint32_t> precedence_order) noexcept;

  /// Move ctor — explicit because we need to null out the source's
  /// `acl_ctx_` so the moved-from instance's destructor doesn't double-free.
  RuleTable(RuleTable&& other) noexcept;
  RuleTable& operator=(RuleTable&& other) noexcept;

  RuleTable(const RuleTable&) = delete;
  RuleTable& operator=(const RuleTable&) = delete;
  ~RuleTable();

  /// Move-out accessor for `groups_`. Used by `MaybeReload` to extract the
  /// newly-compiled groups without copying. After this call the source
  /// RuleTable's `groups_` is empty (moved-from).
  [[gnu::always_inline]] std::vector<CompiledFilterGroup>&& MoveGroupsOut() noexcept { return std::move(groups_); }

  /// Move-out accessor for `precedence_order_`. Same as `MoveGroupsOut`.
  [[gnu::always_inline]] std::vector<std::uint32_t>&& MovePrecedenceOrderOut() noexcept {
    return std::move(precedence_order_);
  }

  /**
   * @brief Rebuild the combined rte_acl_ctx in place from new filter groups.
   *
   * Replaces the current `groups_` and `precedence_order_`, then calls
   * `rte_acl_reset_rules` + `rte_acl_add_rules` + `rte_acl_build` on the
   * existing `acl_ctx_`. No allocation occurs on the heap beyond the
   * `std::vector` moves — the rte_hash's internal storage was sized at
   * create time and is reused.
   *
   * **Concurrency**: callers MUST ensure no worker is concurrently calling
   * `Match()` on this RuleTable. The pipeline uses a reload_barrier atomic
   * + `rte_eal_mp_wait_lcore` symmetric wait to drain workers before
   * invoking this method.
   *
   * @return void on success; `std::unexpected` if `rte_acl_add_rules` or
   *         `rte_acl_build` fails (e.g. -ENOSPC if new rule count exceeds
   *         the original `max_rule_num`).
   */
  [[nodiscard]] std::expected<void, std::string> RebuildInPlace(
      std::vector<CompiledFilterGroup> new_groups,
      std::vector<std::uint32_t> new_precedence_order) noexcept;

  /**
   * @brief Match packet against all groups in precedence order.
   *
   * Single `rte_acl_classify` call against the combined context returns a
   * `results[cat]` for every category; we then walk the categories in
   * precedence order (lowest precedence value = highest priority) and
   * return the first category with a non-zero userdata.
   *
   * Complexity: O(log n) for the ACL trie walk, plus O(G) for the
   * precedence walk — strictly better than the per-group loop's O(G·log n)
   * because the per-group context-switch overhead disappears.
   */
  [[nodiscard]] ClassificationResult Match(const PacketMetadata& packet) const noexcept;

  /**
   * @brief Resolve SPI→DPI static link bindings in-place.
   *
   * Walks every `CompiledFilterGroup::bound_dpi_name` (the transient
   * string populated by `CompileRuleTable` from `dpi_filter_group` in the
   * config), looks up the named DPI filter group in the supplied DPI rule
   * table, and writes the resolved index into `bound_dpi_filter_index`.
   * After the resolution pass, every group's `bound_dpi_name` is cleared
   * so the hot path stays cache-line-friendly.
   *
   * Called once from `Pipeline::Pipeline` construction and once per
   * `MaybeReload` (SIGUSR1). NOT called from `Match()`.
   *
   * @param dpi  The DPI rule table to resolve link targets against.
   * @return void on success; `std::unexpected` if a `dpi_filter_group`
   *         reference cannot be resolved (typically because a SIGUSR1
   *         reload removed the named DPI group — the operator must fix
   *         the config or restart the pipeline).
   */
  [[nodiscard]] std::expected<void, std::string> ResolveDpiLinks(
      const dpdk::dpi::DpiRuleTable& dpi) noexcept;

  /**
   * @brief Tuple-Space Search (TSS) pre-check on a flow 5-tuple.
   *
   * Returns the matched group index (or `kNoTssHit`) when `key` exactly
   * matches an SPI filter that specifies the FULL 5-tuple (source_ip +
   * destination_ip + at least one port + protocol). For CIDR ranges or
   * "any" wildcards the corresponding entry is not inserted and the
   * cache-miss path falls through to `rte_acl_classify` unchanged.
   *
   * Hot path: linear-probing 4-slot cache + 16-bit group index. Fits
   * in a single L1 cache line, ~3-5 cycles on hit, ~15-25 cycles on
   * miss (2-3 probes through 4 slots).
   *
   * @param key  Canonical 5-tuple (must already be passed through
   *             `MakeCanonical` so it compares equal across both
   *             directions of a flow).
   * @return The matched group's category_index, or `kNoTssHit` on miss.
   */
  [[nodiscard, gnu::hot]] std::uint32_t ProbeTss(const FlowKey& key) const noexcept;

  /// Sentinel for `ProbeTss` indicating "no exact 5-tuple match found".
  static constexpr std::uint32_t kNoTssHit{std::numeric_limits<std::uint32_t>::max()};

  /// Build a `ClassificationResult` for the group at `cat_index` (a TSS
  /// hit result). Marked `[[gnu::always_inline]]` because the caller
  /// uses it on every cache-miss packet. Returns an empty `matched=false`
  /// result if `cat_index` is out of range.
  [[gnu::always_inline]] ClassificationResult ResultForCategory(
      std::uint32_t cat_index) const noexcept {
    if (cat_index >= groups_.size()) [[unlikely]] {
      return {};
    }
    const auto& group{groups_[cat_index]};
    return ClassificationResult{
        .group_name = group.name,
        .label = {},
        .action = group.action,
        .group_precedence = group.precedence,
        .matched = true,
        .l7_required = group.l7_required,
        .bound_dpi_filter_index = group.bound_dpi_filter_index,
    };
  }

  /// Return the number of filter groups.
  [[nodiscard]] std::size_t GroupCount() const noexcept { return groups_.size(); }

  /// Return the total number of filters across all groups.
  [[nodiscard]] std::size_t FilterCount() const noexcept;

 private:
  std::vector<CompiledFilterGroup> groups_;
  /// Combined rte_acl_ctx holding all groups' filters. One `rte_acl_classify`
  /// call returns a result for every category — we then walk categories in
  /// `precedence_order_` to find the highest-precedence match.
  rte_acl_ctx* acl_ctx_{nullptr};
  /// Category indices in precedence order (lower precedence value first).
  /// `precedence_order_[i] = cat_index` means "check `results[cat_index]`
  /// at step i". Sized to `groups_.size()` — index 0..groups_.size()-1.
  std::vector<std::uint32_t> precedence_order_;

  /// Tuple-Space Search table — open-addressed linear-probing hash keyed
  /// on canonical 5-tuple bytes → group `category_index`. Populated by
  /// `CompileRuleTable` for SPI filters whose 5-tuple is fully specified
  /// (no CIDR, no "any"); probed on every cache-miss classification via
  /// `ProbeTss`.
  ///
  /// The key is stored as 16 raw bytes (same size + layout as `FlowKey`,
  /// defined in `spi_flow_table.hpp`) — the include is forward-only here
  /// to avoid the header cycle. The probe (in spi_rule_engine.cpp) does
  /// a 16-byte memcmp against a `const FlowKey&` cast to bytes.
  ///
  /// Sized to `kTssCapacity` (next power of 2 ≥ 64 entries; 128 fits in
  /// 4 KB = 64 cache lines, well within L2). Entries are unused when
  /// `group_idx == kNoTssHit`.
  struct TssEntry {
    std::array<std::uint8_t, 16> key{};
    std::uint32_t group_idx{kNoTssHit};
  };
  static constexpr std::size_t kTssCapacity{128};
  std::array<TssEntry, kTssCapacity> tss_{};
  std::size_t tss_size_{0};

  /// Build the TSS table from the (already sorted, category_index-assigned)
  /// groups. Called by `CompileRuleTable` once after groups sort. Filters
  /// whose 5-tuple is fully specified (source_ip + dest_ip + (src_port OR
  /// dst_port) + protocol — no CIDR, no "any") contribute one TSS entry
  /// each, keyed on the filter's exact 5-tuple.
  void BuildTssFromGroups() noexcept;
};

/**
 * @brief Compile YAML SPI filter group config into a runtime rule table.
 *
 * Sorts groups by precedence. Parses CIDR, protocols, and actions.
 * @param config  SPI configuration loaded from config.yaml.
 * @return A RuleTable on success, or an error string.
 */
[[nodiscard]] std::expected<RuleTable, std::string> CompileRuleTable(const SpiConfig& config) noexcept;

}  // namespace dpdk::spi
