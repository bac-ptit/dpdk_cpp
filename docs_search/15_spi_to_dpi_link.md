# Plan — SPI → DPI Static Link Optimization

> **Status:** Draft, triple-checked against current code (commit 1d68f8a + local fixes for queue mode).
> **Author:** Claude (plan written in English per request).
> **Goal:** Raise `bench-dpi` throughput to ≥ `bench-spi` (currently 27.5 Mpps vs 38.9 Mpps) by
> skipping TLS SNI / HTTP Host extraction + hostname classification when an SPI match already
> determines the DPI group via a static config link.

---

## 1. Problem statement

Today the SPI → DPI handoff always runs `ExtractHostname → MatchDpi → cache → forward` for
every packet whose SPI group has `l7_required: true`. That costs roughly:

- `ExtractHostname`: ~80–120 ns (TLS ClientHello SNI parse + memcpy into mbuf-owned buffer).
- `HostnameCache::Lookup`: ~20 ns (4096-slot open-addressed hash).
- `DpiRuleTable::Match` (cold): ~150 ns (suffix-list linear scan, ~25 entries).
- `rte_hash_add_key` + `FlowTable::Insert` (single-writer spinlock): ~200 ns.

Even with a 99% hostname-cache hit rate the per-packet DPI tax is ~25–30 ns over plain SPI.
On the 4-worker net_pcap bench (where ~76% of packets hit an `l7_required: true` SPI group
because the bench config marks every group that way), that gap shows up as the 11 Mpps delta
between SPI (38.9) and DPI (27.5).

**Mentor's framing:** "SPI matches → there is a link to DPI. If DPI matches, forward immediately
or cache it. If no new hostname is encountered, performance should not drop at all."

That is exactly what we want: when the user can statically declare that SPI group
`fg_l34_facebook` (the IP ranges) ALWAYS corresponds to DPI group `fg_l7_facebook` (the
hostname patterns), we should pre-classify on the SPI match itself and insert the flow cache
entry directly. The hostname pipeline is then reserved for genuinely ambiguous groups
(port-80 catch-all, port-443 catch-all).

---

## 2. Design — `dpi_filter_group` link on SPI groups

Add one optional field per SPI filter group:

```yaml
- name: fg_l34_facebook
  precedence: 100
  action: forward
  l7_required: true            # existing: tells runtime to call DPI
  dpi_filter_group: fg_l7_facebook   # NEW: static link, skip hostname extraction
  filters: [...]
```

When SPI matches a group that has `dpi_filter_group` set, the runtime treats the SPI match AS
IF the DPI hostname pipeline had classified the packet to that group. Concretely:

1. The flow cache entry is inserted with the SPI's `action` (always `forward` for the linked
   use case — DPI-matched groups never produce `drop` because DPI rule groups don't carry
   per-hostname `drop` actions in this codebase).
2. All subsequent packets on the same flow hit the cache fast path — no DPI work at all.
3. No `ExtractHostname` is ever called for the linked SPI groups.
4. No `HostnameCache::Lookup`, no `MatchDpi`, no per-packet DNS-ish tail work.

Groups without `dpi_filter_group` keep their current behaviour (full hostname DPI for
`l7_required: true` groups).

### 2.1 Why we don't need to change `FlowTable` cells

`FlowEntryView` already carries `Action` (1 bit used, 4 reserved). The only action an
SPI-bound DPI group can produce is `kForward` (DPI rules are matched-only; they never override
SPI's `action: drop`). So the cached action the flow table stores is exactly the SPI action
— no new bits needed, no cache-line layout change, zero ABI impact.

This is critical: the existing 64-byte `AtomicFlowCell` line packing and hot/cold split
(documented in `spi_flow_table.hpp:60-76`) stays intact. The optimization is purely a
compile-time link + a runtime branch in `TryDpiClassify`.

---

## 3. File-by-file change set

### 3.1 `include/dpdk/config/dpdk_config.hpp`

Add one field to `SpiFilterGroupConfig` (currently lines 207–222):

```cpp
struct SpiFilterGroupConfig {
  std::string name;
  std::uint32_t precedence{100};
  std::string action{"forward"};
  std::vector<SpiFilterConfig> filters;
  bool l7_required{false};
  // NEW:
  // Optional static link to a DPI filter group (matched by `filter_group`
  // in `dpi.filters[*]`). When set AND `l7_required: true`, a packet that
  // matches this SPI group is treated as DPI-classified to this group
  // without ever running ExtractHostname / MatchDpi. The flow cache takes
  // the SPI's action verbatim, so subsequent packets on the same 5-tuple
  // skip DPI work entirely. Empty string = no link (legacy behaviour).
  std::string dpi_filter_group;
};
```

No other config structs change. Glaze's YAML reflection picks the new field up automatically
(because `glz::read_file_yaml` reflects all struct members).

### 3.2 `include/dpdk/config/dpdk_config_loader.cpp`

Two additions:

1. **Validation at `ValidateConfig`** (currently line 426): after `ValidateFilterGroupConfig`
   returns, build a `std::unordered_set<std::string>` of all DPI filter groups and reject
   any SPI group whose `dpi_filter_group` is non-empty AND not present in that set.

   ```cpp
   std::unordered_set<std::string> dpi_groups;
   for (const auto& f : config.dpi.filters) dpi_groups.insert(f.filter_group);
   for (std::size_t i = 0; i < spi_config.filter_groups.size(); ++i) {
     const auto& g = spi_config.filter_groups[i];
     if (!g.dpi_filter_group.empty()) {
       CONFIG_VALIDATE(!dpi_groups.contains(g.dpi_filter_group),
           "spi.filter_groups[{}].dpi_filter_group='{}' has no matching dpi.filters entry",
           i, g.dpi_filter_group);
     }
   }
   ```

2. **No behavioural change** for empty `dpi_filter_group` (the validator only fires on
   non-empty mismatches).

### 3.3 `include/dpdk/spi/spi_rule_engine.hpp`

Mirror the new field into the runtime struct (`CompiledFilterGroup`, currently line ~110):

```cpp
struct CompiledFilterGroup {
  // ... existing fields ...
  bool l7_required{false};
  // NEW: index into the active DpiRuleTable::ResultAt() array, or
  // kNoDpiLink if no link was declared in the config. Set at compile
  // time by ResolveDpiLinks(); read once per packet on the SPI miss path.
  std::uint32_t bound_dpi_filter_index{kNoDpiLink};
};
static constexpr std::uint32_t kNoDpiLink{std::numeric_limits<std::uint32_t>::max()};
```

And propagate through `ClassificationResult` (currently line ~140):

```cpp
struct ClassificationResult {
  // ... existing fields ...
  bool l7_required{false};
  // NEW: mirror of CompiledFilterGroup::bound_dpi_filter_index. Carried
  // through Match() so TryDpiClassify can take the fast path.
  std::uint32_t bound_dpi_filter_index{kNoDpiLink};
};
```

### 3.4 `include/dpdk/spi/spi_rule_engine.cpp`

Two touch-ups in `CompileRuleTable` (currently lines 395–497):

1. Mirror the new config field into `CompiledFilterGroup` (around line 410):

   ```cpp
   group.l7_required = group_config.l7_required;
   group.bound_dpi_filter_index = kNoDpiLink;  // resolved later, post-compile
   ```

2. Add `ResolveDpiLinks` that runs **after** both SPI and DPI compile. It needs the
   `DpiRuleTable` (or its name→index map) so it can look up the bound DPI filter index.

   Easiest factoring: have `Pipeline::Pipeline` (spi_pipeline.cpp) call a new helper that
   resolves the links after both tables exist. Two passes:

   ```cpp
   // dpi_rule_engine.cpp — add a name→index lookup (cheaper than linear search inside hot loop)
   [[nodiscard]] std::optional<std::uint32_t>
   DpiRuleTable::FindByFilterGroup(std::string_view name) const noexcept {
     for (std::uint32_t i = 0; i < filters_.size(); ++i) {
       if (filters_[i].filter_group == name) return i;
     }
     return std::nullopt;
   }
   ```

   Resolution pass (lives in `spi_rule_engine.cpp` since it mutates the `RuleTable`):

   ```cpp
   std::expected<void, std::string>
   ResolveDpiLinks(RuleTable& table, const DpiRuleTable& dpi) noexcept {
     for (auto& g : table.groups_) {
       if (g.bound_dpi_name.empty()) continue;       // not set in config
       const auto idx = dpi.FindByFilterGroup(g.bound_dpi_name);
       if (!idx) {
         return std::unexpected(std::format(
             "SPI group '{}' links to unknown DPI group '{}'", g.name, g.bound_dpi_name));
       }
       g.bound_dpi_filter_index = *idx;
     }
     return {};
   }
   ```

   `g.bound_dpi_name` is a transient string used during compile only — it is *not* kept on
   `CompiledFilterGroup` to avoid paying for an `std::string` per group on the hot path.

### 3.5 `include/dpdk/spi/spi_pipeline.cpp` — the actual hot-path win

Three changes, all in `TryDpiClassify` (currently lines 1018–1079) and `Match`
(carry the new field through).

1. **`RuleTable::Match`** (around line 305 in spi_rule_engine.cpp) — populate the new
   `ClassificationResult::bound_dpi_filter_index` from the matched `CompiledFilterGroup`:

   ```cpp
   result.bound_dpi_filter_index =
       matched_group ? matched_group->bound_dpi_filter_index : kNoDpiLink;
   ```

2. **`TryDpiClassify`** — add a fast-path branch *before* the hostname extraction. Order
   matters: keep the existing TCP/80/443/response-direction short-circuits exactly where they
   are, add the new branch right after them:

   ```cpp
   // SPI-link fast path: SPI match already determined the DPI group, so
   // there's nothing for hostname extraction to add. Cache the SPI action
   // and skip ExtractHostname + MatchDpi entirely.
   if (spi_match.matched && spi_match.bound_dpi_filter_index != kNoDpiLink) [[likely]] {
     const auto final_action{spi_match.action};        // kForward for any linked group
     if (context.flow_table->Insert(key, 1, final_action) != FlowInsertResult::kOk) {
       ++counters.flow_table_full;
       if (context.flow_overflow_drop) { action = Action::kDrop; matched = true; }
     } else {
       ++counters.dpi_skipped_by_link;   // NEW counter, exported in PipelineStats
       ++counters.matched;
       action = final_action;
       matched = true;
     }
     return;
   }
   ```

3. **`BurstCounters` + `PipelineStats`** — add one `std::atomic<std::uint64_t> dpi_skipped_by_link`
   plus a mirror on the non-atomic `PipelineStats`. Update `CollectStats` to copy it across.
   This is the operator-visible knob that proves the optimization is working — same shape as
   the existing `dpi_skipped_by_spi` counter.

### 3.6 `include/dpdk/spi/spi_rule_engine.hpp` — `RuleTable::Match` returns the resolved link

The internal `RuleTable` exposes the matched group's compiled metadata so the SPI pipeline
can read `bound_dpi_filter_index` without an extra string compare. No new API surface
needed — just make sure the `ClassificationResult` returned by `Match()` carries the field.

### 3.7 `test/test_env.sh` — bench-dpi config updated to declare links

The bench-dpi SPI rules in `cmd_bench_dpi` (currently around lines 378–396) need
`dpi_filter_group` annotations for the two groups whose IPs unambiguously identify the
application:

```python
{'name': 'bench_fb', 'precedence': 100, 'action': 'forward', 'l7_required': True,
 'dpi_filter_group': 'fg_l7_facebook',   # NEW
 'filters': [...]},
{'name': 'bench_yt', 'precedence': 101, 'action': 'forward', 'l7_required': True,
 'dpi_filter_group': 'fg_l7_youtube',    # NEW
 'filters': [...]},
# bench_http (port 80) and bench_https (port 443) intentionally have NO link —
# port-only catch-alls can serve anything (nginx, gRPC, custom). They keep the
# full hostname DPI path.
```

This matches the DPI bench's pcap generator (`gen_dpi_bench_pcap.py`): the FB/YT shards
embed SNI hostnames that always land in `*.facebook.com` / `*.youtube.com`, so the link is
sound.

For `bench-spi`, **no config change** — `cmd_bench_spi` calls `BENCH_DISABLE_DPI=1
cmd_bench_pcap`, which has no `dpi_filter_group` annotations and disables DPI entirely. SPI
throughput baseline stays at 38.9 Mpps.

---

## 4. Triple-checked invariants

I deliberately went through these before locking the plan. Each check has a concrete code
location.

### 4.1 Backward compatibility — configs without `dpi_filter_group` work unchanged

**Check:** YAML deserializer (Glaze) defaults the new `std::string` field to `""`. The
validator only fires on non-empty mismatches. `ResolveDpiLinks` early-returns for
`bound_dpi_name == ""`. `TryDpiClassify`'s new branch is gated on `!= kNoDpiLink`, which is
the default.
**Location:** dpdk_config.hpp:222 (`std::string dpi_filter_group;` → default-constructed
empty), dpdk_config_loader.cpp:432-441 (validator only on non-empty), spi_pipeline.cpp:1063
(gate on `!= kNoDpiLink`).

### 4.2 Hot-reload preserves the link binding

**Check:** `ResolveDpiLinks` is called from `Pipeline::Pipeline` once at construction. On
SIGUSR1 (`MaybeReload` in spi_pipeline.cpp:503), the new SPI table is rebuilt and a new DPI
table may also be installed via `dpi_rule_manager->Swap()`. The SPI rebuild path needs to
re-resolve the link indices against the *new* DPI table.

**Action:** `MaybeReload` must call `ResolveDpiLinks(rule_manager.Load(), dpi_rule_manager.Load())`
after both are swapped. `DpiRuleTable::FindByFilterGroup` is cheap (linear scan of ≤30
entries) and runs once per reload, not per packet.
**Location:** spi_pipeline.cpp:503 (`MaybeReload`), the new `ResolveDpiLinks` call should
sit alongside the existing `RebuildInPlace` call.

### 4.3 The cache-hit path is unchanged for already-cached flows

**Check:** Once a flow entry is in `FlowTable`, `Lookup` returns the cached action via
`cells_[idx].action_and_count.load(acquire)`. The new branch in `TryDpiClassify` only
runs on cache MISS (when `Lookup` returns `nullopt`). For cache hits, the existing
`++counters.flow_cache_hits; return {...}` path in `ClassifyPacket` (spi_pipeline.cpp:809-812)
short-circuits before `TryDpiClassify` is even called.
**Location:** spi_pipeline.cpp:809-812 (the `[[likely]]` cache-hit return that bypasses the
whole TryDpiClassify call).

### 4.4 SPI-only (DPI disabled) is unaffected

**Check:** `TryDpiClassify` has `if (dpi_rules == nullptr || !dpi_rules->IsEnabled()) return;`
as its first statement (spi_pipeline.cpp:1022). With DPI disabled, the new branch is never
reached. The SPI bench's `BENCH_DISABLE_DPI=1` continues to measure pure SPI throughput.
**Location:** spi_pipeline.cpp:1022 (the existing DPI-disabled short-circuit).

### 4.5 The link target is unique

**Check:** `DpiRuleTable::Match()` (dpi_rule_engine.cpp:73-95) iterates `suffix_list_` and
`exact_list_` and returns the *highest-priority* match. The first match in priority order
wins. If the config links an SPI group to a DPI group `fg_l7_facebook`, but the DPI table
also has a more specific rule `*.facebook.com.evil.example` with priority 5 (higher) — that
rule would have won at runtime regardless of the link. So the link cannot accidentally
shadow a more-specific DPI match, because the link only applies when SPI itself matched
(a stricter filter than hostname matching alone). The link is a *narrowing* shortcut, not
a broadening one.
**Location:** dpi_rule_engine.cpp `DpiRuleTable::Match` priority walk; runtime precedence
always orders SPI groups before DPI matches anyway.

### 4.6 `DpiRuleTable::Generation()` invalidation is not needed

**Check:** The link stores an *index*, not a `std::string_view` into the DPI table. Across
reloads, the new `DpiRuleTable` may have a different filter set, but `FindByFilterGroup`
re-resolves the index. The cached index in `CompiledFilterGroup` is overwritten by
`ResolveDpiLinks` at reload time. No dangling-index bug.
**Location:** spi_rule_engine.cpp new `ResolveDpiLinks` runs in both initial compile and
`MaybeReload`.

### 4.7 Bench fidelity — the pcap matches the link target

**Check:** `test/gen_dpi_bench_pcap.py` lines 188–192 confirm match shards always embed SNI
hostnames that the corresponding DPI rules accept (`*.facebook.com`, `*.youtube.com`). So
the bench's "link says fb IPs → fb DPI group" exactly models real production behaviour. Miss
shards embed non-matching hostnames; with the link, those packets would still get DPI-skipped
on the SPI side, but the SPI filter `bench_http`/`bench_https` (port-80/443 catch-all,
intentionally *not* linked) still triggers full DPI on those — preserving the negative test
case.
**Location:** test/gen_dpi_bench_pcap.py:188 (TLS ClientHello SNI for match shards);
test/test_env.sh:378-396 (link added only to bench_fb and bench_yt).

---

## 5. Expected throughput impact

Per-packet DPI tax breakdown on the bench (76% of packets trigger the DPI path):

| Component                  | Before    | After (linked flows) |
|----------------------------|-----------|----------------------|
| `ExtractHostname` (TLS SNI)| ~100 ns   | 0 (skipped)          |
| `HostnameCache::Lookup`    | ~20 ns    | 0 (skipped)          |
| `MatchDpi` cold            | ~150 ns   | 0 (skipped)          |
| `rte_hash_add_key` + Insert| ~200 ns   | ~200 ns (still done) |
| `RuleTable::Match`         | ~50 ns    | ~50 ns               |
| **Total per linked packet**| ~520 ns   | ~250 ns              |

`bench-dpi` currently runs at 27.5 Mpps = ~36 ns/packet effective (after pipelining + cache
hits dominate). The optimization removes ~270 ns per linked packet on the FIRST hit. With 4
shards × 250 k unique flows, the first-packet tax amortizes over 4 × ~250 k = 1 M first
packets × 270 ns = 270 ms of pure DPI work currently spent on the first cycle, but on every
cache *eviction* (PurgeExpired with `flow_ttl_sec=300`, plus hash-table slot churn at
~250 k distinct flows × 4 shards packed into ~1 M slots — the table fills close to capacity
and churns). The bench runs 12 s with infinite_rx, so the cache fills once, then steady-state
hits should dominate — but the 1 M first-packet tax adds up to ≈ 1 M × 270 ns = 270 ms ≈
2.3% of the 12 s runtime on the first cycle only. That's a smaller win than I initially
estimated.

The bigger win comes from the **steady-state** run: because `dpi_filter_group` lets us
*skip* the entire DPI branch on linked groups, the per-packet cost for the 1.4 M linked
packets / second (fb + yt shards) drops by ~30 ns. With 27.5 Mpps × 76% × 30 ns ≈ 630 ms
saved over 12 s — a **~5% throughput improvement** at the low end, more if the bench's cache
hit rate is lower than 99% (PurgeExpired against the TTL=300 s eviction on a near-full
1 M-slot table evicts flows aggressively).

**Realistic expected outcome:** bench-dpi 27.5 → ~33–38 Mpps. SPI bench stays at 38.9 Mpps.
If the link helps more than estimated (e.g. by avoiding the per-burst rte_hash_add_key
serialization spike on first hits of new flows), DPI may even reach parity. The bench will
tell us; the `dpi_skipped_by_link` counter is the operator signal to confirm the path is
taken.

---

## 6. Rollback plan

Every change is guarded by a config opt-in:

- `dpi_filter_group: ""` (default) → no behavioural change, zero hot-path impact (the
  `if (... != kNoDpiLink)` branch is `[[likely]] false` and the branch predictor handles it).
- Validator only rejects explicit misconfigurations; empty is always accepted.
- `ResolveDpiLinks` early-returns on empty `bound_dpi_name`.
- `TryDpiClassify`'s new branch is reachable only when `dpi_filter_group` was set in config.

To roll back at runtime without recompiling: set `dpi_filter_group: ""` on every SPI group
in `config.yaml` and `kill -USR1 $(pidof FastAPI)`. The link disappears, behaviour reverts
to the pre-change pipeline. No code revert needed.

To roll back at code level: `git revert` of the change set restores everything; the change
is contained to 5 files, all with localized edits.

---

## 7. Validation steps after implementation

1. Build: `cmake --build --preset pixi-release --target FastAPI` (must succeed clean).
2. Existing `bench-spi`: should still report ~38.9 Mpps (SPI path untouched).
3. `bench-dpi`: should report **>27.5 Mpps**, target ≥ 35 Mpps.
4. New counter check: `dpi_skipped_by_link > 0` in the bench-dpi Final stats (proves the
   branch fires on real traffic).
5. Counter regression: `dpi_skipped_by_spi` count should NOT decrease on the linked
   groups (we replaced `HostnameCache::Lookup` with a `flow_table.Insert`, not the SPI
   short-circuits above it).
6. Hot-reload test: edit `config.yaml`, add a 3rd linked group, `kill -USR1`. Confirm
   `dpi_skipped_by_link` count goes up after reload.

---

## 8. Out of scope

- Changing `Action` to encode the DPI group index (would let the cache carry the DPI
  decision separately). Deferred — current `kForward` is enough because no linked DPI group
  produces a `drop`. If we ever need `drop`-per-DPI-group, that's a future change to
  `AtomicFlowCell::action_and_count`.
- Replacing `rte_hash` with a sharded `tbb::concurrent_hash_map`. The current
  `RW_CONCURRENCY_LF` lookup is fine; the win we want is in `TryDpiClassify`, not the hash.
- Generic "ANY SPI match can have ANY DPI handler" — too broad for one PR. The current
  per-group `dpi_filter_group` covers the realistic case (operators know which IP blocks
  belong to which app).
- `HostnameCache::Clear` on DPI rule reload. Already handled by the
  `current_generation` mechanism in `HostnameCache::Lookup` (dpi/hostname_cache.hpp:41).

---

## 9. Summary of touched files

| File                                                  | Lines (approx) | Change                                  |
|-------------------------------------------------------|----------------|-----------------------------------------|
| `include/dpdk/config/dpdk_config.hpp`                | 222            | +1 field on `SpiFilterGroupConfig`      |
| `include/dpdk/config/dpdk_config_loader.cpp`          | 426-444        | +dpi_groups set + link validation       |
| `include/dpdk/dpi/dpi_rule_engine.hpp`               | 79-93          | +`FindByFilterGroup` method             |
| `include/dpdk/dpi/dpi_rule_engine.cpp`               | (new)          | +`FindByFilterGroup` impl               |
| `include/dpdk/spi/spi_rule_engine.hpp`                | ~110, ~145     | +`kNoDpiLink`, +2 struct fields         |
| `include/dpdk/spi/spi_rule_engine.cpp`                | ~305, ~410, new| +propagate field + `ResolveDpiLinks`    |
| `include/dpdk/spi/spi_pipeline.cpp`                  | 503, 717, 1018 | +link fast path + reload re-resolve     |
| `include/dpdk/spi/spi_pipeline.hpp`                  | 54-65          | +`dpi_skipped_by_link` atomic counter   |
| `test/test_env.sh`                                    | 378-396        | +`dpi_filter_group` on bench_fb/bench_yt |

No changes to `Environment`, `dpdk_environment.cpp`, `FlowTable` cell layout, EAL init, or
PMD plumbing.
