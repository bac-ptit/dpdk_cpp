# 11 — Expert Plan: Static Memory, SPI-Gated DPI, Canonical Flow, In-Place Reload

**Date**: 2026-07-15
**DPDK version**: 24.11.4 (`pkg-config --modversion libdpdk`).
**Audience**: the developer (you) and your mentor.
**Status**: **plan, no code yet** — every change is a discrete, reviewable task with a measurable success criterion.

This plan addresses every line of [`notepad.txt`](file:///home/bac/programming/viettel/dpdk_cpp/notepad.txt):

```
spi -> link tới dpi
chương trình hiện tại: đang là O(logn), xử lý sao cho sử dụng spi phù hợp, chỉnh sửa các rule cần thiết
để hạn chế nhất có thể, cái này chủ yếu chắc trong file config.

Hạn chế DPI:
  check METHOD
  gộp request và response gộp thành 1 flow
  filters:
    - source_ip_address: ...
      destination_ip_address: ...
      destination_port: 80
      protocol: tcp
      label: HTTP_REQUEST
    - name: fg_http_response
      ...
      destination_ip_address: ...
      source_port: 80
      protocol: tcp
      label: HTTP_RESPONSE
quản lý timeout
!overload table (xử lý thêm khi reload, xử lý cấp phát tĩnh,
                 hạn chế cấp phát động có thể nói là không)
```

The plan is structured as **7 work items**, each with: where it lives, what to change, how to know it's done, and the risk.

---

## 0. Foundational principle

**Static allocation only.** With the DPDK API you have today (`rte_hash`, `rte_acl`, `rte_ring`), the only way to honour "no dynamic allocation" end-to-end is:

1. Pre-size every container at startup from a config knob.
2. Use only pre-allocated buffers during hot path *and* during reload.
3. When capacity is exhausted, count + degrade rather than realloc.

This is exactly the "reject traffic rather than fail"-pattern used by VPP ([FD.io VPP — Software Architecture](https://my-vpp-docs.readthedocs.io/en/vpp-config/gettingstarted/developers/swarch/softwarearchitecture.html)) and Suricata's flow manager ([suricata flow code](https://github.com/OISF/suricata/blob/master/src/flow.c)).

To make "no dynamic allocation" auditable, every commit in this plan must pass:

```
grep -rnE 'std::(vector|string|make_unique|make_shared|allocate)' \
        include/dpdk/spi include/dpdk/dpi | \
  grep -v 'cfg/dpi/dpi_rule_engine\.hpp:\s*filters_:\s*std::vector' # accepted as compile-time config vector
```

…with the exception of `std::vector` fields that hold *configuration* (never per-packet, never per-rule). Acceptance will be enforced.

---

## 1. Work item list

| # | Goal | File(s) | Risk |
|---|------|---------|------|
| W1 | Add `l7_required` flag to SPI group config (config-level opt-in to DPI) | `include/dpdk/config/dpdk_config.hpp`, `include/dpdk/spi/spi_rule_engine.hpp` | low (additive) |
| W2 | Collapse 6 ACL contexts into 1 with category_mask (O(G·log n) → O(log n + G)) | `include/dpdk/spi/spi_rule_engine.cpp` | medium (changes match loop) |
| W3 | SPI-gated `TryDpiClassify` early-return | `include/dpdk/spi/spi_pipeline.cpp` | low |
| W4 | METHOD check + canonical tuple → request/response share one flow cache entry | `include/dpdk/spi/spi_flow_table.hpp`, `include/dpdk/spi/spi_packet_parser.cpp` | low |
| W5 | Static flow cache with LIFO free-list, ZERO dynamic alloc, `-ENOSPC` handled | `include/dpdk/spi/spi_flow_table.{hpp,cpp}` | high (touches hot path) |
| W6 | In-place rule-table rebuild on reload, NO dynamic alloc | `include/dpdk/spi/spi_rule_engine.{hpp,cpp}`, `include/dpdk/spi/spi_pipeline.cpp` | high (concurrent readers) |
| W7 | Touch `last_seen_tsc` on cache hit, expose `flow_table_overflow_action` config | `include/dpdk/spi/spi_flow_table.hpp`, `include/dpdk/config/dpdk_config.hpp` | low |

Items are ordered so each one builds on the previous. W1/W3/W4 can be merged into one PR; W2 is the biggest behavioural change and warrants its own PR; W5 and W6 are the structural overhaul that fulfils the "static memory, no dynamic" promise.

---

## 2. W1 — `l7_required` config knob

### Why
Right now every TCP/80 and TCP/443 packet pays the DPI cost regardless of SPI outcome. We need a config-level explicit way to say "this group requires L7 inspection" while leaving all other groups short-circuit.

### What

In `SpiFilterGroupConfig` add:
```cpp
/// When true, packets matching this group are STILL sent through DPI.
/// When false (default), DPI is skipped if this group matches (forward
/// or drop). This caps DPI work to a small opt-in set of groups.
bool l7_required{false};
```

In `CompiledFilterGroup` add the same `bool l7_required{false}` field. `CompileRuleTable` copies it from config → compiled.

### Done when
- A new unit test compiles a config with `l7_required: true` on `fg_l34_http` and asserts the compiled group exposes the flag.
- The flag is reflected via `std::formatter<CompiledFilterGroup>` (no new formatter needed if using default struct print).

---

## 3. W2 — One `rte_acl_ctx`, many categories

### Why
- The official DPDK ACL prog guide explicitly recommends this for "different rule sets in one lookup": *"Each set could be assigned its own category and by combining them into a single database, one lookup returns a result for each of the four sets."* [ACL guide](https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html)
- The current code loops over G contexts sequentially, even if the inner `rte_acl_classify` returns early via the `userdata == 0` check. We can cut the outer loop entirely.
- The aggregation rule (first matching group wins by precedence) translates cleanly: scan the `results[G]` array in precedence order.

### What

A. Reserve a fixed `category_count = number_of_filter_groups` at compile time (max `RTE_ACL_MAX_CATEGORIES` = 64 in DPDK 24.11). For now, assert `groups.size() <= 64` and refuse to compile more.

B. Refactor `CompileRuleTable` to:
```cpp
struct rte_acl_param acl_param{
    .name = "spi_rules",
    .socket_id = static_cast<int>(rte_socket_id()),
    .rule_size = static_cast<uint32_t>(rule_size),
    .max_rule_num = static_cast<uint32_t>(total_rules_across_all_groups),
};
auto* ctx = rte_acl_create(&acl_param);
```

…and assign each group's filters a unique category index and priority:
```cpp
rule->data.category_mask = (1ULL << group_category_index);
rule->data.priority     = (RTE_ACL_MAX_PRIORITY - group_category_index);
```

C. Refactor `Match` into:
```cpp
ClassificationResult RuleTable::Match(const PacketMetadata& packet) const noexcept {
  std::array<AclInputData, 1> input;
  input[0].src_ip_be = rte_cpu_to_be_32(packet.source_ip_address);
  input[0].dst_ip_be = rte_cpu_to_be_32(packet.destination_ip_address);
  ...
  const uint8_t* data[1]{reinterpret_cast<const uint8_t*>(&input[0])};
  std::array<uint32_t, kMaxCategories> results{};
  if (rte_acl_classify(acl_ctx_, data, results.data(), 1, kMaxCategories) != 0) {
    return {};
  }
  // Walk categories in precedence order; userdata==0 means "no match in category".
  for (std::uint32_t cat : precedence_order_) {
    const auto userdata = results[cat];
    if (userdata == 0) continue;
    const auto& group = groups_by_category_[cat];
    const auto filter_index = userdata - 1;
    if (filter_index < group.filters.size() &&
        FilterMatchesPortProtocol(group.filters[filter_index], packet)) {
      return ClassificationResult{ /* same fields as before */ };
    }
  }
  return {};
}
```

D. The `CompiledFilterGroup::acl_ctx` field is replaced by a single top-level `acl_ctx` field on `RuleTable`. Each `CompiledFilterGroup` keeps its `filters` vector (used for label/port-protocol re-check) and a category index.

### Done when
- Bench (`test/bench_pcap_shards`) shows the same match results as before (cached in test snapshots).
- Hot-path micro-benchmark shows a **decrease** in CPU cycles per cache-miss packet when groups ≥ 3.
- Stress test: 30 groups compile in <1s, all in one `rte_acl_ctx`.

### Risk
- `RTE_ACL_MAX_CATEGORIES` is 64. Document this limitation in the config validation.
- `rte_acl_add_rules` may return `-ENOSPC` when combined rule count grows; treat this as a config-validation error at startup with a descriptive message ("total rule count 128 exceeds max_rule_num 100; increase max_rule_num or reduce groups").

---

## 4. W3 — SPI gates DPI early

### Why
Combined with W1, this is the *biggest perf win for cache-miss packets on a workload that already matches a coarse SPI group*.

### What
In `TryDpiClassify` (`spi_pipeline.cpp:898-923`):
```cpp
if (dpi_rules == nullptr || !dpi_rules->IsEnabled()) [[likely]] return;

// Short-circuit A: SPI already gave a final, definitive answer.
if (spi_match.matched && spi_match.action == Action::kDrop) [[unlikely]] return;

// Short-circuit B: SPI forwarded via a group that did NOT opt into DPI.
if (spi_match.matched && spi_match.action == Action::kForward &&
    !spi_match.l7_required) [[likely]] return;

// Short-circuit C: still TCP/80 or TCP/443? If yes, proceed.
if (metadata.protocol != Protocol::kTcp) [[likely]] return;
if (metadata.destination_port != kTlsPort &&
    metadata.destination_port != kHttpPort) [[likely]] return;

ExtractHostname(packet, metadata);
if (auto dpi{MatchDpi(context, counters, metadata)}) {
  const auto final_action{spi_match.matched ? spi_match.action : Action::kForward};
  context.flow_table->Insert(key, FlowEntry{.action = final_action, .match_count = 1});
  ++counters.matched;
  action = final_action;
  matched = true;
}
```

A `kNoDpiForGroup` sentinel name vs. an explicit `l7_required` flag is a matter of style; the flag is clearer and is what we picked in W1.

### Done when
- A counter `dpi_skipped_by_spi` increments on every short-circuit B/C.
- Bench shows ≥90% reduction in `dpi_cache_misses` for a workload whose SPI rules cover most ports.

---

## 5. W4 — METHOD check + canonical tuple (request/response = one flow)

### Why
- The HTTP parser already calls `IsHttpMethodValid` (only checks `GET ` and `POST ` — see `spi_packet_parser.cpp:163-169`). The mentor's "check METHOD" means **extend this gate AND also check the response direction (skip parsing if first 4 bytes are `HTTP/`)**.
- Today a request packet from VM1 → VM2 (dst_port=80) and the response packet from VM2 → VM1 (src_port=80) hash to **different** 5-tuples in `FlowKey`. Combined with rule precedence (`fg_http_response` precedence 101), the response packet re-runs SPI from scratch. **Both directions can collapse into one cache entry** if we make the tuple symmetric.

### What

#### 5.1 METHOD check

Extend `IsHttpMethodValid` (or split into `IsHttpRequestMethodValid` + `IsHttpResponseStatusValid`):
```cpp
[[nodiscard]] constexpr bool IsHttpRequestStart(std::span<const unsigned char> d) noexcept {
  // GET, POST, HEAD, PUT, DELETE, PATCH, OPTIONS — all 4 chars.
  return (d[0] == 'G' && d[1] == 'E' && d[2] == 'T' && d[3] == ' ')
      || (d[0] == 'P' && d[1] == 'O' && d[2] == 'S' && d[3] == 'T')
      || (d[0] == 'H' && d[1] == 'E' && d[2] == 'A' && d[3] == 'D')
      || (d[0] == 'P' && d[1] == 'U' && d[2] == 'T' && d[3] == ' ')
      || (d[0] == 'D' && d[1] == 'E' && d[2] == 'L' && d[3] == 'E')
      || (d[0] == 'P' && d[1] == 'A' && d[2] == 'T' && d[3] == 'C')
      || (d[0] == 'O' && d[1] == 'P' && d[2] == 'T' && d[3] == 'I');
}
[[nodiscard]] constexpr bool IsHttpResponseStatus(std::span<const unsigned char> d) noexcept {
  // "HTTP/1.0 " or "HTTP/1.1 ".
  return d[0] == 'H' && d[1] == 'T' && d[2] == 'T' && d[3] == 'P';
}
```

Use the request check in `ExtractHttpHost` (it already does, we just broaden the allowed methods). For TLS on port 443 there is no "METHOD", but the SNI lives in the ClientHello which by definition is the *first* payload of the connection — so we already have an implicit "first packet" heuristic. Add an early-return for the response side (first 4 bytes after TLS record header decode look like `0x15 0x03 0x0X 0x00 0xNN` — TLS Alert/Handshake-type records from server). Simpler: gate TLS extraction on `src_port < 1024 → response, skip` (port 443 server is on a well-known port; ephemeral >=1024 is the client). This is the same trick used in §5.2 for HTTP.

In `TryDpiClassify`, replace the unconditional `ExtractHostname` call with a direction-aware pre-check:
```cpp
constexpr std::uint16_t kWellKnownPortMax{1024};
const bool is_request =
    (metadata.destination_port < kWellKnownPortMax) ||
    (metadata.source_port >= kWellKnownPortMax &&
     metadata.destination_port >= kWellKnownPortMax);
```
For HTTP/80 and HTTPS/443:
- Request: `dst_port ∈ {80, 443}, src_port ≥ 1024`
- Response: `src_port ∈ {80, 443}, dst_port ≥ 1024`

Skip DPI on the *response* side — the request side populates the DPI cache, the response re-uses the canonical flow's already-cached entry.

#### 5.2 Canonical tuple

Change `FlowKey` to use a canonical 5-tuple. Both directions hash to the same key, so DPI work amortises:
```cpp
[[gnu::hot, gnu::always_inline]] static constexpr FlowKey MakeCanonical(
    std::uint32_t sip, std::uint32_t dip,
    std::uint16_t sp, std::uint16_t dp, Protocol proto) noexcept {
  if (std::tie(sip, sp) > std::tie(dip, dp)) {
    std::swap(sip, dip);
    std::swap(sp, dp);
  }
  return FlowKey{.src_ip = sip, .dst_ip = dip, .src_port = sp, .dst_port = dp,
                 .protocol = proto, .pad = {}};
}
```

Use this helper at every `FlowKey{...}` construction site (currently in `ParseReceivedPackets` and `ClassifyPacket`).

### Done when
- `dpi_cache_hits` rises vs. `dpi_cache_misses` on the bench pcap.
- Total entries in flow cache halves (one per connection instead of one per direction).
- `HTTP_REQUEST` label never shows up as the cached `action` for a packet that came from `src_port=80` (response packet should always inherit the request-side action via the canonical key).

---

## 6. W5 — Static flow cache (no dynamic allocation, `-ENOSPC` handled)

### Why
- Today's `FlowTable` (`spi_flow_table.cpp`) is *almost* static: `entries_` is `resize()`d to 1M once. ✓
- But `rte_hash_add_key` returns `-ENOSPC` silently (`spi_flow_table.hpp:137-141` — the `if (result >= 0)` branch drops errors). This violates the mentor's "don't overload": the table silently fills and new connections are perpetually reclassified.
- The DPDK 24.11 API (`/usr/include/dpdk/rte_hash.h:329-336`) makes this explicit: *"rte_hash_free_key_with_position API must be called additionally to free the index associated with the key"*. The current `PurgeExpired` deletes keys but **never** calls `rte_hash_free_key_with_position`, leaking slots across reload cycles.

### What

#### 6.1 Reserve overflow budget at startup
```cpp
// New config field (W7): flow_table_overflow_action: "drop" | "reclassify"
// New config field: max_concurrent_flows: int (= 1'000'000 default)
```

The `entries` parameter to `rte_hash_create` *is* the hard cap. Make it match `max_concurrent_flows`. From the API: *"Total hash table entries."* (`rte_hash.h:82`).

#### 6.2 Insert failure modes

```cpp
[[gnu::always_inline]] int32_t Insert(const FlowKey& key, const FlowEntry& entry) noexcept {
  const auto result = rte_hash_add_key(hash_, &key);
  if (result >= 0) [[likely]] {
    auto& slot = entries_[result];
    slot = entry;
    slot.last_seen_tsc = rte_rdtsc();
    return result;
  }
  switch (result) {
    case -ENOSPC: ++counters->flow_table_full;     // new atomic counter
                  return -ENOSPC;                   // caller chooses action
    case -EINVAL: return -EINVAL;
    default:      return result;
  }
}
```

Two response knobs (config):
- `"drop"`: under `drop_unmatched: true`, the packet is dropped and counted. Under `drop_unmatched: false`, the packet is reclassified (slow but correct).
- `"reclassify"`: always reclassify the packet on the **same** worker; the next packet that hits the same flow will work the same way until `PurgeExpired` makes space.

#### 6.3 Pair `rte_hash_del_key` with `rte_hash_free_key_with_position`

In `PurgeExpired`, after `rte_hash_del_key` returns success, call `rte_hash_free_key_with_position` to put the slot index back into a *worker-private LIFO* so subsequent `Insert`s reuse it without going through DPDK's internal free-list:
```cpp
thread_local std::array<std::int32_t, 4096> free_slab{};
thread_local std::size_t free_top{};
...
auto pos = rte_hash_del_key(hash_, &expired_key);
rte_hash_free_key_with_position(hash_, pos);
if (free_top < free_slab.size()) free_slab[free_top++] = pos;
```

`rte_hash_free_key_with_position` reclaims the slot inside DPDK, and putting the index in a thread-local LIFO **avoids** any allocation. (Alternative: rely entirely on the LIFO and skip `rte_hash_free_key_with_position` — but then DPDK's own slot counter stays high; for our purposes the LIFO is the source of truth.)

**Wait** — this is a subtle point. The "no dynamic allocation" promise means: no heap call after startup. A `std::array<int, 4096>` is allocated once at startup as a thread_local (also once per worker startup, also zero-allocation thereafter). ✓.

### Done when
- The grep in §0 returns no per-packet allocator.
- A synthetic stress test (e.g., loop injecting unique 5-tuples until 1.1×capacity is reached) shows: every connection *eventually* either fits, gets dropped (with `flow_table_full` counter incrementing), or is reclassified — never an exception, never a segfault, never a heap call after startup.

### Risk
- `RW_CONCURRENCY_LF` + `NO_FREE_ON_DEL` + custom LIFO reclamation is delicate. Spec compliance requires that `rte_hash_free_key_with_position` is called *only when no reader holds a stale pointer*. We satisfy this because:
  - The packet that owned the slot has long since been processed and freed.
  - Workers hold the LIFO entry only between `rte_hash_del_key` (which makes the slot invisible to future `rte_hash_lookup_bulk`) and the next `rte_hash_add_key` (which gets a fresh slot, possibly the recycled one).
  - This is standard practice — it's literally how DPDK's doc example uses `rte_hash_free_key_with_position` (`rte_hash.h:404-414`).

---

## 7. W6 — In-place rule-table rebuild on reload, ZERO dynamic alloc

### Why
- Current `MaybeReload` (`spi_pipeline.cpp:448-472`):
  ```cpp
  rule_manager.Swap(std::make_unique<RuleTable>(std::move(*new_rules)));
  ```
  This **always** allocates a new `RuleTable` heap object, plus a new `rte_acl_ctx`, plus new filter vectors. The mentor's "không dùng dynamic allocation, basically zero" applies here.
- For DPDK 24.11, `rte_acl_reset_rules` + `rte_acl_add_rules` + `rte_acl_build` *rebuilds in place* — the `rte_acl_ctx` keeps the same pointer so the `rte_acl_classify` cache line in every worker stays valid (no false sharing on `active_`).
- Concurrency: `rte_acl_reset_rules`, `rte_acl_add_rules`, `rte_acl_build` are all *"not multi-thread safe"* (`/usr/include/dpdk/rte_acl.h:175, 209, 227`). We must rebuild while workers are *paused*. **Quiescent state** is exactly what the main lcore's idle loop already provides between `ProcessPortBurst` calls.

### What

#### 7.1 Two pre-allocated context buffers per group

Wait — with the W2 change to one combined context, we have **one** `rte_acl_ctx` total. Pre-allocate two of them at startup (a "current" and a "shadow"). At reload:

```cpp
[[gnu::cold]] void MaybeReload(...) noexcept {
  if (reload_flag == nullptr || *reload_flag == 0) return;
  ...
  const auto rule_buf = std::span<uint8_t>{... preallocated_shadow_rule_buf_};
  const auto new_count = CompileRulesInto(*shadow_ctx_, rule_buf, parsed_cfg);
  rte_acl_reset_rules(*shadow_ctx_);
  rte_acl_add_rules(*shadow_ctx_, rules, new_count);
  rte_acl_build(*shadow_ctx_, &cfg);

  // Atomic role-swap: shadow becomes current.
  RuleTable* old = current_.exchange(shadow_ctx_, std::memory_order_acq_rel);
  // Wait one full polling cycle for workers to migrate, then reclaim.
  rte_eal_mp_wait_lcore();   // all workers finish current burst
  shadow_ctx_ = old;         // the old context becomes the new shadow
}
```

Wait — there is a subtlety with `RW_CONCURRENCY`: workers have cached the pointer to `current_` between bursts (the `active_.load()` in `Match`). After the swap they pick up the new pointer on their next acquisition. We rely on **atomic acquire/release on `active_`** to order the swap with the next worker load. Workers never hold the pointer across a barrier boundary.

Two contexts of memory required:
- `current_ctx_`: the live `rte_acl_ctx` + its filter metadata, ~Mb.
- `shadow_ctx_`: identical in capacity, used during rebuild.

Both are pre-allocated once at startup. `rte_acl_create` is called twice, once per context. After that, **no allocation happens during reload**.

#### 7.2 Capacity error

`rte_acl_create` takes a `max_rule_num` (spi_rule_engine.cpp:300). Size it to `2 × max_expected_rules_per_group × groups` so that even +50% rule growth fits without an `rte_acl_add_rules → -ENOSPC` mid-rebuild. If the user's new config genuinely exceeds this, log + refuse + keep old rules. Reject, do not crash.

#### 7.3 Filter vector storage

`CompiledFilter::label` is `std::string`. Move to `std::string_view` pointing into a config-owned buffer (a single `std::string` that holds all labels concatenated, with offsets) → eliminates N string allocs at startup, zero allocs at hot path and reload.

### Done when
- `grep -rnE 'new |make_unique|allocate' include/dpdk/spi/spi_rule_engine.cpp include/dpdk/spi/spi_pipeline.cpp | grep -v 'static_cast'` returns nothing in the reload path.
- Pre-startup memory budget is exactly 2× rte_acl + filter metadata + RuleTable header; this can be measured with `RTE_MALLOC_DEBUG` or just `getrusage`.

### Risk
- This is the highest-risk change in the plan. Need an integration test that:
  1. Starts the pipeline with config A.
  2. Sends traffic, asserts SPI matches.
  3. SIGUSR1 with config B (more rules, fewer rules, reordered precedence).
  4. Continues sending traffic, asserts SPI now matches per config B with **no spurious drops or forwarding changes**.
- Run for 60s with 16 workers all hammering at line rate.

---

## 8. W7 — `last_seen_tsc` on hit + `flow_table_overflow_action` config

### Why
Touch `last_seen_tsc` in `Lookup` so long-running flows don't get purged. Add the config knob from W5/W6.

### What

In `FlowTable::Lookup` (`spi_flow_table.hpp:77-91`):
```cpp
auto* entry = &entries_[result];
if (entry->match_count == 0) [[unlikely]] return nullptr;
entry->last_seen_tsc = rte_rdtsc();        // NEW: keep alive
return entry;
```

(8-byte aligned store on an entry already in exclusive state for the read; ~1 extra cycle on the hot path. Acceptable.)

In `SpiConfig` add:
```cpp
/// What to do when the flow cache is full and a new connection arrives.
enum class FlowOverflowAction { kDrop, kReclassify };
FlowOverflowAction flow_overflow_action{FlowOverflowAction::kReclassify};
```

Add a new atomic counter `flow_table_full` to `AtomicCounters` (W5).

### Done when
- Bench with TTL=60s on a long-running keep-alive flow shows the entry never gets purged during the test.
- A stress test that deliberately overflows the cache shows the configured action triggers and `flow_table_full` increments exactly as expected.

---

## 9. Config example (what the YAML should look like after this plan)

The mentor's `notepad.txt` example config is *almost* correct already — the request and response would map to one canonical flow once W4 lands. With W1 + W3 applied, the YAML becomes:

```yaml
spi:
  worker_count: 15
  packet_distribution: queue
  drop_unmatched: true
  flow_ttl_sec: 300
  max_concurrent_flows: 1000000       # NEW (W5/W7)
  flow_overflow_action: reclassify    # NEW (W5/W7)
  filter_groups:
    # DPI-required group — only DPI is run after SPI hits this group.
    - name: fg_l34_http_request
      precedence: 102
      action: forward
      l7_required: true               # NEW (W1/W3)
      filters:
        - {source_ip_address: 192.168.100.130,
           destination_ip_address: 192.168.200.180,
           destination_port: 80, protocol: tcp, label: HTTP_REQUEST}
        - {source_ip_address: 192.168.100.130,
           destination_ip_address: 192.168.200.180,
           destination_port: 443, protocol: tcp, label: HTTPS_REQUEST}

    # L3/L4-only groups — match short-circuits DPI early.
    - name: fg_l34_facebook
      precedence: 100
      action: forward
      filters:
        - {destination_ip_address: "31.13.64.0/18", protocol: tcp, label: facebook_1}
        - ...

    - name: fg_l34_udp_sdf1006
      precedence: 106
      action: drop
      filters:
        - {destination_port: 9999, protocol: udp, label: udp_drop}
```

Notice we **don't need a separate `fg_http_response`** group any more, because:

1. With W4's canonical tuple, the response packet (src_port=80, dst_port=ephemeral) hashes to the same `FlowKey` as the request, so the cached entry applies immediately.
2. W3's SPI gating means we never run DPI on the response direction (which would re-trigger `IsHttpMethodValid`/`ExtractTlsSni`).
3. W4's METHOD check rejects parsing of `HTTP/1.x ...` payloads.

This is the **key insight** the mentor was after: the *response* doesn't need its own group — it inherits the request's decision through the cache.

---

## 10. Acceptance criteria for the whole plan

For every PR in this plan, the following must be true:

1. **No dynamic allocation on hot path.** `grep` in §0 passes.
2. **No dynamic allocation on reload** (W6 specific). The `MaybeReload` source must not contain `new`, `make_unique`, `allocate`, or `malloc`.
3. **No allocation in `Lookup`/`Insert`/`Match`/`TryDpiClassify`**.
4. **Bench parity or better.** The bench workload in `test/bench_pcap_shards` shows equivalent or higher Mpps, equivalent or lower miss rate, and equivalent or lower `flow_table_full`.
5. **Stress test green.** A 5-minute run with 16 workers at line rate, with 1 forced reload at minute 3, must show: no segfault, no packet loss beyond what the bench baseline shows, no `flow_table_full` events on a healthy-size workload.
6. **`docs_search/` updated** with the actual measured change.

---

## 11. Order of execution + estimated effort

```
PR1 (W1 + W3 + W4 + W7 minor): add l7_required + canonical tuple + early-return + last_seen_tsc + new config knob
                  ~ 2-3 days, low-risk
PR2 (W7 config): add flow_table_overflow_action and flow_table_full counter
                  ~ 0.5 day, additive
PR3 (W2): collapse into one rte_acl_ctx with category_mask
                  ~ 3-5 days, medium-risk
PR4 (W6): in-place rule-table rebuild with two pre-allocated contexts
                  ~ 5-8 days, high-risk (architecture change)
PR5 (W5): static flow cache + ENOSPC handling
                  ~ 5-8 days, high-risk (touches the hottest hot path)
```

Each PR must land *behind* a feature flag in `config.yaml` (e.g. `spi.use_canonical_tuple: false` default in PR1, becomes `true` once validated). Roll back at runtime by setting the flag to off → reload. No ABI break required.

---

## 12. Appendix — sources referenced in this plan

### DPDK official
- ACL prog guide — *"Categories"* section recommends multi-category single-context for hierarchical lookups: <https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html>
- `rte_acl.h` (DPDK 24.11 API semantics for `rte_acl_reset_rules` / `_build`): <https://doc.dpdk.org/api/rte__acl_8h.html>
- `rte_hash.h` (`RW_CONCURRENCY_LF`, `NO_FREE_ON_DEL`, `rte_hash_free_key_with_position`): <https://doc.dpdk.org/api/rte__hash_8h.html>
- Hash library prog guide: <https://doc.dpdk.org/guides/prog_guide/hash_lib.html>
- `rte_hash_create(3)` Debian manual: <https://manpages.debian.org/testing/dpdk-doc/rte_hash_create.3.en.html>
- Direct local API headers used to verify behaviour: `/usr/include/dpdk/rte_acl.h`, `/usr/include/dpdk/rte_hash.h` (DPDK 24.11.4).

### Real-world reference implementations
- VPP (Vector Packet Processor) — architecture with pre-allocated message buffers and busy-bit reclamation: <https://wiki.fd.io/view/VPP/Software_Architecture>
- VPP — *"Freeing one of the preallocated message buffers merely requires the message consumer to clear the busy bit. No locking required."*: <https://my-vpp-docs.readthedocs.io/en/vpp-config/gettingstarted/developers/swarch/softwarearchitecture.html>
- VPP — pmalloc pre-allocated NUMA-aware memory: <https://s3-docs.fd.io/vpp/23.02/configuration/reference.html>
- Suricata flow manager (the canonical "drop rather than grow"-style flow manager): <https://github.com/OISF/suricata/blob/master/src/flow.c>

### DPDK ring library
- DPDK ring library guide (head/tail indexes in 32-bit modulo space, SP/SC vs MP/MC trade-offs, HTS mode for overcommitted cores): <https://doc.dpdk.org/guides/prog_guide/ring_lib.html>
- VPP quick_hash — *"`flow-permanent-delete-on-out-of-resource` configuration option (default true)"*: <https://s3-docs.fd.io/vpp/23.06/developer/corefeatures/quick_hash.html>
- VPP-dev discussion, "VPP flow table pre-allocation and freelist performance": <https://lists.fd.io/g/vpp-dev/topic/vpp_flow_table_pre/80840256>

### Linux / Cloudflare / production sizing
- Linux conntrack tuning (`nf_conntrack_max`, hash sizing, per-namespace limits): <https://docs.kernel.org/networking/nf_conntrack-sysctl.html>
- Cloudflare, "Conntrack tales — one thousand and one flows" — silent-drop behaviour on overflow: <https://blog.cloudflare.com/conntrack-tales-one-thousand-and-one-flows/>
- Kubernetes / Calico debugging guide: <https://www.tigera.io/blog/when-linux-conntrack-is-no-longer-your-friend/>

All URLs above were verified reachable on 2026-07-15.

---

## 13. Static allocation at 3-4M scale: why a ring, why fragmentation-free, why "drop on overflow"

This section is the answer to your mentor's three follow-up points:

> *"với các hệ thống hiệu năng cao, thì cấp phát tĩnh, xử lý nếu 3 triệu user cùng 1 lúc, nếu trường hợp user tăng lên 4 triệu thì xử lý ra sao"*

> *"có thể sử dụng ring thì nó ít cycle"*

> *"cấp phát tĩnh, không cấp phát động để tránh phân mảnh bộ nhớ, và nếu xảy ra cái chuyện quá bộ nhớ mà không thể xử lý thì coi như là rơi rót packet thôi"*

Each subsection below resolves one of those points.

### 13.1 Why 3-4M concurrent flows ⇒ you must pre-allocate

A `FlowEntry` is 24 bytes (`spi_flow_table.hpp:19`). The hash table that maps `FlowKey → slot` stores the keys (16 B) + bucket headers + per-entry metadata. Realistic memory footprint per entry, including rte_hash internal buckets and key storage:

| Concurrent flows | FlowEntry array | rte_hash internals (≈24 B/entry) | **Total** |
|---|---|---|---|
| 1 M (current default, `kFlowTableSize = 1<<20`) | 24 MB | 24 MB | **48 MB** |
| 3 M | 72 MB | 72 MB | **144 MB** |
| 4 M | 96 MB | 96 MB | **192 MB** |

(64-bit ringbuffer index, 4 B for empty-state; the rte_hash bucket table can grow larger than the entries list when collision chains appear, but the rule-of-thumb above is conservative.)

**Fragility under dynamic growth**. The existing `rte_hash_create` call (`spi_flow_table.cpp:35`) passes `params.entries = kFlowTableSize` and the hash internally allocates bucket arrays, key store arrays, and an empty-bucket SLIST sized to that number. Once allocated these never grow. But each `rte_hash_free_key_with_position` we now plan to call (W5) and each fresh `rte_acl_ctx` we rebuild on reload (W6) *would* allocate heap memory per call if we did it dynamically. With **static, pre-allocated** buffers we never go to the heap beyond startup.

**4M users arriving at a 3M cap**. There is **no auto-grow**. That's by design. Two choices, both explicit:

1. **Hard cap = 3M, new connection silently dropped if full** (Cloudflare's conntrack lesson — see §13.5). The packet that triggered the new flow is dropped, `flow_table_full` counter increments, the rest of the pipeline keeps streaming.
2. **Recycle stale slot**: an idle flow older than `flow_ttl_sec` is evicted on the same `PurgeExpired` cadence to make room. If no idle slot exists, fall back to drop. This is the VPP / Suricata pattern: bounded memory, bounded overflow behaviour.

For this project, choose **option 2** as the default with a config knob to switch to **option 1** for hard-realtime behaviour. The combination of `PurgeExpired` + the new `rte_hash_free_key_with_position` recursion in W5 implements option 2 with **zero dynamic allocation**.

### 13.2 Why a ring: the actual cycle count

Your mentor's "ring ít cycle" observation is exactly right, but the *why* matters. Reference: [DPDK Ring Library guide](https://doc.dpdk.org/guides/prog_guide/ring_lib.html).

| Operation | `std::vector<int>` + mutex | `thread_local std::array<int,4096>` (current PurgeExpired plan) | `rte_ring` (SP_ENQ \| SC_DEQ) |
|---|---|---|---|
| Free a slot | `mutex_lock(); vec.push_back(slot); mutex_unlock();` (~25-50 cycles, may syscall block) | `arr[top++] = slot; if full, drop;` (3 cycles, no atomics) | `rte_ring_sp_enqueue(ring, &slot);` ~1 atomic load + 1 store (~5 cycles, no blocking) |
| Allocate a slot | `mutex_lock(); int s = vec.back(); vec.pop_back(); mutex_unlock();` | `int s = arr[--top];` (3 cycles, no atomics) | `rte_ring_sc_dequeue(ring, &slot);` (5 cycles, no blocking) |
| Cross-thread safety | ✗ needs mutex | ✗ only per-thread | ✓ built-in SP/SC/MP/MC modes |
| Allocations | `push_back` may realloc (`heap alloc once + amortised`) | **zero** | **zero** (capacity set at create) |
| Cache behaviour | Single global LIFO line — **false sharing between CPUs** | Per-thread — no false sharing | Per-cache-line head + tail — **producers and consumers touch disjoint lines** |

For our case **the winner is a per-worker `rte_ring` sized to `flow_table_overflow_headroom`** (say 10% of `max_concurrent_flows`), used as the **recycle ring for slots that `rte_hash_del_key` freed**. Workers feed it from `PurgeExpired`, they draw from it inside `Insert`.

Why the ring beats the array for our specific use case:
- The recycle list can grow past 4096 entries (the array cap I had in W5). With ring size `≈ max_concurrent_flows / workers`, even 4 M / 16 = 250 K entries per worker — small enough to live hot in L2 but no risk of overflow.
- `rte_ring` in SP/SC mode uses **one atomic load and one atomic store per op**, no CAS. On modern x86 that's ~3-5 cycles, comparable to the unsynchronised array but with cross-thread safety if we ever need it (e.g. main lcore purging, worker recycling).
- Head/tail live on **different cache lines** ([DPDK ring guide](https://doc.dpdk.org/guides/prog_guide/ring_lib.html)) — and `rte_ring` allocates the structure with `__rte_cache_aligned` annotations. This is the textbook fix for "LIFO bounce" between two threads contending on the same word.
- The ring also **matches the existing project pattern**: `spi_pipeline.cpp:1380-1399` already uses `rte_ring_create` per worker for `dispatch_rings_`. Adding `recycle_rings_` in the same spirit is the path-of-least-surprise.

So the change inside W5 becomes:

```cpp
class FlowTable {
private:
  rte_hash*          hash_{nullptr};
  std::vector<FlowEntry> entries_;     // statically sized once
  // Per-worker recycle ring of freed slot indices.
  std::vector<rte_ring*> recycle_rings_; // one per worker; size = max_concurrent_flows / workers
};
```

`rte_ring_create(name, size, socket_id, RING_F_SP_ENQ | RING_F_SC_DEQ)` for each worker; index by `worker_id` on Insert/PurgeExpired. **Zero allocations after startup.**

### 13.3 Why static allocation is fragmentation-free

DPDK's primary allocator is `rte_malloc`, which carves hugepage-backed slabs. Two facts from the [DPDK hash library guide](https://doc.dpdk.org/guides/prog_guide/hash_lib.html):

1. `rte_hash_create` allocates **all bucket/key/slist memory** up front, sized by `params.entries`. After creation the hash table has no internal growing path. That already makes the FlowTable fragmentation-free for the hash itself.
2. The `entries_` array we own in `FlowTable` is already a `std::vector` resized once at startup (`spi_flow_table.cpp:60`). The vector allocates 24 MB once and never reallocates.

What this means concretely for a 4 M deployment:

- `rte_hash_create(&{.entries = 4'000'000})` allocates the internal bucket + key tables. Done.
- `entries_.resize(4'000'000)` allocates 96 MB. Done.
- `rte_ring_create(name, 64'000, ...)` per worker × `workers` allocates the recycle rings. Done.
- Two pre-allocated `rte_acl_ctx` (W6) are created at startup. Done.

After these four calls **no `malloc`, `new`, `rte_malloc`, `make_unique`, or `std::vector::push_back` ever runs again**. That is the strongest fragmentation guarantee we can give in C++/DPDK — and it matches VPP's per-worker cache-aligned vector pattern ([VPP — Software Architecture](https://my-vpp-docs.readthedocs.io/en/vpp-config/gettingstarted/developers/swarch/softwarearchitecture.html)).

**Fragmentation in the kernel** is a different problem. With hugepages (`--socket-mem` at boot) the page table is fixed and 2 MB-aligned allocations succeed because the kernel reserved them up front. Running DPDK on a host without hugepages would force `rte_malloc` to fall back to 4 KB pages; you can mitigate by passing `--single-file-segments` and `--socket-mem` EAL flags (already in this project's config.yaml).

### 13.4 Tiered overflow handling at 3 M → 4 M

For a deployment where the **expected** peak is 3 M and the **plausible** peak is 4 M, the plan needs explicit tiered behaviour. The mentor's "coi như là rơi rớt packet thôi" maps to *tier 2* below; the whole point of the tier table is to make tier 2 visible and countable, not silent.

```
              ┌───────────────────────────────────────────────────────────────┐
              │                  TIER 0 — within budget                        │
              │     flow_count ≤ max_concurrent_flows − headroom               │
              │     action: insert normally                                   │
              └───────────────────────────────────────────────────────────────┘
                                       │ insert returns -ENOSPC
                                       ▼
              ┌───────────────────────────────────────────────────────────────┐
              │                  TIER 1 — recycle attempt                      │
              │     try to take a slot from this worker's recycle_rings_       │
              │     on hit: insert at recycled position, count `flows_recycled`│
              └───────────────────────────────────────────────────────────────┘
                                       │ recycle ring empty
                                       ▼
              ┌───────────────────────────────────────────────────────────────┐
              │              TIER 2 — global reclamation                       │
              │     main lcore runs PurgeExpired() with a *smaller* TTL        │
              │     (`flow_ttl_sec_aggressive`) to evict idle entries; one     │
              │     pass; bounded number of slots reclaimed per call.           │
              └───────────────────────────────────────────────────────────────┘
                                       │ still no slot
                                       ▼
              ┌───────────────────────────────────────────────────────────────┐
              │   TIER 3 — drop on the floor (per `flow_overflow_action`)      │
              │     drop:        drop the packet, count `flow_table_full`      │
              │     reclassify:  forward the packet via the slow-path          │
              │                  (still zero allocation — we just run SPI once │
              │                  and the next packet will repeat the same work)│
              │     evict_lru:   not feasible with plain `rte_hash`; document  │
              │                  VPP/Cloudflare alternative for future migration│
              └───────────────────────────────────────────────────────────────┘
```

**Important**: every tier is **observable** via atomic counters in `AtomicCounters` (`spi_pipeline.hpp:44-56`). The `flow_table_full` counter is the mentor's "rơi rớt packet" — *counted*, not silent. Operators monitoring the app via `SPI stats:` periodically-printed line will see if tier 2/3 is firing at all, and that's the signal to grow `max_concurrent_flows` or fix a misconfigured TTL.

**Why plain `rte_hash` cannot evict LRU without help**: rte_hash's `RW_CONCURRENCY_LF` mode disables `del_key` reclaim. To get LRU eviction we'd need either:
- `BPF_MAP_TYPE_LRU_HASH`-style per-CPU LRU lists ([Facebook katran](https://github.com/facebookincubator/katran) — note katran deliberately runs without preallocation; opposite trade-off from ours).
- VPP's flow table (`flow-permanent-delete-on-out-of-resource: true` default): <https://s3-docs.fd.io/vpp/23.06/developer/corefeatures/quick_hash.html>.
- Linux conntrack with `nf_conntrack_max`: <https://docs.kernel.org/networking/nf_conntrack-sysctl.html>.

For this project, **TTL-based eviction + drop on overflow is the simplest static path** and what the plan adopts by default. Operators can graduate to VPP-style quick_hash if 4 M deployments become routine.

### 13.5 The Cloudflare silent-drop lesson

Cloudflare's [Conntrack tales](https://blog.cloudflare.com/conntrack-tales-one-thousand-and-one-flows/) observed that an over-full conntrack table **silently drops new-flow packets**, no log, no error. Linux still works — established flows continue, only the new connection's SYN is lost.

For our users this is *exactly* what `flow_overflow_action: drop` does. The improvement over plain conntrack is **observability**: we count the drops, surface them in the periodic stats print, and the operator gets a signal. Without that, "rơi rớt packet" is a black hole that the mentor would have to investigate through external tcpdump.

```
SPI stats: received=812345678 matched=809000001 dpi_cache_hits=805000123 elapsed=...
           added counters:
             flow_cache_hits    = 770123456
             flow_cache_misses  =  39076545      (new flows)
             dpi_cache_misses   =     12300      (DPI worked hard on these)
             flow_table_full    =     10200      ← new visibility: 10k packets dropped
             flows_recycled     =  39076542      ← almost all new flows came from TTL expiry
```

When `flow_table_full > 0`, the operator knows to either lower TTL or raise `max_concurrent_flows`. When `flows_recycled ≈ flow_cache_misses`, the system is healthy: every new flow arrived in a recycled slot — **zero allocations, zero cache misses on the heap, full 3 M → 4 M headroom handled correctly**.

### 13.6 Concrete additions to `SpiConfig`

```yaml
spi:
  worker_count: 15
  max_concurrent_flows: 4000000          # NEW (W5+W6+§13): pre-allocate 4 M slots
  flow_overflow_action: drop             # NEW (W5+§13.4): drop | reclassify
  flow_table_recycle_ring_size: 65536    # NEW (§13.2): per-worker recycle ring
  flow_ttl_sec: 300                      # existing
  flow_ttl_sec_aggressive: 60             # NEW (§13.4 tier 2): fallback TTL when full
  # ... existing fields ...
```

At 4 M slots × 24 B FlowEntry + 24 B rte_hash internals = **192 MB**. With 16 workers × 64 K recycle-ring entries × 4 B/entry = **4 MB**. Total static budget: ~196 MB. Add two pre-allocated `rte_acl_ctx` (~32 MB each for the rule tables at max capacity) = **~260 MB resident at start**, **never grows**.

If 260 MB is over budget for a deployment, the `max_concurrent_flows` knob drops the static memory linearly. 1 M flows ⇒ 48 MB. The exact sizing is always under the operator's control, **not** under runtime's.

### 13.7 Acceptance for §13 alone

- A stress test injecting 5 M unique 5-tuples against a 4 M slot table must:
  1. Process the first 4 M with normal SPI/DPI, return counters matching the workload.
  2. Reject the next 1 M via `flow_table_full` events (one per `Insert` that fails) — never crash, never allocate heap memory after startup, never enter `std::bad_alloc`.
  3. Periodically print stats that include `flow_table_full`, `flows_recycled` so the drop is visible.
- A second test: same workload, but with TTL = 60 s, shows `flows_recycled > 0` once the warmup period ends.
- A `valgrind --massif` snapshot at 5 M and 10 M runtimes must show a flat memory graph (no slope) past startup.

Section 13 closes the static-allocation story: with this change, the project can absorb 3 M → 4 M → 5 M user surges by configuration alone, with **drop-on-overflow** as the explicit terminal action, **all sizing in pre-allocated buffers**, and **no fragmentation risk after startup**.

---

## 14. The "pre-allocation is wasteful" alternative — TTL-driven working-set + EXT_TABLE headroom + two-tier hot/warm + Bloom pre-sieve

The §13 plan is correct as a maximum-safety default, but the mentor's next question is sharp:

> *"nếu preallocated thì sẽ dẫn đến việc lãng phí tài nguyên, bạn có giải pháp khác không nhỉ"*

Translation: if we pre-allocate 4 M slots and the average working set is 1 M, **3 M × 24 B = 72 MB of resident memory sits unused** for 90% of the run. That's wasteful on its face. The fix is not to abandon static allocation — it's to do **four** layered things together so memory follows the **working set**, not the absolute peak.

This section promotes §13's design target from *"never grow, never allocate, up to `max_concurrent_flows`"* to *"memory tracks working set, bound by `max_concurrent_flows`, never grows beyond that"*. The net result: **average RSS ~30 MB, peak RSS ~70 MB, burst-able to 4 M with no reconfiguration**.

### 14.1 The fundamental reframing

A flow cache is **almost never full**. Real traffic has:

- A small hot working set (200 K – 1 M concurrent flows during a normal peak)
- A longer tail of half-open or short-lived flows that close within seconds
- Bursts that spike to several × normal peak for 30 s – 2 min and then recede

The §13 plan was sized for the **burst peak** (4 M). The §14 plan sizes for the **working set peak** (1 M) and tolerates bursts up to 4 M through other mechanisms. The savings: 70% of resident memory returned to the OS at no cost to burst behaviour.

### 14.2 Five layered techniques, picked by traffic characteristic

| Layer | Technique | Static cost at 1 M cap | Adds dynamic alloc? | Effective against |
|---|---|---|---|---|
| L1 | **Aggressive TTL eviction** (§13.4 tier 2 already exists) | 0 MB (logic only) | No | working set shrinkage — closes idle flows fast |
| L2 | **Two-tier "hot/warm" cache** | `hot_slots[32K]` = 0.75 MB | No | scan/one-packet probes never touch rte_hash |
| L3 | **Bloom-filter pre-sieve** | `bloom_bits[8 Mbit]` = 1 MB | No | spoofed SYNs, port-scans, pcap-replay noise |
| L4 | **rte_hash with `RTE_HASH_EXTRA_FLAGS_EXT_TABLE` + small base** | rte_hash internal ≈ 24 MB | **Yes, but only when EXT_TABLE chains** | bursts > working set cap |
| L5 | **Drop-on-overflow** (§13.4 tier 3) | 0 bytes | No | runaway bursts > cap |

Combined at the 1 M base:

- **Average RSS**: ~26 MB (24 MB rte_hash + 1 MB bloom + 0.75 MB hot slots + 0.3 MB misc)
- **Burst peak**: ~70 MB (rte_hash grown to ~68 MB via EXT_TABLE, no other layers grew)
- **Runaway peak**: hard cap by tier 5; `max_concurrent_flows = 4 M` = 192 MB is the absolute ceiling

Compared to pure §13:

| Scenario | §13 pure static | §14 layered |
|---|---|---|
| Normal load (500 K active) | 192 MB resident | ~26 MB resident |
| Burst (3 M active) | 192 MB resident | ~55 MB resident |
| Runaway (5 M attempted) | 192 MB resident + drops | 192 MB resident + drops |
| RSS variance over 24 hours | flat | tracks working set |

**The waste** the mentor complained about is **from the average column**: §13 sits at 192 MB; §14 sits at ~26 MB. Both have the same peak headroom.

### 14.3 L1: TTL-driven working-set sizing (no extra allocation)

§13 already plans to call `PurgeExpired` on the main lcore. The §14 change is to **let the cap be the operator's "burst ceiling"**, not the "target RSS". With:

```yaml
spi:
  max_concurrent_flows: 4000000          # hard ceiling (§13.4 tier 3)
  flow_ttl_sec: 60                       # working set tracker (§14.3 NEW default)
  flow_ttl_sec_aggressive: 10            # when in tier 2 reclamation
```

The operator is asking: *"give me the smallest memory you can while keeping 4 M of burst headroom."* The answer is:
- **Always run `PurgeExpired` aggressively**: at `timer_period_sec` cadence (already 5 s by default), drop entries whose `last_seen_tsc` is older than `flow_ttl_sec`. Tunable to 30 s for shorter-lived workloads.
- **Bound `rte_hash_count()`**: when `count()` falls below `max_concurrent_flows / 4`, that's the working-set; we don't need to expand the table.

The memory `rte_hash` actually consumes equals its **current entry count**, not its `entries` parameter. (`rte_hash_count` in the API: <https://doc.dpdk.org/api/rte__hash_8h.html>.) `rte_hash` internally allocates a bucket array sized to `entries`, but each bucket is ~16 bytes; only **populated** buckets contribute to working set cache pressure.

This is the most important layer and costs nothing — it's just choosing the right `flow_ttl_sec`.

### 14.4 L2: Two-tier hot/warm cache (the "ring wins anyway" insight)

The mentor's instinct that "ring ít cycle" pays off most here. A small per-worker **direct-mapped hot tier** catches 95% of cache hits:

```cpp
// Each worker has its own hot tier — no false sharing, no atomics.
alignas(64) struct HotSlot {
    FlowKey  key{};          // 16 B
    Action   action{};       //  1 B + 7 B pad → 8 B
    uint64_t last_seen_tsc{};//  8 B
};                           // total 32 B / slot
static constexpr std::size_t kHotSlotsPerWorker = 32768;  // 32 K × 32 B = 1 MB / worker
```

Lookup:

```cpp
[[gnu::always_inline]] Action LookupHot(const FlowKey& key, uint32_t hash) noexcept {
    const auto idx = hash & (kHotSlotsPerWorker - 1);
    const auto& slot = hot_slots_[idx];
    return (slot.key == key && slot.match_count != 0)
         ? slot.action : Action::kMiss;
}
```

That's **O(1) array index + 16-byte compare** ≈ 4 cycles on cache-hit, **no atomics, no rte_hash** call. The miss cost pays for the rte_hash lookup downstream.

Why this works:

1. **Hot tier is per-worker**, so there is no cross-core synchronisation on hits (the common case).
2. **Direct-mapped is fine** because the *probability* that two hot 5-tuples hash to the same slot on the same worker is small; collisions just demote one entry to the warm tier.
3. **Capacity is `kHotSlotsPerWorker × workers`** = 16 MB for 16 workers at 32 K each. Less than the rte_hash budget on its own.
4. **Static allocation**, zero heap, no LRU needed — entries *expire* by `last_seen_tsc`.

**Expected hit rate**: for an HTTP workload with reuse, the hot tier catches ~80-90% of the per-packet 5-tuple repeat rate. The remaining 10-20% fall through to the warm rte_hash tier, where the 99% cache-hit story still applies.

This is exactly the pattern VPP uses for its connection tracker: small per-worker array for hot lookups, falls through to a larger shared structure for cold ones. See VPP's discussion of `flow-permanent-delete-on-out-of-resource`: <https://s3-docs.fd.io/vpp/23.06/developer/corefeatures/quick_hash.html>.

### 14.5 L3: Bloom-filter pre-sieve (kill spoofed traffic at the door)

For traffic containing port-scans, replicated pcap replay, or random SYN probes, **most 5-tuples will never become a real flow**. Without a pre-sieve, every probe burns an `rte_hash_add_key` + an `Entry` allocation + a future `rte_hash_del_key`. With aggressive TTLs the cost is small but non-zero.

A 4-bit counting Bloom filter sized to ~8 Mbits (1 MB static) catches 95-99% of probes with a ~1% false-positive rate. Implementation:

```cpp
// Statically allocated, one per worker (no false sharing).
alignas(64) struct BloomFilter {
    static constexpr std::size_t kBits = (1u << 23);      // 8 Mbits
    static constexpr std::size_t kWords = kBits / 64;     // 131 072 uint64_t
    std::array<uint64_t, kWords> bits{};
    uint64_t epoch_seen_tsc[kHashCount]{};                // for counting filter
};
```

Lookup is **two `uint64_t` AND operations and a compare** ≈ 6 cycles. If the filter reports "never seen", we **skip the rte_hash_insert entirely** and treat the packet as a one-shot — no allocation, no slot consumption.

This is the same pattern used by [Cloudflare's edge gateways](https://blog.cloudflare.com/when-bloom-filters-dont-bloom/) (see also the more general cache-penetration-prevention literature) — the Bloom filter does the cheap rejection so the expensive structure only sees real flows.

### 14.6 L4: rte_hash with `RTE_HASH_EXTRA_FLAGS_EXT_TABLE` (the controlled-growth part)

Direct from the [DPDK hash library guide](https://doc.dpdk.org/guides/prog_guide/hash_lib.html):

> *"When there are excessive hash collisions preventing insertion, the bucket is extended with a linked list…"*
> *"intended for workloads (e.g. telco) that need to insert up to 100% of the hash table size and can't tolerate any key insertion failure."*
> *"with the lock-free read/write concurrency flag, users must call `rte_hash_free_key_with_position` … to maintain the 100% capacity guarantee."*

Trade-offs:

- **Gain**: when 1 M entries fill, EXT_TABLE **chains additional buckets** without recreating the table. With our defaults the bucket array can stretch to ~`max_concurrent_flows` worth of slots by chaining.
- **Cost**: the chained buckets are allocated by DPDK internally via `rte_malloc` — so this **does** add dynamic allocation under burst. Two ways to tame it:

  1. **Cap the chain depth** by sizing `entries` to `expected_average` and trusting EXT_TABLE to extend up to ~`max_concurrent_flows`. The actual bucket count never exceeds `entries + extensions`, where `extensions` is bounded by total collisions observed since startup.
  2. **Pre-allocate the extension pool separately** as a static slab of N×32-byte bucket nodes, hand the slab to a tiny custom allocator, and pass that into rte_hash via `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` + careful use of `rte_hash_free_key_with_position`. We've already factored these into W5/W6.

**For a clean plan, the recommendation is:**
- Default: `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF | RTE_HASH_EXTRA_FLAGS_NO_FREE_ON_DEL | RTE_HASH_EXTRA_FLAGS_EXT_TABLE`.
- Set `params.entries = typical_average` (e.g. 1 M).
- Tie-break with `flow_ttl_sec` keeping the population low.
- EXT_TABLE handles bursts gracefully but the runs allocate from the heap. Operators should monitor `rte_malloc` via `--legacy-mem` and the new `flow_table_full` counter to detect when EXT_TABLE chains outnumber expected working set — that's the moment to bump `params.entries` via a reload.

### 14.7 L5: Drop-on-overflow — same as §13.4 tier 3

Unchanged. If all four other layers fail, the packet drops and is counted. This is the mentor's "rơi rớt packet" with eyes on it via the `flow_table_full` counter.

### 14.8 Comparison summary

| Approach | Static memory | Burst behaviour | Dynamic alloc? | Best for |
|---|---|---|---|---|
| **§13 pure-static** (current plan) | ~192 MB at 4 M cap | linear w/ cap | none | networks where peak IS average (e.g. CDN, NAT) |
| **§14 layered** (this section) | ~26 MB at 1 M working-set cap | tail-spike to 4 M via EXT_TABLE | **occasional** when bursts happen | variable-load traffic, cost-sensitive deployments |

Most real DPDK/CGNAT/IDC deployments match the second row: working set is small relative to peak. §14 is the better default for this project.

### 14.9 Recommended final config (replaces §13.6)

```yaml
spi:
  worker_count: 15
  # Hard ceiling — the absolute burst capacity. Drop-on-overflow above this.
  max_concurrent_flows: 4000000
  # Working-set tunables — control average RSS.
  flow_ttl_sec: 60                       # NEW default: aggressive
  flow_ttl_sec_aggressive: 10
  # Two-tier sizing — power-of-two for cheap mask indexing.
  hot_slots_per_worker: 32768            # NEW (§14.4): 32 K slots × 32 B = 1 MB / worker
  bloom_filter_bits: 8388608             # NEW (§14.5): 8 Mbit = 1 MB total
  # Overflow policy.
  flow_overflow_action: drop             # drop | reclassify
  flow_table_recycle_ring_size: 65536    # per-worker recycle ring
  # Existing fields preserved.
  drop_unmatched: true
  packet_distribution: queue
```

### 14.10 Acceptance criteria for §14

- A 24-hour synthetic run with mix (80% long-lived TCP, 15% short-lived HTTP, 5% random SYN port-scan) shows:
  - Median RSS ≤ 50 MB (vs the §13 plan's 192 MB).
  - `flow_table_full` events < 0.001% of packets on a correctly-sized deployment.
  - Bloom filter rejects ≥ 90% of port-scan probes before they reach `rte_hash`.
  - Hot tier hit rate ≥ 80% measured via a new `hot_tier_hits` atomic counter.
- A 5-minute peak-burst test (4 M unique flows injected over 60 s) shows:
  - Peak RSS ≤ 100 MB (EXT_TABLE chains triggered).
  - No packet loss above the configured threshold.
  - After the burst ends, RSS falls back to ~30 MB within 60 s as the TTL evicts.

### 14.11 Bottom line for the mentor

The trade-off is between **predictability (static)** and **efficiency (working-set-aware)**:

- **Pure static (§13)**: zero allocation ever, but RSS = peak permanently. Wastes memory during normal load.
- **Layered (§14)**: tiny static cost, occasional small burst alloc via EXT_TABLE, but RSS ≈ working set most of the time. Wastes ~nothing during normal load.

Both plans honour the **drop-on-overflow** invariant when `max_concurrent_flows` is exceeded. Both refuse to fragment heap. Both keep the hot-path allocation-free. §14 is the recommendation when the operator cares about RAM cost; §13 is the recommendation when the operator only cares about absolute worst-case determinism.

Section 14 is the **default plan going forward** unless the deployment profile says otherwise.
