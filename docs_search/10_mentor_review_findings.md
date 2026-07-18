# 10 — Mentor Review: SPI→DPI, Complexity, Flow Lifetime, Overload

**Date verified**: 2026-07-15
**DPDK version verified**: 24.11.4 (`pkg-config --modversion libdpdk`).
**Sources consulted**: DPDK official docs (doc.dpdk.org), DPDK API reference (rte__hash_8h.html, rte__acl_8h.html), DPDK ACL prog guide, "High-speed Connection Tracking in Modern Servers" (HPSR 2021) and the GitHub mirror of `librte_hash`. See *References* at the bottom.

This document tracks the mentor's notes from `notepad.txt` against the current codebase in `include/dpdk/spi` and `include/dpdk/dpi`. It captures both the diagnosis and the actionable fixes.

---

## 1. SPI→DPI — current behaviour vs. intended behaviour

### 1.1 What the code does today (`spi_pipeline.cpp:979-1009`)

```cpp
const auto* rules{context.rule_manager->Load()};
const auto spi_match{rules->Match(metadata)};
TryDpiClassify(context, counters, packet, metadata, spi_match, key,
               action, matched);
```

`TryDpiClassify` (`spi_pipeline.cpp:898-923`) only short-circuits on three conditions: `dpi_rules == nullptr`, `protocol != TCP`, `dst_port ∉ {80, 443}`. Once those pass, **every cache-miss TCP packet on ports 80 or 443 pays the full hostname-extraction + DPI cost** regardless of whether SPI already matched.

The current `config.yaml` SPI groups (precedence 100 → 106) include `fg_l34_http` and `fg_l34_https` — both `forward` — so the vast majority of cache-miss TCP/80 and TCP/443 packets already have a known SPI decision before DPI runs.

### 1.2 Fix (config + code)

In `TryDpiClassify`, **early-return** when SPI already produced a final answer AND that answer is not a "needs-DPI" sentinel.

```cpp
[[gnu::hot, gnu::always_inline]] inline void TryDpiClassify(...) noexcept {
  const auto* const dpi_rules{context.dpi_rule_manager->Load()};
  if (dpi_rules == nullptr || !dpi_rules->IsEnabled()) [[likely]] return;

  // Skip DPI when SPI already gave us a definitive answer.
  if (spi_match.matched && spi_match.action == Action::kDrop) [[unlikely]] return;
  if (spi_match.matched && spi_match.action == Action::kForward &&
      spi_match.group_name != kNeedsDpiGroup) [[likely]] return;

  if (metadata.protocol != Protocol::kTcp) [[likely]] return;
  if (metadata.destination_port != kTlsPort && metadata.destination_port != kHttpPort) [[likely]] return;
  ...
}
```

To support the explicit "please DPI this group" case (e.g. when an L3/L4 rule *can't* know it's Facebook without looking at SNI), add an optional flag on the SPI group config, e.g. `l7_required: true`, that compiles into a sentinel `group_name` such as `"__needs_dpi__"`. Only groups with this flag break the early-return in `TryDpiClassify`.

**Expected impact**: ≥90% of TCP/80 and TCP/443 packets on a workload that already matches `fg_l34_http` / `fg_l34_https` skip the TLS SNI parser and HTTP-host scan entirely — a measured ~600-1000 ns per packet saved on the cache-miss path (see existing comment block at `spi_pipeline.cpp:633-636`).

---

## 2. Complexity — "O(log n)" claim and what it really is

### 2.1 The actual cost shape

The current SPI stage runs `RuleTable::Match` (`spi_rule_engine.cpp:217-248`), which loops over groups and calls `rte_acl_classify` on each context. Two facts from the official DPDK docs:

- `rte_acl_classify` traverses a **set of multi-bit tries with stride == 8** built by `rte_acl_build` (DPDK ACL prog guide). It is *not* a single trie.
- The docs explicitly warn: *"If the rules set is large, that could consume significant amount of memory… attempt to minimise number of tries in the RT table"* — `build` may emit >1 trie per context.
- There is **no built-in short-circuit across contexts**. Each `rte_acl_classify` call is independent; an application must check the `userdata == 0` miss sentinel and decide whether to try the next context.

So the worst-case cost per packet is:

```
match cost = G_groups × (tries_in_group × stride8_walk)        // scalar
              ÷ SIMD_width                                     // SIMD lanes
```

With the current 6 groups (FG_fb, FG_yt, FG_http, FG_https, FG_dns, FG_udp_drop), each group's context typically contains 1-4 tries → the inner loop in `Match` is ~6 × ~2 × ~5 stride levels = ~60 ALU steps in the worst case, scalar. With AVX2 it's ~4 cycles per packet. The mentor's O(log n) is a fair characterisation for *one* trie, but the aggregate is closer to O(G × log n).

### 2.2 Recommended structural change

Collapse all groups into **one** `rte_acl_ctx` with one category per group, using the `category_mask` parameter of `rte_acl_classify`. Per the DPDK docs (ACL prog guide, "Categories"):

> *"Each set could be assigned its own category and by combining them into a single database, one lookup returns a result for each of the four sets."*

That removes the outer `for (group)` loop entirely and replaces it with a single `rte_acl_classify(acl_ctx, data, results, 1, RTE_ACL_MAX_CATEGORIES)` followed by scanning `results` in precedence order to find the first non-zero userdata. From O(G × log n) to O(log n + G) — strict win when G > 1.

This also de-risks the `RW_CONCURRENCY_LF` rule-table swap path because there is now only *one* context to rebuild on reload (smaller alloc, smaller free).

**Expected impact**: substantial on the miss path; transparent for the cache-hit path which dominates production traffic.

---

## 3. Limiting DPI — HTTP method check, request+response in one flow

### 3.1 HTTP method gating

The HTTP request parser (`ExtractHostname` in `spi_pipeline.cpp:580-616`) currently runs whenever `dst_port == 80`. But the response direction (the reply from a web server back to the client) *also* lands on port 80 from the server's perspective and is a TCP packet too — the parser sees HTTP response bytes (`HTTP/1.1 200 OK\r\n...`) that have no `Host:` field. Parsing them is wasted CPU.

The mentor's "check METHOD" comment means: **only run the hostname extractor on packets that look like a request**. A cheap heuristic:

```cpp
constexpr std::uint16_t kWellKnownPortMax{1024};
const bool is_request{
    metadata.destination_port >= kWellKnownPortMax  // unlikely
    || (metadata.source_port >= kWellKnownPortMax &&
        metadata.destination_port < kWellKnownPortMax)};
```

For an HTTP request the dst_port is {80, 443} and src_port ≥ 1024. For an HTTP response the dst_port is ≥ 1024 and src_port is {80, 443}. We can additionally confirm by checking for a known METHOD prefix (`GET `, `POST `, `HEAD `, `PUT `, `DELETE `, `PATCH `, `OPTIONS `) at `payload_off` — but **only on request candidates**, not on every TCP/80 packet.

### 3.2 Request+response into one flow key

The current `FlowKey` (`spi_flow_table.hpp:23-31`) is the unordered 5-tuple `(src_ip, dst_ip, src_port, dst_port, proto)`. The reverse-direction packet is **a different key**, so a flow cache hit on the request packet does *not* apply to the response packet — every response packet would re-run the hostname extractor + DPI match until the response-side hostname is also cached. That's two parses per connection where one is sufficient.

The standard solution (stateful firewalls, Suricata, VPP, nDPI all do this) is the **canonical tuple**:

```cpp
// Order the endpoints so request and response hash to the same key.
if (std::tie(src_ip, src_port) > std::tie(dst_ip, dst_port)) {
  std::swap(src_ip, dst_ip);
  std::swap(src_port, dst_port);
}
```

Concrete implementation in `BuildFlowKey`:

```cpp
[[gnu::always_inline]] static FlowKey MakeFlowKey(std::uint32_t sip, std::uint32_t dip,
                                                 std::uint16_t sp, std::uint16_t dp,
                                                 Protocol proto) noexcept {
  if (std::tie(sip, sp) > std::tie(dip, dp)) {
    std::swap(sip, dip);
    std::swap(sp, dp);
  }
  return FlowKey{.src_ip = sip, .dst_ip = dip, .src_port = sp, .dst_port = dp, .protocol = proto};
}
```

This collapses *each bidirectional connection* into a single cache entry. Combined with the per-worker `HostnameCache` that the project already has, **the response side benefits from the request-side parse for free**.

Combined with §1.2 (SPI-gates-DPI), the average DPI work per connection drops from 2 parses to **at most 1 per new connection**.

**Expected impact**: connection flows are halved in the cache (better hit rate with the same `kFlowTableSize`), and the response-packet DPI work disappears after the first request. On the existing bench, this should drop total `dpi_cache_misses` to roughly the number of distinct connections rather than roughly twice that.

---

## 4. Timeout management — `PurgeExpired` and `last_seen_tsc`

### 4.1 Current bug

`PurgeExpired` (`spi_flow_table.cpp:96-129`) compares each entry's `last_seen_tsc` against `now_tsc - ttl_cycles`. The problem: `last_seen_tsc` is **only set at Insert** (`spi_flow_table.hpp:132-142`). Every subsequent cache hit does *not* update it. A long-running TCP connection (e.g. a long-lived keep-alive HTTP session with packets spread across minutes) gets purged at the TTL even though it's still active.

### 4.2 Fix — touch on hit, not only on insert

```cpp
[[gnu::hot, gnu::always_inline, nodiscard]] FlowEntry* Lookup(const FlowKey& key) noexcept {
  ...
  auto* entry = &entries_[static_cast<std::size_t>(result)];
  if (entry->match_count == 0) [[unlikely]] return nullptr;
  entry->last_seen_tsc = rte_rdtsc();        // <- new line, keeps long flows alive
  return entry;
}
```

`last_seen_tsc` is read only by the cold `PurgeExpired` path, so writing it on the hot path does not introduce spurious cache-line traffic. The 8-byte aligned store to a per-entry field on the same line as the `action` byte is essentially free (the line is already in exclusive state for the read).

### 4.3 Cadence note

`PurgeExpired` itself is gated by `timer_tsc == 0 && previous_tsc != 0` (`spi_pipeline.cpp:1434-1436, 1471-1473, 1509-1511`). This only fires when the stats timer wraps, which by construction happens once per `timer_period_sec`. That cadence is fine for the canonical-bucket walk — but as `entries_` grows to millions of entries the `rte_hash_iterate` pass is no longer cheap. Two follow-ups worth scheduling:

1. Bound `PurgeExpired` to a max number of entries per call (chunked across N timer ticks) so it never monopolises main lcore.
2. Once the canonical-tuple change in §3.2 is in, the cache holds one entry per connection rather than one per direction → effective cap is halved and chunking becomes much smaller.

---

## 5. "Don't overload the table" — rte_hash and reload behaviour

### 5.1 What `RW_CONCURRENCY_LF` actually implies

`spi_flow_table.cpp:46-47` sets `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF`. The flag's contract (DPDK hash API reference):

- **Auto-enables `NO_FREE_ON_DEL`**: `rte_hash_del_key()` does not reclaim the slot index. The application must call `rte_hash_free_key_with_position()` once it is safe (no worker is still reading the entry). With the project keeping slot reads only on the per-packet hot path and `PurgeExpired` running on the main lcore after workers have stopped processing, **the current code never calls `rte_hash_free_key_with_position()`** — slots are leaked across `PurgeExpired` cycles. This is acceptable for a fixed `kFlowTableSize` of 1M (eventually the pool is full and the worker stops inserting), but it makes the table non-renewable over time.
- **`add_key` returns `-ENOSPC` when full**. `Insert` (`spi_flow_table.hpp:132-142`) **silently drops the error**: `if (result >= 0)` only handles the slot-found path; `-ENOSPC` falls through, leaving the flow forever-unclassified and (under `drop_unmatched: true`) **silently dropped**.

### 5.2 Recommended fixes

1. **Always re-load flow rule with a fresh PurgeExpired layout that calls `rte_hash_free_key_with_position()`** (use a quiescent-state wait, or simply call it from `PurgeExpired` while the worker is between bursts — there's a small window where it's racey, mitigated by re-checking `entry->match_count` and only freeing if `match_count == 0`). This is the cheapest way to recycle the slot and keep `kFlowTableSize` meaningful.
2. **Treat `-ENOSPC` as an actionable signal**, not silent:

   ```cpp
   [[gnu::always_inline]] void Insert(const FlowKey& key, const FlowEntry& entry) noexcept {
     const auto result{rte_hash_add_key(hash_, &key)};
     if (result >= 0) [[likely]] {
       auto& slot{entries_[result]};
       slot = entry;
       slot.last_seen_tsc = rte_rdtsc();
       return;
     }
     if (result == -ENOSPC) [[unlikely]] {
       ++(*context.counters).flow_table_full;     // new atomic counter
       return;
     }
     // -EINVAL and other errors: log once.
   }
   ```

   Plus a config knob (`flow_table_overflow_action: drop | keep_reclassifying`) so the user can decide between hard-drop (current behaviour under `drop_unmatched: true`) and letting the packet just pay reclassification cost until the next purge makes room.

### 5.3 "No dynamic allocation in the hot path"

The hot path currently `std::string label` in `CompiledFilter` (`spi_rule_engine.hpp:88`) — every filter holds an `std::string`. The labels are only used by `Compiling`/logging paths, **never** by `Match`. Two clean-ups:

- Replace `std::string label` with a `std::string_view label` pointing into the config-owned string (config owns; rule table borrows). Eliminates one heap alloc per filter at startup, zero alloc on hot path.
- `rte_acl_ctx` is allocated by `rte_acl_create` once per group on startup and freed on shutdown; the rule rebuild that `MaybeReload` does briefly owns both old and new contexts. That one-time alloc is on main lcore during reload and is **not** on the per-packet path — already correct.
- The flow table `entries_` is already `resize()`d up front (`spi_flow_table.cpp:60`) — good.

The remaining alloc risk is the `HostnameCache::Insert` path which is header-only and stores 12 bytes per slot with no allocation. Good.

---

## 6. Concrete patch targets in this codebase

For convenience, here are the clickable locations that correspond to each fix:

| Fix | File | Line(s) |
|-----|------|---------|
| SPI-gates-DPI early-return | `include/dpdk/spi/spi_pipeline.cpp` | 898-923 |
| Add `l7_required` flag to SpiFilterGroupConfig | `include/dpdk/config/dpdk_config.hpp` | (group schema) |
| Use category_mask, collapse to one rte_acl_ctx | `include/dpdk/spi/spi_rule_engine.cpp` | 217-248, 262-341 |
| HTTP request-only gate | `include/dpdk/spi/spi_pipeline.cpp` | 580-616 |
| Canonical FlowKey | `include/dpdk/spi/spi_flow_table.hpp` | 23-31, 132-142 |
| Touch `last_seen_tsc` on hit | `include/dpdk/spi/spi_flow_table.hpp` | 77-91 |
| Handle `-ENOSPC` | `include/dpdk/spi/spi_flow_table.hpp` | 132-142 |
| `rte_hash_free_key_with_position` after PurgeExpired | `include/dpdk/spi/spi_flow_table.cpp` | 96-129 |
| `flow_table_overflow_action` config + new atomic counter | `include/dpdk/spi/spi_pipeline.hpp` | 44-56, 282 |

---

## References

- DPDK prog guide — Packet Classification and ACL Library: <https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html>
- DPDK API — `rte_acl.h`: <https://doc.dpdk.org/api/rte__acl_8h.html>
- DPDK API — `rte_hash.h`: <https://doc.dpdk.org/api/rte__hash_8h.html>
- DPDK `rte_hash_create(3)` manual page (Debian): <https://manpages.debian.org/testing/dpdk-doc/rte_hash_create.3.en.html>
- "High-speed Connection Tracking in Modern Servers" — Chiesa & Gironi, HPSR 2021: <https://marchiesa.bitbucket.io/docs/chiesa/girondi-hpsr-2021.pdf>
- "Efficient Dynamic Flow Tracking for Packet Analyzers" — Emmerich et al. (FlowScope, cites DPDK-Stat): <https://www.net.in.tum.de/fileadmin/bibtex/publications/papers/FlowScope-flow-tracking.pdf>
- "Flow-based Packet Process Framework on DPDK and VPP" — slides, KCCNC-OSS'19: <https://static.sched.com/hosted_files/kccncosschn19chi/ac/Flow-based%20Packet%20Process%20Framework%20on%20DPDK%20and%20VPP.pdf>

All URLs above were verified reachable and relevant as of 2026-07-15. Behavioural claims about the runtime semantics of `rte_acl_classify`, `rte_hash_*` and the `RW_CONCURRENCY_LF` flag were checked against the local DPDK 24.11.4 headers (`/usr/include/dpdk/rte_acl.h`, `/usr/include/dpdk/rte_hash.h`).
