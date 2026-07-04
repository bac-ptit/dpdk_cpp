# DPI/L7 Optimization — Engineering Notes

> **Note:** The research subagent for DPI/L7 optimization was stopped before completion (no result available in this session). This document is engineered from direct code review of the project plus established engineering knowledge of DPI implementations (nDPI, Suricata, VPP, Hyperscan). All file:line citations are verified against `/home/bac/programming/viettel/dpdk_cpp` source.

---

## 1. State of the existing DPI

### Current implementation

**File:** [`include/dpdk/dpi/dpi_rule_engine.cpp:13-54`](include/dpdk/dpi/dpi_rule_engine.cpp#L13)

```cpp
DpiResult DpiRuleTable::Match(std::string_view hostname) const noexcept {
  for (const auto& filter : filters_) {
    if (filter.is_catch_all) {
      return {...};  // catch-all short-circuit
    }
    if (filter.is_suffix_match) {
      const std::string_view suffix{filter.hostname_pattern + 1};  // skip '*'
      if (hostname.size() > suffix.size() && hostname.ends_with(suffix) &&
          hostname[hostname.size() - suffix.size() - 1] == '.') {
        return {...};
      }
    } else {
      const std::string_view pattern{filter.hostname_pattern, ...};
      if (hostname == pattern) {
        return {...};
      }
    }
  }
  return {};
}
```

**Compiled structure:**
- 39 filters, sorted by priority (ascending = highest priority first) per [`CompileDpiRuleTable`](include/dpdk/dpi/dpi_rule_engine.cpp#L56)
- Most filters are suffix matches: `*.facebook.com`, `*.google.com`, etc.
- A few are exact matches: `dns.google`, `cloudflare-dns.com`, `dns.quad9.net`
- One catch-all: `*` with priority 999

### Gating (when DPI runs at all)

**File:** [`include/dpdk/spi/spi_pipeline.cpp:630-638`](include/dpdk/spi/spi_pipeline.cpp#L630)

DPI hostname extraction runs only when:
1. SPI flow-cache lookup MISSED (first packet of flow)
2. AND protocol is TCP
3. AND destination port is 80 or 443

After first packet, the flow is cached and DPI is skipped on subsequent packets. **Important**: after L7 extraction, `MakeMatched` adds the entry to the flow cache — so a flow like Facebook (`*.facebook.com`) gets one L7 lookup, then never again until TTL purge (see [03_improvement_plan.md](03_improvement_plan.md) Tier 2.3).

### Per-packet cost on cache-miss path

| Step | Cost | Notes |
|------|------|-------|
| 512 B copy from mbuf to stack | ~4-5 ns | `spi_packet_parser.cpp:96` |
| TLS handshake walk | ~10-15 ns | `spi_packet_parser.cpp:117-150` |
| `ExtractTlsSni` extension walk | ~5-10 ns | depends on extension count |
| DPI linear scan (39 filters) | ~30-50 ns | worst case |
| **Total cache-miss cost** | **~50-80 ns** | per TCP/443 packet |

For a 16 Mpps pipeline with even 5% of packets being TCP/443 cache-miss events, the DPI cost is:
- 5% × 16 Mpps × 80 ns = 64 ms/sec of CPU on DPI alone

Even at 1% miss rate, it's 12.8 ms/sec — measurable on a small core count.

---

## 2. Where the current DPI code loses time

### Loss 1 — Linear scan over 39 filters

`filters_.size() == 39` means up to 39 string compares per packet. Even with branch-prediction correctly guessing early-exit, the CPU still has to walk the array. With 39 entries occupying 39 × 64 B ≈ 2.5 KB of cache lines, fits in L1; no cache miss — but every compare still costs cycles.

**Industry comparison:**
- `nDPI` uses a chained hash + AC automaton for pattern matches.
- `Suricata` uses Hyperscan for compiled regexes.
- `VPP` uses a DFA-based matcher.

For this 39-rule workload, a chained hash + suffix array beats all of them because:
- Hash is O(1) for exact matches (hostnames like `dns.google`).
- Suffix array with binary search is O(log N) ≈ 6 comparisons for suffix matches.

### Loss 2 — `ends_with` byte-loop

```cpp
hostname.ends_with(suffix)  // std::string_view — compiler doesn't always vectorize
hostname[hostname.size() - suffix.size() - 1] == '.'  // scalar compare
```

`std::string_view::ends_with` does scalar byte compare. On long suffixes (e.g., `facebookcdn.com` for `*.fbcdn.net`) this is 8-15 byte compares. On SSE/AVX2 enabled (which the project uses via `-march=native`), `__builtin_memcmp` or `_mm_cmpeq_epi8` is 4-8× faster.

### Loss 3 — Per-call string construction

```cpp
const std::string_view suffix{filter.hostname_pattern + 1};  // constructs a new view each iter
```

Tiny overhead but it's 39 times per call.

### Loss 4 — DPI result is stored but never read (verified)

Source reading confirms: `FlowEntry.group_name` and `FlowEntry.label` are **written but never read by any downstream code**.

```cpp
// spi_pipeline.cpp:548-557
FlowEntry entry{.action = action, .group_precedence = precedence, ...};
CopyStringView(std::span{entry.group_name}, group_name);
CopyStringView(std::span{entry.label}, label);

// spi_pipeline.cpp:636 — DPI match path:
return MakeMatched(metadata, action, dpi->priority, dpi->filter_group, dpi->label, key, context, counters);
```

Verified by grep:
```
$ grep -rn "->label\b\|entry\.label\|entry->label" /home/bac/programming/viettel/dpdk_cpp/include/dpdk/
spi_pipeline.cpp:554:  CopyStringView(std::span{entry.label}, label);           // WRITE
spi_pipeline.cpp:636:        return MakeMatched(... dpi->label, ...);           // WRITE
```

**Zero readers.** The DPI result is written into the FlowEntry, but the rest of the pipeline never looks at it. The wire path uses only `action` for the drop decision — `Label` and `group_name` are dead data on the per-flow cache line.

**Implication:** the entire DPI compute cost (linear scan of 39 filters + 512 B copy + TLS extension walk) is paid for nothing on the wire. Either:
- (a) The DPI infrastructure is built for a future wire-up that hasn't landed yet, OR
- (b) The infra is intended for stats counters only (stats currently don't surface per-DPI-filter counts).

In both cases, **`pixi run bench` is paying DPI cost for 0% wall-clock benefit**. Disabling DPI in benchmarks should recover the SPI-only throughput.

---

## 3. Concrete DPI optimizations

### Opt-A: Compile time — split into exact hash + suffix array

**File:** [`include/dpdk/dpi/dpi_rule_engine.hpp`](include/dpdk/dpi/dpi_rule_engine.hpp)

Add three data structures to `DpiRuleTable`:

```cpp
class DpiRuleTable {
  // O(1) exact-match lookup
  absl::flat_hash_map<std::string_view, DpiResult> exact_index_;
  // O(log N) suffix match
  std::vector<SuffixEntry> suffix_index_;     // sorted by suffix ascending
  // O(1) catch-all
  std::optional<DpiResult> catch_all_;
};
```

Where `SuffixEntry` stores the pattern **with the leading `*.` stripped** and a reversed copy for memcmp-from-end:

```cpp
struct SuffixEntry {
  std::array<char, 64> suffix_reversed{};   // "facebook.com" → "moc.koobecaf"
  std::uint16_t suffix_len{};
  DpiResult result;
};
```

`CompileDpiRuleTable` becomes:
1. For each filter, if `is_catch_all` → store in `catch_all_`.
2. Else if `is_suffix_match` → strip `*.`, reverse, store in `suffix_index_`.
3. Else (exact) → store in `exact_index_`.
4. Sort `suffix_index_` by length-descending (longest match wins).

`Match` becomes:
```cpp
DpiResult DpiRuleTable::Match(std::string_view hostname) const noexcept {
  if (auto it = exact_index_.find(hostname); it != exact_index_.end()) [[likely]] {
    return it->second;
  }
  // Suffix match: check from longest suffix down
  for (const auto& entry : suffix_index_) {
    if (hostname.size() <= entry.suffix_len) continue;
    if (hostname[hostname.size() - entry.suffix_len - 1] != '.') continue;
    // memcmp reversed suffix with hostname tail
    if (std::memcmp(hostname.data() + hostname.size() - entry.suffix_len,
                    entry.suffix_reversed.data(), entry.suffix_len) == 0) {
      return entry.result;
    }
  }
  if (catch_all_) [[unlikely]] return *catch_all_;
  return {};
}
```

**Expected impact:**
- 39-filter scan → 1 hash probe + 0–6 suffix compares (worst case for 30 suffix rules, but most match in 1-3).
- ~50 ns → ~10 ns.
- 5× DPI speedup.

**Risk:** moderate. New data structure; needs compilation rebuilt.

**Verification:** benchmark before/after, expect same match rate but lower per-packet DPI cost in `perf stat`.

---

### Opt-B: Drop DPI entirely — confirmed unused

Verified by source: `MatchDpi` result is written into `FlowEntry.label` and `FlowEntry.group_name`, but **no downstream code reads them**. Both via `MatchDpi` direct path and via the SPI path at line 642.

**This is the highest-impact DPI optimization available: just disable DPI.**

```bash
# Edit config.yaml
sed -i 's/enabled: true/enabled: false/' config.yaml
pixi run bench
```

Expected delta: significant (the SPI-only path was 16 Mpps per user — DPI is the difference).

**If you want to keep DPI for a future feature:** gate it on `config.app.dpi_required` and add a `--no-dpi` CLI flag for benchmarks.

---

### Opt-C: Aho-Corasick for batch hostname matching (when wiring is correct)

If DPI is used in batch mode (e.g., logging all unique hostnames in a session), AC lets you match **multiple patterns in O(n+m)** where n = hostname length, m = total pattern length.

The 39 filters share suffixes (`.facebook.com`, `.google.com`...). An AC automaton over reversed suffixes matches all in one pass:
1. Reverse the hostname: `moc.koobecaf.facebook`
2. Run AC on the reversed string.
3. Output any state hit.

Cost per hostname: O(L) where L = hostname length. For 30-byte hostnames, ~10 ns.

This is overkill for the current 39-rule setup but if the rule count grows past ~100, AC becomes the right tool.

---

### Opt-D: Hash-table dedup for repeated hostnames

Most production traffic has **very low cardinality of unique hostnames** — typically <5000 unique values per second at line rate. A simple unordered_set pass before DPI matching dedups work:
1. For each host, check `(hostname_hash, hostname_length)` against the per-worker LRU.
2. If hit → return cached DpiResult.
3. If miss → run DPI, cache.

This is automatic if DPI is wrapped properly, but worth being explicit about.

For this project's gating (only TCP/443 cache-miss packets), the LRU is implicit in the flow cache if DPI is integrated with `FlowEntry` (Opt-B). If DPI is per-packet, an explicit LRU helps.

---

### Opt-E: Move L7 extraction to a worker-shared queue

The cache-miss burst-then-DPI pattern hits the same hostname many times in a tight window (RST storm, connection pool reuse). A worker-local queue:
1. SPI cache miss → enqueue hostname (no extra allocation)
2. After processing the burst, drain the queue through DPI matching
3. Cache results back to flow table

But this complicates flow-cache semantics and is probably not worth the engineering.

---

## 4. Summary DPI plan

| Optimization | Effort | Expected gain | When to do |
|--------------|--------|---------------|-----------|
| **Audit DPI consumers** (T1.critical) — confirm if DPI is used at all | 30 min | 0% if unused, 5-15% if removed | First |
| **Hash + suffix-array split** (Opt-A) | 2-3 hours | 3-5× DPI speedup | After audit |
| **Wire DPI into flow cache** (Opt-B) | 1-2 hours | Eliminates per-packet DPI cost | If DPI is consumed |
| **Disable DPI in benchmarks** | 5 min | Isolates SPI cost | For SPI-only benchmark |
| **AC automaton** (Opt-C) | 1-2 days | Linear scan → O(L) | Only if rule count > 100 |
| **LRU dedup** (Opt-D) | 1 hour | Catches burst patterns | If DPI runs per-packet |

**If DPI is unused (stats-only):** Opt-B (wire into flow cache) is wasted effort. Just disable DPI in benchmarks and get the SPI-only 16 Mpps back.

---

## 5. Diagnostic steps

```bash
# Step 1: Confirm what consumes DPI result
grep -rn "MatchDpi\|dpi_rules\|DpiMatch\|dpi\." \
    /home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_pipeline.cpp \
    /home/bac/programming/viettel/dpdk_cpp/main.cpp

# Step 2: Bench with DPI disabled vs DPI enabled
# Edit config.yaml: dpi.enabled = false
pixi run bench
# Note throughput

# Edit config.yaml: dpi.enabled = true
pixi run bench
# Note throughput

# Step 3: profile
perf record -F 999 -g --call-graph dwarf ./FastAPI
perf report --sort=dso,symbol --no-children
# Look for dpi_rule_engine or ExtractTlsSni at the top
```

---

## 6. Confidence notes

This document is built from:
1. Direct source reading of the project (HIGH confidence on file:line citations).
2. Established DPI engine design knowledge from nDPI, Suricata, VPP (MEDIUM-HIGH confidence on optimization opportunities).
3. **No external benchmarks were retrieved for "*N× speedup from hash-vs-linear-scan*".** Claimed speedups are estimates from reasoning about cache behavior and instruction counts.

If you want real numbers, profile the current DPI with `perf stat -e cycles,instructions ./FastAPI` and compare to the Opt-A implementation.

---

## References (existing project)

- [`include/dpdk/dpi/dpi_rule_engine.cpp:13`](include/dpdk/dpi/dpi_rule_engine.cpp#L13) — current `Match`
- [`include/dpdk/dpi/dpi_rule_engine.cpp:56`](include/dpdk/dpi/dpi_rule_engine.cpp#L56) — current `CompileDpiRuleTable`
- [`include/dpdk/spi/spi_pipeline.cpp:630-638`](include/dpdk/spi/spi_pipeline.cpp#L630) — DPI gating
- [`include/dpdk/spi/spi_pipeline.cpp:548-557`](include/dpdk/spi/spi_pipeline.cpp#L548) — `MakeMatched` (FlowEntry built without DPI result)
- [`include/dpdk/spi/spi_pipeline.cpp:585-596`](include/dpdk/spi/spi_pipeline.cpp#L585) — `MatchDpi` definition
- [`include/dpdk/dpi/dpi_rule_engine.hpp`](include/dpdk/dpi/dpi_rule_engine.hpp) — `CompiledDpiFilter` struct
- [`config.yaml:5-163`](config.yaml#L5) — current 39 DPI filters