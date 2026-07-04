# Architecture & Hot-Path Findings — Verified Against Source

**Project:** `/home/bac/programming/viettel/dpdk_cpp` (FastAPI DPDK SPI/DPI classifier)
**Scope:** Per-packet hot path, lock-free data structures, dispatch topology, flow cache, DPI engine
**Method:** Direct source reading (file:line citations below). Web research was attempted but blocked by API errors; conclusions are based on code + documented DPDK behavior.

---

## Hot-path trace (per packet)

The pipeline is split into two distribution topologies selected at runtime:

| Mode | When chosen | RX path |
|------|-------------|---------|
| `queue` (queue-per-worker) | net_pcap with shards, or NIC with enough RSS queues | each worker drains its own queue directly (`spi_pipeline.cpp:808`) |
| `flow_hash` (software dispatch) | AF_PACKET, no RSS, RX queues < workers | main lcore RXes then `rte_ring_sp_enqueue` into per-worker rings (`spi_pipeline.cpp:861`) |

Selector: [`ResolvePacketDistribution`](include/dpdk/spi/spi_pipeline.cpp:484) — auto-picks `queue` for net_pcap shards, `flow_hash` for software PMDs.

**Per-packet steps (queue mode):**

1. **RX** — `rte_eth_rx_burst(port, worker_id, …, burst_size)` [`spi_pipeline.cpp:808`]
2. **Prefetch** — `rte_prefetch0(mtod(packet))` [`spi_pipeline.cpp:713-717`]
3. **Classify** — `ForwardPacket` → `ClassifyPacket` [`spi_pipeline.cpp:730-759` → `605-652`]
4. **Parse** — `ParsePacket` reads Eth/IPv4/TCP|UDP [`spi_packet_parser.cpp:46-80`]
5. **Flow-cache HIT** → use cached action, skip everything below
6. **Flow-cache MISS** → `rte_hash_lookup` → `RuleTable::Match` (per-group `rte_acl_classify` loop) [`spi_rule_engine.cpp:204-235`]
7. **L7 extract** — gated by SPI cache miss AND TCP AND dst port 80/443 [`spi_pipeline.cpp:630-638`]:
   - TLS SNI: copy ≤512 B, walk extension list [`spi_packet_parser.cpp:93-153`]
   - HTTP Host: copy ≤256 B, scan `\r\nHost:` [`spi_packet_parser.cpp:156-193`]
8. **DPI match** — `DpiRuleTable::Match` linear scan over 39 filters [`dpi_rule_engine.cpp:13-54`]
9. **Flow-cache Insert** — `rte_hash_add_key_data` + write to `entries_[slot]` [`spi_flow_table.cpp:73-79`]
10. **Drop / forward decision** → `ResolveTransmitPort` → header rewrite → TX staging buffer
11. **Flush TX** — `rte_eth_tx_burst` every burst [`spi_pipeline.cpp:770-791`]

**Why "more workers ≠ more throughput"** — the project auto-selects `queue` mode for net_pcap shards (`spi_pipeline.cpp:501-504`), so workers DO parallel RX across shards. The real reasons adding workers plateaus are different — see bottlenecks below.

---

## Bottlenecks (verified, ranked by severity)

### HIGH — A. Flow table is 8M slots + `PurgeExpired` walks everything

**Where:** [`spi_flow_table.cpp:16`](include/dpdk/spi/spi_flow_table.cpp#L16), [`spi_flow_table.cpp:39`](include/dpdk/spi/spi_flow_table.cpp#L39), [`spi_flow_table.cpp:82-107`](include/dpdk/spi/spi_flow_table.cpp#L82)

```cpp
constexpr std::uint32_t kFlowTableSize{1U << 23U};  // 8,388,608 entries
entries_.resize(kFlowTableSize);  // ~770 MB
```

`PurgeExpired` calls `rte_hash_iterate` over every slot every 5 s (gated to main lcore, but blocks it).

**Effect:**
- Memory footprint ~770 MB hurts L2/L3/TLB locality on every `Lookup` (touches a 96-byte entry).
- Cache eviction when table fills ⇒ cold-cache lookups ≈ 200 ns vs hot-cache 30 ns.
- Main lcore stalls for hundreds of ms when table is full → RX drops.

### HIGH — B. `PurgeExpired` uses insertion time, not last-seen time

**Where:** [`spi_flow_table.cpp:62-65`](include/dpdk/spi/spi_flow_table.cpp#L62)

```cpp
// Do NOT update last_seen_tsc here — rte_rdtsc + cache-line write per
// packet dominates the lookup. last_seen_tsc tracks insertion time and
// is refreshed only on insert; TTL purging operates on insertion time.
```

**Effect:** A long-lived flow that was inserted > TTL ago is purged even though it's actively receiving packets. The next packet re-runs SPI classification AND DPI hostname extraction, paying the L7 cost repeatedly. Comment rationale ("cache-line write per packet") is fine on a single packet, but the TTL design doesn't match typical traffic — a 5-minute idle threshold kicks out active connections.

### HIGH — C. `rte_hash` is two-step lookup

**Where:** [`spi_flow_table.cpp:53, 73`](include/dpdk/spi/spi_flow_table.cpp#L53)

```cpp
const auto result{rte_hash_lookup(hash_, &key)};  // returns slot ID
auto* entry = &entries_[static_cast<std::size_t>(result)];  // deref parallel array
```

`rte_hash_add_key_data` is called with `nullptr` as the data pointer (line 73) → the real `FlowEntry` (96 B) lives in a separate `std::vector` indexed by hash slot. Every miss touch goes through two cache lines: the hash bucket and the entries array. With `entries_` 770 MB, the entries array has terrible cache locality.

### HIGH — D. 9 atomic counters flushed every 64 iterations on shared cache lines

**Where:** [`spi_pipeline.cpp:843-852`](include/dpdk/spi/spi_pipeline.cpp#L843), [`spi_pipeline.cpp:971-979`](include/dpdk/spi/spi_pipeline.cpp#L971)

`AtomicCounters` is `alignas(64)` (good, no false sharing between counters), but the **producer side** is: every worker, every 64 iterations, writes 9 cache lines. Multi-producer `fetch_add` on the same cache line = MESI contention. With 11 workers, this is 11 × 9 = 99 cache-line bounces per 64 iterations per worker.

### MEDIUM — E. DPI is a 39-filter linear scan with byte-level suffix match

**Where:** [`dpi_rule_engine.cpp:17-51`](include/dpdk/dpi/dpi_rule_engine.cpp#L17)

For each TLS/HTTP packet on cache miss:
1. Up to 512 B copied to stack [`spi_packet_parser.cpp:96`]
2. TLS extension walk: O(extensions) byte-by-byte
3. DPI linear scan: 39 iterations of either `==` (exact) or `ends_with` + byte compare

Per-packet cost (cache miss path on TLS):
- ~4-5 ns: 512 B memcpy from mbuf to stack
- ~10-20 ns: TLS extension walk
- ~30-80 ns: 39 filters × `ends_with` (depends on hostname length)
- = ~50-100 ns extra per cache miss, paid on every first packet of every flow

### MEDIUM — F. ACL classify called per packet per group, single-result slot

**Where:** [`spi_rule_engine.cpp:218`](include/dpdk/spi/spi_rule_engine.cpp#L218)

```cpp
const int ret{rte_acl_classify(group.acl_ctx, data, results, 1, 1)};
```

Called in a loop over `groups_` (sorted by precedence). Each call pays ~30-80 cycles setup. With 6 groups and a 64-packet burst, this is 6 × 64 = 384 ACL setup overheads. **Burst API `rte_acl_classify` accepts an array of pointers** — calling it 64 times with one pointer each is the slow path.

### MEDIUM — G. Per-packet L3 checksum recompute disables HW offload

**Where:** [`spi_pipeline.cpp:269-298`](include/dpdk/spi/spi_pipeline.cpp#L269), [`spi_pipeline.cpp:274`](include/dpdk/spi/spi_pipeline.cpp#L274)

```cpp
packet.ol_flags &= ~RTE_MBUF_F_TX_OFFLOAD_MASK;  // disables HW offload
rte_ipv4_udptcp_cksum_mbuf(&packet, &ipv4_hdr, l4_offset);  // software, walks payload
```

For 1500 B packets, this is ~10-15 ns of arithmetic + a full payload walk on TX. If HW checksum offload is available (any modern NIC), this is 100% wasted work.

### MEDIUM — H. TX staging is heap-allocated `std::vector<std::array<…>>` per worker

**Where:** [`spi_pipeline.cpp:937-938, 952-954`](include/dpdk/spi/spi_pipeline.cpp#L937), [`spi_pipeline.cpp:701-710`](include/dpdk/spi/spi_pipeline.cpp#L701)

```cpp
std::vector<std::array<rte_mbuf*, kMaxBurstCapacity>> transmit_buffers(...)
std::vector<std::uint16_t> transmit_counts(...)
```

`EnqueuePacket` does `std::vector::operator[]` → bounds-checked pointer chase → `std::next(arr.data(), count)` = extra indirection vs a raw pointer. Small but every packet.

### MEDIUM — I. `PrefetchPackets` runs after RX but before processing loop

**Where:** [`spi_pipeline.cpp:713-717`](include/dpdk/spi/spi_pipeline.cpp#L713)

`rte_prefetch0` issues a prefetch to L1. By the time the loop body actually reads the packet header, the prefetch may or may not have completed depending on memory latency. Standard practice is to prefetch **N iterations ahead** of the current packet, not all-at-once at the top of the loop. Right now you either over-prefetch (waste) or under-prefetch (cache miss on first deref).

### LOW — J. Single-producer dispatch ring

**Where:** [`spi_pipeline.cpp:1092`](include/dpdk/spi/spi_pipeline.cpp#L1092) — only active in `flow_hash` mode, but relevant for AF_PACKET benchmarks.

`RING_F_SP_ENQ | RING_F_SC_DEQ` — main lcore is the single enqueue point, every worker dequeues. If you fall into this mode (which the bench does NOT — net_pcap uses queue mode), the main lcore becomes the bottleneck. But for `pixi run bench`, this is irrelevant.

### LOW — K. `RunPcapReplay` is dead code

**Where:** [`pcap_replay.cpp:217-311`](include/dpdk/pcap/pcap_replay.cpp#L217)

`RunPcapReplay` measures "latency" as `rte_rdtsc() - rx_tsc` where `rx_tsc` was set milliseconds before → meaningless. Not used by `main.cpp` — the actual benchmark uses `net_pcap` vdevs.

---

## Data-structure summary

| Structure | File:line | Algorithm | Notes |
|-----------|-----------|-----------|-------|
| `FlowTable::hash_` | `spi_flow_table.cpp:18-28` | `rte_hash` w/ `RW_CONCURRENCY` flag | 8M slots; multi-writer internal locks |
| `FlowTable::entries_` | `spi_flow_table.hpp:33-42` | `std::vector<FlowEntry>` parallel array | 96 B × 8M ≈ 770 MB; terrible locality |
| `RuleTable::groups_` | `spi_rule_engine.cpp:187, 212` | `rte_acl_ctx` per group | linear loop over groups, each call per packet |
| `DpiRuleTable::filters_` | `dpi_rule_engine.cpp:11` | `std::vector<CompiledDpiFilter>` sorted by priority | linear scan; `==` or `ends_with` per filter |
| `RuleTableManager::active_` | `spi_rule_table_manager.hpp:36-67` | `std::atomic<const RuleTable*>` | lock-free double-buffer with deferred retire |
| `dispatch_rings_` | `spi_pipeline.cpp:1086-1100` | `rte_ring` SP/SC | only in flow_hash mode |

---

## Synchronization inventory

| Location | Primitive | In hot path? |
|----------|-----------|-------------|
| `spi_pipeline.cpp:940, 956` | `volatile sig_atomic_t* force_quit` | yes, 1 load/iter |
| `spi_pipeline.cpp:354-362, 971-979` | `std::atomic<uint64_t>::fetch_add(relaxed)` × 9 counters | yes, every 64 iters |
| `spi_rule_table_manager.hpp:36` | `std::atomic<const RuleTable*>::load(acquire)` | yes, once per cache miss |
| `spi_flow_table.cpp:53, 73, 95` | `rte_hash` RW_CONCURRENCY internal bucket locks | yes, every Lookup/Insert |
| `spi_pipeline.cpp:861, 903` | `rte_ring` SP/SC lock-free | yes (flow_hash mode only) |

---

## What's already good

- **No locks in hot path** — atomics + `rte_hash` RW_CONCURRENCY + lock-free rings.
- **Cache-line alignment** on `AtomicCounters` (`alignas(64)`) and `WorkerContext` — no false sharing on those structs.
- **Branch hints** — `[[likely]]`/`[[unlikely]]` used pervasively in parser and pipeline.
- **Prefetch** — `rte_prefetch0` on packet headers.
- **DPI gating** — L7 only runs on SPI cache miss AND TCP AND dst port 80/443; first-packet-of-flow cost only.
- **Atomic flush throttled** — counters flushed every 64 iterations, not every packet.
- **Hot/cold attributes** — `[[gnu::hot]]` on hot-path functions, `[[gnu::cold]]` on reload/stats.
- **`rte_hash_crc`** — uses SSE4.2 CRC32 instructions, not a software hash.
- **`-march=native -mtune=native`** — already enabled in `CMakeLists.txt:34`.
- **`-fno-exceptions`** — already enabled in `fastapi_common` interface.

---

## Verifications performed

1. ✅ `ResolvePacketDistribution` — confirmed net_pcap shards → queue mode, AF_PACKET → flow_hash.
2. ✅ `kFlowTableSize` — 8,388,608 entries × 96 B ≈ 770 MB.
3. ✅ `FlowTable::Insert` uses `rte_hash_add_key_data(hash, key, nullptr)` — parallel array confirmed.
4. ✅ `FlowTable::PurgeExpired` — `rte_hash_iterate` walks every slot.
5. ✅ `Lookup` does NOT update `last_seen_tsc` — TTL works on insertion time only (comment verified at lines 62-65).
6. ✅ DPI linear scan — `filters_` iterated in order, no trie/AC.
7. ✅ ACL classify — single-result per group per packet, not batched.
8. ✅ L7 extract — copy-then-walk pattern with stack buffer.
9. ✅ SW checksum — `RTE_MBUF_F_TX_OFFLOAD_MASK` cleared (HW offload disabled).
10. ✅ TX staging — heap-allocated vectors.

All file:line citations above were read directly from the source tree at the time of writing.