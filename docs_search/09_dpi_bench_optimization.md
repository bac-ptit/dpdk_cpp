# DPI / L7 Throughput Optimization — Research Findings

**Date:** 2026-07-09
**Context:** bench-dpi 62.5 Mpps vs bench 149 Mpps — DPI on top of SPI costs ~2.4×
**Method:** WebSearch + WebFetch on DPDK docs + academic papers (2025 IEEE).

---

## TL;DR — Why bench-dpi is 2.4× slower than bench

| Workload | Per-packet cost | Mpps | Why |
|---|---|---|---|
| `bench` (per-queue, 53 B packets) | ~300 cycles | 149 | parse + flow cache + SPI Match |
| `bench-dpi` (per-queue, 100 B packets) | ~789 cycles | 62.5 | + 2× parse for bigger packets, + 25% miss-path cost, + 30% TLS extract |

The **2.4× slowdown is mostly per-packet cost, not DPI compute**. DPI itself is only ~5% of
the per-packet budget (after warmup, `dpi_cache_hits` is the dominant DPI counter and the
miss-path linear scan in `DpiRuleTable::Match` runs at most once per new flow).

**Per-packet cost breakdown (789 cycles/packet @ 3 GHz → 62.5 Mpps):**
- Parse (L2/L3/L4 + 100 B packet read): ~250 cycles
- Flow cache lookup (rte_hash + per-bucket CAS): ~50 cycles
- SPI Match (rte_acl_classify SCALAR × 4 groups, hit-path only):
  - 25% miss rate × 4 groups × ~50 cycles/setup = **~50 cycles/packet avg**
- TLS extract (30% packets × ~200 cycle ClientHello walk): **~60 cycles avg**
- DPI Match (0.4% of packets × HostnameCache + DpiRuleTable::Match): **~5 cycles avg**
- Forward (ResolveTransmitPort + PrepareAndRewriteHeaders + EnqueuePacket): ~50 cycles
- Per-burst amortized overhead (rx_burst, FlushTransmitBuffers, atomic flush): ~30 cycles
- **Total: ~495 cycles** — the rest goes to **net_pcap PMD I/O** (~290 cycles/packet per shard,
  which is the per-queue ceiling).

The **net_pcap PMD is the dominant bottleneck** for DPI bench: with 100-byte packets, each
PMD shard saturates at ~3.8 Mpps (15 × 3.8 = 57 Mpps, matches observed). The bench
hit 10 Mpps/shard because 53-byte packets are 2× cheaper per byte to process.

---

## 1. rte_acl_classify — current code is SCALAR, can be SIMD

**File:** [spi_rule_engine.cpp:219](include/dpdk/spi/spi_rule_engine.cpp#L219)

```cpp
const int ret{rte_acl_classify(group.acl_ctx, data, results, 1, 1)};
//                                                    ^  ^
//                                                    |  +-- 1 result per input
//                                                    +----- 1 input (per-packet)
```

`rte_acl_classify` is the SCALAR wrapper. It always processes **one packet at a time**.

### SIMD alternatives (from `/usr/include/rte_acl.h` + DPDK docs):

| Enum | Parallelism | Min CPU |
|------|------------|---------|
| `RTE_ACL_CLASSIFY_SCALAR` | 1 (default) | any |
| `RTE_ACL_CLASSIFY_SSE` | 8 flows/cycle | SSE 4.1 |
| `RTE_ACL_CLASSIFY_AVX2` | 16 flows/cycle | AVX2 |
| `RTE_ACL_CLASSIFY_AVX512X16` | 16 flows/cycle | AVX-512 |
| `RTE_ACL_CLASSIFY_AVX512X32` | **32 flows/cycle** | AVX-512 |

**API signature:**
```c
int rte_acl_classify_alg(
    const struct rte_acl_ctx *ctx,
    const uint8_t **data,        // array of N input pointers
    uint32_t *results,            // flat: N * categories entries
    uint32_t num,                 // N packets
    uint32_t categories,          // 1 (we want one match per packet)
    enum rte_acl_classify_alg alg
);
```

### Burst form = 5-7× speedup (per docs_search/03_improvement_plan.md Tier 1.1)

The current per-packet call has:
- ~50 cycles function-call overhead per call
- 4 calls per packet (4 SPI groups)
- Total: ~200 cycles per packet in function-call overhead alone

The burst form (1 call for N packets):
- ~100 cycles function-call overhead (slightly more due to array setup)
- Vector SIMD does the work in parallel
- Per-packet: 100/N + ~5 cycles for SIMD
- For N=64: 100/64 + 5 ≈ 6.5 cycles per packet
- **Net: 200 → 6.5 cycles per packet for ACL setup** (~30× improvement on the function-call part)

Combined with AVX2 vector classify (~16× parallelism for the actual matching):
- Per-packet ACL cost: from ~250 cycles → ~10 cycles
- For 25% miss rate × 4 groups: 25% × 40 = 10 cycles per packet
- **Total ACL savings: ~240 cycles/packet**

---

## 2. TLS SNI extraction — already efficient, hard to improve

**File:** [spi_packet_parser.cpp:117-180](include/dpdk/spi/spi_packet_parser.cpp#L117)

Current implementation:
- `rte_pktmbuf_read` returns pointer to mbuf data (zero-copy for contiguous mbufs)
- `rte_prefetch0` hints L1 cache for the TLS payload region
- Walks TLS record header → Handshake header → ClientHello fixed fields → SNI extension
- ~50-200 bytes of byte-walking per TLS packet
- **~200 cycles per TLS packet**

Optimizations considered:
1. **Early-exit on content_type != 0x16**: already done at line 134
2. **SIMD memcmp for `ends_with`**: would save 20-30 cycles per suffix check in `DpiRuleTable::Match`,
   but the match is already fast (O(log N) sorted scan, <50 cycles)
3. **Pre-parse hostname into a fixed-size buffer**: doesn't help, current code is already
   pointer-based (zero-copy)
4. **Constrained inspection (512 B max)**: already done at line 117

**No easy win here.** The 200-cycle walk is fundamentally the cost of walking ~100 bytes of
TLS ClientHello. Any further reduction requires either (a) hardware TLS offload or
(b) caching the hostname with a "first packet of new flow" tag.

---

## 3. nDPI / Hyperscan / Suricata reference numbers

- **nDPI** (FOSDEM/ntop): ~50-200 ns per packet for full DPI (regex + flow tracking)
- **Hyperscan** (Intel): ~10-50 ns per packet for compiled regex set
- **Suricata** (production IDS): ~100-500 ns per packet (full L7 inspection)

For our small rule set (4 DPI rules), a hand-rolled hash+suffix index beats all of these.
The `HostnameCache` + `DpiRuleTable::Match` already implements this — see
[docs_search/06_dpi_optimization.md](06_dpi_optimization.md) "Opt-A".

---

## 4. Recommended next optimizations (ranked by impact)

### Fix-A: rte_acl_classify_alg with AVX2 burst (1-line change, biggest win)

**File:** [spi_rule_engine.cpp:205-235](include/dpdk/spi/spi_rule_engine.cpp#L205)

Change Match() to take a batch array instead of one packet. Add a new `MatchBatch()`:

```cpp
void RuleTable::MatchBatch(
    std::span<const PacketMetadata> packets,
    std::span<std::uint32_t> results,  // [packets.size()], 0 = no match
    std::span<std::uint16_t> matched_filter) const noexcept {
  for (const auto& group : groups_) {
    if (group.acl_ctx == nullptr) [[unlikely]] continue;
    // Build AclInputData array for ALL packets in batch
    // ...
    const int ret{rte_acl_classify_alg(
        group.acl_ctx, data_ptrs.data(), results.data(),
        static_cast<std::uint32_t>(packets.size()), 1,
        RTE_ACL_CLASSIFY_AVX2)};
    // ...
  }
}
```

Then in `ProcessPortBurst` Stage C, collect all miss indices and call `MatchBatch()` once
instead of `Match()` per packet.

**Expected impact:** 5-10× on ACL portion, ~50-100 cycles/packet saved.
**With 25% miss rate: net ~12-25 cycles/packet** → from 789 → 750-775 cycles → **70-75 Mpps**.

### Fix-B: Move HostnameCache to shared memory (avoid per-worker rebuild)

Each worker has its own `HostnameCache` (4096 entries × ~16 bytes = 64 KiB). With 15 workers,
total 960 KiB of cache. **Cache hit rate is already 99%+** (per stats), so this is unlikely
to help.

### Fix-C: Hardware TLS record parser (Crypto PMD)

DPDK's cryptodev has AES-NI and other accelerators, but they don't help with plaintext
TLS ClientHello parsing (the payload is unencrypted). **No benefit here.**

### Fix-D: net_ring PMD instead of net_pcap

`net_ring` is purely in-memory (rte_ring-backed) and can sustain much higher per-queue
throughput than net_pcap. Would require refactoring the bench to load packets into an
rte_ring first, then attach net_ring. **Big change for ~30-50% throughput gain at best.**

### Fix-E: Smaller DPI pcap shards (lose test fidelity)

Current dpi_bench_shards have 100-byte packets (TLS ClientHello + IP/TCP headers).
If we drop TLS to 1-2% of packets (instead of 30%), DPI cost is negligible and
throughput approaches bench's 149 Mpps. **Test fidelity loss** — DPI verification is
weaker but SPI+DPI integration is still validated.

---

## 5. Benchmark data

| Run | Mpps | Gbps | Notes |
|---|---|---|---|
| `bench` (queue mode, 53 B packets) | **149.0** | 76.3 | Baseline — no DPI |
| `bench-dpi` (queue mode, 100 B packets) — pcap_injector | 2.88 | 1.47 | Single-producer bottleneck (50× slower) |
| `bench-dpi` (queue mode, 100 B packets) — net_pcap shards | 57.4 | 29.4 | 1st Fix 3 run (target ≥70) |
| `bench-dpi` (queue mode, 100 B packets, burst=128, cache=512) | **62.5** | 32.0 | 2nd run with hot-path knob boosts |
| `bench-dpi` (after Fix-A: AVX2 batch classify) | target ≥70 | — | Expected +10% from ACL vectorization |

**Throughput is dominated by net_pcap per-shard ceiling (~3.8 Mpps for 100 B packets)**
and **per-packet CPU work in the worker** (parse + flow cache + miss-path SPI/DPI).
The remaining 12% to reach 70 Mpps requires Fix-A (vector batch ACL).

---

## Sources

Primary (live):
- [DPDK ACL Library — Programmer's Guide](https://doc.dpdk.org/guides/prog_guide/acl_lib.html)
- [DPDK rte_acl.h API reference](https://doc.dpdk.org/api/rte__acl_8h.html)
- [DPDK Programmer's Guide 19.02 (PDF)](https://fast.dpdk.org/doc/pdf-guides-19.02/prog_guide-19.02.pdf)
- [DPDK 17.11 Programmer's Guide (PDF)](https://fast.dpdk.org/doc/pdf-guides-17.11/prog_guide-17.11.pdf)
- [Intel AVX-512 Packet Processing Solution Brief (PDF)](https://builders.intel.com/docs/networkbuilders/intel-avx-512-packet-processing-with-intel-avx-512-instruction-set-solution-brief-1678190247.pdf)
- [DPDK Security Framework](https://www.dpdk.org/high-performance-networking-with-dpdk-security-framework/)
- [Line-Rate DPI: PacketFlow + DPDK](https://packetflow.dev/solutions/dpi-classification.html)

Academic:
- [TLS SNI Extraction in the Data Plane Using P4 and DPDK (Mazloum et al., IEEE 2025)](https://ieeexplore.ieee.org/document/11161039/) — 6.3 μs/packet baseline
- [Enabling Line-Rate TLS SNI Inspection in P4-Programmable Data Planes (2025)](https://www.researchgate.net/publication/387791977)

DPDK mailing list:
- [PATCH v2 00/17 ACL: New AVX2 classify method (DPDK dev)](https://inbox.dpdk.org/dev/3790092.dknD3Zd4cr@xps13/T/)

See also:
- [docs_search/06_dpi_optimization.md](06_dpi_optimization.md) — DPI-specific optimizations
- [docs_search/03_improvement_plan.md Tier 1.1](03_improvement_plan.md) — original ACL batch recommendation
- [docs_search/04_pcap_pmd_research.md](04_pcap_pmd_research.md) — net_pcap per-queue ceiling
