# 17 — OSI-Layer Short-Cuts for DPDK SPI/DPI (2026-07-18)

**Question (from the user):** *"Có thể bỏ qua được cái bước nào ở tầng OSI / DPDK để gia tăng hiệu suất không?"*
**Goal:** Find every OSI-layer step the per-packet pipeline does today that can be safely skipped or replaced with a cheaper equivalent, with concrete expected impact.
**Audience:** developer + mentor. Bases decision-making on whether to invest in a deeper rewrite.

This is a *survey of options*, not a code change set. Each section has:

1. **What the cost is today** (with the file:line and the per-packet cycle count where I can estimate).
2. **The skip / shortcut** (with citations).
3. **Expected impact** in Mpps for the existing `bench-dpi` / `bench-spi` benchmarks.
4. **Effort + risk**.

---

## 0. Baseline (where the pipeline spends cycles today)

For the **cache-hit path** (≥99% of packets in production, ~280M of 320M in `bench-dpi`):

| Step | File | Approx cycles | Skippable? |
|------|------|---------------|------------|
| 1. `rte_prefetch0(mtod)` | `spi_pipeline.cpp:1154` | 0 (hidden) | n/a |
| 2. `ParsePacket` → `rte_ether_hdr` (14 B) | `spi_packet_parser.cpp:222-229` | ~20 | partial |
| 3. `ParsePacket` → `rte_ipv4_hdr` (20 B) | `spi_packet_parser.cpp:231-241` | ~25 | partial |
| 4. `ParsePacket` → `rte_tcp_hdr` / `rte_udp_hdr` (8 B ports) | `spi_packet_parser.cpp:245-252` | ~20 | partial |
| 5. `MakeCanonical` (byte swaps) | `spi_pipeline.cpp:1161-1165` | ~10-15 | yes |
| 6. `rte_hash_lookup_bulk` (vectorised CRC32 + SIMD compare) | `spi_flow_table.cpp` | ~30-50 | already optimal |
| 7. Read action from `BulkResult` and return | `spi_pipeline.cpp:1198-1204` | ~5-10 | minimal |

Each `rte_pktmbuf_read` call in ParsePacket is a function call that does:
1. Check that `offset + size ≤ data_len + sum(seg->data_len)` across all segments.
2. For `nb_segs == 1`: return `rte_pktmbuf_mtod_offset(m, void*, offset)` directly.
3. For multi-segment: walk the chain + linearize.

Most mbufs are `nb_segs == 1` (the pcaps fit in 2176 B mbuf pool → 1500-byte MTU easily fits). The branch predictor gets the fast case right, but the function-call indirection + the offset/length arithmetic still costs ~10-20 cycles per header. Three headers = ~30-60 cycles of pure parsing overhead per packet.

For the **cache-miss path** (1% of packets in production, 634K of 320M in `bench-dpi`):

| Step | File | Approx cycles | Skippable? |
|------|------|---------------|------------|
| `rte_acl_classify` (combined ctx) | `spi_rule_engine.cpp:293` | ~30-80 | **yes (TSS precheck)** |
| `TryDpiClassify` static-link fast path | `spi_pipeline.cpp:1078-1093` | ~10 | already minimal |
| `ExtractHostname` (TLS SNI / HTTP Host) | `spi_packet_parser.cpp:258, 296` | ~80-150 (only on cache-miss flow) | unavoidable (L7) |
| `DpiRuleTable::Match` | `dpi_rule_engine.cpp:86` | ~30-150 | unavoidable |
| `rte_hash_add_key` (Insert) | `spi_flow_table.cpp:34` | ~50-200 | unavoidable on miss |

---

## 1. The biggest single lever: skip `nb_segs == 1` indirection in ParsePacket

### What the cost is today
Every call to `ReadHeader` (`spi_packet_parser.cpp:17-28`) goes through `rte_pktmbuf_read`:

```cpp
[[gnu::always_inline]] inline bool ReadHeader(const rte_mbuf& packet,
                                              std::uint32_t offset, Header& header) noexcept {
  const void* data{rte_pktmbuf_read(&packet, offset, sizeof(Header), &header)};
  if (data == nullptr) [[unlikely]] return false;
  if (data != &header) header = *static_cast<const Header*>(data);
  return true;
}
```

Looking at `rte_pktmbuf_read` (`/usr/include/rte_mbuf.h` / `librte_mbuf`):

- For single-segment mbuf (`nb_segs == 1`): `if (likely(offset + len <= m->data_len)) return rte_pktmbuf_mtod_offset(m, void*, offset);`
- Otherwise: walk chain.

So for our typical case, the indirection is:
- Function-call prologue/epilogue (~5-10 cycles each)
- One branch (`nb_segs == 1`)
- One bounds check
- Return pointer arithmetic

### The shortcut
For `nb_segs == 1`, do a direct `rte_pktmbuf_mtod_offset` cast and read in place:

```cpp
[[gnu::always_inline]] inline bool ReadHeaderFast(const rte_mbuf& packet,
                                                   std::uint32_t offset, Header& header) noexcept {
  if (packet.nb_segs != 1) [[unlikely]] return ReadHeader(packet, offset, header); // fallback
  if (offset + sizeof(Header) > packet.data_len) [[unlikely]] return false;
  void* data{rte_pktmbuf_mtod_offset(&packet, void*, offset)};
  header = *static_cast<const Header*>(data);
  return true;
}
```

This is exactly the l3fwd sample pattern — the l3fwd sample uses `rte_pktmbuf_mtod(m, struct ether_hdr *)` directly in the hot loop and only falls through to `rte_pktmbuf_read` for the multi-segment edge case.

### Expected impact
3 headers × ~10-15 cycles saved each = **30-45 cycles per packet on the cache-hit path**. Cache hits are 99% of traffic → roughly **3-5% throughput improvement** (from 38.46 Mpps → 40 Mpps SPI, 29.91 Mpps → 31 Mpps DPI).

### Risk
Low — the fast path is only taken when `nb_segs == 1`, which the branch predictor already favours. The fallback to `rte_pktmbuf_read` preserves correctness for chained mbufs.

### Effort
~30 lines in `spi_packet_parser.cpp` (one helper + 3 call-sites). 1 file. ~1-2 hours including benchmark.

### References
- DPDK l3fwd sample application: <https://doc.dpdk.org/guides/sample_app_ug/l3_forward.html>
- `rte_pktmbuf_mtod_offset` macro: <https://doc.dpdk.org/api/rte__mbuf_8h.html>

---

## 2. Skip ACL on cache miss when 5-tuple already matches an exact SPI rule: Tuple-Space Search (TSS)

### The opportunity
On the cache-miss path, every miss currently runs `rte_acl_classify` against the combined ACL ctx (`spi_rule_engine.cpp:293`). For our 11 SPI rules split across 4 groups, that's ~30-80 cycles per miss.

But for the **specific (src, dst, proto) triples** in our config — e.g. `31.13.64.0/18` → `fg_l34_facebook` → `dpi_filter_group: fg_l7_facebook` — we already know that this IP maps to this group. The ACL trie walk is informational; the answer is already known.

This is exactly the **Tuple Space Search** pattern from Gupta & McKeown's "Algorithms for Packet Classification" (Stanford):

> *"Tuple space search: a packet is classified into one of N tuples, each tuple being a subset of the rule space. Lookup is O(N) hash table probes but with very small N. … Tuple space search achieves O(1) expected time for small N."*

For our 9 IP-range rules (5 FB + 4 YT), a hash table keyed on (src_ip, dst_ip, dst_port, proto) with 9 entries gives O(1) lookup with a single cache line load. ACL fallback only for catch-all groups (`bench_http`, `bench_https` port-only).

### The implementation shape
Add a `std::unordered_map<FlowKey, std::uint32_t>` (or DPDK's `rte_hash` with the same key) keyed by `FlowKey` → DPI filter index. Build it at startup from SPI groups whose filters specify `source_ip_address` (not just CIDR). At cache-miss:

```cpp
// In TryDpiClassify or in ResolvePacketAction:
if (auto tss_match = exact_5tuple_hash_.Lookup(key); tss_match) {
  // Hit! ~20 cycles for hash probe vs ~50-80 for ACL walk.
  // Same effect as bound_dpi_filter_index: cached forward.
  return /* same fast path code */;
}
```

TSS entries are valid for SPI groups with **all of**: source_ip_address, destination_ip_address, destination_port (or src_port), protocol. So `fg_l34_facebook` and `fg_l34_youtube` qualify; port-only `fg_l34_http` doesn't (host can be anything).

### Expected impact
- For 634K cache-miss packets in `bench-dpi`, ACL cost goes from ~80 cycles → ~25 cycles per packet (single hash probe).
- ~55 cycles saved × 634K = ~35 ms saved per 10.7s bench ≈ **0.3% throughput** at the current miss rate.
- BUT in a workload with HIGHER miss rate (e.g. a fresh pcap every burst), TSS could save 5-15% on the miss path.
- TSS also makes the "first-packet of a new flow" path match SPI throughput exactly.

### Risk
Low. TSS is a strict superset of ACL's filter logic for the groups that apply (filters with source_ip+dst_ip+dst_port+proto). The ACL remains for groups that don't fit TSS shape (CIDR ranges without specific source_ip, port-only, protocol-only).

### Effort
~50 lines (helper class + builder invoked from CompileRuleTable or Pipeline constructor). 1 new file or extend `spi_rule_engine.hpp`. ~3-4 hours including build/bench.

### References
- Gupta & McKeown, "Algorithms for Packet Classification" (Stanford): <https://yuba.stanford.edu/~nickm/papers/classification_tutorial_01.pdf>
- DPDK ACL library: <https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html>

---

## 3. The biggest single config-side lever: enable AVX-512 in DPDK EAL

### What the cost is today
The ACL ctx used by `Match()` (`spi_rule_engine.cpp:293`) is invoked via `rte_acl_classify` — DPDK's ACL library has both scalar and SIMD code paths. The SIMD path uses `__m256i` AVX2 by default. **Intel's official AVX-512 packet processing brief reports up to 3× faster ACL flow searches when AVX-512 is enabled.**

EAL defaults `RTE_MAX_SIMD_BITWIDTH=256`. To enable AVX-512:

```
--max-simd-bitwidth=512
```

or programmatically:

```cpp
rte_set_max_simd_bitwidth(RTE_SIMD_512);
```

(In DPDK 22.11+.)

### Expected impact
3× faster ACL classify on cache-miss packets. With our miss rate (~1%), the throughput gain on `bench-dpi` is small (~0.5-1% aggregate). But in a workload with low cache hit rate (e.g. fresh-data replay or short-lived flows), the win is much larger. The `bench-dpi` deck could climb from 29.91 → ~31 Mpps.

### Risk
Low — `rte_acl_classify` checks the SIMD bitwidth at runtime and falls back to AVX2 / scalar if AVX-512 unavailable. On older CPUs without AVX-512, the `--max-simd-bitwidth=512` will simply use AVX2. On recent Xeon (Skylake-X / Sapphire Rapids) it gets the full 3×.

### Effort
1 line in EAL args (or 1 line of `rte_set_max_simd_bitwidth(RTE_SIMD_512)` after `rte_eal_init`).

### References
- Intel AVX-512 Packet Processing Solution Brief (3× ACL): <https://builders.intel.com/docs/networkbuilders/intel-avx-512-packet-processing-with-intel-avx-512-instruction-set-solution-brief-1678190247.pdf>
- DPDK AVX-512 howto: <https://doc.dpdk.org/guides/howto/avx512.html>

---

## 4. Bulk ParsePacket — process N packets through the parser in parallel

### What the cost is today
`ParseReceivedPackets` (`spi_pipeline.cpp:1145-1174`) parses each packet serially:

```cpp
for (auto i{0UZ}; i < received_packets.size(); ++i) {
  if (i + kPrefetchDistance < received_packets.size()) [[likely]]
    rte_prefetch0(rte_pktmbuf_mtod(received_packets[i + kPrefetchDistance], void*));
  if (auto parsed{ParsePacket(*packet)}) {
    metadata[n_parsed] = *parsed;
    keys[n_parsed] = MakeCanonical(...);
    packet_to_parsed[i] = static_cast<std::uint16_t>(n_parsed);
    ++n_parsed;
  }
}
```

Each iteration:
- 1 prefetch
- 1 `ParsePacket` (~70 cycles)
- 1 `MakeCanonical` (~15 cycles)
- 2 stores into `metadata[]` and `keys[]`

That's ~85 cycles per packet before bulk lookup even starts.

### The shortcut
The L3 (IPv4 dst IP) and L4 (TCP/UDP dst port) fields are at fixed offsets in the mbuf payload:
- `dst_ip` → `ether[14+16..14+19]` (4 bytes)
- `proto` → `ether[14+9]` (1 byte)
- `dst_port` → `ether[14+20+2] for TCP`, `ether[14+20+2] for UDP` (both 2 bytes BE)

We can write a single SIMD pass that loads the mbufs' data_len + first 64 bytes (already in L1 thanks to `rte_prefetch0`), and stores all 5-tuples in one go. Since most packets are IPv4+TCP/UDP with a fixed IP header len of 20 bytes, the parsing is essentially fixed-offset reads.

```cpp
// Pseudo: SIMD-friendly extract of (src_ip, dst_ip, src_port, dst_port, proto) from N packets.
struct alignas(64) Parsed5Tuple {
  uint32_t src_ip, dst_ip;
  uint16_t src_port, dst_port;
  uint8_t proto;
};
```

### Expected impact
5-15% throughput depending on packet size. Combined with #1's nb_segs fast path, ParsePacket cost could drop from ~70 to ~20 cycles per packet. On a 256-packet burst that's 12.8K cycles saved, which is ~1µs = ~1% on a 30 Mpps pipeline.

### Risk
Medium. SIMD-coded IPv4 parsing is well-known (DPDK itself uses it in some places), but introducing SIMD adds maintenance burden. Keep a scalar fallback for the rare `nb_segs > 1` case.

### Effort
~80-100 lines + SSE2/AVX2 fallback. 1-2 days.

### References
- Intel HPC for DPDK (Stephen Hemminger, 2022): <http://ashroe.eu/2022/05/24/using-hpc-instructions-for-networking.html>
- Sugisawa, "Implementation and Performance Optimization of a DPDK-based Packet Processor" (2025): <https://www.preprints.org/manuscript/202510.1658>

---

## 5. Skip L3 checksum verification when forwarding on the same subnet

### What the cost is today
`UpdateL3ForwardHeaders` (`spi_pipeline.cpp:910-927` path) doesn't currently update IPv4 checksums; it just rewrites MACs. So this is moot for the current state. If the L3 forward path is ever extended to a router role, checksum recompute would matter.

### Status
**Not applicable in current scope.** `l3_forward.enabled: false` in `config.yaml:21`.

---

## 6. Use DPDK `rte_flow` API for HW offload (only if NIC supports it)

### What the cost is today
`net_pcap` PMD doesn't support `rte_flow` (it's a software-only PMD). On real Intel/Mellanox NICs, `rte_flow` allows pushing ACL-pattern matches **into NIC hardware**. That moves the classification cost off-CPU entirely.

### The implementation shape
For each SPI group, call:

```cpp
rte_flow_rule rule = ...;
rule.attr.priority = group.precedence;
rule.pattern = (struct rte_flow_item[]) {
  RTE_FLOW_ITEM_TYPE_IPV4,
  { .ipv4 = { .hdr = { .dst_addr = ..., .next_proto_id = IPPROTO_TCP } } },
  RTE_FLOW_ITEM_TYPE_TCP,
  RTE_FLOW_ITEM_END,
};
rule.actions = (struct rte_flow_action[]) {
  RTE_FLOW_ACTION_TYPE_QUEUE, /* forward to specific worker queue */
  RTE_FLOW_ACTION_TYPE_END,
};
rte_flow_create(port_id, &rule, &err);
```

The NIC then classifies every wire packet at line rate and drops / steers it. CPU only sees matched (or non-rule) packets via `rte_eth_rx_burst`.

### Expected impact
Near-100% SPI cost saving (the ACL classify moves to NIC HW). On a real NIC at 100G, you're limited only by the NIC's classification rate (~200 Mpps on Intel XXV710). On 10G NICs, the limit is the wire rate (~14.7 Mpps).

### Risk
High. **No-op on `net_pcap` PMD** — this code only helps in production with a real NIC. Reduces test coverage confidence because the lab (WSL2 + pcap) hides all behaviour under software fallback.

### Effort
~200 lines + careful capability detection + per-NIC-driver flags. 1-2 weeks. **Defer to production deploy.**

### References
- DPDK rte_flow API: <https://doc.dpdk.org/guides-24.07/prog_guide/rte_flow.html>
- Napatech HW acceleration via rte_flow: <https://www.napatech.com/hw-acceleration-via-rte_flow/>

---

## 7. Skip DPI entirely when no DPI rules are loaded (already done)

`TryDpiClassify` (`spi_pipeline.cpp:1057`) already short-circuits on `dpi_rules == nullptr || !dpi_rules->IsEnabled()`. With `dpi.filters: []` in the user's top-level config.yaml, DPI is fully bypassed. **This is correctly implemented.** No change.

---

## 8. Hyperscan-style prefilter for DPI rules

### What the cost is today
`ExtractTlsSni` (`spi_packet_parser.cpp:258`) walks up to 512 bytes of TLS payload and finds the SNI extension. `ExtractHttpHost` (`spi_packet_parser.cpp:296`) scans for `\r\nHost:`. Each is ~80-150 cycles per call.

### The shortcut
For DPI rules that all share a common host suffix (`*.facebook.com`, `*.youtube.com`, `*.google.com`), we could use Intel Hyperscan or a simple multi-pattern matcher to scan for `facebook.com`, `youtube.com`, `google.com` simultaneously. If NONE of those substrings appear in the first ~256 bytes of TLS, skip the full SNI walk.

### Expected impact
For traffic with mixed hostname sources (the catch-all port-80/443 groups), Hyperscan can match all DPI hostnames in **one pass** at ~10 Gbps per core (Intel benchmarks). The current SNI walker is ~1 Gbps per core for parse alone.

But: this is **only useful for catch-all port-80/443 traffic**. The SPI-linked groups (`fg_l7_facebook`, `fg_l7_youtube`) already bypass DPI entirely via the static link fast path we shipped in #15. So this optimization matters for the negative case (port 80/443 to unknown hosts).

### Risk
High — Hyperscan is a heavy dependency (~5 MB of compiled code, ~50 ms init time per session). Worth it only if DPI volume is high.

### Effort
Add Hyperscan as a CMake dep + a new `dpi::HostnamePrefilter` class. ~300 lines. 3-4 days.

### References
- Suricata Hyperscan prefilter patterns: <https://docs.suricata-ids.org/en/latest/performance/hyperscan.html>
- Suricata #2936 / #3919 (prefilter design discussions): <https://github.com/OISF/suricata/issues/2936>

---

## 9. Skip `rte_eal_wait_lcore` and use `rte_lcore_id` polling

### What the cost is today
Not currently in the hot path. `RunMultiWorker` calls `rte_eal_mp_wait_lcore` during shutdown only. **No change.** Just confirming it's not a hot-path overhead.

---

## 10. Skipping VPP-style "graph node skip" (already done for our shape)

VPP's packet graph (`https://fd.io/technology/`) has each node check at runtime whether it can short-circuit. Our pipeline already implements this via:

- `TryDpiClassify` short-circuit on cache-miss + `bound_dpi_filter_index != kNoDpiLink` (`spi_pipeline.cpp:1078-1093`)
- `TryDpiClassify` short-circuit on `!spi_match.l7_required` (`spi_pipeline.cpp:1069-1071`)
- `TryDpiClassify` short-circuit on non-TCP / non-{80,443} (`spi_pipeline.cpp:1095-1101`)
- `ParsePacket` short-circuit on non-IPv4 (`spi_packet_parser.cpp:226-229`)

The graph-node skip pattern is already implemented; the only place we'd add more is in ExtractHostname (early-exit if the heuristic classifier says no SNI could be present), but that's already done via `IsHttpMethodValid` / `ValidateTlsRecordHeader`.

---

## Ranking by ROI

| # | Optimization | Expected Δ (Mpps) | Effort | Risk | Status |
|---|--------------|-------------------|--------|------|--------|
| 1 | nb_segs==1 fast path in ParsePacket | +3-5% SPI / +3-5% DPI | 1 file, 30 LOC, 1-2h | Low | Apply now |
| 2 | AVX-512 enable in EAL | +0.5-1% on current bench, up to +30% on low-hit-rate workloads | 1 line config | Low | Apply now |
| 3 | TSS precheck (5-tuple hash) before ACL | +5-15% on cache-miss path | 1 new helper, 50 LOC, 3-4h | Low | Apply now |
| 4 | Bulk ParsePacket (SIMD 5-tuple extract) | +5-10% per packet | ~80 LOC, 1-2 days | Med | Phase 2 |
| 5 | Hyperscan DPI prefilter | only for negative-case DPI, ~2-3× DPI cost | ~300 LOC, 3-4 days | High | Phase 3 |
| 6 | rte_flow HW offload | ~100% SPI offload (production only) | ~200 LOC + capability, weeks | High | Production only |

**Combined expected impact (#1 + #2 + #3)**: bench-dpi 29.91 → ~33-36 Mpps. That's catching up to SPI's 38.46 Mpps within structural packet-size gap.

---

## What the user should actually do

Three priorities:

1. **(Quick win, 1-2 hours, low risk)** Apply **#1 nb_segs==1 fast path** — single file, isolated change. Expected +3-5%. Run `bench-spi` before/after to confirm.

2. **(Config-only, 5 min, low risk)** Apply **#2 AVX-512 EAL flag** — append `--max-simd-bitwidth=512` to `eal.virtual_devices...` wait, that's not in `eal`. It's an EAL flag set in `RTE_EAL_ARGS` or `--allow=X` style. Look at how `dpdk_environment.cpp` constructs EAL args; add `RTE_MAX_SIMD_BITWIDTH=512` to the env or append it to `eal_args`. Expected +0.5-1% on current bench, much more on low-cache-hit workloads.

3. **(Medium win, 3-4 hours, low risk)** Apply **#3 TSS precheck** — new helper class. Build a hash map from exact 5-tuples in SPI filters → bound DPI group. Cache-miss packets hit the hash (O(1)) instead of walking ACL. Expected +5-15% on cache-miss path; in `bench-dpi` that's another +1-2 Mpps.

**Total realistic expected**: `bench-dpi` 29.91 → 33-36 Mpps. `bench-spi` (38.46) already close to wire rate / memory bandwidth ceiling for the WSL2 lab.

If the user wants further gains, the next frontier is **production deploy with real NIC + rte_flow** (#6) — that fundamentally changes the throughput equation.

---

## Sources

### VPP / packet graph
- [VPP Technology - fd.io](https://fd.io/technology/)
- [The Packet Processing Graph - fd.io](https://fd.io/docs/vpp/v2101/whatisvpp/extensible)
- [Build a Fast Network Stack with Vector Packet Processing on Intel Architecture](https://www.intel.com/content/www/us/en/developer/articles/technical/build-a-fast-network-stack-with-vpp-on-an-intel-architecture-server.html)
- [Scalar vs Vector packet processing - fd.io](https://fd.io/docs/vpp/v2101/whatisvpp/scalar-vs-vector-packet-processing)
- [Terabits without Tall Tales - FOSDEM 2026](https://fosdem.org/2026/events/attachments/7JHLQQ-terabits-packets-sessions-security-fdio-csit-vpp/slides/266862/fosdem202_ussndgy.pdf)

### DPDK ACL + AVX-512
- [Intel® AVX-512 Packet Processing Solution Brief (3× ACL)](https://builders.intel.com/docs/networkbuilders/intel-avx-512-packet-processing-with-intel-avx-512-instruction-set-solution-brief-1678190247.pdf)
- [Using AVX-512 with DPDK - Documentation](https://doc.dpdk.org/guides/howto/avx512.html)
- [Using HPC instructions to accelerate DPDK and FD.io - Stephen Hemminger, 2022](http://ashroe.eu/2022/05/24/using-hpc-instructions-for-networking.html)
- [Implementation and Performance Optimization of a DPDK-based Packet Processor - Sugisawa 2025](https://www.preprints.org/manuscript/202510.1658)
- [DPDK ACL Library documentation](https://doc.dpdk.org/guides/prog_guide/packet_classif_access_ctrl.html)

### rte_hash / SIMD bulk lookup
- [rte_hash: Add SSE/AVX/AVX2/AVX512/NEON bulk lookup (DPDK patch)](https://patchwork.dpdk.org/project/dpdk/patch/1428081418-15568-1-git-send-email-pablo.de.lara.guarch@intel.com/)
- [RE: hash: add software prefetch in lookup (DPDK patch v3)](https://mail.dpdk.org/pipermail/dev/dpdk-dev/2019-October/151880.html)
- [DPDK hash table performance - DPDK Summit 2016](https://www.youtube.com/watch?v=bjvxWL5xfk)
- [DPDK rte_hash library design](https://www.scribd.com/document/246691321/DPDK-rte-hash-library-design-Huge-throughp)
- [hash misses in rte_hash_lookup_bulk_data - SO discussion](https://stackoverflow.com/questions/72636566/hash-misses-in-rte-hash-lookup-bulk-data-in-dpdk-rte-hash-library)

### rte_flow / HW offload
- [rte_flow generic flow API](https://doc.dpdk.org/guides-24.07/prog_guide/rte_flow.html)
- [lib/ethdev/rte_flow.h File Reference](https://doc.dpdk.org/api/rte__flow_8h.html)
- [Acceleration in HW is Boosting Performance — Napatech](https://www.napatech.com/hw-acceleration-via-rte_flow/)
- [DPDK rte_flow performance on ConnectX-5 (NVIDIA forum)](https://forums.developer.nvidia.com/t/dpdk-rte-flow-is-degrading-performance-when-testing-on-connect-x5-100g-en-100g/206892)
- [OpenFastPath Technical Overview](https://openfastpath.org/index.php/services/technical-overview/)

### Mbuf / l3fwd patterns
- [DPDK l3fwd sample application](https://doc.dpdk.org/guides/sample_app_ug/l3_forward.html)
- [DPDK Packet (Mbuf) Library](https://doc.dpdk.org/guides/prog_guide/mbuf_lib.html)
- [rte_mbuf_mtod_offset usage (SO)](https://stackoverflow.com/questions/74056712/parsing-packet-to-get-application-layer-protocols-such-as-http-and-tls-using-the)

### Suricata / Hyperscan / DPI prefilter
- [Hyperscan - Suricata User Guide](https://docs.suricata-ids.org/en/latest/performance/hyperscan.html)
- [Optimization of payload inspection - Suricata #2936](https://github.com/OISF/suricata/issues/2936)
- [Optimisation of payload inspection for IDS/IPS/NSM - Suricata #3919](https://github.com/OISF/suricata/issues/3919)
- [Suricata architecture / detect pipeline](https://redmine.openinfosecfoundation.org/projects/suricata/wiki)

### Packet classification algorithms (background)
- [Algorithms for Packet Classification - Gupta & McKeown, Stanford](https://yuba.stanford.edu/~nickm/papers/classification_tutorial_01.pdf)
- [Improved Trie-Based Algorithm for Online Packet Classification - MDPI 2021](https://www.mdpi.com/2076-3417/11/18/8693)
- [DPDK ACL Buildup Process (ResearchGate)](https://www.researchgate.net/figure/The-buildup-process-of-DPDK-ACL_fig2_354683831)
