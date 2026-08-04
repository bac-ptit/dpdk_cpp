# Large-Scale Rule Engine Bottlenecks & Architectural Analysis (4096 Groups x 2048 Rules)

- **Date Verified**: 2026-08-01
- **Target Scale**: 4,096 Filter Groups × 2,048 Rules/Group (~8.38 Million Rules)

## 1. Scale Comparison: Current `config.yaml` vs Mentor Requirement

| Metric | Current `config.yaml` | Mentor Requirement | Scale Increase |
|--------|-----------------------|--------------------|----------------|
| **Filter Groups** | 5 groups | 4,096 groups | **819×** |
| **Rules per Group** | 2 - 5 rules | 2,048 rules | **409–1,024×** |
| **Total SPI Rules** | ~13 rules | **8,388,608 rules** (~8.38M) | **645,000×** |
| **Configuration Size** | ~10 KB YAML | **~500 MB – 1 GB YAML/JSON** | **50,000×** |

## 2. Identified Scale Bottlenecks in Current Architecture

### Bottleneck A: DPDK `rte_acl` Category Limit (`RTE_ACL_MAX_CATEGORIES`)
- **Limit**: DPDK `rte_acl` restricts the number of category output slots per `rte_acl_ctx` (`RTE_ACL_MAX_CATEGORIES` = 16 or 64).
- **Issue**: Mapping 4,096 filter groups directly as individual categories in `rte_acl_ctx` causes `rte_acl_build` to fail with `-EINVAL`.
- **Solution at Scale**:
  1. Group rules by IP/port ranges using Tuple Space Search (TSS) or 5-tuple hash tables rather than raw ACL categories.
  2. Partition the 4,096 filter groups into multiple ACL contexts or linear bucket groups.

### Bottleneck B: Control-Plane Memory & Reload Latency (Glaze / YAML Parsing)
- **YAML Overhead**: Parsing 8.38 million YAML rules via Glaze / YAML string deserialization produces massive memory allocations (~2–4 GB transient heap) and multi-second parsing delay.
- **Solution at Scale**:
  1. Use binary serialization (BSON, FlatBuffers, or pre-compiled binary mmap rule blobs) for rule database transfers.
  2. Incremental / Delta Rule Reloading (pushing individual rule diffs rather than re-parsing the full 1 GB database).

### Bottleneck C: Double-Buffering Memory Footprint
- **Memory Consumption**: Double-buffering 8.38M compiled filter objects requires ~1.5 GB of RAM per `RuleTable`. Holding two tables simultaneously during hot-swap spikes memory usage to ~3 GB.
- **Solution at Scale**:
  1. Compact packed filter structures (`uint32_t` IPv4, 16-byte IPv6, bitpacked flags).
  2. RCU (Read-Copy-Update) index updates for fine-grained rule delta swaps.

### Bottleneck D: DPI Pattern Scaling (Aho-Corasick / Hyperscan)
- **Regex matching**: Linear scanning over 8.38M hostname strings is impossible in 100Gbps data planes.
- **Solution at Scale**:
  1. Use Aho-Corasick string tries or Intel Hyperscan (`hs_compile_multi`) for multi-pattern regex matching.
  2. Leverage static SPI→DPI filter links to skip DPI when L3/L4 rules already decide packet action.
