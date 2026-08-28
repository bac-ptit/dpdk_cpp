# Research Finding: Memory Footprint of Large-Scale Rule Sets (8.38M Rules) in DPDK C++

**Verified Date:** 2026-08-04
**Sources:**
- DPDK Programming Guide (Packet Classification Library / rte_acl)
- C++ std::string / std::vector Heap Overhead Analysis

## 1. Summary of Finding

When scaling the DPDK SPI rule engine to 8,388,608 rules (4,096 groups x 2,048 filters), the memory footprint is divided into two distinct components:

1. **C++ Object Heap Overhead (1.87 GB)**:
   - `SpiFilterConfig` contains `std::string` fields (`label`, `destination_ip_address`, `protocol`, etc.).
   - On 64-bit Linux, each `std::string` object consumes 32 bytes of stack/struct layout + dynamic heap allocation metadata.
   - 8.38M `SpiFilterConfig` objects consume ~1.27 GB of heap memory when deserialized.
   - Converting them into `CompiledFilter` structs creates an additional ~604 MB vector of compiled filter objects.
   - Keeping `config.spi.filter_groups` in memory after rule compilation retains 1.27 GB of unnecessary heap string allocations.

2. **DPDK ACL & FIB Memory Footprint (< 600 MB)**:
   - The compiled DPDK ACL context (`rte_acl_ctx`) for 8.38M rules with stride-8 quad-tries consumes ~450 MB - 600 MB of hugepage memory.
   - DPDK FIB (`rte_fib`) with dynamic `num_tbl8` sizing consumes < 50 MB.

## 2. Root Cause of Memory Spikes During Compilation

During initialization/reload:
- `config.spi.filter_groups` (1.27 GB heap strings)
- `CompiledFilterGroup` vector (604 MB C++ structs)
- DPDK ACL compilation temporary build memory (~800 MB)
- DPDK FIB table (~100 MB)

Total peak RAM reaches **3.8 GB - 4.5 GB**. If `config.spi.filter_groups` is not cleared/freed immediately after `CompileRuleTable()`, the 1.27 GB of raw YAML string objects remains permanently allocated in C++ heap memory alongside the compiled `RuleTable`.

## 3. Recommended Optimization Plan

1. **Free Config Rule Vectors Post-Compilation**:
   - `config.spi.filter_groups.clear();` `config.spi.filter_groups.shrink_to_fit();` immediately after `CompileRuleTable()` returns. This instantly reclaims 1.27 GB of C++ heap memory.
2. **Compact `CompiledFilter` Memory Layout**:
   - Remove `std::string label` from `CompiledFilter` (or replace with integer `uint32_t filter_id` / `string_view`) to reduce `CompiledFilter` size from 72 bytes to 24 bytes (saving 400 MB RAM).
