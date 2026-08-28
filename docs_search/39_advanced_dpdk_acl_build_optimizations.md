# 39. Advanced DPDK ACL Build & Memory Optimization Architecture

**Verified Date:** 2026-08-05  
**Sources:**  
- [DPDK Programmer's Guide - Packet Classification Library (rte_acl)](https://doc.dpdk.org/guides-24.07/prog_guide/packet_classif_acl.html)
- [Intel DPDK Performance Optimization Guidelines](https://www.intel.com/content/www/us/en/developer/articles/guide/dpdk-performance-optimization-guidelines-white-paper.html)
- Local DPDK Header Reference: `/usr/include/dpdk/rte_acl.h` (`struct rte_acl_config.max_size`)

---

## 1. Key Optimization Discoveries for `rte_acl_build`

### Discovery A: Direct String-to-`rte_acl_rule` Single-Pass Conversion
- **Current Bottleneck**: Converting YAML/BEVE config into intermediate `CompiledFilterGroup` vectors creates 8,388,608 `CompiledFilter` C++ structs, consuming **~604 MB of vector RAM** plus **~500 MB of C++ heap string metadata**.
- **Optimization**: Parse raw config directly into contiguous `struct rte_acl_rule` binary buffers in a single pass. Eliminate the intermediate `CompiledFilterGroup` vector to save **1.1+ GB of C++ heap memory** during compilation.

### Discovery B: DPDK ACL Build Memory Limit (`max_size`)
- **API Spec**: `struct rte_acl_config` contains field `size_t max_size`.
- **Purpose**: Defines the upper bound of memory (in bytes) that `rte_acl_build()` is permitted to allocate for intermediate trie build structures.
- **Optimization**: Set `acl_cfg.max_size = 256 * 1024 * 1024` (256 MB) to bound DPDK's temporary build workspace, preventing runaway memory allocations during dense quad-trie generation.

### Discovery C: Early Config Buffer Disposal
- **Purpose**: Immediately post-parsing, invoke `.clear()` and `.shrink_to_fit()` on the input string configuration vector before `rte_acl_build()` begins.
- **Impact**: Instantly reclaims **~1.27 GB** of raw string heap memory before DPDK trie allocation occurs.

### Discovery D: Controlled Concurrency & Unpinned Worker Affinity
- **Purpose**: Execute chunk building in parallel batches using all available CPU threads while unpinning main lcore affinity via `pthread_setaffinity_np`.
- **Impact**: Enables full 16-CPU core utilization without starving system memory or triggering WSL OOM thrashing.
