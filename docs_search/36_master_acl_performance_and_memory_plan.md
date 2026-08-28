# 36. Master Plan: DPDK ACL Rule Loading, Memory Spike & Multithreading Optimization

**Verified Date:** 2026-08-04  
**Target Codebase:** `dpdk_cpp` (Modern C++26 DPDK SPI/DPI Engine)

---

## Executive Summary

This master plan addresses performance & stability issues identified in the DPDK ACL rule subsystem:
1. **Compilation Bottlenecks & Lock Contention**: Multi-threaded `rte_acl_build()` stalls or hits spinlock contention when scaling across CPUs due to DPDK EAL memory lock contention (`rte_mcfg_tailq_rwlock`).
2. **RAM Explosion with 16 Worker Lcores**: Simultaneous execution of 16 chunk context builds creates a 16x temporary build workspace RAM spike (~4.8 GB), combined with un-cleared C++ `std::string` heap allocations (~1.27 GB) and per-lcore mempool cache footprint.

*Note: As per user directive, Phase 1 (Pre-compiled binary BEVE format change) is SKIPPED. The high-level string format is retained, and optimizations focus on concurrency control, memory reclamation, and classification speed.*

---

## Core Optimization Plan (Phases 1-4)

### Phase 1: Controlled Build Concurrency & EAL Memory Lock Prevention
- **Problem**: Calling `rte_acl_create()` and `rte_acl_build()` concurrently across 16 CPU threads triggers DPDK global memory spinlock contention and multiplies temporary build workspace memory by 16x.
- **Action**:
  1. Use parallel C++ threads (`std::async`) for string parsing into rule structures in memory.
  2. Implement a **Controlled Build Semaphore / Pool** limiting concurrent `rte_acl_build()` execution to **2 - 4 threads maximum** (e.g. `kMaxConcurrentBuildThreads = 4`).
- **Expected Impact**: Completely eliminates EAL spinlock contention, prevents RAM spikes during compilation, and maintains smooth multi-core scaling.

---

### Phase 2: Immediate Post-Build Heap Reclaim
- **Problem**: Raw YAML/Config structures holding `std::string` objects consume ~1.27 GB C++ heap memory and remain allocated alongside compiled `rte_acl_ctx` tables.
- **Action**:
  1. Immediately post-compilation in `CompileRuleTable()`, execute:
     ```cpp
     config.filter_groups.clear();
     config.filter_groups.shrink_to_fit();
     ```
  2. Compact `CompiledFilter` layout by removing redundant `label` string fields or replacing them with lightweight 32-bit integer IDs (`uint32_t filter_id`).
- **Expected Impact**: Reclaims **~1.27 GB** of C++ heap RAM instantly upon build completion.

---

### Phase 3: Vectorized SIMD Classification (`rte_acl_classify_alg`)
- **Problem**: Single-packet `rte_acl_classify` calls suffer from per-packet setup overhead (30–80 CPU cycles/packet).
- **Action**:
  1. Move classification from per-packet to per-burst (`MatchBulk`).
  2. Explicitly specify SIMD algorithms (`RTE_ACL_CLASSIFY_AVX2` or `RTE_ACL_CLASSIFY_AVX512X32`) for burst sizes up to 64 mbufs.
- **Expected Impact**: Boosts SPI packet classification speed by **5x - 8x**.

---

### Phase 4: Per-Lcore Mempool & Queue Scaling Tuning
- **Problem**: 16 worker lcores expand per-lcore mempool caches and hardware RX/TX ring descriptors, increasing Hugepage baseline memory.
- **Action**:
  1. Set `cache_size` in `rte_mempool_create` to an optimal balance (e.g., 256 or 512).
  2. Ensure worker lcores isolate memory allocations on local NUMA sockets (`rte_socket_id()`).
- **Expected Impact**: Stabilizes system RAM usage at scale with 16+ worker threads.
