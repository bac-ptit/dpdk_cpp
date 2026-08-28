# 37. DPDK Mempool Cache & Queue Scaling Mechanics

**Verified Date:** 2026-08-04  
**Sources:**  
- DPDK Programmer's Guide - Mempool Library & Ethdev Library
- Local DPDK Header: `/usr/include/dpdk/rte_mempool.h`

---

## Why Mempool & Queue Tuning is Required for 16 Worker Lcores

When scaling DPDK applications from 4 lcores to 16 lcores, memory consumption and buffer availability undergo non-linear changes due to three core factors:

### 1. Per-Lcore Mempool Cache Expansion (`struct rte_mempool_cache`)
- To prevent atomic/spinlock lock contention during `rte_pktmbuf_alloc` / `rte_pktmbuf_free`, DPDK assigns a private cache to each lcore.
- Each lcore can cache up to `1.5 * cache_size` mbufs locally.
- With 16 lcores and `cache_size = 512`:
  $$\text{Cached Mbufs} = 16 \times (1.5 \times 512) = 12,288 \text{ mbufs}$$
- At ~2.176 KB per mbuf, this pins **~26.7 MB** of Hugepage memory purely in per-core local caches.

### 2. Hardware RX/TX Queue Descriptor Accumulation
- 16 worker lcores require 16 RX Queues and 16 TX Queues on the NIC interface.
- With `nb_rx_desc = 2048` and `nb_tx_desc = 2048`:
  - 16 RX Queues = 32,768 mbufs occupied in hardware DMA rings.
  - 16 TX Queues = 32,768 mbufs reserved in hardware transmission rings.
  - Total HW Ring mbufs = **65,536 mbufs (~142 MB Hugepages RAM)**.

### 3. Mempool Sizing Formula
To prevent packet drops (`rte_pktmbuf_alloc` returning `NULL`), the total mbuf count $N$ must satisfy:
$$N > (\text{Num Queues} \times \text{RX\_Desc}) + (\text{Num Queues} \times \text{TX\_Desc}) + (\text{Num Lcores} \times 1.5 \times \text{Cache Size}) + (\text{Burst Size} \times \text{Num Lcores})$$

- **If $N$ is too small**: 16 lcores starve the mempool, causing 100% packet drops.
- **If $N$ is too large**: Millions of pre-allocated mbufs waste Gigabytes of Hugepage RAM unnecessarily.

### 4. NUMA Alignment
- Allocating mempools on a single NUMA socket while worker lcores run across multi-socket CPUs introduces cross-socket UPI/QPI bus latency. Mempools must be allocated per NUMA socket (`rte_socket_id()`).
