# 22 — Adversarial review of `MULTI_WRITER_ADD` and worker scaling

**Verified:** 2026-07-20
**DPDK:** installed `libdpdk.pc` reports 25.11.0 (`/usr/lib/x86_64-linux-gnu/pkgconfig/libdpdk.pc:8`)
**Scope:** explain the 32.90 Mpps (4 workers) to 72.70 Mpps (15 workers) result without changing application code. This note separates what the DPDK hash source proves from what is actually active in this benchmark.

## Executive conclusion

The claim under review is **substantively supported for the DPDK hash add path, but it is not the cause of the current benchmark result**.

The v25.11 `rte_cuckoo_hash.c` branch supplied in the research question directly sets both `use_local_cache = 1` and `writer_takes_lock = 1` when `RTE_HASH_EXTRA_FLAGS_MULTI_WRITER_ADD` is enabled. The later `rte_rwlock_write_lock()` call is an exclusive writer acquisition on the hash's reader-writer lock (not a shared/read-mode acquisition). Thus, local free-slot allocation does not imply parallel insertion: concurrent add operations can queue behind one writer lock. The primary source is sufficient for that mechanism.

There are three important qualifications:

1. The quote alone does not prove that *every* hash mutation, wrapper, delete, or reset takes the same lock; it proves the guarded writer path. The stronger wording should be read as “the protected add/write path,” not literally every possible write API.
2. This project does **not** set `MULTI_WRITER_ADD`. `CreateHashParams()` sets only `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` (`include/dpdk/spi/spi_flow_table.cpp:20-54`). `FlowTable::Insert()` is explicitly serialized by the application's `rte_spinlock_t` (`include/dpdk/spi/spi_flow_table.hpp:304-342`), and `PurgeExpired()` now uses that same lock (`include/dpdk/spi/spi_flow_table.cpp:188-243`). Therefore an internal DPDK writer lock cannot explain the measured 4→15-worker slope.
3. Enabling the flag in this implementation would not simply make the current design faster: the slot index is used to index `cells_` and `last_seen_tsc_`, while the multi-writer hash can return IDs beyond `params.entries` and relocate keys. That invalidates the project's slot-indexed side arrays; the v3 design intentionally omitted the flag (`spi_flow_table.hpp:159-164`, `spi_flow_table.cpp:28-53`). If the external spinlock remained, it would also continue to serialize inserts regardless of DPDK's internal lock.

## What the authoritative sources establish

- **Primary v25.11 source:** `https://git.dpdk.org/dpdk/tree/lib/hash/rte_cuckoo_hash.c?h=v25.11` contains the quoted initialization and guarded `rte_rwlock_write_lock(h->readwrite_lock)` path. `rte_rwlock_write_lock` is exclusive writer mode; “shared read-write lock” is acceptable only if “shared” means one lock object shared by threads, not shared/read ownership.
- **DPDK API header:** `https://doc.dpdk.org/api/rte__hash_8h.html` defines `MULTI_WRITER_ADD` as bit `0x02`, `RW_CONCURRENCY` as `0x04`, and lock-free RW concurrency as `0x20`. The same API documents that a key ID may be larger than the user entry count when `MULTI_WRITER_ADD` is set, and that add/delete operations require the concurrency flag or external serialization.
- **Hash structure documentation:** `https://doc.dpdk.org/api/structrte__hash.html` describes the local cache as per-lcore free-slot allocation. This cache reduces allocator contention; it does not remove the writer lock around the protected cuckoo update.
- **Mempool is separate:** `https://doc.dpdk.org/guides/prog_guide/mempool_lib.html` describes an independent per-lcore mbuf cache. Do not conflate this with the hash key-slot cache.
- **Source quality/date:** the v25.11 in-tree source is the correct primary source for this version, not a marketing benchmark or forum claim. Historical patch discussions are useful context but should not override the v25.11 source.

## Local hot-path evidence

### 1. The disputed DPDK lock is inactive in this run

`CreateHashParams()` configures `params.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` only (`include/dpdk/spi/spi_flow_table.cpp:20-54`). The hot path calls `rte_hash_lookup_bulk()` in chunks of at most 64 (`spi_pipeline.cpp:1239-1253`), then loads the indexed cell with acquire semantics and writes the per-entry timestamp (`spi_flow_table.cpp:119-170`). The current lookup path is therefore the lock-free-reader mode, not `MULTI_WRITER_ADD` plus `writer_takes_lock`.

The only current add serialization is application-owned:

```text
FlowTable::Insert
  rte_spinlock_lock(&insert_lock_)
  rte_hash_add_key(hash_, &key)
  publish cells_[idx]
  rte_spinlock_unlock(&insert_lock_)
```

This appears at `include/dpdk/spi/spi_flow_table.hpp:321-342`. Consequently, the under-review DPDK lock mechanism is a valid **counterfactual** hypothesis, but not a valid explanation of the observed 32.90→72.70 Mpps data.

### 2. The benchmark deliberately gives every worker the same flow sequence

`test/gen_dpi_bench_pcap.py:164-172` keeps a separate `shard_counts` counter and assigns `shard = index % shards`; each shard therefore receives the same `local_index` sequence. Source/destination addresses and ports are generated from `local_index` (`:174-200`). With 15 queue shards, worker 0's packet at local index *j* and worker 14's packet at local index *j* have the same canonical 5-tuple.

The production benchmark then performs a lookup and timestamp store on every cache hit (`include/dpdk/spi/spi_flow_table.cpp:148-165` for bulk lookup; `spi_flow_table.hpp:205-220` for single lookup). `ColdTsc` is aligned to 64 bytes, which prevents **false sharing with neighboring slots**, but it cannot prevent **true sharing of the same slot**. Identical tuples on all queue shards make multiple lcores write the same `last_seen_tsc_[idx]` cache line. That line must migrate between cores under MESI/coherence, and the cost grows with worker count. This is a high-confidence, directly testable explanation for sublinear scaling.

The comments claiming that the split “does not ping-pong” (`spi_flow_table.hpp:214-219`, `:455-470`) are only true for unrelated slot indices. They do not apply when the benchmark duplicates each flow across queues.

### 3. The lcore list oversubscribes physical cores with SMT

`config.yaml:28` enables lcores `0-15`; `include/dpdk/spi/spi_pipeline.cpp:671-681` selects worker lcores in ascending `RTE_LCORE_FOREACH_WORKER` order, so a 15-worker run uses lcores 1 through 15 while the main lcore is 0. The local WSL2 topology reports:

- `/proc/cpuinfo`: AMD Ryzen 7 6800H, 8 physical cores, 16 siblings, `hypervisor` flag, SMT pairs `(0,1), (2,3), …, (14,15)`.
- `/sys/devices/system/cpu/online`: `0-15`.
- `/sys/devices/system/cpu/smt/active`: `1`.
- `/sys/devices/system/node/online`: `0`.

Thus the benchmark's “4 workers” are not four isolated physical cores: workers 2 and 3 are SMT siblings, while worker 1 shares physical core 0 with the mostly-idle main lcore. The 7-worker run also contains three SMT pairs; 11 and 15 workers increasingly fill SMT siblings. The 4→15 comparison is therefore not 4 physical execution contexts versus 15 equivalent physical contexts. SMT normally adds less than a second full execution context, and memory/coherence pressure is shared. This is a confirmed topology confounder, not a claim that SMT alone explains all of the gap.

### 4. The flow-table footprint is large and random-access

At `max_concurrent_flows: 1000000` (`config.yaml:248-252`), `AtomicFlowCell` occupies 64 bytes per slot and `ColdTsc` also occupies a 64-byte cache line (`spi_flow_table.hpp:98-105`, `:463-477`). The two side arrays alone are approximately 128 MiB at one million slots, before the rte_hash metadata. The 15 workers repeatedly perform random hash-table reads plus a write to the timestamp line. The working set is far beyond a small per-core cache and competes for LLC, memory bandwidth, and coherence traffic as workers are added.

This is a likely secondary amplifier of the duplicated-flow true-sharing effect. It is not evidence of a hash writer lock: cache-hit lookup traffic does not call `rte_hash_add_key`.

### 5. Mempool settings are not currently persuasive as the primary cause

`config.yaml:121-125` creates one shared 1,050,000-object mbuf pool with `cache_size: 256`; `dpdk_environment.cpp:283-298` passes those values to `rte_pktmbuf_pool_create()`. The installed DPDK build sets `RTE_MEMPOOL_CACHE_MAX_SIZE 512` (`/usr/include/x86_64-linux-gnu/dpdk/rte_config.h:59-62`), so 256 is valid and leaves room for 512.

The prior project measurements are not consistent with a simple “cache too small” explanation: 15 workers at cache 256 measured 72.70 Mpps, while cache 512 measured 71.90 Mpps (`docs_search/19_apples_to_apples_bench.md:163-177`). This does not rule out allocator contention, but it makes it a lower-confidence hypothesis than true-sharing and SMT. The mempool cache is also independent from the hash local free-slot cache.

### 6. net_pcap queue setup is structurally correct, but per-packet I/O remains a ceiling

`config.yaml:38` supplies 15 distinct `rx_pcap=` files and `:134-137` requests 15 RX/TX queues. `BuildEalArgs()` forwards the vdev string unchanged (`include/dpdk/dpdk_environment.cpp:83-111`), `SetupReceiveQueues()` configures each queue (`:539-556`), and queue mode calls `rte_eth_rx_burst(port, context.worker_id, ...)` (`include/dpdk/spi/spi_pipeline.cpp:1364-1395`). Existing source research in `docs_search/04_pcap_pmd_research.md` and `docs_search/21_pcap_pmd_quote_misread.md` correctly rejects the shared-`pcap_t` and per-queue-lock explanations for this `rx_pcap=` setup.

The pcap PMD still allocates/copies packets per RX operation, so it can be an I/O-side per-queue ceiling. `infinite_rx=1` removes EOF termination, not the per-packet replay work. Measure this separately with a NULL PMD or a prefilled ring before attributing the plateau to the hash.

### 7. WSL2 affects reproducibility and absolute throughput

The local kernel is `6.18.33.2-microsoft-standard-WSL2`; `/proc/cpuinfo` exposes `hypervisor`, and `/proc/meminfo` reports 7.39 GiB total RAM, 2 GiB swap, and `HugePages_Total: 0`. The application requests `memory_size: 3418` MiB and legacy memory (`config.yaml:28-36`). Microsoft documents that WSL2 runs Linux in a managed VM and that `.wslconfig` controls VM `processors`, `memory`, and `swap`: `https://learn.microsoft.com/en-us/windows/wsl/compare-versions` and `https://learn.microsoft.com/en-us/windows/wsl/wsl-config`.

These facts make CPU scheduling, memory bandwidth, page/TLB behavior, and host background load part of the measurement environment. They do not prove WSL2 is the root cause. The benchmark should record the effective WSL processor/memory limits and EAL startup memory mode, and should report a median and spread over multiple runs.

## Ranked root-cause hypotheses

1. **High confidence:** benchmark shards duplicate the same canonical tuples, causing true cache-line sharing on `last_seen_tsc_` across workers. This directly increases coherence traffic with worker count.
2. **High confidence:** the 15-worker point uses all 16 logical CPUs on an 8-core/16-thread SMT topology; the 4-worker point is not a four-physical-core baseline. SMT and shared resources reduce the expected ratio.
3. **Medium confidence:** the 128-MiB side-array plus hash metadata working set increases LLC/memory-bandwidth pressure at 15 workers, amplifying #1 and #2.
4. **Low-to-medium confidence:** net_pcap per-packet allocation/copy limits each queue or adds CPU contention. The queue/handle-lock hypotheses are not applicable, but the PMD's work still needs an isolated measurement.
5. **Low confidence from current results:** central mempool contention. Cache 512 did not improve over 256; collect allocator counters or use a NULL/ring source before elevating this.
6. **Not a current cause:** `MULTI_WRITER_ADD`'s internal writer lock. The flag is absent from the current hash parameters; inserts are serialized by the application's external spinlock instead.

## Measurement plan (no application-code changes required)

1. **Correct the topology comparison first.** Run workers on one logical CPU per physical core, then add SMT siblings. Record `rte_get_main_lcore()`, each worker lcore, `/proc/self/task/*/stat`, and `sched_getcpu()`. Compare 4/7/8 physical workers and 15 logical workers; do not label contiguous lcore IDs as physical-core IDs without checking `/proc/cpuinfo`.
2. **Break the duplicated-flow confounder.** Generate an otherwise identical set where each shard has a disjoint source-port/IP range, then compare against the current same-sequence shards. Keep packet count, packet size, match/drop mix, burst, queues, and timeout fixed. A large recovery at 15 workers confirms true-sharing on `last_seen_tsc_`.
3. **Measure write-sharing directly.** Run `perf stat` (or equivalent available in the WSL kernel) on `cycles`, `instructions`, `cache-misses`, `LLC-load-misses`, `dTLB-load-misses`, `page-faults`, and coherence/offcore events available on the host. Compare same-flow and disjoint-flow shards at 4/8/15 workers. If hardware coherence events are unavailable in WSL2, use the controlled shard comparison as the primary experiment.
4. **Isolate pipeline from pcap.** Repeat with a NULL PMD or an in-memory/ring source and with the same worker/core mappings. If the slope remains, it is pipeline/cache/topology; if it improves sharply, pcap replay is limiting. Existing pcap research lists `net_null` and `net_ring` as suitable isolation PMDs: `https://doc.dpdk.org/guides/nics/null.html` and `https://doc.dpdk.org/guides/nics/ring.html`.
5. **Test allocator pressure separately.** Hold topology and shard key distribution constant; sweep mempool cache 0/128/256/512 and record `rte_mempool_avail_count()` plus RX `nombuf`/drop statistics. Treat the existing 256 versus 512 result as evidence against a dominant central-ring bottleneck, not as proof of absence.
6. **Test hash inserts independently.** Run a miss-heavy input with unique keys and instrument only in a benchmark harness (or use existing counters) to report insert attempts, `flow_table_full`, and cycles per insert. Do not enable `MULTI_WRITER_ADD` in this application without redesigning the slot-indexed side arrays and validating key-ID/relocation semantics. To test the DPDK claim itself, use a standalone `rte_hash` microbenchmark with and without the flag, and measure lock wait/contention; do not infer it from this cache-hit-dominated pipeline.
7. **Record WSL2 conditions.** Capture `uname -a`, `/proc/cpuinfo`, `/proc/meminfo`, `/sys/devices/system/cpu/online`, SMT state, effective `.wslconfig` processor/memory/swap settings, EAL startup logs, and whether hugepage allocation succeeded. Repeat after a clean WSL restart and report median/p10/p90 across at least five runs.

## Sources

- DPDK v25.11 primary source: https://git.dpdk.org/dpdk/tree/lib/hash/rte_cuckoo_hash.c?h=v25.11
- DPDK hash API: https://doc.dpdk.org/api/rte__hash_8h.html
- DPDK hash structure/local cache: https://doc.dpdk.org/api/structrte__hash.html
- DPDK mempool per-lcore cache: https://doc.dpdk.org/guides/prog_guide/mempool_lib.html
- DPDK net_pcap guide: https://doc.dpdk.org/guides/nics/pcap.html
- DPDK v25.11 net_pcap source: https://github.com/DPDK/dpdk/blob/v25.11/drivers/net/pcap/pcap_ethdev.c
- WSL2 architecture: https://learn.microsoft.com/en-us/windows/wsl/compare-versions
- WSL2 VM settings: https://learn.microsoft.com/en-us/windows/wsl/wsl-config
- Project files: `/home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_flow_table.cpp`, `/home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_flow_table.hpp`, `/home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_pipeline.cpp`, `/home/bac/programming/viettel/dpdk_cpp/include/dpdk/dpdk_environment.cpp`, `/home/bac/programming/viettel/dpdk_cpp/config.yaml`, `/home/bac/programming/viettel/dpdk_cpp/test/gen_dpi_bench_pcap.py`, `/home/bac/programming/viettel/dpdk_cpp/docs_search/04_pcap_pmd_research.md`, `/home/bac/programming/viettel/dpdk_cpp/docs_search/19_apples_to_apples_bench.md`, `/home/bac/programming/viettel/dpdk_cpp/docs_search/21_pcap_pmd_quote_misread.md`.
