# 22 — net_pcap Queue Handles and 4→15 Worker Scaling (DPDK 25.11)

**Verified:** 2026-07-20
**Scope:** adversarial review of the claim that every net_pcap RX queue owns an independent `pcap_t`, plus a root-cause/measurement plan for the 32.90→72.70 Mpps result.
**No application code was changed for this note.**

## Executive verdict

The cited line

```c
pcap = pp->rx_pcap[pcap_q->queue_id];
```

proves only that the RX callback selects a handle from an array using the queue ID. The line

```c
pp->rx_pcap[0] = pp->tx_pcap[0];
```

proves the `single_iface` RX/TX alias. Neither line alone proves that every RX-array slot was initialized with a *distinct* handle.

The broader factual claim is nevertheless **supported for this project's `rx_pcap=` configuration by the upstream DPDK v25.11 source**: each `rx_pcap=<file>` key is processed by `open_rx_pcap`, which opens a handle and calls `add_queue`; `eth_from_pcaps_common` copies each `queue[i].pcap` to `pp->rx_pcap[i]`; and `eth_pcap_rx` indexes that array by `queue_id`. The `single_iface` branch is a separate `iface=` path that aliases RX queue 0 to TX queue 0. The cited `emmericp/dpdk` `master` fork is not a sufficient current-DPDK citation: it is a personal fork, has no v25.11 release tag, uses the older `rte_eth_pcap.c` path, and its visible copyright/source structure predates DPDK 25.11. Therefore the claim is **technically true for the demonstrated multi-`rx_pcap` setup, but the supplied quote/source is an overreach as proof of the current release**.

The handle-contention explanation should be rejected for this benchmark. Independent per-queue handles remove cross-queue libpcap-handle sharing. The strongest local leads are instead shared flow-cache writes caused by deliberately duplicated flow sequences across shards, SMT saturation, and the fixed per-queue `pcap_next_ex` + mbuf allocation/copy cost. Mempool and counter sharing are plausible secondary effects that need measurement.

## Current upstream DPDK evidence

Sources:

* [DPDK v25.11 `pcap_ethdev.c`](https://raw.githubusercontent.com/DPDK/dpdk/v25.11/drivers/net/pcap/pcap_ethdev.c) (primary source, checked 2026-07-20)
* [Official DPDK 25.11 pcap/ring PMD guide](https://doc.dpdk.org/guides-25.11/nics/pcap_ring.html)
* [Cited personal fork](https://github.com/emmericp/dpdk/blob/master/drivers/net/pcap/rte_eth_pcap.c) (not a v25.11 tag)

Relevant v25.11 control flow, summarized from the tagged source:

1. `open_rx_pcap()` calls `open_single_rx_pcap()` for the value of each processed `rx_pcap` key, then calls `add_queue()` with the resulting pointer.
2. `add_queue()` increments the devargs queue count and stores that pointer in the corresponding `devargs_queue` entry.
3. `eth_from_pcaps_common()` loops over RX queues and performs `pp->rx_pcap[i] = queue->pcap`.
4. `eth_pcap_rx()` obtains the process-private structure and performs `pp->rx_pcap[pcap_q->queue_id]`, then calls `pcap_next_ex()` on the selected handle.
5. In the `single_iface` branch, `open_single_iface()` fills `pp->tx_pcap[0]` and the driver explicitly assigns `pp->rx_pcap[0] = pp->tx_pcap[0]`; stop closes the shared handle once and clears both pointers.

That is adequate evidence for one handle per RX devargs queue in the project's multi-file pattern. It does **not** mean a pcap handle is globally unique across every possible mode: `iface=` intentionally aliases RX/TX queue 0, and process-private arrays are distinct per process. The official guide is useful for devarg semantics but does not itself spell out the repeated-key-to-array assignment; the tagged source is the authority for that detail.

## What the local application actually configures

* `config.yaml:38` passes fifteen distinct `rx_pcap=/.../bench_qN.pcap` values and `infinite_rx=1`; it does not pass `iface=`.
* `config.yaml:135-137` configures 15 RX and 15 TX queues. `config.yaml:28` enables lcores 0-15.
* `include/dpdk/dpdk_environment.cpp:82-124` forwards each virtual-device string unchanged as an EAL `--vdev` argument.
* `include/dpdk/dpdk_environment.cpp:539-556` calls `rte_eth_rx_queue_setup()` for every configured RX queue, all with the same `memory_buffer_pool_`.
* `include/dpdk/spi/spi_pipeline.cpp:625-665` forces queue-per-worker mode when configured as `queue` and identifies the pcap PMD; it does not create a software dispatch ring in this mode.
* `include/dpdk/spi/spi_pipeline.cpp:1364-1395` calls `rte_eth_rx_burst(port_id, context.worker_id, ...)`. Each worker therefore owns its queue ID in the direct queue mode.
* `include/dpdk/spi/spi_pipeline.cpp:672-682` selects the first requested worker lcores returned by `RTE_LCORE_FOREACH_WORKER`; the contiguous EAL list is not a physical-core-only placement.

The current net_pcap RX path is still expensive per packet even with independent handles: `pcap_next_ex()` parses the stream, `rte_pktmbuf_alloc()` obtains an mbuf, and the PMD copies the captured bytes into the mbuf. This gives each queue a serial source cost. It can cap aggregate scaling, but it is not cross-queue lock contention.

## High-value local finding: all shards replay the same flow sequence

Both benchmark generators reset `local_index` independently for every shard:

* `test/gen_test_pcap.py:168-189` selects `shard = index % shards`, then increments `shard_counts[shard]` and uses that shard-local index.
* `test/gen_test_pcap.py:196-207` derives the rule and source port from `local_index`; `sport = 1024 + (local_index % 60000)`.
* `test/gen_dpi_bench_pcap.py:164-194` repeats the same layout and local-index derivation for DPI-shaped packets.

Thus shard 0 packet 0, shard 1 packet 0, ..., and so on use the same rule/tuple sequence (apart from the outer timestamp). With the same shard count as worker count, separate RX queues intentionally feed the same canonical 5-tuples to different workers. This is not an RX queue ownership violation; it is a benchmark workload property that creates cross-worker sharing in the application cache.

## Shared flow-table mechanism that can flatten scaling

The flow table is one object shared by all workers:

* `include/dpdk/spi/spi_pipeline.cpp:1614-1617` creates one `std::unique_ptr<FlowTable>`.
* `include/dpdk/spi/spi_pipeline.cpp:1746-1752` stores the same raw `flow_table_` pointer in every `WorkerContext`.
* `include/dpdk/spi/spi_flow_table.cpp:20-54` creates one `rte_hash` with `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` and deliberately omits `MULTI_WRITER_ADD`.
* `include/dpdk/spi/spi_flow_table.hpp:205-220` performs a shared hash lookup and then writes `last_seen_tsc_[idx]` on every hit.
* `include/dpdk/spi/spi_flow_table.cpp:140-166` does the corresponding lookup-bulk operation and the same per-hit TSC store.
* `include/dpdk/spi/spi_flow_table.hpp:321-342` protects every insert with one external `rte_spinlock_t`.

The `alignas(64)` padding on each `ColdTsc` prevents *adjacent slots* from false-sharing. It cannot prevent true sharing when the duplicated shard sequences make different workers hit the **same slot**. Each worker then performs a write to the same cache line, and the shared `rte_hash` buckets are also read by all workers. This is a strong mechanistic explanation for diminishing returns, but its magnitude is not yet measured.

The installed DPDK 25.11 headers document the relevant contract: `RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF` enables lock-free reader/writer concurrency, while `rte_hash_add_key()` is not multi-thread safe by default and requires a creation flag for concurrent writers. The project's explicit spinlock is therefore a correctness choice for the omitted multi-writer mode, but it makes cache-miss inserts serial. See [installed `rte_hash.h`](https://doc.dpdk.org/api/rte__hash_8h.html), especially the definitions and `rte_hash_add_key`/delete notes.

## CPU/SMT and WSL2 observations

The benchmark host reports (2026-07-20):

```text
16 logical CPUs, 8 cores, 1 socket, 1 NUMA node
AMD Ryzen 7 6800H, 2 threads per core
Hypervisor vendor: Microsoft
Linux 6.18.33.2-microsoft-standard-WSL2
L3: 16 MiB
```

The application reserves lcore 0 as the main lcore and launches workers from the remaining contiguous lcores. On this topology, worker counts are not equivalent to physical-core counts: lcores 1 and 0 are SMT siblings, and lcores 2/3, 4/5, etc. are sibling pairs. At 15 workers all 16 logical CPUs are occupied, including all SMT siblings; the main lcore also performs stats/reload/eviction polling. The labels in the existing benchmark table such as “one worker per physical core” should therefore be treated as descriptive, not proven placement.

Microsoft's [WSL configuration documentation](https://learn.microsoft.com/en-us/windows/wsl/wsl-config), verified 2026-07-20, says `.wslconfig` controls the WSL2 VM's logical processor count and memory, with `processors` defaulting to the host's logical processor count; changes require the VM to stop/restart. WSL2 scheduling, host background load, and SMT frequency/power behavior are therefore part of this result. This does not prove WSL2 caused the shortfall, but it makes a bare-metal-style linear-core assumption invalid until placement and host conditions are controlled.

## Mempool and other shared-state assessment

`Environment::CreateMempool()` (`include/dpdk/dpdk_environment.cpp:282-297`) creates one shared pool of 1,050,000 mbufs with `cache_size=256` (`config.yaml:121-125`). The DPDK 25.11 mempool guide says that each core uses its own cache and only refills/drains the central ring when its cache is empty/full. That makes the 256-object cache a sensible first setting for 128-packet bursts and argues **against** a central-ring lock being the sole cause. The 512-object comparison (71.90 Mpps versus 72.70 Mpps at 256 in the existing table) also does not show a useful win, although those are single runs.

Mempool contention remains measurable rather than disproven: the pcap PMD allocates on RX and the pipeline frees dropped/unsent mbufs and transmits through the same pool. Collect per-lcore mempool statistics or central-ring refill counts before attributing throughput loss to it.

`AtomicCounters` is shared and workers flush all counters every 256 bursts (`spi_pipeline.cpp:1424-1434`, `1577-1593`). The flush interval greatly reduces, but does not eliminate, cache-line RMW traffic. Queue mode does not use the per-worker dispatch rings; ring contention is therefore not a first-order explanation for this exact benchmark.

## Interpretation of the measured curve

The supplied runs are:

| Workers/queues | Mpps | Relative to 4 |
|---:|---:|---:|
| 4 | 32.90 | 1.00x |
| 7 | 50.93 | 1.55x |
| 11 | 61.83 | 1.88x |
| 15 | 72.70 | 2.21x |

The ideal 15/4 ratio is 3.75x. The curve is consistent with multiple ceilings: physical-core capacity first, then SMT siblings with lower incremental capacity, plus a shared-flow-cache coherence/insert cost and the serial per-queue pcap source. It is **not** evidence of RX pcap handle sharing. The burst-256 result (43.09 Mpps) shows that a larger burst can worsen this workload's cache/working-set behavior; it does not identify the primary scaling limiter.

## Measurement plan (no application-code change required for the first pass)

1. **Prove placement.** Record `lscpu -e=CPU,CORE,SOCKET,NODE`, the EAL `Worker lcores` log, `/proc/$pid/task/*/status`, `taskset -pc`, and `mpstat -P ALL`. Run the same worker counts with a physical-core-only EAL list (main plus one logical CPU from each core), then with SMT siblings. Compare cycles/packet and Mpps.
2. **Separate duplicated-flow sharing from pcap I/O.** Generate temporary shards whose source-port/rule index includes the global packet index (unique sequences per shard), keeping packet lengths, count, and match percentage unchanged. Compare `flow_cache_hits`, `matched`, `flow_table_full`, and Mpps against the current reset-per-shard generator. A material improvement specifically with unique tuples implicates shared `rte_hash`/`last_seen_tsc_` coherence.
3. **Measure shared-cache traffic.** Use `perf stat` for `cycles,instructions,cache-references,cache-misses,LLC-load-misses` and, if exposed by this WSL kernel, locked-load/HITM events. `perf c2c` or a short instrumented lab build can identify cache-line bouncing in `last_seen_tsc_`, the hash buckets, and `AtomicCounters`. A failed/unsupported PMU event in WSL is itself a limitation to record, not a reason to infer no contention.
4. **Measure pcap source ceilings.** Collect per-queue RX packet/error/drop counters via `rte_eth_stats_get`/xstats or `dpdk-proc-info` while the process runs. Compare queue rates and empty-burst frequency at 4, 7, 11, and 15. Keep all shards on the Linux filesystem used here; repeat once from a Windows-mounted path only to test filesystem effects, not as the primary baseline.
5. **Measure mempool pressure.** Capture `rte_mempool_get_count()`/in-use counts and per-lcore cache/refill statistics (enable DPDK mempool stats if the build exposes them). Repeat cache sizes 0, 128, 256, and 512 with multiple runs and confidence intervals. Do not infer contention from one 512-object run.
6. **Control WSL variance.** Fix `.wslconfig` `processors` and `memory`, restart with `wsl --shutdown`, use a stable Windows power mode, close competing workloads, and record host/guest kernel versions. Repeat on native Linux or a real NIC/traffic source before making production hardware claims.
7. **Warm-up and confidence.** Run at least 5 repetitions per point, report median and spread, and separate the first warm-up interval from steady state. Keep `burst_size`, mempool cache, flow-table capacity/TTL, packet count, packet lengths, and shard count constant.

### Confidence summary

| Finding | Confidence | Reason |
|---|---|---|
| The emmericp quote alone does not prove distinct initialization | High | Array indexing and one alias do not establish construction/lifetime invariants. |
| Current DPDK v25.11 `rx_pcap` path gives one handle per RX devargs queue in this setup | High | Tagged upstream source shows open → add_queue → per-index assignment → indexed RX. |
| RX pcap handle contention explains this curve | Low / rejected | The configured `rx_pcap` shards are independent; no cross-queue handle lock is shown. |
| Shards duplicate canonical flow sequences | High | Both local generators reset `local_index` per shard and derive the tuple from it. |
| Shared flow-cache coherence/insert cost contributes | Medium-high mechanism, unmeasured magnitude | Shared table, per-hit same-slot atomic stores, and one insert spinlock are visible in local code. |
| SMT/WSL topology contributes | Medium-high | Topology is measured; the throughput effect needs physical-only and SMT-controlled runs. |
| Mempool central-ring contention is primary | Low currently | Per-lcore caches and the 256-vs-512 result argue against it, but counters are missing. |

## Additional sources

* [DPDK 25.11 writing efficient code](https://doc.dpdk.org/guides-25.11/prog_guide/writing_efficient_code.html) — shared RW data can generate cache misses; per-lcore/cache-aligned data is recommended.
* [DPDK 25.11 mempool library](https://doc.dpdk.org/guides-25.11/prog_guide/mempool_lib.html) — per-core caches reduce central-ring CAS/refill traffic.
* [DPDK 25.11 thread-safety guidance](https://doc.dpdk.org/guides-25.11/prog_guide/thread_safety.html) — queue ownership and shared-object synchronization requirements.
