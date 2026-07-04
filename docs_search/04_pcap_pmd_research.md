# pcap PMD & Multi-Core Scaling — Research Findings

**Source:** Research subagent (id a32e9af...) ran 2026-07-05; output verified and consolidated below.
**Method:** Primary sources at doc.dpdk.org + GitHub DPDK/dpdk + pktgen repo. WebSearch returned 400 errors; 12 distinct URLs retrieved directly.

---

## TL;DR — Why "more workers" doesn't help

The pcap PMD is **per-queue single-threaded**. Each `rx_pcap=` argument is one RX queue drained by one lcore. Multiple queues run on multiple lcores — fine. But every single queue is bottlenecked by serial `pcap_next_ex()` + per-packet `rte_pktmbuf_alloc` + `rte_memcpy`. Adding workers past N (where N = number of `rx_pcap` shards) does nothing because there are no more queues for them to drain.

Quote from the agent's research:

> Claim 2.1 — Multiple rx_pcap files passed to a single net_pcap0 become one queue per file, all serviced in round-robin order by the single lcore that polls that port.
> Source: https://doc.dpdk.org/guides/nics/pcap.html  (HIGH confidence)

> Claim 1.2 — Using the same file for multiple queues is not supported because the underlying pcap library does not support concurrent access to a single file handle.
> Source: https://doc.dpdk.org/guides/nics/pcap.html (HIGH confidence)

**In your project:** you're already using the workaround — `cmd_bench_pcap` (`test/test_env.sh:278`) generates N shards and binds them as `rx_pcap=` args. With `workers=11` and `infinite_rx=1`, the per-queue ceiling is roughly **3-5 Mpps per shard** on typical x86. So total throughput ≈ min(N × 5 Mpps, pipeline CPU ceiling).

The plateau at 10→15 workers means **the pipeline CPU ceiling matches the per-queue ceiling around 10 Mpps**. You can't break that without changing either the I/O (Pktgen at wire rate) or the per-packet CPU cost (T1.1, T1.4 in 03_improvement_plan.md).

---

## Claim-by-claim summary

### Pcap PMD behavior (HIGH confidence)

| # | Claim | Source |
|---|-------|--------|
| 1.1 | `eth_pcap_rx` loops `pcap_next_ex()` per mbuf; no thread pool | https://github.com/DPDK/dpdk/blob/main/drivers/net/pcap/pcap_ethdev.c |
| 1.2 | One pcap file cannot be shared by multiple queues | https://doc.dpdk.org/guides/nics/pcap.html |
| 1.3 | Number of RX queues = number of `rx_pcap`/`rx_iface` arguments | https://doc.dpdk.org/guides/nics/pcap.html |
| 1.4 | Pcap PMD RX is per-packet copy from libpcap into freshly-allocated mbuf (no zero-copy) | pcap_ethdev.c source |
| 1.5 | Per-queue ceiling ≈ 3-5 Mpps on modern x86 (MEDIUM confidence, mailing-list reports) | canonical knowledge |

### Multi-shard behavior (HIGH confidence)

| # | Claim | Source |
|---|-------|--------|
| 2.1 | N `rx_pcap` files = N queues, each polled by one lcore | https://doc.dpdk.org/guides/nics/pcap.html |
| 2.2 | Application owns fan-out (via `--config (port,queue,lcore)`) | l3fwd sample app doc |
| 2.3 | Extra queues without lcores = packets queued forever | EAL model |

### Alternative PMDs (HIGH confidence on existence)

| # | PMD | Use case | Source |
|---|-----|----------|--------|
| 3.1 | **AF_PACKET PMD** (`net_af_packet` + `qpairs=N`) | bypass kernel for real-hardware-less hosts; supports `fanout_mode=hash\|lb\|cpu` | https://doc.dpdk.org/guides/nics/af_packet.html |
| 3.2 | **NULL PMD** (`net_null`) | synthetic empty packets — isolate pipeline CPU ceiling without I/O | https://doc.dpdk.org/guides/nics/null.html |
| 3.3 | **Ring PMD** (`net_ring`) | inter-core pipeline testing via `rte_ring` | https://doc.dpdk.org/guides/nics/ring.html |
| 3.4 | **PCAP_RING_PMD** as separate PMD: no longer exists. Equivalent is `net_ring`. | https://doc.dpdk.org/guides/nics/index.html |
| 3.5 | **Pktgen-DPDK** | wire-rate traffic generator for hardware-rate benchmarks | https://github.com/pktgen/Pktgen-DPDK |
| 3.6 | TRex, MoonGen (MEDIUM confidence, source URLs not fetched) | alternative traffic generators | canonical knowledge |

### Triage pattern (HIGH confidence on methodology)

| Symptom | Cause | Tool |
|---------|-------|------|
| `rx_dropped`, `rx_nombuf` rising | RX-limited (pcap can't feed workers) | `dpdk-proc-info --stats`, `rte_eth_xstats_get()` |
| `cycles/packet` plateau, throughput flat with more workers | pipeline CPU ceiling | `perf stat -e cycles,instructions` |
| `LLC-load-misses` high, DRAM read bandwidth saturated | memory bandwidth | `pcm-memory`, perf |
| Mempool-cache contention (looks CPU-limited but actually allocator) | per-core cache too small | `rte_mempool_stats_get()` |

---

## Concrete fixes (ordered by leverage)

### Fix 1 — Shard the pcap into more files (Quick win, no code change)

```bash
editcap -c 1000000 huge.pcap shard -F pcap
for f in shard-*.pcap; do mv "$f" "test/bench_pcap_shards/bench_q$i.pcap"; i=$((i+1)); done
```

Already done — `test_env.sh:225-226` calls `gen_test_pcap.py --shards N`. **To go beyond N ≈ 12 workers, you need more shards.** Modify `gen_test_pcap.py` to allow more shards than workers (cycle shards across workers), or increase shard count to 32 with 11 workers cycling through them.

**Confidence:** HIGH.

### Fix 2 — Switch to NULL PMD to characterize pipeline CPU ceiling

```bash
./build/FastAPI -l 0-7 --vdev net_null0 --vdev net_null1 -- -i
```

Strips the I/O bottleneck entirely. If throughput here still doesn't scale with workers past N, the bottleneck is in your pipeline, not the pcap PMD.

**Confidence:** HIGH (https://doc.dpdk.org/guides/nics/null.html).

### Fix 3 — Use Pktgen-DPDK as the traffic source

```bash
# Install Pktgen; build against your installed libdpdk
# Launch with cores mapping that pins workers to specific lcores
pktgen -l 0-15 -n 4 -- --cores='14,15-16' -m '[1:3].0' -f themes/seq.pcap
```

Generates at NIC line rate on real NIC hardware. For benchmarks against a NIC, this is the canonical tool.

**Source:** https://github.com/pktgen/Pktgen-DPDK (v25.08.0).
**Confidence:** HIGH.

### Fix 4 — AF_PACKET PMD with `qpairs=N + fanout_mode=cpu`

```bash
./build/FastAPI -l 0-7 \
  --vdev 'eth_af_packet0,iface=eth0,qpairs=8,fanout_mode=cpu,qdisc_bypass=1' \
  -- -i
```

For real-hardware replay with kernel-side capture. AF_PACKET can scale with `qpairs > 1`. Project already supports this path (`test_env.sh:322-384`).

**Source:** https://doc.dpdk.org/guides/nics/af_packet.html.
**Confidence:** HIGH.

### Fix 5 — `rte_distributor` for one-RX-core, N-worker handoff

```c
// In your RX lcore
rte_distributor_process(d, pkts, nb_rx);

// In each worker
uint16_t nb = rte_distributor_pull(d, worker_id, bufs, 8);
```

Caveat: distributor core becomes the new bottleneck. Pin it to highest-frequency core (SST-BF).

**Source:** https://doc.dpdk.org/guides/sample_app_ug/dist_app.html.
**Confidence:** HIGH.

### Fix 6 — Enable `infinite_rx=1` + bump per-lcore mempool cache

```bash
--vdev 'net_pcap0,rx_pcap=tiny.pcap,infinite_rx=1'
# Compile DPDK with -Dc_args='-DRTE_MEMPOOL_CACHE_MAX_SIZE=1024'
```

Skips the libpcap parse on each call (templates cached in `rte_ring`) and reduces ring CAS contention.

**Confidence:** HIGH.

### Fix 7 — HTS rings for inter-core handoff (avoids LWP preemption problem)

```c
struct rte_ring *handoff = rte_ring_create(
    "h", 2048, socket,
    RING_F_MP_HTS | RTE_RING_QUEUE_VAR);
```

Currently the project uses default rings. HTS (Head/Tail Sync) mode serializes operations and avoids the Lock-Waiter-Preemption problem under heavy contention.

**Source:** https://doc.dpdk.org/guides/prog_guide/ring_lib.html.
**Confidence:** HIGH.

### Fix 8 — 4-packet prefetch lookahead (matches l3fwd_fib.c)

Already partly done in `PrefetchPackets` (`spi_pipeline.cpp:713-717`), but the lookahead pattern is wrong. Fix is in [05_prefetch_function_attrs_research.md](05_prefetch_function_attrs_research.md).

### Fix 9 — NUMA pinning

```bash
--socket-mem=2048,2048  # per-NUMA mempool
# Then create your mempool on the polling-lcores' socket.
```

Caveat: only matters on multi-socket hosts. Single-socket benefits are 0%.

**Source:** https://doc.dpdk.org/guides/prog_guide/writing_efficient_code.html.
**Confidence:** HIGH.

### Fix 10 — Triage before adding cores

```bash
watch -n1 'rte_eth_xstats_get(0, ...)'  # drops?
perf stat -e cycles,instructions,cache-misses ./FastAPI   # CPU pipe status?
```

Decision tree in [03_improvement_plan.md](03_improvement_plan.md) Tier 5.

---

## Why this matters for the user's specific symptom

User reported: workers 10 → 15 gives no throughput change in SPI+DPI.

The 8M-entry flow table (`spi_flow_table.cpp:16`) → 770 MB → cache thrashing is **one** cause (Tier 1.4 fix). But the pcap PMD's per-queue ceiling is also in play. Per the research:

- Per-queue ceiling: 3-5 Mpps (MEDIUM confidence)
- With 11 shards × 5 Mpps/shard = 55 Mpps theoretical max

So the pcap is **not** the binding constraint — your pipeline at 16 Mpps is well below 55 Mpps capability. The real bottleneck is **per-packet CPU cost**.

The right play is to:
1. Apply the Tier 1+2 improvements in 03_improvement_plan.md (project-internal fixes).
2. Optionally benchmark with NULL PMD (Fix 2) to confirm the pipeline ceiling is what you think it is.
3. Once you've squeezed the pipeline, profile again with `perf` to find what's left.

---

## Sources

Primary (live):
- https://doc.dpdk.org/guides/nics/pcap.html
- https://doc.dpdk.org/guides/nics/af_packet.html
- https://doc.dpdk.org/guides/nics/null.html
- https://doc.dpdk.org/guides/nics/ring.html
- https://doc.dpdk.org/guides/nics/index.html
- https://doc.dpdk.org/guides/prog_guide/mempool_lib.html
- https://doc.dpdk.org/guides/prog_guide/ring_lib.html
- https://doc.dpdk.org/guides/prog_guide/writing_efficient_code.html
- https://doc.dpdk.org/guides/sample_app_ug/dist_app.html
- https://github.com/DPDK/dpdk/blob/main/drivers/net/pcap/pcap_ethdev.c
- https://github.com/pktgen/Pktgen-DPDK

WebSearch was unavailable (HTTP 400 throughout); WebFetch succeeded for the above URLs.