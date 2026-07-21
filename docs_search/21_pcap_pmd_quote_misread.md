# 21 — pcap PMD "Special iface case" quote misread

**Source:** https://github.com/DPDK/dpdk/blob/main/drivers/net/pcap/pcap_ethdev.c
**Verified:** 2026-07-19 (DPDK main + v25.11 branches)
**Affects:** scaling analysis of `pixi run bench` and any root-cause reasoning
that pins throughput sub-linearity on a "pcap handle contention" hypothesis.

## Finding (1 paragraph)

The quote **"Special iface case. Single pcap is open and shared between
tx/rx."** that appears in `eth_dev_start()` and `eth_dev_stop()` of the DPDK
net_pcap PMD documents the **`single_iface` exception path**, not the general
case. That path is taken only when the vdev is configured with the
`iface=<name>` argument (one live interface shared between TX queue 0 and RX
queue 0). In the **multi-queue mode used by this project** — 15 separate
`rx_pcap=/path/bench_qN.pcap` shards in `config.yaml` — `pmd_pcap_probe`
calls `open_rx_pcap` once per `rx_pcap=` argument, each call invokes
`pcap_open_offline` (or `pcap_open_live`) and produces a fresh `pcap_t *`,
then `eth_from_pcaps_common` writes that handle into
`pp->rx_pcap[queue_id]` — one queue, one handle per argument. Therefore the
"shared handle" pathology the quote describes **does not exist in this
project's setup**: every lcore/worker polls its own dedicated pcap_t and
there is no cross-lcore libpcap state to corrupt.

## Source code evidence (DPDK main, verified)

`pmd_pcap_probe` / `open_rx_pcap` / `add_queue`:
```c
static int
open_rx_pcap(const char *key, const char *value, void *extra_args) {
    ...
    if (open_single_rx_pcap(pcap_filename, &pcap) < 0)
        return -1;
    if (add_queue(rx, pcap_filename, key, pcap, NULL) < 0) { ... }
    return 0;
}
ret = rte_kvargs_process(kvlist, ETH_PCAP_RX_PCAP_ARG,
                         &open_rx_pcap, &pcaps);
```

`eth_from_pcaps_common`:
```c
for (i = 0; i < nb_rx_queues; i++) {
    struct pcap_rx_queue *rx = &(*internals)->rx_queue[i];
    struct devargs_queue *queue = &rx_queues->queue[i];
    pp->rx_pcap[i] = queue->pcap;   // <-- separate pcap_t per queue
    ...
}
```

The `single_iface` branch in `eth_dev_start` (the one that contains the
quoted comment) is gated by `internals->single_iface`, which is set true
only via the `iface=` devargs path (`ETH_PCAP_IFACE_ARG == "iface"`), not
via the `rx_pcap=` path. The project's `config.yaml` vdev line uses
`rx_pcap=...` fifteen times plus `infinite_rx=1`; there is no `iface=`
token, so `single_iface` is false at start.

## What is true vs. what is unsupported

| Sub-claim | Status | Evidence |
|---|---|---|
| "No per-queue lock in pcap PMD datapath" | TRUE | No mutex/spinlock/rwlock anywhere in `pcap_ethdev.c`. The only atomic is `eof_signaled`. |
| "`pcap_next_ex()` / `pcap_sendpacket()` invoked directly" | TRUE | `eth_pcap_rx` and `eth_pcap_tx` call them without wrappers. |
| "Each pcap_t must be polled by exactly one lcore" | TRUE — but **this is the general DPDK convention** (one queue polled by one lcore), **not a libpcap-specific quirk**. The cited quote does not assert this. | DPDK Programmer's Guide §"Driver RX/TX callbacks". |
| "Or libpcap state machine will corrupt internal offsets and replay packets out of order" | UNSUPPORTED speculation | Libpcap's man page says concurrent `pcap_next_ex` on the same handle is undefined, but the specific mechanism ("corrupt internal offsets", "replay out of order") is not documented by either DPDK or libpcap. The "replay" framing is wrong: pcap_open_offline streams each packet once and never replays. |
| Quote supports the claim | FALSE | Quote documents the `iface=` exception where one handle is shared between TX and RX. The project does not use `iface=`. |

## Applicability to this codebase

- `config.yaml` — virtual_devices entry uses `rx_pcap=...` x15 + `infinite_rx=1`,
  no `iface=`. See /home/bac/programming/viettel/dpdk_cpp/config.yaml
  (lines for `virtual_devices`).
- `include/dpdk/dpdk_environment.cpp` — `BuildEalArgs` (around L108-111)
  forwards each `virtual_devices` entry as `--vdev <string>`. No code
  touches the `single_iface` path.
- `include/dpdk/pcap/pcap_replay.cpp` — the project's *secondary* pcap
  path (in-memory injection) uses `pcap_open_offline` once per
  `PcapReader`; the bench config does not enable `pcap_injector`, so
  these readers are not on the hot path during `pixi run bench`.

## Implication for the 32.90 → 72.70 Mpps scaling question

The pcap-PMD-handle-contention hypothesis (and its supporting quote) does
not explain the 2.21x / 3.75x shortfall. Each of the 15 shards is opened
once and read by exactly one lcore, which is the correct pattern. Other
bottlenecks worth investigating (per the broader research question):

1. Per-lcore `rte_hash` flow table — does it scale linearly or does
   `rte_hash` contention show up?
2. `rte_mempool` cache sizing vs. burst size for hot-path allocation
   pressure at 15 workers.
3. ACL (`rte_acl_classify`) SIMD path on WSL2 (no AVX-512).
4. WSL2 virtual-clock / `infinite_rx=1` pcap re-read serialization.
5. SMT / single-socket WSL2 topology — all lcores on one die.

## Measured impact

N/A — the hypothesis is falsified at the source-code level. Recommended
follow-up: per-worker `rte_eth_stats_get` counters and per-worker
`rte_mempool` cache stats to localize the real scaling ceiling before
proposing further pcap-PMD changes.