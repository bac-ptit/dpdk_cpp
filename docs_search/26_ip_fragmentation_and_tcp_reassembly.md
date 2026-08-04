# DPDK IP Fragmentation Reassembly (`rte_ip_frag`) & TCP GRO (`rte_gro`)

- **Date Verified**: 2026-08-02
- **Source Headers**: `/usr/include/dpdk/rte_ip_frag.h`, `/usr/include/dpdk/rte_gro.h`

## 1. Overview of Edge-Case Network Handling

In real-world network traffic, packets often arrive fragmented or segmented:
1. **IP Packet Fragmentation**: When IP packets exceed Path MTU, routers or endpoints fragment them across multiple IPv4/IPv6 packets. Non-first fragments lack L4 TCP/UDP headers.
2. **TCP Segmentation / Stream Reassembly**: Large TCP payloads (e.g. TLS ClientHello or HTTP headers) can be split across multiple TCP segments.

## 2. DPDK API Support

### IP Reassembly (`<rte_ip_frag.h>`)
- **Table Allocation**: `rte_ip_frag_table_create(bucket_num, bucket_entries, max_entries, max_cycles, socket_id)`
- **IPv4 Reassembly**: `rte_ipv4_frag_reassemble_packet(tbl, dr, mb, tms, ip_hdr)`
- **IPv6 Reassembly**: `rte_ipv6_frag_reassemble_packet(tbl, dr, mb, tms, ip_hdr)`
- **Fragment Detection**:
  - IPv4: `rte_ipv4_frag_pkt_is_fragmented(const struct rte_ipv4_hdr *ip_hdr)` (checks `fragment_offset` for `MF` bit or non-zero offset).

### TCP GRO - Generic Receive Offload (`<rte_gro.h>`)
- **Burst Reassembly**: `rte_gro_reassemble_burst(pkts, nb_pkts, param)`
- Merges sequential TCP segments of the same flow within a RX burst before passing to pipeline parsing and DPI L7 extraction.

## 3. Implementation Plan for Codebase

- **Worker Context Integration**: Add `rte_ip_frag_tbl*` to `WorkerContext` allocated per-worker lcore on socket NUMA node.
- **Parsing Flow**:
  1. Inspect `rte_ipv4_hdr` / `rte_ipv6_hdr` in `ParsePacket`.
  2. If `rte_ipv4_frag_pkt_is_fragmented` is true:
     - Delegate packet to `rte_ipv4_frag_reassemble_packet`.
     - If reassembly is incomplete, return `std::nullopt` (waiting for remaining fragments).
     - Once reassembled, parse complete L4 headers.
  3. Pre-process TCP bursts using `rte_gro_reassemble_burst` for DPI stream reassembly.
