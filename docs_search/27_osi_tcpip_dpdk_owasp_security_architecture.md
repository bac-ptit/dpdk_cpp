# Multi-Layer Network & OWASP Security Architecture for DPDK (L2–L7)

- **Date Verified**: 2026-08-02
- **References**:
  - DPDK Programmer's Guide: `librte_ip_frag`, `librte_gro`, `librte_reorder`, `librte_net`
  - OWASP Network Security & Evasion Prevention Guidelines

## 1. OSI / TCP-IP Layer Breakdown & Edge-Case Vulnerabilities

### Layer 2 (Data Link - Ethernet / 802.1Q VLAN)
- **Structure**: `rte_ether_hdr` (14B), `rte_vlan_hdr` (4B 802.1Q / 802.1ad QinQ).
- **Edge Cases**: Double VLAN tagging, Jumbo frames (up to 9600B MTU).
- **Handling**: Hardware VLAN stripping or offset shifting in parser; mempool sized for jumbo frames (`memory_buffer_size = 2176` or `9600`).

### Layer 3 (Network - IPv4 / IPv6)
- **Structure**: `rte_ipv4_hdr` (20-60B), `rte_ipv6_hdr` (40B fixed + Extension Headers).
- **Security Vulnerabilities (OWASP)**:
  - **IP Fragmentation Attacks**: Non-first fragments lack L4 ports, bypassing naive L4 filters.
  - **Tiny Fragment Attack**: Fragments < 8 bytes L4 payload obscure port information.
  - **Overlapping Fragments (Teardrop)**: Malformed overlapping offsets designed to crash kernel or confuse DPI.
  - **Fragment Flood DoS**: Flooding incomplete fragments to exhaust memory pools.
- **DPDK Solution**:
  - `librte_ip_frag` (`rte_ipv4_frag_reassemble_packet` / `rte_ipv6_frag_reassemble_packet`).
  - Per-lcore `rte_ip_frag_tbl` (lockless, thread-safe when paired with RSS flow affinity).
  - Normalization: Drop overlapping fragments, drop tiny fragments, enforce aggressive fragment TTL timeouts.

### Layer 4 (Transport - TCP / UDP)
- **Structure**: `rte_tcp_hdr` (20-60B), `rte_udp_hdr` (8B).
- **Security Vulnerabilities (OWASP)**:
  - **TCP Segmentation & Out-of-Order**: Splitting L7 signatures across TCP segments to evade DPI.
  - **TCP Overlapping Segments (Ptacek & Newsham Evasion)**: Conflicting bytes sent on overlapping sequence numbers to exploit OS-specific reassembly differences (First-write vs Last-write).
  - **SYN Flood / State Exhaustion**: Opening idle connections to fill flow cache tables.
- **DPDK Solution**:
  - `librte_gro` (`rte_gro_reassemble_burst`) for intra-burst TCP segment merging.
  - Flow Table state tracking (SYN -> ESTABLISHED -> FIN/RST) to purge closed connections immediately.
  - Deterministic TCP sequence normalization.

### Layer 7 (Application - DPI: TLS SNI / HTTP Host / DNS)
- **Structure**: TLS ClientHello (`0x16` Handshake, `0x01`), HTTP Request (`Host:` header), DNS queries.
- **Security Vulnerabilities (OWASP)**:
  - **DPI Evasion via Multi-Segment Split**: Spanning `"Host: target.com"` across multiple TCP segments.
  - **Case & Space Obfuscation**: `"hOsT:  domain.com"`.
- **DPDK Solution**:
  - Stream-buffered payload assembly for `l7_required: true` flows before calling `DpiRuleTable::Match()`.
  - Case-insensitive, whitespace-trimmed HTTP/TLS header extraction.

## 2. Integrated Security Architecture

```
[Packet Ingest (rte_eth_rx_burst)]
             │
             ▼
[L2 Ethernet / VLAN Parse]
             │
             ▼
[L3 IP Fragment Check (librte_ip_frag)]
   ├── If Fragmented ──> Reassemble via per-lcore rte_ip_frag_tbl ──┐
   └── If Complete ──────────────────────────────────────────────────┤
                                                                     ▼
                                                  [L4 TCP GRO / Reassembly (librte_gro)]
                                                                     │
                                                                     ▼
                                                  [SPI 5-Tuple Lookup / Flow Table]
                                                                     │
                                                                     ▼
                                                  [L7 DPI Engine (Aho-Corasick / Trie)]
                                                                     │
                                                                     ▼
                                                  [Forward / Drop Action]
```
