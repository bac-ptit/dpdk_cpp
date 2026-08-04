# DPDK ACL Bulk Vectorization & Performance Optimization Plan

**Source**: Verified via DPDK 24.11 documentation (`rte_acl_classify` AVX2/AVX-512 vectorization)  
**Date**: August 2026  

## Finding Overview
DPDK's `rte_acl_classify` utilizes CPU SIMD vector units (AVX2/AVX-512) to classify packets in parallel.
- AVX2 classifies up to 16 packets per vector operation.
- AVX-512 classifies up to 32 packets per vector operation.
- Calling `rte_acl_classify` packet-by-packet (`num_packets = 1`) defeats SIMD vectorization and incurs significant per-call overhead when traversing multiple `AclChunk` tables.

## Applicability to Codebase
1. **Bulk Vectorized Match (`RuleTable::MatchBulk`)**:
   - Files: `include/dpdk/spi/spi_rule_engine.hpp`, `include/dpdk/spi/spi_rule_engine.cpp`, `include/dpdk/spi/spi_pipeline.cpp`.
   - Action: Replace single-packet `Match` with `MatchBulk(std::span<PacketMetadata> burst)` using `num_packets = 32`.

2. **Big-Endian Zero-Copy Preservation**:
   - Files: `include/dpdk/spi/spi_packet_parser.cpp`, `include/dpdk/spi/spi_rule_engine.cpp`.
   - Action: Keep L3/L4 IP/Port fields in Big-Endian format directly from mbuf headers, avoiding 2x `bswap` byte swapping per packet.

3. **Struct Memory Layout & Caching (`alignas(64)`)**:
   - Files: `include/dpdk/spi/spi_rule_engine.hpp`.
   - Action: Order struct fields by decreasing size and apply `alignas(64)` to align with 64-byte L1 cache lines.
