# DPDK IPv4 & IPv6 Efficient Packet Handling & Profiling

- **Source URLs**:
  - `https://doc.dpdk.org/guides/prog_guide/writing_efficient_code.html`
  - `https://doc.dpdk.org/guides/prog_guide/profile_app.html`
  - `https://doc.dpdk.org/guides/prog_guide/asan.html`
- **Date Verified**: 2026-08-01

## 1. Summary of Findings

### Memory & Header Parsing
- **Zero-Copy Header Access**: Avoid `libc` functions (`memcpy`) or heap allocations (`malloc`) in the packet processing hot path. For single-segment mbufs (`nb_segs == 1`), access headers directly using `rte_pktmbuf_mtod_offset`.
- **Fast Path Branching**: Use inline single-segment bounds check fast-paths (`ReadHeaderFast`), falling back to `rte_pktmbuf_read` only when mbufs are multi-segment (`nb_segs > 1`).
- **IPv4 vs IPv6 Processing**:
  - IPv4 headers (`rte_ipv4_hdr`) have a variable header length (`(version_ihl & 0x0F) * 4`), requiring length validation before L4 offset calculation.
  - IPv6 headers (`rte_ipv6_hdr`) have a fixed 40-byte header size (`sizeof(rte_ipv6_hdr)`), allowing direct constant-offset L4 header reading.

### Data Plane Optimization Guidelines (DPDK Programmer's Guide)
- **Burst Processing**: Process packets in bursts (`rte_eth_rx_burst` / `rte_eth_tx_burst`) to amortize PCIe MMIO tail pointer write costs.
- **Branch Prediction**: Annotate Ethernet type checks (`RTE_ETHER_TYPE_IPV4` and `RTE_ETHER_TYPE_IPV6`) and protocol checks (`IPPROTO_TCP`, `IPPROTO_UDP`) with compiler likelihood attributes (`[[likely]]`, `[[unlikely]]`).
- **Memory Alignment & Cache**: Keep key packet metadata aligned and non-allocating.

### Profiling & AddressSanitizer Integration
- **Profiling (`gprof` / `perf`)**: Profile CPU cycles using `perf top` or `perf record -g` during packet processing benchmark loops.
- **AddressSanitizer (ASan)**: Build with `-fsanitize=address` to detect out-of-bounds packet memory accesses or multi-segment buffer overruns.

## 2. Applicability to Codebase

- `include/dpdk/spi/spi_packet_parser.hpp`: Update `ParsePacket` and helpers to support both IPv4 and IPv6 packets efficiently.
- `include/dpdk/spi/spi_packet_parser.cpp`: Implement `ParseL4Ipv6` for `rte_ipv6_hdr` along with fast-path Ethernet EtherType dispatch for `RTE_ETHER_TYPE_IPV6`.
- `include/dpdk/spi/spi_ip_address.hpp` / `include/dpdk/spi/spi_ip_address.cpp`: Provide high-performance IPv6 address parsing helpers (`ParseIpv6Address`, `ParseIpv6Cidr`).
- `include/helpers/format_helpers.hpp`: Add `FormatIpv6` and update `std::formatter<dpdk::spi::PacketMetadata>` to display IPv6 addresses formatted cleanly.

## 3. Expected Impact

- Enables full dual-stack IPv4/IPv6 classification and packet parsing.
- Zero extra allocations or performance degradation on the IPv4 hot path.
- Low-overhead IPv6 parsing with direct 40-byte offset calculation.
