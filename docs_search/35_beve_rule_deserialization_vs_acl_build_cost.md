# 35. BEVE Binary Rule Stream Deserialization vs. DPDK ACL Rule Compilation Overhead

**Verified Date:** 2026-08-04  
**Sources:**  
- Codebase files: `include/dpdk/config/dpdk_config_loader.cpp`, `include/dpdk/spi/spi_rule_engine.cpp`
- Glaze Library C++ Serialization Architecture

---

## 1. Overview of the Question

When loading rules via `rule_path` using `.beve` binary format (`glz::read_file_beve`), is there still a string parsing cost during startup?

---

## 2. Technical Findings

1. **BEVE Stores Config Structs with `std::string` Fields**:
   - Glaze binary format (`.beve`) serializes the high-level C++ configuration structures (`SpiFilterConfig`).
   - `SpiFilterConfig` contains string members such as `destination_ip_address` (`std::optional<std::string>`), `source_ip_address`, and `protocol` (e.g. `"31.13.64.0/18"`, `"tcp"`).
   - Therefore, deserializing `.beve` avoids YAML text tokenizing, but still instantiates millions of `std::string` objects on the C++ heap.

2. **Secondary Conversion Step (`CompileFilter`)**:
   - `rte_acl_build()` requires native binary numeric ranges (`uint32_t` IPv4 address, netmask, `uint16_t` port ranges, `uint8_t` protocol).
   - In [`spi_rule_engine.cpp`](file:///home/bac/programming/viettel/dpdk_cpp/include/dpdk/spi/spi_rule_engine.cpp#L188-L235), `CompileFilter` must execute:
     - `ParseIpv4Address()` / `inet_pton` to convert `"192.168.1.1"` into `uint32_t` integer values.
     - `ParseCidr()` to find `/`, split prefix string, and generate binary bitmasks.
     - `ParseProtocol()` string comparison (`"tcp"` / `"udp"`).
   - For 8.38M rules, executing 8.38M `ParseIpv4Address` + `ParseCidr` conversions on C++ strings retains substantial CPU overhead.

3. **Optimization Strategy**:
   - To eliminate 100% of IPv4 string conversion overhead, pre-compile binary rules directly into native `struct rte_acl_rule` or binary `uint32_t` structs before saving to `.beve`.
