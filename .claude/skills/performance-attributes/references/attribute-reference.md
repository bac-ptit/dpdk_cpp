# Performance Attribute Reference

Complete reference for C++23/C++26 and GCC performance attributes applicable to DPDK projects.

## Table of Contents

1. [GCC Function Attributes](#gcc-function-attributes)
2. [C++ Standard Attributes](#c-standard-attributes)
3. [Alignment and Cache](#alignment-and-cache)
4. [Branch Prediction](#branch-prediction)
5. [Advanced](#advanced)

---

## GCC Function Attributes

### `[[gnu::hot]]`

Marks a function as hot — GCC places its code in `.text.hot` section for better I-cache utilization.

```cpp
[[gnu::hot]] int WorkerLoop(void* arg) noexcept {
  auto* context = static_cast<WorkerContext*>(arg);
  while (*context->force_quit == 0) {
    ProcessWorkerIteration(*context, ...);
  }
  return 0;
}
```

### `[[gnu::cold]]`

Marks a function as cold — GCC places its code in `.text.unlikely` section, keeping it out of I-cache.

```cpp
[[gnu::cold]] void DropPacket(BurstCounters& counters, rte_mbuf* packet) noexcept {
  ++counters.dropped;
  rte_pktmbuf_free(packet);
}
```

### `[[gnu::flatten]]`

GCC recursively inlines ALL functions called within the marked function. Creates one monolithic function.

```cpp
[[gnu::hot, gnu::flatten]]
void ProcessPortBurst(WorkerContext& context,
                      const std::vector<std::uint16_t>& active_ports,
                      std::uint16_t port_id, ...) noexcept {
  const auto received{rte_eth_rx_burst(port_id, queue_id, packets.data(), burst_size)};
  for (std::uint16_t i{0}; i < received; ++i) {
    ForwardPacket(context, active_ports, counters, packets[i], ...);
  }
  FlushTransmitBuffers(context, transmit_buffers, transmit_counts, counters);
}
```

**Effect**: GCC inlines `ForwardPacket` → `ClassifyPacket` → `ParsePacket` → `ReadHeader` → `FlowTable::Lookup` → `RuleTable::Match` all into `ProcessPortBurst`.

### `[[gnu::always_inline]]`

Force inlining. Must be used with `inline` keyword.

```cpp
// In header (for member functions)
[[gnu::always_inline]] inline FlowEntry* Lookup(const FlowKey& key) noexcept {
  if (hash_ == nullptr) [[unlikely]] return nullptr;
  const auto result{rte_hash_lookup(hash_, &key)};
  if (result < 0) [[unlikely]] return nullptr;
  return &entries_[static_cast<std::size_t>(result)];
}

// In anonymous namespace (for helpers)
template <typename Header>
[[nodiscard, gnu::always_inline]] inline bool ReadHeader(
    const rte_mbuf& packet, std::uint32_t offset, Header& header) noexcept {
  const void* data{rte_pktmbuf_read(&packet, offset, sizeof(Header), &header)};
  if (data == nullptr) [[unlikely]] return false;
  if (data != &header) header = *static_cast<const Header*>(data);
  return true;
}
```

### `[[gnu::optimize("O3")]]`

Per-function optimization level override.

```cpp
// Global is -O2, but this function needs -O3 auto-vectorization
[[gnu::optimize("O3"), gnu::hot]]
std::uint32_t HashPacketFlow(const rte_mbuf& packet, std::uint16_t port) noexcept {
  // FNV-1a hash — benefits from -O3 vectorization
  ...
}
```

### `[[gnu::target("avx2")]]`

Target specific ISA extension for a function.

```cpp
[[gnu::target("avx2"), gnu::hot]]
std::uint32_t BatchHash(const std::uint32_t* data, std::size_t len) noexcept {
  // AVX2 codegen for this function only
}
```

### `[[gnu::target_clones("default","avx2")]]`

Runtime dispatch — GCC generates multiple versions and selects at runtime.

```cpp
[[gnu::target_clones("default", "avx2"), gnu::hot]]
std::uint32_t HashPacketFlow(...) noexcept {
  // GCC creates two versions: default and AVX2
  // Runtime selects based on CPU capabilities
}
```

---

## C++ Standard Attributes

### `[[assume(expr)]]` (C++23)

Tells the compiler about invariants for optimization. **False assumption = UB.**

```cpp
// After successful burst receive
const auto received{rte_eth_rx_burst(...)};
[[assume(received <= kMaxBurstCapacity)]];

// After bounds check
if (transmit_port >= transmit_buffers.size()) [[unlikely]] return;
[[assume(transmit_port < transmit_buffers.size())]];

// After ReadHeader succeeds
if (!ReadHeader(packet, 0, ether_hdr)) [[unlikely]] return std::nullopt;
[[assume(rte_pktmbuf_data_len(&packet) >= sizeof(rte_ether_hdr))]];
```

### `[[nodiscard]]`

Warns if return value is ignored. Already used extensively in this project.

```cpp
[[nodiscard]] std::expected<void, DpdkError> init() noexcept;
[[nodiscard]] const RuleTable* Load() const noexcept;
[[nodiscard]] FlowEntry* Lookup(const FlowKey& key) noexcept;
```

### `[[no_unique_address]]` (C++20)

Empty member optimization — zero size for stateless types.

```cpp
struct DropPolicy {
  void operator()(rte_mbuf* p) const noexcept { rte_pktmbuf_free(p); }
};

struct ForwardingContext {
  [[no_unique_address]] DropPolicy drop_policy{};  // 0 bytes if stateless
  const RuleTable* rules{};
  // ...
};
```

---

## Alignment and Cache

### `alignas(64)` — Cache-Line Alignment

Prevent false sharing between cores.

```cpp
// Atomic counters — each field on same cache line
struct alignas(64) AtomicCounters {
  std::atomic<std::uint64_t> received{};
  std::atomic<std::uint64_t> transmitted{};
  // ...
};

// Per-worker context — workers must not share cache lines
struct alignas(64) WorkerContext {
  const RuleTableManager* rule_manager{};
  FlowTable* flow_table{};
  // ...
};

// Flow entries — if accessed by multiple workers
struct alignas(64) FlowEntry {
  Action action{Action::kForward};
  std::uint64_t match_count{};
  // ...
};
```

---

## Branch Prediction

### `[[likely]]` / `[[unlikely]]` (C++20)

```cpp
// Error checks — unlikely to fail
if (!ReadHeader(packet, 0, ether_hdr)) [[unlikely]] return std::nullopt;
if (result < 0) [[unlikely]] return nullptr;
if (hash_ == nullptr) [[unlikely]] return nullptr;

// Dominant paths — likely to match
if (ether_type == RTE_ETHER_TYPE_IPV4) [[likely]] { ... }
if (next_proto == IPPROTO_TCP) [[likely]] { ... }
if (auto* cached = Lookup(key)) [[likely]] { ... }
```

### `__builtin_expect_with_probability` (GCC extension)

Fine-grained probability — only when `[[likely]]`/`[[unlikely]]` is insufficient.

```cpp
// 95% of packets are TCP in this deployment
if (__builtin_expect_with_probability(
        ipv4_hdr.next_proto_id == IPPROTO_TCP, 1, 0.95)) {
  return ParseL4<rte_tcp_hdr>(...);
}
```

---

## Advanced

### `std::start_lifetime_as` (C++23)

Zero-copy type punning for packet buffers. Use only when alignment is guaranteed.

```cpp
// Current approach (safe, involves copy):
rte_ether_hdr ether_hdr{};
if (!ReadHeader(packet, 0, ether_hdr)) { return std::nullopt; }

// Alternative (zero-copy, requires alignment guarantee):
auto* ether_hdr = std::start_lifetime_as<rte_ether_hdr>(
    rte_pktmbuf_mtod(&packet, void*));
```

**Note**: DPDK mbufs are 2-byte aligned. Only use when alignment is verified.

### `consteval` (C++20)

Force compile-time evaluation. Catches config errors at build time.

```cpp
[[nodiscard]] consteval Protocol MustParseProtocol(std::string_view protocol) {
  if (protocol == "tcp") return Protocol::kTcp;
  if (protocol == "udp") return Protocol::kUdp;
  std::unreachable();  // compile error if not tcp/udp
}
```

### GCC Vector Extensions (alternative to std::simd)

```cpp
// 8x uint32_t SIMD vector
using v8su = std::uint32_t __attribute__((vector_size(32)));

v8su BatchHash(const v8su& ips) {
  constexpr v8su kFnvPrime{16777619U, 16777619U, 16777619U, 16777619U,
                           16777619U, 16777619U, 16777619U, 16777619U};
  v8su hashes = v8su{2166136261U};
  hashes ^= ips;
  hashes *= kFnvPrime;
  return hashes;
}
```
