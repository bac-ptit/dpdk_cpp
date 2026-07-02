---
name: performance-attributes
description: >
  Apply C++23/C++26 and GCC performance attributes to DPDK packet-processing code.
  Use when: (1) optimizing hot-path functions for throughput, (2) adding branch prediction
  hints, (3) forcing inlining on per-packet helpers, (4) marking hot/cold functions for
  I-cache optimization, (5) using [[assume]] for compiler optimization hints.
  Triggers: "optimize performance", "add attributes", "hot path", "inline", "branch prediction",
  "I-cache", "assume", "flatten", "performance tuning".
---

# C++23/C++26 Performance Attributes for DPDK

Apply GCC and C++ standard attributes to maximize packet-processing throughput.

## Decision Tree

1. **Function is in per-packet call tree** → `[[gnu::hot]]`
2. **Function is error/init/cleanup path** → `[[gnu::cold]]`
3. **Small helper called per-packet** → `[[gnu::always_inline]]`
4. **Top-level burst function** → `[[gnu::hot, gnu::flatten]]`
5. **Branch with known dominant path** → `[[likely]]` / `[[unlikely]]`
6. **Invariant the compiler can't deduce** → `[[assume(expr)]]`
7. **Struct shared across cores** → `alignas(64)`
8. **Empty policy/stateless member** → `[[no_unique_address]]`

## Hot/Cold Classification

```cpp
// Hot — per-packet call tree
[[gnu::hot]] void ProcessPortBurst(...) noexcept { ... }
[[gnu::hot]] void ForwardPacket(...) noexcept { ... }
[[gnu::hot]] PacketClassification ClassifyPacket(...) noexcept { ... }
[[gnu::hot]] void FlushTransmitBuffers(...) noexcept { ... }
[[gnu::hot]] int WorkerLoop(void* arg) noexcept { ... }

// Cold — error paths, init, cleanup
[[gnu::cold]] void DropPacket(...) noexcept { ... }
[[gnu::cold]] void MaybeReload(...) noexcept { ... }
```

## Force Inlining

```cpp
// On function definition (header or .cpp)
[[gnu::always_inline]] inline FlowEntry* Lookup(const FlowKey& key) noexcept { ... }

// On template helpers in anonymous namespace
template <typename Header>
[[nodiscard, gnu::always_inline]] inline bool ReadHeader(
    const rte_mbuf& packet, std::uint32_t offset, Header& header) noexcept { ... }
```

**Rule**: Use `[[gnu::always_inline]]` only on small (<20 line) per-packet helpers.
The compiler inlines most things with `-O2`/`-O3` — this is a guarantee, not a hint.

## Flatten (Recursive Inlining)

```cpp
// Apply to ONE top-level burst function only.
// GCC inlines ALL called functions into one monolithic function.
[[gnu::hot, gnu::flatten]]
void ProcessPortBurst(WorkerContext& context, ...) noexcept {
  // GCC inlines: PrefetchPackets, ForwardPacket, ClassifyPacket,
  // ParsePacket, FlowTable::Lookup, RuleTable::Match, EnqueuePacket
}
```

**Caution**: `flatten` causes code bloat. Apply to at most 1-2 functions.
Validate with `perf stat -e L1-icache-load-misses` before/after.

## Branch Prediction

```cpp
// In packet parser — most packets are IPv4
if (ether_type != RTE_ETHER_TYPE_IPV4) [[unlikely]] {
  return std::nullopt;
}

// TCP is dominant protocol
if (next_proto == IPPROTO_TCP) [[likely]] {
  return ParseL4<rte_tcp_hdr>(...);
}

// Flow cache hit is common
if (auto* cached = flow_table->Lookup(key)) [[likely]] {
  return cached->action;
}

// Hash miss / empty slot
if (result < 0) [[unlikely]] return nullptr;
```

## Compiler Assumptions

```cpp
// After ReadHeader succeeds, buffer is large enough
if (!ReadHeader(packet, 0, ether_hdr)) [[unlikely]] return std::nullopt;
[[assume(rte_pktmbuf_data_len(&packet) >= sizeof(rte_ether_hdr))]];

// After bounds check
[[assume(transmit_port < transmit_buffers.size())]];

// After burst receive
[[assume(received <= kMaxBurstCapacity)]];
```

**Rule**: Only assume invariants that are PROVABLY true by construction.
False assumption = undefined behavior.

## Cache-Line Alignment

```cpp
// AtomicCounters — accessed by multiple cores
struct alignas(64) AtomicCounters { ... };

// WorkerContext — one per worker, must not share cache lines
struct alignas(64) WorkerContext { ... };

// FlowEntry — if shared across workers
struct alignas(64) FlowEntry { ... };
```

## Full Attribute Reference

See [references/attribute-reference.md](references/attribute-reference.md) for the complete
list of applicable C++23/C++26 and GCC attributes with detailed examples.
