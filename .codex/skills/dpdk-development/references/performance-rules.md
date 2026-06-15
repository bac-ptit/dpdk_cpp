# Performance Rules

## Zero-Overhead Abstraction
- Wrappers MUST compile to equivalent C code — no hidden runtime cost
- Profile before optimizing — do not guess bottlenecks

## noexcept
- `noexcept` on ALL functions in DPDK context
- Enables compiler to skip unwind table generation → smaller code → better cache

Example — every function signature:
```cpp
explicit Environment(DpdkConfig config) noexcept;
~Environment();
[[nodiscard]] std::expected<void, DpdkError> init() noexcept;
[[nodiscard]] std::expected<void, DpdkError> init_eal() noexcept;
[[nodiscard]] std::expected<void, DpdkError> create_mempool() noexcept;
void cleanup() noexcept;
```

## constexpr
- Use `constexpr` for pure helpers that can be evaluated at compile time
- Combine `constexpr` with `noexcept` when the function cannot fail
- Good targets: protocol checks, bit masks, fixed conversions, constants
- Do NOT force `constexpr` onto runtime DPDK calls, config loading, logging, or
  functions that allocate memory

Example — protocol helper:
```cpp
[[nodiscard]] constexpr bool IsTcpOrUdp(std::uint8_t protocol) noexcept {
  return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP;
}
```

Example — fixed mask helper:
```cpp
[[nodiscard]] constexpr std::uint32_t PortMask(std::uint16_t port_id) noexcept {
  return port_id < 32U ? (std::uint32_t{1} << port_id) : 0U;
}
```

## const Correctness
- Use `const auto` for computed values that won't change
- Use `const auto&` for references to avoid copies

Example — computed values:
```cpp
const auto args{build_eal_args(config_.eal)};
auto argv{to_c_argv(args)};
const int argc{static_cast<int>(argv.size())};
```

Example — config alias:
```cpp
const auto& mc{config_.mempool};
const auto num_mbufs{static_cast<unsigned>(
  std::max(mc.num_mbufs, static_cast<std::size_t>(port_count_) * 1024U)
)};
```

## Container Optimization
- `reserve()` when size is known ahead of time

Example:
```cpp
std::vector<std::string> args;
args.reserve(16);
```

```cpp
std::vector<char*> argv;
argv.reserve(args.size());
```

## std::format over string concatenation
- Use `std::format` for error messages — type-safe, no allocations until needed
- Use `std::print` / `std::println` for console output — no `std::endl`

Example — error messages:
```cpp
std::format("{} failed (ret={})", func, ret)
std::format("rte_pktmbuf_pool_create '{}' failed", mc.name)
std::format("Port mask 0x{:x} exceeds available ports (0x{:x})", port_mask, ...)
```

Example — console output:
```cpp
std::print("Checking link status");
std::print(".");
std::println(" done");
std::println("Closing port {}...", port_id);
```

## Avoid
- No `std::endl` — use `"\n"` or `std::println` (avoids unnecessary flush)
- No `std::ostringstream` — use `std::format`
- No heap allocation in per-packet operations
- No virtual dispatch in packet processing hot path
