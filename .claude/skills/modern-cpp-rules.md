# Modern C++ Rules (C++20/23/26)

## Brace Initialization
- Brace init `{}` everywhere for variables with initial values
- Empty constructor — drop `{}`:
  ```cpp
  DpdkConfig config;     // GOOD — empty ctor
  DpdkConfig config{};   // BAD — redundant
  ```

Example — local variables:
```cpp
const auto args{build_eal_args(config_.eal)};
auto argv{to_c_argv(args)};
const int argc{static_cast<int>(argv.size())};
rte_eth_dev_info dev_info{};
auto local_port_conf{default_port_conf_};
rte_ether_addr mac_addr{};
rte_eth_link link{};
```

Example — member defaults:
```cpp
bool initialized_{false};
rte_mempool* mbuf_pool_{nullptr};
std::uint16_t port_count_{};
```

Example — std::optional and return values:
```cpp
if (mask) {
  const auto port_mask{*mask};
  // ...
}
if (initialized_) return {};  // empty expected
```

## if-init (C++17)
- Limit variable scope to the block where it's used

Example — macro using if-init:
```cpp
#define DPDK_PROPAGATE(expr) \
  do { if (const auto r{expr}; !r) return std::unexpected(r.error()); } while (0)
```

Example — inline error check:
```cpp
if (const auto ret{rte_eth_link_get_nowait(port_id, &link)}; ret < 0) {
  // handle error
}
```

Example — validation:
```cpp
if (auto mask{parse_port_mask(pc.port_mask)}; !mask) {
  return std::unexpected(DpdkError{...});
}
```

## Type Deduction
- `const auto` for computed values that won't change
- `auto` when type is obvious from initializer

Example:
```cpp
const auto args{build_eal_args(config_.eal)};  // type obvious from function
auto argv{to_c_argv(args)};                     // type obvious from function
const auto& mc{config_.mempool};                // const ref alias
auto dev_info{configure_port(port_id, pc)};     // expected<rte_eth_dev_info, DpdkError>
```

## Explicit Types When Needed
- Use explicit width types when size matters: `std::uint16_t`, `std::uint32_t`
- Use explicit types for DPDK API interop: `rte_ether_addr`, `rte_eth_link`

Example:
```cpp
std::uint16_t nb_ports_available{0};
for (std::uint16_t port_id{0}; port_id < port_count_; ++port_id) {
  // ...
}
```

## std::expected (C++23)
- Return type for all fallible operations
- Check with `if (!result)` or propagate with `DPDK_PROPAGATE`

Example — function signature:
```cpp
[[nodiscard]] std::expected<void, DpdkError> init() noexcept;
[[nodiscard]] std::expected<rte_eth_dev_info, DpdkError> configure_port(
  std::uint16_t port_id, const PortConfig& pc) noexcept;
```

Example — usage:
```cpp
auto result{env.init()};
if (!result) {
  std::println(stderr, "DPDK init failed: {}", result.error().message);
  return 1;
}
```

## std::optional (C++17)
- For values that may not exist (parsing, lookup)

Example — parse function:
```cpp
[[nodiscard]] std::optional<std::uint32_t> parse_port_mask(const std::string& mask) {
  if (mask.empty()) return std::nullopt;
  char* end{nullptr};
  const auto val{std::strtoul(mask.c_str(), &end, 16)};
  if (end == mask.c_str() || *end != '\0') return std::nullopt;
  return static_cast<std::uint32_t>(val);
}
```

## std::format (C++20)
- Type-safe string formatting over `printf` / `std::ostringstream`
- Use `{}` placeholders with format specifiers: `{:x}`, `{:>10}`

Example:
```cpp
std::format("{} failed (ret={})", func, ret)
std::format("rte_pktmbuf_pool_create '{}' failed", mc.name)
std::format("Port mask 0x{:x} exceeds available ports (0x{:x})", port_mask, ...)
```

## std::print / std::println (C++23)
- Direct console output — no `std::cout <<` or `printf`

Example:
```cpp
std::print("Checking link status");
std::print(".");
std::println(" done");
std::println("Closing port {}...", port_id);
std::println("DPDK environment cleaned up");
```

## Avoid
- No `using namespace` in headers
- No C-style casts — use `static_cast`, `reinterpret_cast`
- No `NULL` / `0` for null pointers — use `nullptr`
- No `std::endl` — use `"\n"` or `std::println`
- No raw `new` / `delete`
- No `typedef` — use `using`
