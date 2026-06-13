# Code Style Rules (Google C++ Style)

## Naming Convention
| Element | Convention | Example |
|---------|-----------|---------|
| Files | `snake_case` | `dpdk_environment.cpp` |
| Types | `CamelCase` | `DpdkConfig`, `Environment`, `DpdkError` |
| Functions | `CamelCase` | `InitEal()`, `GetMemPool()`, `SetupPorts()` |
| Variables | `snake_case` | `port_count`, `mbuf_pool`, `nb_rxd` |
| Constants | `kCamelCase` | `kDefaultBufSize` |
| Namespaces | `lower_case` | `dpdk` |
| Macros | `ALL_CAPS` | `DPDK_CHECK_RET`, `DPDK_PROPAGATE` |
| Members | `snake_case_` (trailing _) | `initialized_`, `config_`, `mbuf_pool_` |

Example — class members:
```cpp
DpdkConfig config_;
bool initialized_{false};
rte_mempool* mbuf_pool_{nullptr};
std::uint16_t port_count_{};
std::vector<std::uint16_t> active_ports_;
std::vector<rte_ether_addr> port_mac_addrs_;
```

## Braces
- K&R style — opening brace on same line

Example:
```cpp
if (mbuf_pool_ == nullptr) {
  return std::unexpected(DpdkError{
    std::format("rte_pktmbuf_pool_create '{}' failed", mc.name),
    errno
  });
}
```

## Includes
- Order: related header → C system → C++ stdlib → other libs → project headers
- Use `#pragma once`

Example:
```cpp
#include "dpdk_environment.hpp"

#include <format>
#include <optional>
#include <print>
```

## Formatting
- 2-space indentation
- 80 character line limit
- Pointer/reference bind to type: `rte_mempool* pool`, not `rte_mempool *pool`

## Classes
- `explicit` on all single-argument constructors
- Non-copyable when owning resources (`= delete`)
- Public → Private member order

Example:
```cpp
class Environment final {
public:
  explicit Environment(DpdkConfig config) noexcept;
  ~Environment();

  Environment(const Environment&) = delete;
  Environment& operator=(const Environment&) = delete;

  [[nodiscard]] std::expected<void, DpdkError> init() noexcept;
  [[nodiscard]] bool is_initialized() const noexcept { return initialized_; }

private:
  // ...
};
```

## Functions
- Short functions: aim for 20-40 lines
- `[[nodiscard]]` on all functions returning values
- Pass by value for small types; `const&` for large

Example — `[[nodiscard]]` on every function with return:
```cpp
[[nodiscard]] std::expected<void, DpdkError> init_eal() noexcept;
[[nodiscard]] std::expected<rte_eth_dev_info, DpdkError> configure_port(
  std::uint16_t port_id, const PortConfig& pc) noexcept;
[[nodiscard]] std::optional<std::uint32_t> parse_port_mask(const std::string& mask);
```

## Anonymous Namespace
- File-local helpers go in `namespace { }` — not `static`

Example — macros and helper functions:
```cpp
namespace {

#define DPDK_CHECK_RET(expr, func) \
  do { ... } while (0)

[[nodiscard]] std::vector<std::string> build_eal_args(const EalConfig& eal) {
  // ...
}

[[nodiscard]] std::optional<std::uint32_t> parse_port_mask(const std::string& mask) {
  // ...
}

}  // namespace
```
