# DPDK Rules

## Lifecycle Management
- RAII for all DPDK resources — init in constructor, cleanup in destructor
- Cleanup order MUST be reverse of init order
- Non-copyable for resource-owning classes
- `initialized_` guard flag to prevent double-init

Example — constructor takes ownership by move, destructor guards cleanup:
```cpp
Environment::Environment(DpdkConfig config) noexcept : config_{std::move(config)} {}

Environment::~Environment() {
  if (initialized_) {
    cleanup();
  }
}

Environment(const Environment&) = delete;
Environment& operator=(const Environment&) = delete;
```

## Error Handling
- Use `std::expected<T, E>` for all fallible operations — NO exceptions
- Custom error type with message string and DPDK errno
- Propagate errors with macro wrapped in `do { } while (0)`

Example — error type:
```cpp
struct DpdkError {
  std::string message;
  int dpdk_errno{0};
};
```

Example — check `ret < 0` for most `rte_eth_*` APIs:
```cpp
#define DPDK_CHECK_RET(expr, func) \
  do {                             \
    if (const auto ret{(expr)}; ret < 0) { \
      return std::unexpected(DpdkError{ \
        std::format("{} failed (ret={})", func, ret), errno \
      }); \
    } \
  } while (0)
```

Example — check `ret != 0` for `rte_eth_promiscuous_enable`, `rte_eth_dev_info_get`, etc.:
```cpp
#define DPDK_CHECK_RET_NEQ(expr, func) \
  do {                                  \
    if (const auto ret{(expr)}; ret != 0) { \
      return std::unexpected(DpdkError{ \
        std::format("{} failed (ret={})", func, ret), errno \
      }); \
    } \
  } while (0)
```

Example — propagate expected error:
```cpp
#define DPDK_PROPAGATE(expr) \
  do { if (const auto r{expr}; !r) return std::unexpected(r.error()); } while (0)
```

## Initialization Flow
- Ordered steps: `init_eal() → create_mempool() → setup_ports() → check_link_status()`
- Each step is private, returns `std::expected<void, DpdkError>`

Example — orchestrator:
```cpp
std::expected<void, DpdkError> Environment::init() noexcept {
  if (initialized_) return {};  // already initialized, skip

  DPDK_PROPAGATE(init_eal());
  DPDK_PROPAGATE(create_mempool());
  DPDK_PROPAGATE(setup_ports());
  DPDK_PROPAGATE(check_link_status());
  initialized_ = true;

  return {};
}
```

## Config Access
- Use `const auto&` alias to avoid repeated `config_.xxx` access

Example:
```cpp
const auto& mc{config_.mempool};
const auto& pc{config_.port};
```

## Validation
- Validate config values before using them
- Return descriptive error with `std::format`

Example — port mask validation:
```cpp
const auto mask{parse_port_mask(pc.port_mask)};
if (!mask) {
  return std::unexpected(DpdkError{
    std::format("Invalid port mask '{}'", pc.port_mask), 0
  });
}
const auto port_mask{*mask};

if (port_mask & ~((1U << port_count_) - 1U)) {
  return std::unexpected(DpdkError{
    std::format("Port mask 0x{:x} exceeds available ports (0x{:x})",
                 port_mask, (1U << port_count_) - 1U), 0
  });
}
```

## Cleanup
- Best-effort, cannot fail — log errors but continue
- Reverse order of init

Example:
```cpp
void Environment::cleanup() noexcept {
  for (const auto port_id : active_ports_) {
    std::print("Closing port {}...", port_id);
    const int ret{rte_eth_dev_stop(port_id)};
    if (ret != 0) {
      std::print(" rte_eth_dev_stop err={}", ret);
    }
    rte_eth_dev_close(port_id);
    std::println(" Done");
  }

  rte_eal_cleanup();
  std::println("DPDK environment cleaned up");
  initialized_ = false;
}
```
