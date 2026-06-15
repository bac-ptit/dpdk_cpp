# CLAUDE.md — DPDK Project

## Project Overview
DPDK (Data Plane Development Kit) C++ wrapper using modern C++26, zero-overhead abstraction.
Build system: CMake 4.2+, compiler: C++26 with `-fno-exceptions`.

## Build & Compile

### Step 1: Try CLion MCP Build First
Always attempt `mcp__clion__build_project` first:
```
mcp__clion__build_project(projectPath="/home/bac/programming/viettel/dpdk_cpp")
```

### Step 2: Fallback to CLI if MCP Fails
If MCP build fails or returns errors, compile via CLI:
```bash
cd /home/bac/programming/viettel/dpdk_cpp/cmake-build-debug && cmake --build . --target FastAPI
```

### Step 3: Report Results
- If build succeeds: report success
- If build fails: report exact error messages and suggest fixes

## Code Rules

Read ALL rule files before generating or reviewing code:
- `.claude/commands/dpdk-rules.md` — DPDK lifecycle, error handling, RAII
- `.claude/commands/performance-rules.md` — noexcept, zero-overhead, attributes
- `.claude/commands/code-style-rules.md` — Google C++ naming, formatting
- `.claude/commands/modern-cpp-rules.md` — brace init, if-init, expected

## Key Conventions

### Initialization
- Brace init `{}` everywhere: `auto x{42};`, `auto v{func()};`
- Empty constructor drop `{}`: `DpdkConfig config;` NOT `DpdkConfig config{};`
- Member defaults: `int count_{};`, `bool ready_{false};`, `T* ptr_{nullptr};`

### Error Handling
- `std::expected<T, E>` for all fallible operations — NO exceptions
- `noexcept` on ALL functions
- `[[nodiscard]]` on ALL functions returning values
- Macros wrapped in `do { } while (0)`

### Naming (Google C++ Style)
- Files: `snake_case.cpp`
- Types: `CamelCase`
- Functions: `CamelCase`
- Variables: `snake_case`
- Members: `snake_case_` (trailing underscore)
- Constants: `kCamelCase`
- Macros: `ALL_CAPS`

### const
- `const auto` for computed values
- `const auto&` for references (NOT `auto const&`)

### Performance
- Zero-overhead abstraction — wrappers compile to equivalent C code
- `std::format` over string concatenation
- `std::print` / `std::println` over `std::cout`
- `reserve()` when container size is known

## Dependencies
- DPDK: `pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)`
- Glaze: fetched via `FetchContent` (YAML/JSON serialization)
- yaml-cpp: `find_package(yaml-cpp REQUIRED)`

## File Structure
```
main.cpp                    — entry point, config loading
include/
  dpdk/
    dpdk.hpp                — umbrella public include
    dpdk_config.hpp         — config structs (EalConfig, PortConfig, MempoolConfig, L2fwdConfig)
    dpdk_environment.hpp    — Environment class declaration
    dpdk_environment.cpp    — Environment class implementation
```
