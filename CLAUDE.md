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
- `.claude/skills/dpdk-rules.md` — DPDK lifecycle, error handling, RAII
- `.claude/skills/performance-rules.md` — noexcept, zero-overhead, attributes
- `.claude/skills/code-style-rules.md` — Google C++ naming, formatting
- `.claude/skills/modern-cpp-rules.md` — brace init, if-init, expected
- `.claude/skills/custom-formatter/SKILL.md` — std::formatter<T> conventions
- `.claude/skills/performance-attributes/SKILL.md` — C++23/C++26 + GCC performance attributes

## Research & Documentation

When searching the internet for information that could help the DPDK project:

1. **Verify the source**: Use `WebSearch` (Web) and `WebFetch` to confirm the
   finding is authoritative (DPDK docs, GitHub issues, vendor blogs).
2. **Confirm applicability**: Check that the finding applies to THIS
   project's DPDK version (check `/usr/include/rte_*.h` for API symbols,
   not just the latest DPDK).
3. **Save useful findings**: If the research yields a non-trivial insight
   (a new optimization, an API constraint, a perf tip, etc.), save it as
   a markdown file under `docs_search/` so future sessions can reference
   it without re-doing the research.

   Naming convention: `docs_search/<NN_short_topic>.md` where `NN` is a
   zero-padded index (e.g., `09_dpi_tls_extraction_cost.md`).

   Each file should include:
   - Source URL(s) and date verified
   - The finding (1-3 paragraphs)
   - Whether/how it applies to this codebase (specific files/lines)
   - Measured impact or expected impact if applicable

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

## Namespaces

| Namespace | Purpose |
|-----------|---------|
| `dpdk` | Core EAL, environment, signals |
| `dpdk::config` | Config structs, YAML loader |
| `dpdk::spi` | SPI (L3/L4) packet classification |
| `dpdk::dpi` | DPI (L7) hostname/URI classification |

## Architecture

### SPI Rule System (Hierarchical ACL)

```
filter_groups (sorted by precedence ASC):
  ┌─ fg_l34_facebook (precedence=100, action=forward)
  │    ├─ filter: 31.13.64.0/18, tcp
  │    └─ filter: 157.240.0.0/16, tcp
  ├─ fg_l34_dns (precedence=104, action=drop)
  │    ├─ filter: port=53, udp
  │    └─ filter: port=53, tcp

Packet → FlowTable.Lookup(5-tuple)
  HIT → cached action (skip SPI)
  MISS → RuleTable.Match(groups in precedence order)
       → FlowTable.Insert(result)
       → forward or drop
```

### Double-Buffer Hot-Reload

- `RuleTableManager` — atomic pointer swap, zero hot-path overhead
- `SIGUSR1` → `kill -USR1 $(pidof FastAPI)` triggers config reload
- Main lcore polls `ReloadFlag()` in idle loop
- Workers load fresh pointer per batch — no locks, no contention

## File Structure
```
main.cpp                          — entry point, config loading
include/
  dpdk/
    dpdk.hpp                      — top-level umbrella (includes all subfolders)
    dpdk_environment.hpp/cpp      — Environment class (EAL, mempool, ports)
    app_signal.hpp/cpp            — signal handlers (SIGINT, SIGTERM, SIGUSR1)
  helpers/
    format_helpers.hpp            — all std::formatter<T> specializations
  config/
    config.hpp                    — umbrella for config/
    dpdk_config.hpp               — config structs (SpiFilterGroupConfig, etc.)
    dpdk_config_loader.hpp/cpp    — LoadConfig(), ValidateConfig()
  spi/
    spi.hpp                       — umbrella for spi/
    spi_rule_engine.hpp/cpp       — CompiledFilterGroup, RuleTable, Match()
    spi_rule_table_manager.hpp    — double-buffer RuleTableManager
    spi_flow_table.hpp/cpp        — FlowTable (rte_hash flow cache)
    spi_packet_parser.hpp/cpp     — ParsePacket(), L7 extraction
    spi_ip_address.hpp/cpp        — ParseIpv4Address(), ParseCidr()
    spi_pipeline.hpp/cpp          — Pipeline, WorkerContext, PipelineStats
  helpers/
    format_helpers.hpp            — all std::formatter<T> specializations
  dpi/
    dpi.hpp                       — umbrella for dpi/
    dpi_rule_engine.hpp/cpp       — DpiRuleTable, hostname matching
```

## Dynamic Config Reload

```bash
# Edit config.yaml
vim /path/to/config.yaml

# Send reload signal
kill -USR1 $(pidof FastAPI)

# App automatically:
# 1. Main lcore detects flag
# 2. LoadConfig() — parse new YAML
# 3. CompileRuleTable() — build new rule table
# 4. RuleTableManager::Swap() — atomic pointer swap
# 5. Print: "Rules reloaded: 5 groups, 13 filters"
```
