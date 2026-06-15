# Codex Project Instructions

This project is a C++ DPDK wrapper using modern C++26 and zero-overhead
abstractions.

## Build

Prefer the configured IDE build when available. If using the CLI, build from the
repository build directory for this project:

```bash
cmake --build /home/bac/programming/viettel/dpdk_cpp/cmake-build-debug
```

## Code Rules

Before generating, reviewing, or refactoring C++ DPDK code, use the
`dpdk-development` skill and read all rule files under:

```text
.codex/skills/dpdk-development/references/
```

## Key Conventions

- Brace init `{}` for initialized variables.
- Empty constructors do not use redundant `{}`.
- Use `std::expected<T, E>` for fallible operations; do not throw exceptions.
- Add `noexcept` to DPDK-context functions.
- Add `[[nodiscard]]` to functions returning values.
- Wrap macros in `do { } while (0)`.
- Use Google-style naming from the skill references.
- Use `const auto` for computed values and `const auto&` for references.
- Preserve zero-overhead abstractions in hot paths.
- Use `std::format`, `std::print`, and `std::println` instead of stream-based
  formatting.
- Call `reserve()` when container size is known.

## Dependencies

- DPDK: `pkg_check_modules(DPDK REQUIRED IMPORTED_TARGET libdpdk)`
- Glaze: fetched via `FetchContent`
- yaml-cpp: `find_package(yaml-cpp REQUIRED)`
