---
name: docs-generator
description: Use when creating, updating, reviewing, or generating project documentation with Doxygen for this C/C++ DPDK repository, including adding Doxygen comments to headers/sources, maintaining Doxyfile settings, producing HTML API docs, and fixing Doxygen warnings.
---

# Docs Generator

## Workflow

1. Inspect public headers first, then implementation files.
2. Document public APIs before private helpers.
3. Use Doxygen comments that describe contract, ownership, lifetime, errors, and thread-safety where relevant.
4. Run `doxygen Doxyfile` after changing comments or `Doxyfile`.
5. Treat Doxygen warnings as documentation defects unless the warning comes from generated or third-party code.

## Comment Style

Use `///` for short declarations and `/** ... */` for longer API contracts.

```cpp
/// Short one-line summary.
[[nodiscard]] bool IsInitialized() const noexcept;
```

```cpp
/**
 * @brief Initialize EAL, mempool, ports, and link checks.
 *
 * @return Empty success value, or a DpdkError describing the failed step.
 *
 * @pre The environment has not already been initialized.
 * @post DPDK resources are available until destruction or cleanup.
 */
[[nodiscard]] std::expected<void, DpdkError> Init() noexcept;
```

Prefer these tags:

- `@brief` for every public type, function, enum, and non-obvious field.
- `@param` for each parameter whose meaning is not obvious from its name.
- `@return` for non-void functions, especially `std::expected`.
- `@pre`, `@post`, and `@warning` for DPDK lifecycle constraints.
- `@note` for performance, ownership, or threading details.
- `@code{.cpp}` only for examples that compile or closely match the repo style.

## Repository Rules

- Document headers in `include/` as the main API surface.
- Keep comments concise; do not restate the exact C++ type or function name.
- For DPDK resources, state who owns the resource and when it is valid.
- For `std::expected<T, DpdkError>`, describe both success and failure conditions.
- For `noexcept` functions, document any best-effort cleanup behavior instead of implying exceptions.
- Do not document build directories, IDE files, `.codex`, `.claude`, or generated docs.

## Generation

Use the root `Doxyfile`:

```bash
doxygen Doxyfile
```

Open the generated HTML from:

```text
docs/doxygen/html/index.html
```

If warnings appear, fix missing comments, stale references, invalid `@param` names, or unsupported Markdown before considering `Doxyfile` changes.
