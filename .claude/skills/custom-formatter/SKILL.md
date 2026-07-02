---
name: custom-formatter
description: >
  Generate std::formatter specializations for C++20/26 types.
  Use when: (1) user asks to make a type printable with std::format/std::print,
  (2) user provides a struct/class and wants a custom formatter,
  (3) user needs format specifiers (e.g. {:k} for key-only, {:v} for value-only),
  (4) user says "create formatter", "make this formattable", "add std::format support".
---

# Custom std::formatter Generator

Generate `std::formatter<T>` specializations following project conventions.

## Quick Start — Simple Formatter

For types that need a fixed output format (no custom specifiers):

```cpp
// In format_helpers.hpp, after the type definition:
template <>
struct std::formatter<MyType> : std::formatter<std::string_view> {
  auto format(const MyType& val, std::format_context& ctx) const {
    return std::format_to(ctx.out(), "field={}", val.field);
  }
};
```

Key rules:
- Always `struct` (not `class`) for the specialization
- Inherit from `std::formatter<std::string_view>` as base
- Return type is `auto` — deduced from `std::format_to`
- Use `std::format_to(ctx.out(), ...)` to write output
- Place in `include/dpdk/format_helpers.hpp` (project convention)

## Formatter with Custom Format Specifiers

For types needing user-controlled output modes (e.g. key-only vs full output).

See [references/custom-specifier-pattern.md](references/custom-specifier-pattern.md) for the full `parse()` + `format()` pattern with `OutputType` enum, multi-colon sub-formatter delegation, and validation.

### When to Use Custom Specifiers

- Type has distinct "views" (key vs value vs full)
- User wants alignment/format control per sub-field
- Type wraps two formattable sub-values with independent formatting

### Minimal Example

```cpp
template <>
struct std::formatter<KeyValue> {
  constexpr auto parse(auto& context) {
    // Parse '{:b}' for both, '{:k}' for key, '{:v}' for value
    auto iter = begin(context);
    if (iter != end(context) && *iter != '}') {
      switch (*iter) {
        case 'k': case 'K': m_mode = Mode::Key; ++iter; break;
        case 'v': case 'V': m_mode = Mode::Value; ++iter; break;
        case 'b': case 'B': m_mode = Mode::Both; ++iter; break;
        default: throw std::format_error{"Invalid KeyValue format"};
      }
    }
    if (iter != end(context) && *iter != '}') {
      throw std::format_error{"Invalid KeyValue format"};
    }
    return iter;
  }

  auto format(const KeyValue& kv, auto& ctx) const {
    switch (m_mode) {
      case Mode::Key:   return std::format_to(ctx.out(), "{}", kv.key);
      case Mode::Value: return std::format_to(ctx.out(), "{}", kv.value);
      default:          return std::format_to(ctx.out(), "{} - {}", kv.key, kv.value);
    }
  }

private:
  enum class Mode { Key, Value, Both };
  Mode m_mode{Mode::Both};
};
```

## Decision Tree

1. **Type is an enum** → simple switch in `format()`, no `parse()` override needed
2. **Type has one natural representation** → inherit `std::formatter<std::string_view>`, override `format()` only
3. **Type needs user-controlled output modes** → override both `parse()` and `format()`, use enum for mode selection
4. **Sub-fields need independent format control** → use the multi-colon pattern from the reference file

## Project Conventions

- File location: `include/helpers/format_helpers.hpp`
- Include after the type's own header
- `#pragma once` at top (already present)
- Helper functions (e.g. `FormatIpv4`) go in `namespace dpdk`
- Specializations go in global scope (outside namespace), after `}  // namespace dpdk`
- Use `std::unreachable()` after exhaustive enum switch
- Prefer `std::format_to` over string concatenation
- Member naming: `snake_case_` with trailing underscore per project style, or `m_camelCase` if matching existing formatters
