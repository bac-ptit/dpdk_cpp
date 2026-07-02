# Custom Format Specifier Pattern

Full `parse()` + `format()` pattern for types needing user-controlled output modes with sub-formatter delegation.

## Pattern: OutputType Enum + Multi-Colon Sub-Formatter

```cpp
template <>
struct std::formatter<KeyValue> {
public:
  constexpr auto parse(auto& context) {
    std::string key_format, value_format;
    size_t colon_count{0};
    auto iter{begin(context)};

    for (; iter != end(context); ++iter) {
      if (*iter == '}') { break; }

      if (colon_count == 0) {
        // First segment: output type specifier
        switch (*iter) {
          case 'k': case 'K':  m_output_type = OutputType::KeyOnly;   break;
          case 'v': case 'V':  m_output_type = OutputType::ValueOnly; break;
          case 'b': case 'B':  m_output_type = OutputType::KeyAndValue; break;
          case ':':            ++colon_count; break;
          default:             throw std::format_error{"Invalid KeyValue format."};
        }
      } else if (colon_count == 1) {
        // Second segment: key sub-formatter spec
        if (*iter == ':') { ++colon_count; }
        else { key_format += *iter; }
      } else if (colon_count == 2) {
        // Third segment: value sub-formatter spec
        value_format += *iter;
      }
    }

    // Validate sub-formatters by parsing them
    if (!key_format.empty()) {
      std::format_parse_context ctx{key_format};
      m_key_formatter.parse(ctx);
    }
    if (!value_format.empty()) {
      std::format_parse_context ctx{value_format};
      m_value_formatter.parse(ctx);
    }

    if (iter != end(context) && *iter != '}') {
      throw std::format_error{"Invalid KeyValue format."};
    }
    return iter;
  }

  auto format(const KeyValue& kv, auto& ctx) const {
    switch (m_output_type) {
      using enum OutputType;
      case KeyOnly:
        return m_key_formatter.format(kv.key, ctx);
      case ValueOnly:
        return m_value_formatter.format(kv.value, ctx);
      default: {  // KeyAndValue
        auto out = m_key_formatter.format(kv.key, ctx);
        out = std::format_to(out, " - ");
        return m_value_formatter.format(kv.value, ctx);
      }
    }
  }

private:
  enum class OutputType { KeyOnly, ValueOnly, KeyAndValue };
  OutputType m_output_type{OutputType::KeyAndValue};
  std::formatter<std::string> m_key_formatter;
  std::formatter<int>         m_value_formatter;
};
```

## Format Specifier Syntax

```
{:<output-type>[:<key-spec>[:<value-spec>]]}
```

| Specifier | Meaning |
|-----------|---------|
| `{}` or `{:b}` | Full output: `key - value` |
| `{:k}` | Key only |
| `{:v}` | Value only |
| `{:k:>+10}` | Key only, with key's own format spec `>+10` |
| `{:b:.3f:.2e}` | Full output, key with `.3f`, value with `.2e` |

## How It Works

1. `parse()` scans the format string character by character
2. Before the first `:` — reads the output type character (`k`/`v`/`b`)
3. Between first and second `:` — accumulates key sub-formatter spec
4. After second `:` — accumulates value sub-formatter spec
5. Sub-formatter specs are validated by creating a temporary `format_parse_context` and calling `.parse()` on the respective `std::formatter<T>`
6. `format()` switches on `m_output_type` and delegates to sub-formatters

## Adapting to Other Types

To adapt this pattern for a different compound type:

1. Change `KeyValue` to your type name
2. Change `m_key_formatter` / `m_value_formatter` types to match your sub-field types
3. Adjust `format()` to access your type's fields
4. Add/remove `OutputType` variants if you need more or fewer modes
5. If sub-fields share the same type, both sub-formatters can be the same `std::formatter<T>`

## Validation Script

After writing a formatter, validate it compiles:

```cpp
// Quick smoke test (in a .cpp file or scratch):
static_assert(std::formattable<KeyValue, char>);
auto s = std::format("{}", KeyValue{.key="hello", .value=42});
auto s2 = std::format("{:k}", KeyValue{.key="hello", .value=42});
auto s3 = std::format("{:v}", KeyValue{.key="hello", .value=42});
```
