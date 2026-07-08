#pragma once

#include <cstdint>
#include <format>
#include <string_view>
#include <utility>

#include "dpdk/dpdk_environment.hpp"
#include "dpdk/spi/spi_pipeline.hpp"
#include "dpdk/spi/spi_rule_engine.hpp"

namespace dpdk {

/// Format an IPv4 address in host byte order as "A.B.C.D".
[[nodiscard]] inline auto FormatIpv4(std::uint32_t ip, std::format_context& ctx) noexcept {
  return std::format_to(ctx.out(), "{}.{}.{}.{}", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
}

}  // namespace dpdk

// --- DpdkError formatter ---

template <>
struct std::formatter<dpdk::DpdkError> : std::formatter<std::string_view> {
  auto format(const dpdk::DpdkError& err, std::format_context& ctx) const noexcept {
    if (err.dpdk_errno != 0) {
      return std::format_to(ctx.out(), "{} (errno={})", err.message, err.dpdk_errno);
    }
    return std::format_to(ctx.out(), "{}", err.message);
  }
};

// --- Protocol formatter ---

template <>
struct std::formatter<dpdk::spi::Protocol> : std::formatter<std::string_view> {
  auto format(dpdk::spi::Protocol proto, std::format_context& ctx) const noexcept {
    switch (proto) {
      case dpdk::spi::Protocol::kTcp:
        return std::format_to(ctx.out(), "TCP");
      case dpdk::spi::Protocol::kUdp:
        return std::format_to(ctx.out(), "UDP");
    }
    std::unreachable();
  }
};

// --- PacketMetadata formatter ---

template <>
struct std::formatter<dpdk::spi::PacketMetadata> : std::formatter<std::string_view> {
  auto format(const dpdk::spi::PacketMetadata& m, std::format_context& ctx) const noexcept {
    auto out = std::format_to(ctx.out(), "{} src=", m.protocol);
    out = dpdk::FormatIpv4(m.source_ip_address, ctx);
    out = std::format_to(out, ":{}", m.source_port);
    out = std::format_to(out, " dst=");
    out = dpdk::FormatIpv4(m.destination_ip_address, ctx);
    return std::format_to(out, ":{}", m.destination_port);
  }
};

// --- ClassificationResult formatter ---

template <>
struct std::formatter<dpdk::spi::ClassificationResult> : std::formatter<std::string_view> {
  auto format(const dpdk::spi::ClassificationResult& r, std::format_context& ctx) const noexcept {
    if (!r.matched) {
      return std::format_to(ctx.out(), "no-match");
    }
    return std::format_to(ctx.out(), "group={} label=\"{}\" action={} prec={}", r.group_name, r.label,
                          r.action == dpdk::spi::Action::kDrop ? "drop" : "forward", r.group_precedence);
  }
};

// --- PipelineStats formatter ---

template <>
struct std::formatter<dpdk::spi::PipelineStats> : std::formatter<std::string_view> {
  auto format(const dpdk::spi::PipelineStats& s, std::format_context& ctx) const noexcept {
    return std::format_to(ctx.out(),
                          "received={} transmitted={} parsed={} matched={} "
                          "unknown={} malformed={} dropped={} dropped_by_rule={} "
                          "flow_cache_hits={} dpi_cache_hits={} dpi_cache_misses={}",
                          s.received, s.transmitted, s.parsed, s.matched, s.unknown, s.malformed, s.dropped,
                          s.dropped_by_rule, s.flow_cache_hits, s.dpi_cache_hits, s.dpi_cache_misses);
  }
};
