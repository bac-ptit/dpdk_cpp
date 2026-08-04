#pragma once

#include <arpa/inet.h>

#include <array>
#include <cstdint>
#include <cstring>
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

/// Format an IPv6 address array as text.
[[nodiscard]] inline auto FormatIpv6(const std::array<std::uint8_t, 16>& ip, std::format_context& ctx) noexcept {
  in6_addr addr{};
  std::memcpy(&addr.s6_addr, ip.data(), 16);
  char buf[INET6_ADDRSTRLEN]{};
  inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
  return std::format_to(ctx.out(), "{}", buf);
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
  static auto format(const dpdk::spi::PacketMetadata& m, std::format_context& ctx) noexcept {
    auto out = std::format_to(ctx.out(), "{} src=", m.protocol);
    if (m.ip_version == dpdk::spi::IpVersion::kIpv4) {
      out = dpdk::FormatIpv4(rte_be_to_cpu_32(m.source_ip_be), ctx);
      out = std::format_to(out, ":{}", rte_be_to_cpu_16(m.source_port_be));
      out = std::format_to(out, " dst=");
      out = dpdk::FormatIpv4(rte_be_to_cpu_32(m.destination_ip_be), ctx);
      out = std::format_to(out, ":{}", rte_be_to_cpu_16(m.destination_port_be));
    } else {
      out = dpdk::FormatIpv6(m.source_ip6_address, ctx);
      out = std::format_to(out, ":{}", rte_be_to_cpu_16(m.source_port_be));
      out = std::format_to(out, " dst=");
      out = dpdk::FormatIpv6(m.destination_ip6_address, ctx);
      out = std::format_to(out, ":{}", rte_be_to_cpu_16(m.destination_port_be));
    }
    if (m.hostname != nullptr && m.hostname_length > 0) {
      out = std::format_to(out, " host={}", std::string_view(m.hostname, m.hostname_length));
    }
    return out;
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
                          "flow_cache_hits={} dpi_cache_hits={} dpi_cache_misses={} "
                          "dpi_skipped_by_spi={} dpi_skipped_by_link={} flow_table_full={} "
                          "pressure_evictions={} flow_table_resizes={}",
                          s.received, s.transmitted, s.parsed, s.matched, s.unknown, s.malformed, s.dropped,
                          s.dropped_by_rule, s.flow_cache_hits, s.dpi_cache_hits, s.dpi_cache_misses,
                          s.dpi_skipped_by_spi, s.dpi_skipped_by_link, s.flow_table_full,
                          s.pressure_evictions, s.flow_table_resizes);
  }
};
