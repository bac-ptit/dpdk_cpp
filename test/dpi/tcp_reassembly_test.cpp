#include "dpdk/spi/spi_packet_parser.hpp"
#include "dpdk/spi/spi_tcp_reassembly.hpp"

#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace {

[[gnu::always_inline]] void Require(bool condition) noexcept {
  if (!condition) [[unlikely]] {
    std::abort();
  }
}

[[nodiscard]] dpdk::spi::PacketMetadata MakeMetadata(std::uint32_t sequence) {
  return {
      .source_ip_be = 0x010200C0U,
      .destination_ip_be = 0x026433C6U,
      .source_port_be = 0x3930U,
      .destination_port_be = 0x5000U,
      .tcp_sequence = sequence,
      .protocol = dpdk::spi::Protocol::kTcp,
      .ip_version = dpdk::spi::IpVersion::kIpv4,
  };
}

[[nodiscard]] std::span<const unsigned char> Bytes(std::string_view text) {
  return {reinterpret_cast<const unsigned char*>(text.data()), text.size()};
}

void TestInOrderAndRetransmission() {
  dpdk::TcpReassemblyConfig config{.enabled = true, .memory_budget_mb = 1};
  dpdk::spi::TcpStreamReassembler reassembler{config, 1'000'000'000ULL};
  constexpr std::string_view first{"GET / HTTP/1.1\r\nHo"};
  constexpr std::string_view second{"st: example.test\r\n\r\n"};

  const auto first_result{reassembler.Insert(MakeMetadata(100), Bytes(first), 1)};
  Require(first_result.status == dpdk::spi::TcpReassemblyStatus::kReady);
  Require(!dpdk::spi::ExtractHttpHost(first_result.contiguous_payload));

  const auto second_result{reassembler.Insert(
      MakeMetadata(100 + static_cast<std::uint32_t>(first.size())), Bytes(second), 2)};
  const auto host{dpdk::spi::ExtractHttpHost(second_result.contiguous_payload)};
  Require(host.has_value());
  Require(std::string_view{host->first, host->second} == "example.test");

  const auto retransmission{reassembler.Insert(MakeMetadata(100), Bytes(first), 3)};
  Require(retransmission.status == dpdk::spi::TcpReassemblyStatus::kWaiting);
}

void TestOutOfOrderAndConflict() {
  dpdk::TcpReassemblyConfig config{.enabled = true, .memory_budget_mb = 1};
  dpdk::spi::TcpStreamReassembler reassembler{config, 1'000'000'000ULL};
  constexpr std::string_view first{"GET / HTTP/1.1\r\nHo"};
  constexpr std::string_view second{"st: example.test\r\n\r\n"};

  const auto waiting{reassembler.Insert(
      MakeMetadata(500 + static_cast<std::uint32_t>(first.size())), Bytes(second), 1)};
  Require(waiting.status == dpdk::spi::TcpReassemblyStatus::kWaiting);
  const auto complete{reassembler.Insert(MakeMetadata(500), Bytes(first), 2)};
  const auto host{dpdk::spi::ExtractHttpHost(complete.contiguous_payload)};
  Require(host.has_value());
  Require(std::string_view{host->first, host->second} == "example.test");

  constexpr std::string_view conflicting{"BAD / HTTP/1.1\r\nHo"};
  const auto conflict{reassembler.Insert(MakeMetadata(500), Bytes(conflicting), 3)};
  Require(conflict.status == dpdk::spi::TcpReassemblyStatus::kConflictingOverlap);
}

}  // namespace

int main() {
  TestInOrderAndRetransmission();
  TestOutOfOrderAndConflict();
}
