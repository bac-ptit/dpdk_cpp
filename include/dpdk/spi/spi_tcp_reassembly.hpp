#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <unordered_map>
#include <vector>

#include "dpdk/config/dpdk_config.hpp"
#include "dpdk/spi/spi_rule_engine.hpp"

namespace dpdk::spi {

/// Result of adding one TCP segment to the bounded inspection stream.
enum class TcpReassemblyStatus : std::uint8_t {
  kDisabled,
  kWaiting,
  kReady,
  kConflictingOverlap,
  kResourceLimit,
};

struct TcpReassemblyResult {
  TcpReassemblyStatus status{TcpReassemblyStatus::kDisabled};
  std::span<const unsigned char> contiguous_payload{};
};

/// Per-worker, bounded TCP reassembly for L7 inspection. It is deliberately
/// not a TCP endpoint: it never sends ACKs and only retains enough payload to
/// inspect a request prefix safely.
class TcpStreamReassembler final {
 public:
  explicit TcpStreamReassembler(const TcpReassemblyConfig& config,
                                std::uint64_t tsc_hz) noexcept;

  [[nodiscard]] TcpReassemblyResult Insert(
      const PacketMetadata& metadata, std::span<const unsigned char> payload,
      std::uint64_t now_tsc) noexcept;

  void PurgeExpired(std::uint64_t now_tsc) noexcept;

 private:
  struct Endpoint {
    std::array<std::uint8_t, 16> address{};
    std::uint16_t port{};

    [[nodiscard]] friend bool operator==(const Endpoint&, const Endpoint&) = default;
  };

  struct StreamKey {
    Endpoint first{};
    Endpoint second{};
    IpVersion version{IpVersion::kIpv4};

    [[nodiscard]] friend bool operator==(const StreamKey&, const StreamKey&) = default;
  };

  struct StreamKeyHash {
    [[nodiscard]] std::size_t operator()(const StreamKey& key) const noexcept;
  };

  struct PendingSegment {
    std::uint32_t sequence{};
    std::vector<unsigned char> payload;
  };

  struct DirectionState {
    bool base_known{false};
    std::uint32_t base_sequence{};
    std::uint32_t next_sequence{};
    std::vector<unsigned char> contiguous;
    std::vector<PendingSegment> pending;
  };

  struct StreamState {
    std::array<DirectionState, 2> directions;
    std::uint64_t last_seen_tsc{};
  };

  [[nodiscard]] static std::pair<StreamKey, std::size_t> MakeKey(
      const PacketMetadata& metadata) noexcept;
  [[nodiscard]] static bool EndpointLess(const Endpoint& lhs,
                                         const Endpoint& rhs) noexcept;
  [[nodiscard]] static std::size_t StateBytes(const StreamState& state) noexcept;
  [[nodiscard]] static bool IsStreamStart(std::span<const unsigned char> payload) noexcept;
  [[nodiscard]] static std::int32_t SequenceDistance(
      std::uint32_t lhs, std::uint32_t rhs) noexcept;

  [[nodiscard]] TcpReassemblyStatus AddSegment(
      DirectionState& direction, std::uint32_t sequence,
      std::span<const unsigned char> payload) noexcept;
  [[nodiscard]] TcpReassemblyStatus QueuePending(
      DirectionState& direction, std::uint32_t sequence,
      std::span<const unsigned char> payload) noexcept;
  [[nodiscard]] TcpReassemblyStatus AppendAndDrain(
      DirectionState& direction, std::uint32_t sequence,
      std::span<const unsigned char> payload) noexcept;
  [[nodiscard]] TcpReassemblyStatus VerifyOverlap(
      const DirectionState& direction, std::uint32_t sequence,
      std::span<const unsigned char> payload) const noexcept;
  [[nodiscard]] bool HasCapacity(std::size_t additional) const noexcept;
  void AccountAdd(std::size_t bytes) noexcept;
  void AccountRemove(const StreamState& state) noexcept;

  TcpReassemblyConfig config_;
  std::uint64_t timeout_cycles{};
  std::size_t buffered_bytes_{};
  std::size_t memory_budget_bytes_{};
  std::unordered_map<StreamKey, StreamState, StreamKeyHash> streams_;
};

}  // namespace dpdk::spi
