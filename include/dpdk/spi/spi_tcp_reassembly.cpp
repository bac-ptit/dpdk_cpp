#include "dpdk/spi/spi_tcp_reassembly.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace dpdk::spi {
constexpr std::size_t kBytesPerMiB{1024U * 1024U};

bool TcpStreamReassembler::EndpointLess(const Endpoint& lhs,
                                        const Endpoint& rhs) noexcept {
  const int address_order{std::memcmp(lhs.address.data(), rhs.address.data(), lhs.address.size())};
  return address_order < 0 || (address_order == 0 && lhs.port < rhs.port);
}

std::size_t TcpStreamReassembler::StateBytes(const StreamState& state) noexcept {
  std::size_t bytes{};
  for (const auto& direction : state.directions) {
    bytes += direction.contiguous.size();
    for (const auto& pending : direction.pending) {
      bytes += pending.payload.size();
    }
  }
  return bytes;
}

TcpStreamReassembler::TcpStreamReassembler(const TcpReassemblyConfig& config,
                                           std::uint64_t tsc_hz) noexcept
    : config_{config},
      timeout_cycles{static_cast<std::uint64_t>(config.idle_timeout_sec) * tsc_hz},
      memory_budget_bytes_{static_cast<std::size_t>(config.memory_budget_mb) * kBytesPerMiB} {
  streams_.reserve(config.max_concurrent_streams);
}

std::size_t TcpStreamReassembler::StreamKeyHash::operator()(const StreamKey& key) const noexcept {
  constexpr std::size_t kOffset{1469598103934665603ULL};
  constexpr std::size_t kPrime{1099511628211ULL};
  std::size_t hash{kOffset};
  const auto mix{[&hash](const void* data, std::size_t size) noexcept {
    const auto* bytes{static_cast<const unsigned char*>(data)};
    for (std::size_t i{}; i < size; ++i) {
      hash ^= bytes[i];
      hash *= kPrime;
    }
  }};
  mix(&key, sizeof(key));
  return hash;
}

std::pair<TcpStreamReassembler::StreamKey, std::size_t>
TcpStreamReassembler::MakeKey(const PacketMetadata& metadata) noexcept {
  Endpoint source{.port = metadata.source_port_be};
  Endpoint destination{.port = metadata.destination_port_be};
  if (metadata.ip_version == IpVersion::kIpv4) {
    std::memcpy(source.address.data(), &metadata.source_ip_be, sizeof(metadata.source_ip_be));
    std::memcpy(destination.address.data(), &metadata.destination_ip_be, sizeof(metadata.destination_ip_be));
  } else {
    source.address = metadata.source_ip6_address;
    destination.address = metadata.destination_ip6_address;
  }
  const bool source_first{EndpointLess(source, destination)};
  return {StreamKey{.first = source_first ? source : destination,
                    .second = source_first ? destination : source,
                    .version = metadata.ip_version}, source_first ? 0UZ : 1UZ};
}

bool TcpStreamReassembler::IsStreamStart(std::span<const unsigned char> payload) noexcept {
  if (payload.size() >= 6U && payload[0] == 0x16U && payload[1] == 0x03U && payload[5] == 0x01U) {
    return true;
  }
  constexpr std::array<std::string_view, 7> methods{
      "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH "};
  return std::ranges::any_of(methods, [&payload](std::string_view method) {
    return payload.size() >= method.size() &&
           std::equal(method.begin(), method.end(), payload.begin());
  });
}

std::int32_t TcpStreamReassembler::SequenceDistance(std::uint32_t lhs,
                                                     std::uint32_t rhs) noexcept {
  return static_cast<std::int32_t>(lhs - rhs);
}

bool TcpStreamReassembler::HasCapacity(std::size_t additional) const noexcept {
  return additional <= memory_budget_bytes_ - std::min(memory_budget_bytes_, buffered_bytes_);
}

void TcpStreamReassembler::AccountAdd(std::size_t bytes) noexcept {
  buffered_bytes_ += bytes;
}

void TcpStreamReassembler::AccountRemove(const StreamState& state) noexcept {
  buffered_bytes_ -= std::min(buffered_bytes_, StateBytes(state));
}

TcpReassemblyStatus TcpStreamReassembler::VerifyOverlap(
    const DirectionState& direction, std::uint32_t sequence,
    std::span<const unsigned char> payload) const noexcept {
  const auto offset{SequenceDistance(sequence, direction.base_sequence)};
  if (offset < 0) {
    return config_.drop_conflicting_overlap ? TcpReassemblyStatus::kConflictingOverlap
                                             : TcpReassemblyStatus::kWaiting;
  }
  const auto begin{static_cast<std::size_t>(offset)};
  if (begin >= direction.contiguous.size()) {
    return TcpReassemblyStatus::kWaiting;
  }
  const auto overlap{std::min(payload.size(), direction.contiguous.size() - begin)};
  if (!std::equal(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(overlap),
                  direction.contiguous.begin() + static_cast<std::ptrdiff_t>(begin))) {
    return config_.drop_conflicting_overlap ? TcpReassemblyStatus::kConflictingOverlap
                                             : TcpReassemblyStatus::kWaiting;
  }
  return TcpReassemblyStatus::kWaiting;
}

TcpReassemblyStatus TcpStreamReassembler::QueuePending(
    DirectionState& direction, std::uint32_t sequence,
    std::span<const unsigned char> payload) noexcept {
  if (direction.pending.size() >= config_.max_out_of_order_segments || !HasCapacity(payload.size())) {
    return TcpReassemblyStatus::kResourceLimit;
  }
  for (const auto& pending : direction.pending) {
    if (pending.sequence == sequence) {
      return pending.payload.size() == payload.size() &&
                     std::equal(pending.payload.begin(), pending.payload.end(), payload.begin())
                 ? TcpReassemblyStatus::kWaiting
                 : TcpReassemblyStatus::kConflictingOverlap;
    }
  }
  direction.pending.push_back(PendingSegment{.sequence = sequence,
                                              .payload = {payload.begin(), payload.end()}});
  AccountAdd(payload.size());
  return TcpReassemblyStatus::kWaiting;
}

TcpReassemblyStatus TcpStreamReassembler::AppendAndDrain(
    DirectionState& direction, std::uint32_t sequence,
    std::span<const unsigned char> payload) noexcept {
  if (!HasCapacity(payload.size()) || direction.contiguous.size() + payload.size() >
                                          config_.max_buffered_bytes_per_direction) {
    return TcpReassemblyStatus::kResourceLimit;
  }
  direction.contiguous.insert(direction.contiguous.end(), payload.begin(), payload.end());
  AccountAdd(payload.size());
  direction.next_sequence = sequence + static_cast<std::uint32_t>(payload.size());

  bool progressed{true};
  while (progressed) {
    progressed = false;
    for (auto it{direction.pending.begin()}; it != direction.pending.end(); ++it) {
      if (it->sequence != direction.next_sequence) {
        continue;
      }
      const auto pending_size{it->payload.size()};
      if (direction.contiguous.size() + pending_size > config_.max_buffered_bytes_per_direction) {
        return TcpReassemblyStatus::kResourceLimit;
      }
      direction.contiguous.insert(direction.contiguous.end(), it->payload.begin(), it->payload.end());
      direction.next_sequence += static_cast<std::uint32_t>(pending_size);
      direction.pending.erase(it);
      progressed = true;
      break;
    }
  }
  return TcpReassemblyStatus::kReady;
}

TcpReassemblyStatus TcpStreamReassembler::AddSegment(
    DirectionState& direction, std::uint32_t sequence,
    std::span<const unsigned char> payload) noexcept {
  if (payload.empty()) {
    return TcpReassemblyStatus::kWaiting;
  }
  if (!direction.base_known) {
    if (!IsStreamStart(payload)) {
      return QueuePending(direction, sequence, payload);
    }
    direction.base_known = true;
    direction.base_sequence = sequence;
    direction.next_sequence = sequence;
  }
  const auto distance{SequenceDistance(sequence, direction.next_sequence)};
  if (distance == 0) {
    return AppendAndDrain(direction, sequence, payload);
  }
  if (distance > 0) {
    return QueuePending(direction, sequence, payload);
  }
  const auto overlap{VerifyOverlap(direction, sequence, payload)};
  if (overlap == TcpReassemblyStatus::kConflictingOverlap) {
    return overlap;
  }
  const auto end_sequence{sequence + static_cast<std::uint32_t>(payload.size())};
  if (SequenceDistance(end_sequence, direction.next_sequence) <= 0) {
    return TcpReassemblyStatus::kWaiting;
  }
  const auto trim{static_cast<std::size_t>(-distance)};
  return AppendAndDrain(direction, direction.next_sequence, payload.subspan(trim));
}

TcpReassemblyResult TcpStreamReassembler::Insert(
    const PacketMetadata& metadata, std::span<const unsigned char> payload,
    std::uint64_t now_tsc) noexcept {
  if (!config_.enabled || metadata.protocol != Protocol::kTcp) {
    return {};
  }
  PurgeExpired(now_tsc);
  const auto [key, direction_index]{MakeKey(metadata)};
  auto it{streams_.find(key)};
  if (it == streams_.end()) {
    if (streams_.size() >= config_.max_concurrent_streams) {
      return {.status = TcpReassemblyStatus::kResourceLimit};
    }
    it = streams_.emplace(key, StreamState{.directions = {}, .last_seen_tsc = now_tsc}).first;
  }
  auto& state{it->second};
  state.last_seen_tsc = now_tsc;
  const auto data_sequence{metadata.tcp_sequence +
      ((metadata.tcp_flags & RTE_TCP_SYN_FLAG) != 0U ? 1U : 0U)};
  const auto status{AddSegment(state.directions[direction_index], data_sequence, payload)};
  if (status == TcpReassemblyStatus::kConflictingOverlap || status == TcpReassemblyStatus::kResourceLimit) {
    AccountRemove(state);
    streams_.erase(it);
    return {.status = status};
  }
  const auto& contiguous{state.directions[direction_index].contiguous};
  return {.status = status,
          .contiguous_payload = std::span<const unsigned char>{contiguous.data(), contiguous.size()}};
}

void TcpStreamReassembler::PurgeExpired(std::uint64_t now_tsc) noexcept {
  if (timeout_cycles == 0) {
    return;
  }
  for (auto it{streams_.begin()}; it != streams_.end();) {
    if (now_tsc - it->second.last_seen_tsc > timeout_cycles) {
      AccountRemove(it->second);
      it = streams_.erase(it);
    } else {
      ++it;
    }
  }
}

}  // namespace dpdk::spi
